# -*- coding: utf-8 -*-
"""
BridgeDelay — unified Maps-API + SMS webhook
-------------------------------------------
* Polling loop (5-min): calls Google Routes API, computes delay and pushes
  thresholded SMS alerts to registered users.
* Flask app (run under gunicorn) with:
    • /                 health probe 200 OK
    • /api/status      JSON snapshot of last poll
    • /api/signup      POST to register a phone (threshold/windows)
    • /sms             Twilio webhook: STATUS | THRESHOLD n | WINDOW HH:MM-HH:MM[,HH:MM-HH:MM]
"""

from __future__ import annotations

import os
import time
import json
import argparse
import re
import threading
from datetime import datetime
from typing import Any, Dict, List

import requests
from flask import Flask, request, abort, jsonify, Response
from flask_cors import CORS  # no per-route decorator needed with after_request
from twilio.rest import Client
from twilio.twiml.messaging_response import MessagingResponse

# ── Azure Tables (Managed Identity first, conn string fallback) ────────────
from azure.identity import DefaultAzureCredential
from azure.data.tables import TableServiceClient

# Local timezone for window checks
from zoneinfo import ZoneInfo

# ──────────────────── Flask setup ──────────────────────────────────────────
app = Flask(__name__)  # gunicorn target →  bridge_app:app

# Allow our site origins (CORS is origin-only; paths like /signup don't matter)
ALLOWED_ORIGINS = {
    "https://northvanupdates.com",
    "https://www.northvanupdates.com",
}

# Enable CORS globally for /api/* (Flask-CORS), and also add a safety net below.
CORS(
    app,
    resources={r"/api/*": {
        "origins": list(ALLOWED_ORIGINS),
        "allow_headers": ["Content-Type"],
        "methods": ["GET", "POST", "OPTIONS"],
        "max_age": 600
    }}
)

# Safety net: ensure every /api/* response (including OPTIONS) has CORS headers
@app.after_request
def add_cors_headers(resp):
    if request.path.startswith("/api/"):
        origin = request.headers.get("Origin", "")
        if origin in ALLOWED_ORIGINS:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp

# Catch-all preflight for any /api/* path
@app.route("/api/<path:_any>", methods=["OPTIONS"])
def any_api_options(_any):
    return ("", 204)

# ──────────────────── Config — ENV vars ────────────────────────────────────
GOOGLE_KEY   = os.getenv("GOOGLE_MAPS_API_KEY")
ACCOUNT_SID  = os.getenv("TWILIO_ACCOUNT_SID")
AUTH_TOKEN   = os.getenv("TWILIO_AUTH_TOKEN")
FROM_NUMBER  = os.getenv("TWILIO_FROM_NUMBER")
TO_NUMBERS   = os.getenv("TO_NUMBERS", "")  # optional: one-time seed only

# Managed Identity endpoint for Tables (preferred), with local-dev fallback
TABLES_ENDPOINT = os.getenv("TABLES_ENDPOINT")  # e.g. https://<acct>.table.core.windows.net
AZURE_CONN      = os.getenv("AZURE_STORAGE_CONNECTION_STRING")  # optional for local dev

# Background polling configuration
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "300"))  # seconds
ENABLE_POLLING = os.getenv("ENABLE_POLLING", "1").lower() not in ("0", "false", "no")

# Google Routes API endpoint + headers
ROUTES_URL = "https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix"
HEADERS = {
    "Content-Type": "application/json",
    "X-Goog-Api-Key": GOOGLE_KEY,
    "X-Goog-FieldMask": "originIndex,destinationIndex,duration,staticDuration",
}

# Lions Gate coords (lat, lng)
NB_START = (49.283260, -123.119297)
NB_END   = (49.324345, -123.122962)
SB_START = (49.324432, -123.122765)
SB_END   = (49.292738, -123.133985)

# Baselines (minutes)
NB_BASE_MIN = 9
SB_BASE_MIN = 4

# Persistence targets
STATE_FILE         = "last_status.json"    # fallback
USER_SETTINGS_FILE = "user_settings.json"  # fallback
STATE_TABLE        = "lastStatus"
USER_TABLE         = "userSettings"

# Emoji per severity
SEV_EMOJI = {0: "🟢", 1: "🟡", 2: "🟠", 3: "🔴"}

# ──────────────────── Helper functions ─────────────────────────────────────
def _latlng(pair):
    lat, lng = pair
    return {"latLng": {"latitude": lat, "longitude": lng}}

def get_delays() -> Dict[str, Dict[str, int]]:
    """Return live, base (free-flow) and delay minutes for NB & SB."""
    body: Dict[str, Any] = {
        "origins": [
            {"waypoint": {"location": _latlng(NB_START)}},  # originIndex = 0
            {"waypoint": {"location": _latlng(SB_START)}},  # originIndex = 1
        ],
        "destinations": [
            {"waypoint": {"location": _latlng(NB_END)}},    # destinationIndex = 0
            {"waypoint": {"location": _latlng(SB_END)}},    # destinationIndex = 1
        ],
        "travelMode": "DRIVE",
        "routingPreference": "TRAFFIC_AWARE_OPTIMAL",
    }
    r = requests.post(ROUTES_URL, headers=HEADERS, json=body, timeout=10)
    r.raise_for_status()
    items = r.json()  # order not guaranteed

    # Map by (originIndex, destinationIndex)
    by_idx = {(it["originIndex"], it["destinationIndex"]): it for it in items}

    nb = by_idx[(0, 0)]
    sb = by_idx[(1, 1)]

    def to_min(seconds_str: str) -> float:
        # API returns like "534s" or "534.2s"
        return float(seconds_str.rstrip("s")) / 60.0

    def build(elem, fallback_base_min: int):
        live_min = to_min(elem["duration"])
        base_min = to_min(elem["staticDuration"]) if "staticDuration" in elem else float(fallback_base_min)
        delay_min = max(0.0, live_min - base_min)  # avoid negative delay

        return {
            "live": round(live_min),
            "base": round(base_min),
            "delay": round(delay_min),
        }

    return {
        "NB": build(nb, NB_BASE_MIN),
        "SB": build(sb, SB_BASE_MIN),
    }


# ──────────────────── Persistence helpers (Tables + fallback) ─────────────
def _get_table_client(name: str):
    """
    Prefer Managed Identity using TABLES_ENDPOINT.
    Fallback to connection string if provided (e.g., local dev).
    Return None to trigger JSON file fallback when nothing is configured.
    """
    svc = None
    if TABLES_ENDPOINT:
        cred = DefaultAzureCredential()
        svc = TableServiceClient(endpoint=TABLES_ENDPOINT, credential=cred)
    elif AZURE_CONN:
        svc = TableServiceClient.from_connection_string(AZURE_CONN)
    else:
        return None

    try:
        svc.create_table_if_not_exists(name)
    except Exception:
        pass
    return svc.get_table_client(name)

def load_snapshot() -> Dict[str, Any]:
    tc = _get_table_client(STATE_TABLE)
    if tc:
        try:
            ent = tc.get_entity(partition_key="state", row_key="latest")
            return json.loads(ent["data"])
        except Exception:
            return {}
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_snapshot(snap: Dict[str, Any]):
    tc = _get_table_client(STATE_TABLE)
    if tc:
        ent = {"PartitionKey": "state", "RowKey": "latest", "data": json.dumps(snap)}
        tc.upsert_entity(ent)
        return
    with open(STATE_FILE, "w") as f:
        json.dump(snap, f)

def load_user_settings() -> List[Dict[str, Any]]:
    tc = _get_table_client(USER_TABLE)
    if tc:
        users: List[Dict[str, Any]] = []
        for ent in tc.query_entities("PartitionKey eq 'user'"):
            users.append(
                {
                    "phone": ent["RowKey"],
                    "active": bool(ent.get("active", True)),
                    "threshold": int(ent.get("threshold", 0)),
                    "windows": json.loads(ent.get("windows", "[]")),
                }
            )
        return users
    try:
        with open(USER_SETTINGS_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_user_settings(settings: List[Dict[str, Any]]):
    tc = _get_table_client(USER_TABLE)
    if tc:
        for u in settings:
            ent = {
                "PartitionKey": "user",
                "RowKey": u["phone"],
                "active": u.get("active", True),
                "threshold": u.get("threshold", 0),
                "windows": json.dumps(u.get("windows", [])),
            }
            tc.upsert_entity(ent)
        return
    with open(USER_SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)

def get_user_settings():
    # Table is the source of truth — no env fallback at runtime.
    return load_user_settings()

# One-time bootstrap: seed TO_NUMBERS into table if table is empty
_bootstrap_done = False
def bootstrap_env_numbers_once():
    global _bootstrap_done
    if _bootstrap_done:
        return
    _bootstrap_done = True

    tc = _get_table_client(USER_TABLE)
    if not tc:
        return  # running with file fallback; nothing to seed

    has_rows = False
    for _ in tc.query_entities("PartitionKey eq 'user'"):
        has_rows = True
        break
    if has_rows:
        return

    nums = [n.strip() for n in TO_NUMBERS.split(",") if n.strip()]
    for num in nums:
        tc.upsert_entity({
            "PartitionKey": "user",
            "RowKey": num,
            "active": True,
            "threshold": 0,
            "windows": json.dumps([{"start": "00:00", "end": "23:59"}]),
        })
    if nums:
        print(f"Seeded {len(nums)} numbers from TO_NUMBERS into {USER_TABLE}.")

# ──────────────────── Twilio helpers ───────────────────────────────────────
def send_sms(body: str, to: str) -> str:
    client = Client(ACCOUNT_SID, AUTH_TOKEN)
    msg = client.messages.create(body=body, from_=FROM_NUMBER, to=to)
    return msg.sid

# ──────────────────── Business logic ───────────────────────────────────────
def severity_level(delay: int) -> int:
    if delay <= 5:
        return 0
    elif delay <= 15:
        return 1
    elif delay <= 30:
        return 2
    else:
        return 3

def within_window(now: str, windows):
    return any(w["start"] <= now <= w["end"] for w in windows)

def check_and_notify():
    current = get_delays()
    prev    = load_snapshot()

    nb_s, sb_s = current["NB"], current["SB"]
    nb_sev = severity_level(nb_s["delay"])
    sb_sev = severity_level(sb_s["delay"])
    old_nb_sev = severity_level(prev.get("NB", {}).get("delay", -1)) if prev else None
    old_sb_sev = severity_level(prev.get("SB", {}).get("delay", -1)) if prev else None

    if nb_sev == old_nb_sev and sb_sev == old_sb_sev:
        print("No severity change; skipping.")
        return

    save_snapshot(current)

    body = (
        f"🚦 Lions Gate update\n"
        f"NB: {nb_s['live']}m (base {nb_s['base']} +{nb_s['delay']})\n"
        f"SB: {sb_s['live']}m (base {sb_s['base']} +{sb_s['delay']})"
    )

    # Use Vancouver local time for windows
    now = datetime.now(ZoneInfo("America/Vancouver")).strftime("%H:%M")

    for u in get_user_settings():
        if not u.get("active", True):
            continue
        if (nb_s["delay"] < u["threshold"] and sb_s["delay"] < u["threshold"]):
            continue
        if not within_window(now, u["windows"]):
            continue
        sid = send_sms(body, u["phone"])
        print(f"🔔 Sent to {u['phone']}: {sid}")

# ──────────────────── Background scheduler ────────────────────────────────
_poll_lock = threading.Lock()
_poll_started = False

def start_background_polling():
    """Launch a daemon thread that periodically runs check_and_notify."""
    global _poll_started
    if _poll_started:
        return
    _poll_started = True

    # Seed env numbers once into the table if it's empty.
    bootstrap_env_numbers_once()

    if not ENABLE_POLLING or POLL_INTERVAL <= 0:
        print("Background polling disabled.")
        return

    def loop():
        while True:
            with _poll_lock:
                try:
                    check_and_notify()
                except Exception as e:
                    print("Polling error:", e)
            time.sleep(POLL_INTERVAL)

    threading.Thread(target=loop, daemon=True).start()

# Flask 3: start background thread on first request
@app.before_request
def _start_polling() -> None:
    start_background_polling()

# ──────────────────── SMS Webhook helpers ──────────────────────────────────
def parse_windows(s: str):
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if len(parts) > 2:
        raise ValueError("Maximum two windows allowed")
    windows = []
    for part in parts:
        try:
            start, end = part.split("-", 1)
            if not re.match(r"^\d{2}:\d{2}$", start) or not re.match(r"^\d{2}:\d{2}$", end):
                raise ValueError
            if start >= end:
                raise ValueError
        except ValueError:
            raise ValueError(f"Invalid window: '{part}'")
        windows.append({"start": start, "end": end})
    return windows

# ──────────────────── Flask routes ─────────────────────────────────────────
@app.route("/", methods=["GET"])
def health():
    return "ok", 200

@app.route("/api/status", methods=["GET"])
def status():
    snap = load_snapshot()
    return jsonify(snap if snap else {"msg": "no data yet"})

@app.route("/api/signup", methods=["POST"])
def signup():
    # (OPTIONS preflight is handled by any_api_options + after_request)
    phone = (request.json.get("phone") if request.is_json else request.form.get("phone"))
    if not phone:
        abort(400, "phone field is required")

    users = get_user_settings()
    if any(u["phone"] == phone for u in users):
        return {"msg": "already registered"}, 200

    users.append({
        "phone": phone,
        "active": True,
        "threshold": 0,
        "windows": [{"start": "00:00", "end": "23:59"}],
    })
    save_user_settings(users)
    return {"msg": "registered"}, 201

@app.route("/sms", methods=["POST"])
def sms_webhook():
    if not request.form.get("From"):
        abort(400)

    from_number = request.form["From"]
    body_raw    = request.form.get("Body", "").strip()
    parts       = body_raw.upper().split(maxsplit=1)

    users = get_user_settings()
    user  = next((u for u in users if u["phone"] == from_number), None)
    if not user:
        user = {
            "phone": from_number,
            "active": True,
            "threshold": 0,
            "windows": [{"start": "00:00", "end": "23:59"}]
        }
        users.append(user)

    resp = MessagingResponse()

    # STATUS
    if parts[0] == "STATUS":
        try:
            delays = get_delays()
            nb, sb = delays["NB"], delays["SB"]
            nb_sev, sb_sev = severity_level(nb["delay"]), severity_level(sb["delay"])
            msg = (
                f"{SEV_EMOJI[nb_sev]} NB {nb['delay']}m (base {nb['base']})\n"
                f"{SEV_EMOJI[sb_sev]} SB {sb['delay']}m (base {sb['base']})"
            )
        except Exception:
            msg = "⚠️ Couldn’t fetch delay right now."
        resp.message(msg)
        return Response(str(resp), mimetype="application/xml")

    # THRESHOLD n
    if parts[0] == "THRESHOLD" and len(parts) == 2 and parts[1].isdigit():
        user["threshold"] = int(parts[1])
        save_user_settings(users)
        resp.message(f"✅ Threshold set to {parts[1]} minutes.")

    # WINDOW HH:MM-HH:MM[,HH:MM-HH:MM]
    elif parts[0] == "WINDOW" and len(parts) == 2:
        try:
            user["windows"] = parse_windows(parts[1])
            save_user_settings(users)
            win_str = ", ".join(f"{w['start']}-{w['end']}" for w in user["windows"])
            resp.message(f"✅ Windows set to {win_str}")
        except ValueError:
            resp.message("❌ Invalid format. Use: WINDOW HH:MM-HH:MM[,HH:MM-HH:MM]")

    # HELP / LIST
    elif parts[0] in ("LIST", "HELP"):
        resp.message("Commands: STATUS | THRESHOLD n | WINDOW HH:MM-HH:MM[,HH:MM-HH:MM]")

    else:
        resp.message("Unknown command. Send HELP for options.")

    return Response(str(resp), mimetype="application/xml")

# ──────────────────── Entrypoint ───────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BridgeDelay monitor")
    parser.add_argument("--poll", action="store_true", help="Run delay check loop every 5 minutes")
    args = parser.parse_args()

    if args.poll:
        while True:
            try:
                check_and_notify()
            except Exception as e:
                print("Polling error:", e)
            time.sleep(300)

# -*- coding: utf-8 -*-
"""
BridgeDelay — unified Maps-API + SMS + OTP login (hardened)
-----------------------------------------------------------
Public endpoints (CORS-limited to your site):
  GET  /                 -> 200 OK
  GET  /api/status       -> latest snapshot
  POST /api/signup       -> create user (by phone)
  POST /api/otp/start    -> send OTP to registered phone
  POST /api/otp/verify   -> verify OTP, returns JWT if JWT_SECRET set
Protected (Bearer JWT):
  GET/POST /api/user/settings
Twilio webhook:
  POST /sms              -> validates Twilio signature; supports STATUS/THRESHOLD/WINDOW
"""

from __future__ import annotations

import os
import time
import json
import argparse
import re
import threading
import secrets
import hashlib
from datetime import datetime
from typing import Any, Dict, List

import requests
from flask import Flask, request, abort, jsonify, Response, g
from flask_cors import CORS
from functools import wraps

from twilio.rest import Client
from twilio.twiml.messaging_response import MessagingResponse
from twilio.request_validator import RequestValidator

# Azure Tables
from azure.identity import DefaultAzureCredential
from azure.data.tables import TableServiceClient

# Local timezone for window checks
from zoneinfo import ZoneInfo

# Optional JWT for sessions
try:
    import jwt  # PyJWT
except Exception:
    jwt = None

# ──────────────────── Flask setup ──────────────────────────────────────────
app = Flask(__name__)  # gunicorn target → bridge_app:app

ALLOWED_ORIGINS = {
    "https://northvanupdates.com",
    "https://www.northvanupdates.com",
}

CORS(
    app,
    resources={r"/api/*": {
        "origins": list(ALLOWED_ORIGINS),
        "allow_headers": ["Content-Type", "Authorization"],
        "methods": ["GET", "POST", "OPTIONS"],
        "max_age": 600
    }}
)

@app.after_request
def add_cors_headers(resp):
    if request.path.startswith("/api/"):
        origin = request.headers.get("Origin", "")
        if origin in ALLOWED_ORIGINS:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return resp

# Catch-all preflight for any /api/* path
@app.route("/api/<path:_any>", methods=["OPTIONS"])
def any_api_options(_any):
    return ("", 204)

# ──────────────────── Config — ENV vars ────────────────────────────────────
GOOGLE_KEY   = os.getenv("GOOGLE_MAPS_API_KEY")
ACCOUNT_SID  = os.getenv("TWILIO_ACCOUNT_SID")
AUTH_TOKEN   = os.getenv("TWILIO_AUTH_TOKEN")           # also used for Twilio signature check
FROM_NUMBER  = os.getenv("TWILIO_FROM_NUMBER")

TABLES_ENDPOINT = os.getenv("TABLES_ENDPOINT")          # https://<acct>.table.core.windows.net
AZURE_CONN      = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "300"))  # seconds
ENABLE_POLLING = os.getenv("ENABLE_POLLING", "1").lower() not in ("0", "false", "no")

# JWT (required for login token)
JWT_SECRET   = os.getenv("JWT_SECRET")                  # set this to enable token issuance
JWT_TTL_MIN  = int(os.getenv("JWT_TTL_MIN", "43200"))   # 30 days default

# OTP config
OTP_TABLE            = "userOtp"
OTP_CODE_TTL_SEC     = 5 * 60        # 5 minutes
OTP_RESEND_COOLDOWN  = 60            # min seconds between sends
OTP_MAX_ATTEMPTS     = 6             # attempts before lock
OTP_LOCK_MIN         = 10            # lock for N minutes after max attempts

# Google Routes API
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

# Baselines (minutes) — fallback only if staticDuration missing
NB_BASE_MIN = 9
SB_BASE_MIN = 4

# Persistence targets
STATE_FILE         = "last_status.json"    # fallback
USER_SETTINGS_FILE = "user_settings.json"  # fallback
STATE_TABLE        = "lastStatus"
USER_TABLE         = "userSettings"

SEV_EMOJI = {0: "🟢", 1: "🟡", 2: "🟠", 3: "🔴"}

# ──────────────────── Helpers: Tables, phones, JWT ─────────────────────────
def _get_table_service():
    if TABLES_ENDPOINT:
        cred = DefaultAzureCredential()
        return TableServiceClient(endpoint=TABLES_ENDPOINT, credential=cred)
    if AZURE_CONN:
        return TableServiceClient.from_connection_string(AZURE_CONN)
    return None

def _get_table_client(name: str):
    svc = _get_table_service()
    if not svc:
        return None
    try:
        svc.create_table_if_not_exists(name)
    except Exception:
        pass
    return svc.get_table_client(name)

def normalize_phone(raw: str) -> str:
    """604-555-1212, (604)555-1212, 16045551212 → +16045551212 (Canada/US only)."""
    if not raw:
        raise ValueError("invalid phone")
    s = raw.strip()
    if s.startswith("+"):
        digits = re.sub(r"\D", "", s)
        return "+" + digits
    digits = re.sub(r"\D", "", s)
    if len(digits) == 10:                # NPA-NXX-XXXX
        return "+1" + digits
    if len(digits) == 11 and digits[0] == "1":
        return "+1" + digits[1:]
    raise ValueError("invalid phone")

def _jwt_for_phone(phone: str) -> str | None:
    if not (JWT_SECRET and jwt):
        return None
    payload = {
        "sub": phone,
        "iss": "northvanupdates.com",
        "aud": "northvanupdates.com",
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_TTL_MIN * 60,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def _decode_jwt_from_header():
    if not (JWT_SECRET and jwt):
        abort(501, "JWT not configured")
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        abort(401)
    token = auth.split(" ", 1)[1].strip()
    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            audience="northvanupdates.com",
        )
        return claims
    except Exception:
        abort(401)

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        claims = _decode_jwt_from_header()
        g.phone = claims.get("sub")
        if not g.phone:
            abort(401)
        return f(*args, **kwargs)
    return wrapper

# ──────────────────── Google delay logic (index-safe + staticDuration) ─────
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

    by_idx = {(it["originIndex"], it["destinationIndex"]): it for it in items}
    nb = by_idx[(0, 0)]
    sb = by_idx[(1, 1)]

    def to_min(seconds_str: str) -> float:
        return float(seconds_str.rstrip("s")) / 60.0

    def build(elem, fallback_base_min: int):
        live_min = to_min(elem["duration"])
        base_min = to_min(elem["staticDuration"]) if "staticDuration" in elem else float(fallback_base_min)
        delay_min = max(0.0, live_min - base_min)
        return {"live": round(live_min), "base": round(base_min), "delay": round(delay_min)}

    return {"NB": build(nb, NB_BASE_MIN), "SB": build(sb, SB_BASE_MIN)}

# ──────────────────── Persistence: status & users ──────────────────────────
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
    return load_user_settings()

# ──────────────────── Twilio helpers ───────────────────────────────────────
def send_sms(body: str, to: str) -> str:
    client = Client(ACCOUNT_SID, AUTH_TOKEN)
    msg = client.messages.create(body=body, from_=FROM_NUMBER, to=to)
    return msg.sid

# ──────────────────── OTP store (SHA-256 hashed codes) ─────────────────────
def _otp_table():
    return _get_table_client(OTP_TABLE)

def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()

def _gen_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"

def _now_epoch() -> int:
    return int(time.time())

def otp_can_send(ent: Dict[str, Any] | None) -> bool:
    if not ent:
        return True
    last = int(ent.get("lastSentAt", 0))
    return (_now_epoch() - last) >= OTP_RESEND_COOLDOWN

def otp_locked(ent: Dict[str, Any] | None) -> bool:
    if not ent:
        return False
    return _now_epoch() < int(ent.get("lockedUntil", 0))

def otp_issue_and_send(phone_e164: str):
    tc = _otp_table()
    if not tc:
        raise RuntimeError("OTP storage not configured")
    # read current row
    ent = None
    try:
        ent = tc.get_entity(partition_key="otp", row_key=phone_e164)
    except Exception:
        ent = None

    if otp_locked(ent):
        return False, "too_many_attempts"

    if not otp_can_send(ent):
        return False, "cooldown"

    code = _gen_code()
    now = _now_epoch()
    exp = now + OTP_CODE_TTL_SEC
    entity = {
        "PartitionKey": "otp",
        "RowKey": phone_e164,
        "codeHash": _hash_code(code),
        "expiresAt": exp,
        "attempts": 0,
        "lastSentAt": now,
        "lockedUntil": 0,
    }
    tc.upsert_entity(entity)

    # Send SMS (keep message generic)
    send_sms(f"Your NorthVanUpdates code: {code}. Expires in 5 minutes.", phone_e164)
    return True, "sent"

def otp_verify_and_consume(phone_e164: str, code: str) -> bool:
    tc = _otp_table()
    if not tc:
        return False
    try:
        ent = tc.get_entity(partition_key="otp", row_key=phone_e164)
    except Exception:
        return False

    now = _now_epoch()
    attempts = int(ent.get("attempts", 0))

    if otp_locked(ent):
        return False

    if now > int(ent.get("expiresAt", 0)):
        ent["attempts"] = attempts + 1
        if ent["attempts"] >= OTP_MAX_ATTEMPTS:
            ent["lockedUntil"] = now + OTP_LOCK_MIN * 60
        tc.upsert_entity(ent)
        return False

    if _hash_code(code) != ent.get("codeHash"):
        ent["attempts"] = attempts + 1
        if ent["attempts"] >= OTP_MAX_ATTEMPTS:
            ent["lockedUntil"] = now + OTP_LOCK_MIN * 60
        tc.upsert_entity(ent)
        return False

    # success → delete row so code can't be reused
    tc.delete_entity(partition_key="otp", row_key=phone_e164)
    return True

# ──────────────────── Business logic (alerts) ──────────────────────────────
def severity_level(delay: int) -> int:
    if delay <= 5:
        return 0
    elif delay <= 15:
        return 1
    elif delay <= 30:
        return 2
    else:
        return 3

def within_window(now_hhmm: str, windows):
    return any(w["start"] <= now_hhmm <= w["end"] for w in windows)

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

    now_str = datetime.now(ZoneInfo("America/Vancouver")).strftime("%H:%M")

    for u in get_user_settings():
        if not u.get("active", True):
            continue
        if (nb_s["delay"] < u["threshold"] and sb_s["delay"] < u["threshold"]):
            continue
        if not within_window(now_str, u["windows"]):
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

# ──────────────────── Routes ───────────────────────────────────────────────
@app.route("/", methods=["GET"])
def health():
    return "ok", 200

@app.route("/api/status", methods=["GET"])
def status():
    snap = load_snapshot()
    return jsonify(snap if snap else {"msg": "no data yet"})

@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}
    raw = data.get("phone") if request.is_json else request.form.get("phone")
    if not raw:
        abort(400, "phone field is required")
    try:
        phone = normalize_phone(raw)
    except ValueError:
        abort(400, "invalid phone")

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

# ---- OTP: start (send code) -----------------------------------------------
@app.route("/api/otp/start", methods=["POST"])
def otp_start():
    data = request.get_json(silent=True) or {}
    raw = data.get("phone")
    if not raw:
        abort(400, "phone is required")
    try:
        phone = normalize_phone(raw)
    except ValueError:
        # Always respond ok to avoid leaking registration
        return jsonify({"ok": True, "status": "sent"}), 200

    # Only send OTP for registered numbers
    if not any(u["phone"] == phone for u in get_user_settings()):
        return jsonify({"ok": True, "status": "sent"}), 200

    ok, status = otp_issue_and_send(phone)
    if not ok and status == "cooldown":
        return jsonify({"ok": True, "status": "cooldown"}), 200
    if not ok and status == "too_many_attempts":
        return jsonify({"ok": False, "error": "locked"}), 429

    return jsonify({"ok": True, "status": "sent"}), 200

# ---- OTP: verify -----------------------------------------------------------
@app.route("/api/otp/verify", methods=["POST"])
def otp_verify():
    data = request.get_json(silent=True) or {}
    raw = data.get("phone")
    code = (data.get("code") or "").strip()
    if not raw or not code:
        abort(400, "phone and code are required")
    try:
        phone = normalize_phone(raw)
    except ValueError:
        abort(400, "invalid phone")

    if not otp_verify_and_consume(phone, code):
        return jsonify({"ok": False, "error": "invalid_or_expired"}), 401

    token = _jwt_for_phone(phone)
    resp = {"ok": True}
    if token:
        resp["token"] = token
        resp["token_type"] = "Bearer"
        resp["expires_in"] = JWT_TTL_MIN * 60
    return jsonify(resp), 200

# ---- User settings (requires JWT) -----------------------------------------
@app.route("/api/user/settings", methods=["GET"])
@require_auth
def get_my_settings():
    phone = g.phone
    users = get_user_settings()
    me = next((u for u in users if u["phone"] == phone), None)
    if not me:
        me = {"phone": phone, "active": True, "threshold": 0,
              "windows": [{"start": "00:00", "end": "23:59"}]}
        users.append(me)
        save_user_settings(users)
    return jsonify({
        "phone": phone,
        "active": bool(me.get("active", True)),
        "threshold": int(me.get("threshold", 0)),
        "windows": me.get("windows", []),
    })

@app.route("/api/user/settings", methods=["POST"])
@require_auth
def update_my_settings():
    phone = g.phone
    data = request.get_json(silent=True) or {}
    threshold = int(data.get("threshold", 0))

    windows_raw = data.get("windows", [])
    if isinstance(windows_raw, str):
        try:
            windows = parse_windows(windows_raw)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    elif isinstance(windows_raw, list):
        windows = windows_raw
    else:
        windows = [{"start": "00:00", "end": "23:59"}]

    users = get_user_settings()
    me = next((u for u in users if u["phone"] == phone), None)
    if not me:
        me = {"phone": phone}
        users.append(me)
    me["active"] = bool(data.get("active", True))
    me["threshold"] = threshold
    me["windows"] = windows
    save_user_settings(users)
    return jsonify({"ok": True})

# Optional helper for debugging your token
@app.route("/api/whoami", methods=["GET"])
@require_auth
def whoami():
    return jsonify({"phone": g.phone})

# ---- Twilio inbound SMS (with signature verification) ---------------------
@app.route("/sms", methods=["POST"])
def sms_webhook():
    # Verify Twilio signature
    sig = request.headers.get("X-Twilio-Signature", "")
    validator = RequestValidator(AUTH_TOKEN or "")
    if not validator.validate(request.url, request.form, sig):
        abort(403)

    from_number = request.form.get("From", "").strip()
    if not from_number:
        abort(400)

    body_raw = request.form.get("Body", "").strip()
    parts    = body_raw.upper().split(maxsplit=1) if body_raw else ["HELP"]

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

    if parts[0] == "THRESHOLD" and len(parts) == 2 and parts[1].isdigit():
        user["threshold"] = int(parts[1])
        save_user_settings(users)
        resp.message(f"✅ Threshold set to {parts[1]} minutes.")
    elif parts[0] == "WINDOW" and len(parts) == 2:
        try:
            user["windows"] = parse_windows(parts[1])
            save_user_settings(users)
            win_str = ", ".join(f"{w['start']}-{w['end']}" for w in user["windows"])
            resp.message(f"✅ Windows set to {win_str}")
        except ValueError:
            resp.message("❌ Invalid format. Use: WINDOW HH:MM-HH:MM[,HH:MM-HH:MM]")
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

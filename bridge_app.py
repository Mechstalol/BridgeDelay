# -*- coding: utf-8 -*-
"""
BridgeDelay — unified Maps-API + SMS webhook (+ OTP login)
----------------------------------------------------------
Only notify when:
  • severity bucket changes, OR
  • delay moves by >= NOTIFY_MIN_STEP minutes vs last sent message.

Messages now show only delays (no base/live):
  🚦 Lions Gate update
  Northbound delay: Xm
  Southbound delay: Ym
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
from flask import Flask, request, abort, jsonify, Response
from flask_cors import CORS
from twilio.rest import Client
from twilio.twiml.messaging_response import MessagingResponse
from twilio.request_validator import RequestValidator

from azure.identity import DefaultAzureCredential
from azure.data.tables import TableServiceClient
from zoneinfo import ZoneInfo

try:
    import jwt  # PyJWT
except Exception:
    jwt = None

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

@app.route("/api/<path:_any>", methods=["OPTIONS"])
def any_api_options(_any):
    return ("", 204)

# ── Config ─────────────────────────────────────────────────────────────────
GOOGLE_KEY   = os.getenv("GOOGLE_MAPS_API_KEY")
ACCOUNT_SID  = os.getenv("TWILIO_ACCOUNT_SID")
AUTH_TOKEN   = os.getenv("TWILIO_AUTH_TOKEN")
FROM_NUMBER  = os.getenv("TWILIO_FROM_NUMBER")

TABLES_ENDPOINT = os.getenv("TABLES_ENDPOINT")  # https://<acct>.table.core.windows.net
AZURE_CONN      = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "300"))
ENABLE_POLLING = os.getenv("ENABLE_POLLING", "1").lower() not in ("0", "false", "no")

JWT_SECRET  = os.getenv("JWT_SECRET")
JWT_TTL_MIN = int(os.getenv("JWT_TTL_MIN", "43200"))  # 30 days

# NEW: notify rules
NOTIFY_MIN_STEP    = int(os.getenv("NOTIFY_MIN_STEP", "5"))   # minutes
NOTIFY_MIN_GAP_SEC = int(os.getenv("NOTIFY_MIN_GAP_SEC", "60"))

OTP_TABLE            = "userOtp"
OTP_CODE_TTL_SEC     = 5 * 60
OTP_RESEND_COOLDOWN  = 60
OTP_MAX_ATTEMPTS     = 6
OTP_LOCK_MIN         = 10

TWILIO_VALIDATE = os.getenv("TWILIO_VALIDATE", "1").lower() not in ("0", "false", "no")

ROUTES_URL = "https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix"
HEADERS = {
    "Content-Type": "application/json",
    "X-Goog-Api-Key": GOOGLE_KEY,
    "X-Goog-FieldMask": "originIndex,destinationIndex,duration,staticDuration",
}

NB_START = (49.283260, -123.119297)
NB_END   = (49.324345, -123.122962)
SB_START = (49.324432, -123.122765)
SB_END   = (49.292738, -123.133985)

NB_BASE_MIN = 9
SB_BASE_MIN = 4

STATE_FILE         = "last_status.json"
USER_SETTINGS_FILE = "user_settings.json"
STATE_TABLE        = "lastStatus"
USER_TABLE         = "userSettings"

SEV_EMOJI = {0: "🟢", 1: "🟡", 2: "🟠", 3: "🔴"}

# ── Helpers: Tables, phones, JWT ───────────────────────────────────────────
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
    s = (raw or "").strip()
    if not s:
        raise ValueError("invalid phone")
    if s.startswith("+"):
        digits = re.sub(r"\D", "", s)
        return "+" + digits
    digits = re.sub(r"\D", "", s)
    if len(digits) == 10:
        return "+1" + digits
    if len(digits) == 11 and digits[0] == "1":
        return "+1" + digits[1:]
    raise ValueError("invalid phone")

def _jwt_for_phone(phone: str) -> str | None:
    if not (JWT_SECRET and jwt):
        return None
    payload = {
        "sub": phone,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_TTL_MIN * 60,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def _phone_from_request(req) -> str | None:
    if not (JWT_SECRET and jwt):
        return None
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload.get("sub")
    except Exception:
        return None

# ── Google delay logic (index-safe + staticDuration) ───────────────────────
def _latlng(pair):
    lat, lng = pair
    return {"latLng": {"latitude": lat, "longitude": lng}}

def get_delays() -> Dict[str, Dict[str, int]]:
    body: Dict[str, Any] = {
        "origins": [
            {"waypoint": {"location": _latlng(NB_START)}},
            {"waypoint": {"location": _latlng(SB_START)}},
        ],
        "destinations": [
            {"waypoint": {"location": _latlng(NB_END)}},
            {"waypoint": {"location": _latlng(SB_END)}},
        ],
        "travelMode": "DRIVE",
        "routingPreference": "TRAFFIC_AWARE_OPTIMAL",
    }
    r = requests.post(ROUTES_URL, headers=HEADERS, json=body, timeout=10)
    r.raise_for_status()
    items = r.json()
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

# ── Persistence (state & users) ────────────────────────────────────────────
def _load_raw_state() -> Dict[str, Any]:
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

def _save_raw_state(state: Dict[str, Any]):
    tc = _get_table_client(STATE_TABLE)
    if tc:
        ent = {"PartitionKey": "state", "RowKey": "latest", "data": json.dumps(state)}
        tc.upsert_entity(ent)
        return
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def _extract_prev_sent(state: Dict[str, Any]) -> Dict[str, Any] | None:
    # New format: {"poll": {...}, "last_sent": {...}, "last_sent_at": 123}
    if isinstance(state, dict) and "last_sent" in state and isinstance(state["last_sent"], dict):
        return state["last_sent"]
    # Back-compat: old state directly had NB/SB at top
    if "NB" in state and "SB" in state:
        return {"NB": state["NB"], "SB": state["SB"]}
    return None

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

# ── Twilio helpers ─────────────────────────────────────────────────────────
def send_sms(body: str, to: str) -> str:
    client = Client(ACCOUNT_SID, AUTH_TOKEN)
    msg = client.messages.create(body=body, from_=FROM_NUMBER, to=to)
    return msg.sid

def _twilio_request_url(req):
    url = req.url
    xf_proto = req.headers.get("X-Forwarded-Proto", "")
    if xf_proto and url.startswith("http://") and xf_proto == "https":
        url = "https://" + url[len("http://"):]
    return url

def _twilio_signature_ok(req):
    sig = req.headers.get("X-Twilio-Signature", "")
    validator = RequestValidator(AUTH_TOKEN or "")
    url = _twilio_request_url(req)
    if validator.validate(url, req.form, sig):
        return True
    alt = url.rstrip("/") if url.endswith("/") else url + "/"
    return validator.validate(alt, req.form, sig)

# ── OTP (Azure Table) ──────────────────────────────────────────────────────
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

    tc.delete_entity(partition_key="otp", row_key=phone_e164)
    return True

# ── Alert logic ────────────────────────────────────────────────────────────
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

def _should_notify(prev_sent: Dict[str, Any], current: Dict[str, Any]) -> bool:
    """True if severity changed OR either NB/SB delay moved by >= NOTIFY_MIN_STEP."""
    if not prev_sent:
        return False
    nb, sb = current["NB"], current["SB"]
    pnb, psb = prev_sent["NB"], prev_sent["SB"]

    sev_changed = (
        severity_level(nb["delay"]) != severity_level(pnb["delay"])
        or severity_level(sb["delay"]) != severity_level(psb["delay"])
    )
    big_move = (
        abs(nb["delay"] - pnb["delay"]) >= NOTIFY_MIN_STEP
        or abs(sb["delay"] - psb["delay"]) >= NOTIFY_MIN_STEP
    )
    return sev_changed or big_move

def check_and_notify():
    current = get_delays()
    state = _load_raw_state() or {}
    prev_sent = _extract_prev_sent(state)  # None on first run

    # Always record the latest poll (for /api/status)
    new_state: Dict[str, Any] = {"poll": current}
    if "last_sent" in state:
        new_state["last_sent"] = state["last_sent"]
    if "last_sent_at" in state:
        new_state["last_sent_at"] = state["last_sent_at"]

    # If no previous "sent" snapshot, store poll and exit quietly
    if not prev_sent:
        _save_raw_state(new_state)
        return

    # Global cool-down to avoid accidental double-sends
    now_sec = _now_epoch()
    last_at = int(new_state.get("last_sent_at", 0) or 0)
    if last_at and (now_sec - last_at) < NOTIFY_MIN_GAP_SEC:
        _save_raw_state(new_state)
        return

    if not _should_notify(prev_sent, current):
        _save_raw_state(new_state)
        return

    # Build simplified message (delays only)
    nb_s, sb_s = current["NB"], current["SB"]
    body = (
        "🚦 Lions Gate update\n"
        f"Northbound delay: {nb_s['delay']}m\n"
        f"Southbound delay: {sb_s['delay']}m"
    )

    now_str = datetime.now(ZoneInfo("America/Vancouver")).strftime("%H:%M")
    notified_any = False
    for u in get_user_settings():
        if not u.get("active", True):
            continue
        if (nb_s["delay"] < u["threshold"] and sb_s["delay"] < u["threshold"]):
            continue
        if not within_window(now_str, u["windows"]):
            continue
        sid = send_sms(body, u["phone"])
        notified_any = True
        print(f"🔔 Sent to {u['phone']}: {sid}")

    # Mark last_sent regardless to prevent flapping spam
    if notified_any or True:
        new_state["last_sent"] = current
        new_state["last_sent_at"] = now_sec

    _save_raw_state(new_state)

# ── Background poller ─────────────────────────────────────────────────────
_poll_lock = threading.Lock()
_poll_started = False

def start_background_polling():
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

# ── SMS helpers ────────────────────────────────────────────────────────────
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

# ── Routes ─────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def health():
    return "ok", 200

@app.route("/api/status", methods=["GET"])
def status():
    state = _load_raw_state()
    if not state:
        return jsonify({"msg": "no data yet"})
    # Back-compat: if state already NB/SB at top, return it; else return the latest poll
    if "NB" in state and "SB" in state:
        return jsonify(state)
    if "poll" in state:
        return jsonify(state["poll"])
    return jsonify(state)

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

@app.route("/api/otp/start", methods=["POST"])
def otp_start():
    data = request.get_json(silent=True) or {}
    raw = data.get("phone")
    if not raw:
        abort(400, "phone is required")
    try:
        phone = normalize_phone(raw)
    except ValueError:
        return jsonify({"ok": True, "status": "sent"}), 200

    if not any(u["phone"] == phone for u in get_user_settings()):
        return jsonify({"ok": True, "status": "sent"}), 200

    ok, status2 = otp_issue_and_send(phone)
    if not ok and status2 == "cooldown":
        return jsonify({"ok": True, "status": "cooldown"}), 200
    if not ok and status2 == "too_many_attempts":
        return jsonify({"ok": False, "error": "locked"}), 429

    return jsonify({"ok": True, "status": "sent"}), 200

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

@app.route("/api/user/settings", methods=["GET", "POST"])
def user_settings_api():
    phone = _phone_from_request(request)
    if not phone:
        abort(401)
    users = get_user_settings()
    user = next((u for u in users if u["phone"] == phone), None)
    if not user:
        abort(404)
    if request.method == "GET":
        return jsonify({
            "phone": phone,
            "threshold": user.get("threshold", 0),
            "windows": user.get("windows", [])
        })

    data = request.get_json(silent=True) or {}
    if "threshold" in data:
        try:
            user["threshold"] = int(data["threshold"])
        except Exception:
            return jsonify({"ok": False, "error": "invalid_threshold"}), 400
    if "windows" in data:
        try:
            user["windows"] = parse_windows(data["windows"])
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
    save_user_settings(users)
    return jsonify({"ok": True, "settings": user}), 200

@app.route("/sms", methods=["POST"], strict_slashes=False)
def sms_webhook():
    if TWILIO_VALIDATE and not _twilio_signature_ok(request):
        return Response("Forbidden", status=403)

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
            # Simplified STATUS text (header + delays only)
            msg = (
                "🚦 Lions Gate update\n"
                f"Northbound delay: {nb['delay']}m\n"
                f"Southbound delay: {sb['delay']}m"
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

# ── Entrypoint ─────────────────────────────────────────────────────────────
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

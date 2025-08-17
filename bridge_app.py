# -*- coding: utf-8 -*-
"""
BridgeDelay — unified Maps-API + SMS webhook (+ OTP login)
----------------------------------------------------------
De-dupe: Only one instance sends alerts using atomic ETag update on the STATE_TABLE.
Notify when severity changes OR delay jump ≥ NOTIFY_MIN_STEP minutes.
Message shows only delays (no base/live).

New SMS commands:
  PAUSE           -> pause alerts for 1 hour
  DEACTIVATE      -> turn off alerts until reactivated
  REACTIVATE      -> turn alerts back on

Defaults for new users:
  threshold = 15
  windows   = 06:00-09:00,16:00-20:00
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
from azure.core.exceptions import ResourceNotFoundError, ResourceModifiedError
from azure.core.match_conditions import MatchConditions
from zoneinfo import ZoneInfo

try:
    import jwt  # PyJWT
except Exception:
    jwt = None

# ──────────────────── Flask & CORS ─────────────────────────────────────────
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

# ──────────────────── Config — ENV vars ────────────────────────────────────
GOOGLE_KEY   = os.getenv("GOOGLE_MAPS_API_KEY")
ACCOUNT_SID  = os.getenv("TWILIO_ACCOUNT_SID")
AUTH_TOKEN   = os.getenv("TWILIO_AUTH_TOKEN")
FROM_NUMBER  = os.getenv("TWILIO_FROM_NUMBER")

TABLES_ENDPOINT = os.getenv("TABLES_ENDPOINT")  # https://<acct>.table.core.windows.net
AZURE_CONN      = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "300"))
ENABLE_POLLING = os.getenv("ENABLE_POLLING", "1").lower() not in ("0", "false", "no")

# Optional JWT for account pages
JWT_SECRET  = os.getenv("JWT_SECRET")
JWT_TTL_MIN = int(os.getenv("JWT_TTL_MIN", "43200"))  # 30 days

# Notify rules
NOTIFY_MIN_STEP    = int(os.getenv("NOTIFY_MIN_STEP", "5"))   # minutes
NOTIFY_MIN_GAP_SEC = int(os.getenv("NOTIFY_MIN_GAP_SEC", "60"))

# OTP config (Azure Table)
OTP_TABLE            = "userOtp"
OTP_CODE_TTL_SEC     = 5 * 60
OTP_RESEND_COOLDOWN  = 60
OTP_MAX_ATTEMPTS     = 6
OTP_LOCK_MIN         = 10

# Twilio security (signature verification)
TWILIO_VALIDATE = os.getenv("TWILIO_VALIDATE", "1").lower() not in ("0", "false", "no")

# Google Routes API
ROUTES_URL = "https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix"
HEADERS = {
    "Content-Type": "application/json",
    "X-Goog-Api-Key": GOOGLE_KEY,
    "X-Goog-FieldMask": "originIndex,destinationIndex,duration,staticDuration",
}

# Route coordinates
NB_START = (49.283260, -123.119297)
NB_END   = (49.324345, -123.122962)
SB_START = (49.324432, -123.122765)
SB_END   = (49.292738, -123.133985)

# Baselines (fallback if staticDuration missing)
NB_BASE_MIN = 9
SB_BASE_MIN = 4

# Tables / files
STATE_TABLE        = "lastStatus"
USER_TABLE         = "userSettings"
STATE_FILE         = "last_status.json"    # fallback only
USER_SETTINGS_FILE = "user_settings.json"  # fallback only

# Defaults for new users
DEFAULT_THRESHOLD = 15
DEFAULT_WINDOWS   = [{"start": "06:00", "end": "09:00"},
                     {"start": "16:00", "end": "20:00"}]

SEV_EMOJI = {0: "🟢", 1: "🟡", 2: "🟠", 3: "🔴"}

# ──────────────────── Azure Table helpers ──────────────────────────────────
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

# ──────────────────── Phone/JWT helpers ────────────────────────────────────
def normalize_phone(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        raise ValueError("invalid phone")
    if s.startswith("+"):
        digits = re.sub(r"\D", "", s)
        return "+" + digits
    digits = re.sub(r"\D", "", s)
    if len(digits) == 10:           # NPA-NXX-XXXX
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

# ──────────────────── Google delays ────────────────────────────────────────
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

# ──────────────────── Persistence: users ───────────────────────────────────
def load_user_settings() -> List[Dict[str, Any]]:
    tc = _get_table_client(USER_TABLE)
    if tc:
        users: List[Dict[str, Any]] = []
        for ent in tc.query_entities("PartitionKey eq 'user'"):
            users.append(
                {
                    "phone": ent["RowKey"],
                    "active": bool(ent.get("active", True)),
                    "threshold": int(ent.get("threshold", DEFAULT_THRESHOLD)),
                    "windows": json.loads(ent.get("windows", json.dumps(DEFAULT_WINDOWS))),
                    "pausedUntil": int(ent.get("pausedUntil", 0)),
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
                "threshold": u.get("threshold", DEFAULT_THRESHOLD),
                "windows": json.dumps(u.get("windows", DEFAULT_WINDOWS)),
                "pausedUntil": int(u.get("pausedUntil", 0)),
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

# ──────────────────── OTP (Azure Table) ────────────────────────────────────
OTP_TABLE  # (kept; omitted here to save space — unchanged OTP helpers)  # noqa

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

def _otp_table():
    return _get_table_client(OTP_TABLE)

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
    _otp_table().upsert_entity(entity)
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

# ──────────────────── Alert rules ──────────────────────────────────────────
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

# ──────────────────── State entity (atomic update) ─────────────────────────
def _state_get_with_etag(tc):
    """Return (state_dict, etag) from STATE_TABLE, creating empty if missing."""
    try:
        ent = tc.get_entity(partition_key="state", row_key="latest")
        data = json.loads(ent.get("data", "{}") or "{}")
        etag = ent.get("_etag") or ent.get("etag") or getattr(ent, "etag", None) \
               or ent.get("odata.etag") or ent.get("@odata.etag") \
               or (getattr(ent, "metadata", {}) or {}).get("etag")
        return data, etag
    except ResourceNotFoundError:
        init = {"poll": {}, "last_sent": None, "last_sent_at": 0}
        tc.upsert_entity({"PartitionKey": "state", "RowKey": "latest", "data": json.dumps(init)})
        return init, None

def _state_replace_if_match(tc, etag: str | None, new_state: Dict[str, Any]) -> bool:
    """Replace state only if ETag matches (prevents double-send)."""
    entity = {"PartitionKey": "state", "RowKey": "latest", "data": json.dumps(new_state)}
    try:
        if etag:
            tc.update_entity(entity=entity, mode="Replace", etag=etag,
                             match_condition=MatchConditions.IfNotModified)
        else:
            tc.upsert_entity(entity)
        return True
    except ResourceModifiedError:
        return False

# ──────────────────── Core poller with de-dupe ─────────────────────────────
def check_and_notify():
    tc = _get_table_client(STATE_TABLE)
    if not tc:
        # Single-instance fallback
        current = get_delays()
        try:
            with open(STATE_FILE, "r") as f:
                state = json.load(f)
        except Exception:
            state = {}
        prev_sent = state.get("last_sent") or ({"NB": state.get("NB"), "SB": state.get("SB")} if "NB" in state else None)
        state["poll"] = current
        now_sec = int(time.time())
        last_at = int(state.get("last_sent_at", 0))
        if prev_sent and ((now_sec - last_at) >= NOTIFY_MIN_GAP_SEC) and _should_notify(prev_sent, current):
            state["last_sent"] = current
            state["last_sent_at"] = now_sec
            with open(STATE_FILE, "w") as f:
                json.dump(state, f)
            _broadcast_delays(current)
        else:
            with open(STATE_FILE, "w") as f:
                json.dump(state, f)
        return

    # Normal path with atomic table update
    current = get_delays()
    state, etag = _state_get_with_etag(tc)

    new_state = dict(state)
    new_state["poll"] = current

    prev_sent = state.get("last_sent")
    now_sec = int(time.time())
    last_at = int(state.get("last_sent_at", 0) or 0)

    should = False
    if prev_sent and (now_sec - last_at) >= NOTIFY_MIN_GAP_SEC and _should_notify(prev_sent, current):
        should = True

    if not should:
        tc.upsert_entity({"PartitionKey": "state", "RowKey": "latest", "data": json.dumps(new_state)})
        return

    new_state["last_sent"] = current
    new_state["last_sent_at"] = now_sec
    if not _state_replace_if_match(tc, etag, new_state):
        return

    _broadcast_delays(current)

def _broadcast_delays(current: Dict[str, Dict[str, int]]):
    nb_s, sb_s = current["NB"], current["SB"]
    body = (
        "🚦 Lions Gate update\n"
        f"Northbound delay: {nb_s['delay']}m\n"
        f"Southbound delay: {sb_s['delay']}m"
    )
    now_str = datetime.now(ZoneInfo("America/Vancouver")).strftime("%H:%M")
    now_sec = int(time.time())

    for u in get_user_settings():
        if not u.get("active", True):
            continue
        if int(u.get("pausedUntil", 0)) > now_sec:
            continue
        if (nb_s["delay"] < u.get("threshold", DEFAULT_THRESHOLD) and
            sb_s["delay"] < u.get("threshold", DEFAULT_THRESHOLD)):
            continue
        if not within_window(now_str, u.get("windows", DEFAULT_WINDOWS)):
            continue
        sid = send_sms(body, u["phone"])
        print(f"🔔 Sent to {u['phone']}: {sid}")

# ──────────────────── Background poller ────────────────────────────────────
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

# ──────────────────── Utilities ────────────────────────────────────────────
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
    tc = _get_table_client(STATE_TABLE)
    if tc:
        try:
            ent = tc.get_entity(partition_key="state", row_key="latest")
            data = json.loads(ent.get("data", "{}") or "{}")
            if "poll" in data:
                return jsonify(data["poll"])
            return jsonify(data)
        except ResourceNotFoundError:
            return jsonify({"msg": "no data yet"})
    try:
        with open(STATE_FILE, "r") as f:
            return jsonify(json.load(f))
    except Exception:
        return jsonify({"msg": "no data yet"})

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
        "threshold": DEFAULT_THRESHOLD,
        "windows": DEFAULT_WINDOWS,
        "pausedUntil": 0,
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
            "active": user.get("active", True),
            "pausedUntil": int(user.get("pausedUntil", 0)),
            "threshold": user.get("threshold", DEFAULT_THRESHOLD),
            "windows": user.get("windows", DEFAULT_WINDOWS)
        })
    data = request.get_json(silent=True) or {}
    if "active" in data:
        user["active"] = bool(data["active"])
        if user["active"]:
            user["pausedUntil"] = 0
    if "threshold" in data:
        try:
            user["threshold"] = int(data["threshold"])
        except Exception:
            return jsonify({"ok": False, "error": "invalid_threshold"}), 400
    if "windows" in data:
        try:
            user["windows"] = parse_windows(data["windows"]) if isinstance(data["windows"], str) else data["windows"]
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
            "threshold": DEFAULT_THRESHOLD,
            "windows": DEFAULT_WINDOWS,
            "pausedUntil": 0,
        }
        users.append(user)

    resp = MessagingResponse()
    now_sec = int(time.time())

    if parts[0] == "PAUSE":
        user["pausedUntil"] = now_sec + 3600  # 1 hour
        save_user_settings(users)
        resp.message("⏸️ Paused for 1 hour. Send REACTIVATE to resume sooner.")
        return Response(str(resp), mimetype="application/xml")

    if parts[0] == "DEACTIVATE":
        user["active"] = False
        save_user_settings(users)
        resp.message("🔕 Alerts deactivated. Send REACTIVATE to turn them back on.")
        return Response(str(resp), mimetype="application/xml")

    if parts[0] == "REACTIVATE":
        user["active"] = True
        user["pausedUntil"] = 0
        save_user_settings(users)
        resp.message("🔔 Alerts reactivated.")
        return Response(str(resp), mimetype="application/xml")

    if parts[0] == "STATUS":
        try:
            delays = get_delays()
            nb, sb = delays["NB"], delays["SB"]
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
        resp.message("Commands: STATUS | THRESHOLD n | WINDOW HH:MM-HH:MM[,HH:MM-HH:MM] | PAUSE | DEACTIVATE | REACTIVATE")
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

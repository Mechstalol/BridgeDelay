# -*- coding: utf-8 -*-
"""
BridgeDelay — unified Maps-API + SMS webhook (+ OTP login)

Changes in this version:
- Enforce Canada-only + SMS-capable numbers at signup and before OTP.
- Keep raw-number sending (no Messaging Service).
- Add Lookup logging when Twilio send fails to speed up support.
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
import uuid
import atexit
from datetime import datetime
from typing import Any, Dict, List

import requests
from flask import Flask, request, abort, jsonify, Response

# --- Flask-CORS (safe import with fallback for cross_origin) ---------------
try:
    from flask_cors import CORS, cross_origin
except Exception:  # very old Flask-Cors
    from flask_cors import CORS  # type: ignore
    def cross_origin(*_a, **_k):  # no-op decorator
        def _wrap(fn):
            return fn
        return _wrap

from twilio.rest import Client
from twilio.twiml.messaging_response import MessagingResponse
from twilio.request_validator import RequestValidator

from azure.data.tables import TableServiceClient
from azure.core.exceptions import ResourceNotFoundError, ResourceExistsError

from zoneinfo import ZoneInfo

try:
    import jwt  # optional
except Exception:
    jwt = None

import phonenumbers

# ──────────────────── Flask & CORS ─────────────────────────────────────────
app = Flask(__name__)  # gunicorn target → bridge_app:app

_started_once = False

@app.before_request
def _kick_once() -> None:
    global _started_once
    if not _started_once:
        _started_once = True
        start_background_polling()

ALLOWED_ORIGINS = {
    "https://northvanupdates.com",
    "https://www.northvanupdates.com",
}

# Global CORS (plus per-route decorators on /api/* endpoints)
CORS(
    app,
    resources={r"/api/*": {
        "origins": list(ALLOWED_ORIGINS),
        "allow_headers": ["Content-Type", "Authorization"],
        "methods": ["GET", "POST", "OPTIONS"],
        "max_age": 600
    }},
)

@app.after_request
def add_cors_headers(resp):
    if request.path.startswith("/api/"):
        origin = request.headers.get("Origin", "")
        if origin in ALLOWED_ORIGINS:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, content-type, Authorization"
        resp.headers["Access-Control-Max-Age"] = "600"
    return resp

@app.route("/api/<path:_any>", methods=["OPTIONS"])
@cross_origin(origins=list(ALLOWED_ORIGINS),
              methods=["POST", "GET", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization", "content-type"],
              max_age=600)
def any_api_options(_any):
    return ("", 204)

# ──────────────────── Config — ENV vars ────────────────────────────────────
GOOGLE_KEY   = os.getenv("GOOGLE_MAPS_API_KEY")
ACCOUNT_SID  = os.getenv("TWILIO_ACCOUNT_SID")
AUTH_TOKEN   = os.getenv("TWILIO_AUTH_TOKEN")
FROM_NUMBER  = os.getenv("TWILIO_FROM_NUMBER")  # E.164, e.g., +1778XXXXXXX

AZURE_CONN      = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "300"))
ENABLE_POLLING = os.getenv("ENABLE_POLLING", "1").lower() not in ("0", "false", "no")

# JWT tokens can be signed with either JWT_SECRET or legacy OTP_SIGNING_KEY
JWT_SECRET  = os.getenv("JWT_SECRET") or os.getenv("OTP_SIGNING_KEY")
JWT_TTL_MIN = int(os.getenv("JWT_TTL_MIN", "43200"))  # 30 days

NOTIFY_MIN_STEP    = int(os.getenv("NOTIFY_MIN_STEP", "15"))
NOTIFY_MIN_GAP_SEC = int(os.getenv("NOTIFY_MIN_GAP_SEC", "60"))

OTP_TABLE            = "userOtp"
OTP_CODE_TTL_SEC     = 5 * 60
OTP_RESEND_COOLDOWN  = 60
OTP_MAX_ATTEMPTS     = 6
OTP_LOCK_MIN         = 10

TWILIO_VALIDATE = os.getenv("TWILIO_VALIDATE", "1").lower() not in ("0", "false", "no")

# Fail fast if required API credentials are missing.
if not GOOGLE_KEY:
    raise RuntimeError("GOOGLE_MAPS_API_KEY is required")
if not (ACCOUNT_SID and AUTH_TOKEN and FROM_NUMBER):
    raise RuntimeError(
        "Twilio configuration incomplete: set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM_NUMBER"
    )

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

STATE_TABLE = "lastStatus"
USER_TABLE  = "userSettings"

DEFAULT_THRESHOLD_NB = 20
DEFAULT_THRESHOLD_SB = 20
# Backward-compat global default (pre-direction split)
DEFAULT_THRESHOLD = 20
DEFAULT_WINDOWS   = [
    {"start": "06:30", "end": "08:30", "dir": "SB"},
    {"start": "16:30", "end": "19:30", "dir": "NB"},
]

SEV_EMOJI = {0: "🟢", 1: "🟡", 2: "🟠", 3: "🔴"}

# Distributed poller lock
LOCK_PARTITION = "lock"
LOCK_ROW = "poller"
_poll_id = uuid.uuid4().hex

# ──────────────────── Azure Table helpers ──────────────────────────────────
def _get_table_service():
    if AZURE_CONN:
        return TableServiceClient.from_connection_string(AZURE_CONN)
    return None

def _require_table_client(name: str):
    svc = _get_table_service()
    if not svc:
        raise RuntimeError("Azure Table storage not configured: set AZURE_STORAGE_CONNECTION_STRING")
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
    if len(digits) == 10:
        return "+1" + digits
    if len(digits) == 11 and digits[0] == "1":
        return "+1" + digits[1:]
    raise ValueError("invalid phone")

def _jwt_for_phone(phone: str) -> str | None:
    if not (JWT_SECRET and jwt):
        return None
    payload = {"sub": phone, "iat": int(time.time()), "exp": int(time.time()) + JWT_TTL_MIN * 60}
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
    def to_min(seconds_str: str) -> float:
        return float(seconds_str.rstrip("s")) / 60.0

    def build(elem, fallback_base_min: int):
        live_min = to_min(elem["duration"])
        base_min = to_min(elem.get("staticDuration", f"{fallback_base_min * 60}s"))
        delay_min = max(0.0, live_min - base_min)
        return {"live": round(live_min), "base": round(base_min), "delay": round(delay_min)}

    def fetch(origin, dest, fallback_base_min: int) -> Dict[str, int]:
        body: Dict[str, Any] = {
            "origins": [{"waypoint": {"location": _latlng(origin)}}],
            "destinations": [{"waypoint": {"location": _latlng(dest)}}],
            "travelMode": "DRIVE",
            "routingPreference": "TRAFFIC_AWARE_OPTIMAL",
        }
        r = requests.post(ROUTES_URL, headers=HEADERS, json=body, timeout=10)
        if not r.ok:
            try:
                detail = r.json().get("error", {}).get("message", "")
            except Exception:
                detail = r.text
            raise RuntimeError(f"Routes API {r.status_code}: {detail}")
        item = r.json()[0]
        return build(item, fallback_base_min)

    return {
        "NB": fetch(NB_START, NB_END, NB_BASE_MIN),
        "SB": fetch(SB_START, SB_END, SB_BASE_MIN),
    }

# ──────────────────── Persistence: users ───────────────────────────────────
def load_user_settings() -> List[Dict[str, Any]]:
    tc = _require_table_client(USER_TABLE)
    users: List[Dict[str, Any]] = []
    for ent in tc.query_entities("PartitionKey eq 'user'"):
        users.append(
            {
                "phone": ent["RowKey"],
                "active": bool(ent.get("active", True)),
                "threshold_nb": int(ent.get("threshold_nb", ent.get("threshold", DEFAULT_THRESHOLD_NB))),
                "threshold_sb": int(ent.get("threshold_sb", ent.get("threshold", DEFAULT_THRESHOLD_SB))),
                "windows": json.loads(ent.get("windows", json.dumps(DEFAULT_WINDOWS))),
                "pausedUntil": int(ent.get("pausedUntil", 0)),
            }
        )
    return users

def save_user_settings(settings: List[Dict[str, Any]]):
    tc = _require_table_client(USER_TABLE)
    for u in settings:
        ent = {
            "PartitionKey": "user",
            "RowKey": u["phone"],
            "active": u.get("active", True),
            "threshold_nb": u.get("threshold_nb", DEFAULT_THRESHOLD_NB),
            "threshold_sb": u.get("threshold_sb", DEFAULT_THRESHOLD_SB),
            "windows": json.dumps(u.get("windows", DEFAULT_WINDOWS)),
            "pausedUntil": int(u.get("pausedUntil", 0)),
        }
        tc.upsert_entity(ent)

def get_user_settings():
    return load_user_settings()

# ──────────────────── Twilio helpers ───────────────────────────────────────
def _assert_canadian_mobile(client: Client, e164: str):
    """
    Raises RuntimeError unless the number is Canadian and SMS-capable (mobile/voip).
    Uses libphonenumber quick checks + Twilio Lookup (line_type_intelligence in v2).
    """
    try:
        pn = phonenumbers.parse(e164, None)
    except phonenumbers.NumberParseException as e:
        raise RuntimeError("invalid phone") from e

    if phonenumbers.region_code_for_number(pn) != "CA" or not phonenumbers.is_valid_number(pn):
        raise RuntimeError("Canada-only phone numbers.")
    if phonenumbers.number_type(pn) == phonenumbers.PhoneNumberType.FIXED_LINE:
        raise RuntimeError("Mobile/SMS-capable numbers only.")

    try:
        # v2 Lookups: request line type intelligence
        info = client.lookups.v2.phone_numbers(e164).fetch(fields="line_type_intelligence")
    except Exception as e:
        try:
            from twilio.base.exceptions import TwilioRestException
        except Exception:
            TwilioRestException = Exception  # type: ignore
        if isinstance(e, TwilioRestException):
            status = getattr(e, "status", "")
            message = getattr(e, "msg", str(e))
            raise RuntimeError(f"Twilio lookup error {status}: {message}") from e
        raise

    if getattr(info, "country_code", "").upper() != "CA":
        raise RuntimeError("Canada-only phone numbers.")
    lti = getattr(info, "line_type_intelligence", None) or {}
    carrier_type = (lti.get("type") or "").lower()  # "mobile", "landline", "voip", etc.
    if carrier_type == "landline":
        raise RuntimeError("Mobile/SMS-capable numbers only.")

def send_sms(body: str, to: str) -> str:
    client = Client(ACCOUNT_SID, AUTH_TOKEN)
    _assert_canadian_mobile(client, to)
    try:
        # Send directly from your Canadian long code (raw number)
        msg = client.messages.create(body=body, from_=FROM_NUMBER, to=to)
    except Exception as e:
        # Enrich the error with a Lookup snapshot for support/debugging
        try:
            info = client.lookups.v2.phone_numbers(to).fetch(fields="line_type_intelligence")
            lti = getattr(info, "line_type_intelligence", None) or {}
            print("LOOKUP SNAPSHOT:", to,
                  getattr(info, "country_code", None),
                  lti.get("type"),
                  lti.get("carrier_name"))
        except Exception:
            pass
        try:
            from twilio.base.exceptions import TwilioRestException
        except Exception:  # pragma: no cover - import failure unlikely
            TwilioRestException = Exception  # type: ignore
        if isinstance(e, TwilioRestException):
            status = getattr(e, "status", "")
            message = getattr(e, "msg", str(e))
            raise RuntimeError(f"Twilio error {status}: {message}") from e
        raise
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
    return _require_table_client(OTP_TABLE)

def otp_issue_and_send(phone_e164: str):
    tc = _otp_table()
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

def window_direction(now_hhmm: str, windows):
    for w in windows:
        if w["start"] <= now_hhmm <= w["end"]:
            d = w.get("dir")
            if d in ("NB", "SB"):
                return d
            return "BOTH"
    return None

def _should_notify(last_msg: Dict[str, Any], current: Dict[str, Any], direction: str) -> bool:
    if not last_msg:
        return False
    prev = last_msg.get(direction)
    curr = current.get(direction)
    if not prev or not curr:
        return False
    sev_changed = severity_level(curr["delay"]) != severity_level(prev["delay"])
    big_move = abs(curr["delay"] - prev["delay"]) >= NOTIFY_MIN_STEP
    return sev_changed or big_move

# ──────────────────── State helpers (no ETag) ──────────────────────────────
def _state_load(tc):
    """Return dict state (creates skeleton on first run)."""
    try:
        ent = tc.get_entity(partition_key="state", row_key="latest")
        state = json.loads(ent.get("data", "{}") or "{}")
    except ResourceNotFoundError:
        state = {
            "poll": {},
            "last_sent": {"NB": None, "SB": None},
            "last_sent_at": {"NB": 0, "SB": 0},
        }
        tc.upsert_entity({"PartitionKey": "state", "RowKey": "latest", "data": json.dumps(state)})
        return state

    state.setdefault("poll", {})
    ls = state.get("last_sent")
    if not isinstance(ls, dict):
        state["last_sent"] = {"NB": None, "SB": None}
    else:
        ls.setdefault("NB", None)
        ls.setdefault("SB", None)
    lsa = state.get("last_sent_at")
    if not isinstance(lsa, dict):
        state["last_sent_at"] = {"NB": 0, "SB": 0}
    else:
        lsa.setdefault("NB", 0)
        lsa.setdefault("SB", 0)
    return state

def _state_save(tc, state: Dict[str, Any]) -> None:
    tc.upsert_entity({"PartitionKey": "state", "RowKey": "latest", "data": json.dumps(state)})

# ──────────────────── Core poller (single-instance safe) ───────────────────
def _is_first_window(direction: str, now_sec: int, last_sent_at: int) -> bool:
    tz = ZoneInfo("America/Vancouver")
    now = datetime.now(tz)
    start_str = next((w["start"] for w in DEFAULT_WINDOWS if w.get("dir") == direction), None)
    if start_str:
        h, m = map(int, start_str.split(":"))
        start = now.replace(hour=h, minute=m, second=0, microsecond=0)
    else:
        # Fallback to hard-coded defaults
        start = now.replace(hour=6 if direction == "SB" else 16, minute=0, second=0, microsecond=0)
    start_sec = int(start.timestamp())
    return last_sent_at < start_sec <= now_sec


def check_and_notify():
    tc = _require_table_client(STATE_TABLE)

    current = get_delays()
    state = _state_load(tc)

    # Always record latest poll
    state["poll"] = current
    now_sec = int(time.time())

    last_msg = state.get("last_sent", {})
    last_at = state.get("last_sent_at", {})

    to_send: List[str] = []
    first_flags: Dict[str, bool] = {}
    for direction in ("NB", "SB"):
        last_dir_at = int(last_at.get(direction, 0))
        if last_msg.get(direction) and (now_sec - last_dir_at) >= NOTIFY_MIN_GAP_SEC and _should_notify(last_msg, current, direction):
            to_send.append(direction)
            first_flags[direction] = _is_first_window(direction, now_sec, last_dir_at)

    # ── NEW: Global direction filter based on DEFAULT_WINDOWS (morning SB, evening NB)
    now_hhmm_str = datetime.now(ZoneInfo("America/Vancouver")).strftime("%H:%M")
    allowed_dirs = _global_allowed_dirs(now_hhmm_str)
    if allowed_dirs:
        to_send = [d for d in to_send if d in allowed_dirs]
    else:
        to_send = []  # outside any defined window → suppress all

    if not to_send:
        _state_save(tc, state)
        return

    for direction in to_send:
        last_msg[direction] = current[direction]
        last_at[direction] = now_sec
    state["last_sent"] = last_msg
    state["last_sent_at"] = last_at
    _state_save(tc, state)

    for direction in to_send:
        _broadcast_delays(current, direction, first_flags.get(direction, False))

def _broadcast_delays(current: Dict[str, Dict[str, int]], direction: str, first_in_window: bool):
    now_str = datetime.now(ZoneInfo("America/Vancouver")).strftime("%H:%M")
    now_sec = int(time.time())

    data = current[direction]
    label = "Northbound" if direction == "NB" else "Southbound"

    for u in get_user_settings():
        if not u.get("active", True):
            continue
        if int(u.get("pausedUntil", 0)) > now_sec:
            continue
        user_dir = window_direction(now_str, u.get("windows", DEFAULT_WINDOWS))
        if user_dir not in (direction, "BOTH"):
            continue
        threshold = u.get(
            "threshold_nb" if direction == "NB" else "threshold_sb",
            u.get("threshold", DEFAULT_THRESHOLD_NB if direction == "NB" else DEFAULT_THRESHOLD_SB),
        )
        if data["delay"] < threshold:
            continue
        body = f"🚦 Lions Gate update\n{label} delay: {data['delay']}m"
        if first_in_window:
            body += "\nReply PAUSE to pause alerts."
        sid = send_sms(body, u["phone"])
        print(f"🔔 Sent to {u['phone']}: {sid}")

# ──────────────────── Background poller (fixed lock + retry) ───────────────
_poll_lock = threading.Lock()
_poll_started = False

def start_background_polling():
    """
    Start the poller only after we actually acquire the distributed lock.
    If another instance holds the lock, schedule a retry instead of
    flipping _poll_started and giving up forever.
    """
    global _poll_started

    # don’t start multiple loops in this process
    if _poll_started:
        return

    if not ENABLE_POLLING or POLL_INTERVAL <= 0:
        print("Background polling disabled.")
        return

    tc = _require_table_client(STATE_TABLE)
    now = int(time.time())
    expire = now + POLL_INTERVAL * 2

    # Try to acquire/refresh the lock atomically
    acquired = False
    try:
        # First attempt: create (will fail if exists)
        tc.create_entity({
            "PartitionKey": LOCK_PARTITION,
            "RowKey": LOCK_ROW,
            "owner": _poll_id,
            "expiresAt": expire,
        })
        acquired = True
        print(f"[poll] lock created by {_poll_id}")
    except ResourceExistsError:
        try:
            ent = tc.get_entity(LOCK_PARTITION, LOCK_ROW)
            holder = ent.get("owner")
            ttl = int(ent.get("expiresAt", 0))
            if now > ttl:
                # Lock expired → steal by upserting (no delete race)
                ent["owner"] = _poll_id
                ent["expiresAt"] = expire
                tc.upsert_entity(ent)
                acquired = True
                print(f"[poll] lock expired; stolen by {_poll_id} (was {holder})")
            else:
                # Someone else is active; do NOT flip _poll_started — retry later
                print(f"[poll] another instance active ({holder}); retrying in 30s")
        except ResourceNotFoundError:
            # Race: it vanished between create+get → retry create once
            try:
                tc.create_entity({
                    "PartitionKey": LOCK_PARTITION,
                    "RowKey": LOCK_ROW,
                    "owner": _poll_id,
                    "expiresAt": expire,
                })
                acquired = True
                print(f"[poll] lock created after race by {_poll_id}")
            except Exception as e:
                print(f"[poll] lock create race failed; retrying in 30s: {e}")

    if not acquired:
        # schedule a retry; don’t mark started
        threading.Timer(30, start_background_polling).start()
        return

    # From here, we actually own the lock ⇒ now we can mark started
    _poll_started = True

    def release_lock() -> None:
        try:
            ent = tc.get_entity(LOCK_PARTITION, LOCK_ROW)
            if ent.get("owner") == _poll_id:
                tc.delete_entity(LOCK_PARTITION, LOCK_ROW)
                print("[poll] lock released")
        except Exception:
            pass

    atexit.register(release_lock)

    def loop():
        while True:
            with _poll_lock:
                try:
                    check_and_notify()
                except Exception as e:
                    print("Polling error:", e)
            try:
                ent = tc.get_entity(LOCK_PARTITION, LOCK_ROW)
                if ent.get("owner") != _poll_id:
                    print("[poll] lost lock; stopping")
                    break
                ent["expiresAt"] = int(time.time()) + POLL_INTERVAL * 2
                tc.upsert_entity(ent)
            except Exception as e:
                print(f"[poll] lock heartbeat failed; stopping: {e}")
                break
            time.sleep(POLL_INTERVAL)
        release_lock()

    threading.Thread(target=loop, daemon=True).start()

# ──────────────────── Utilities ────────────────────────────────────────────
def _global_allowed_dirs(now_hhmm: str) -> set[str]:
    """
    Derive which directions are globally allowed *right now* from DEFAULT_WINDOWS.
    If now is inside any window(s), allow only those directions.
    If now is outside all windows, return an empty set (suppress sends globally).
    """
    dirs: set[str] = set()
    for w in DEFAULT_WINDOWS:
        if w["start"] <= now_hhmm <= w["end"]:
            d = w.get("dir")
            if d in ("NB", "SB"):
                dirs.add(d)
    return dirs

def parse_windows(s: str):
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if len(parts) > 2:
        raise ValueError("Maximum two windows allowed")
    windows = []
    for part in parts:
        try:
            time_range, direction = part.rsplit(" ", 1)
            direction = direction.upper()
            start, end = time_range.split("-", 1)
            if direction not in ("NB", "SB"):
                raise ValueError
            if not re.match(r"^\d{2}:\d{2}$", start) or not re.match(r"^\d{2}:\d{2}$", end):
                raise ValueError
            if start >= end:
                raise ValueError
        except ValueError:
            raise ValueError(f"Invalid window: '{part}' (use HH:MM-HH:MM NB/SB)")
        windows.append({"start": start, "end": end, "dir": direction})
    return windows

# ──────────────────── Routes ───────────────────────────────────────────────
@app.route("/", methods=["GET"])
def health():
    return "ok", 200

@app.route("/api/status", methods=["GET", "OPTIONS"])
@cross_origin(origins=list(ALLOWED_ORIGINS),
              methods=["GET", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization", "content-type"],
              max_age=600)
def status():
    tc = _require_table_client(STATE_TABLE)
    try:
        ent = tc.get_entity(partition_key="state", row_key="latest")
        data = json.loads(ent.get("data", "{}") or "{}")
        return jsonify(data.get("poll", data))
    except ResourceNotFoundError:
        return jsonify({"msg": "no data yet"})

@app.route("/api/signup", methods=["POST", "OPTIONS"])
@cross_origin(origins=list(ALLOWED_ORIGINS),
              methods=["POST", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization", "content-type"],
              max_age=600)
def signup():
    data = request.get_json(silent=True) or {}
    raw = data.get("phone") if request.is_json else request.form.get("phone")
    if not raw:
        abort(400, "phone field is required")
    try:
        phone = normalize_phone(raw)
    except ValueError:
        abort(400, "invalid phone")

    # ⬇️ NEW: validate at signup so only CA mobile/voip get stored
    try:
        client = Client(ACCOUNT_SID, AUTH_TOKEN)
        _assert_canadian_mobile(client, phone)
    except Exception:
        abort(400, "We only support Canadian mobile numbers.")

    users = get_user_settings()
    if any(u["phone"] == phone for u in users):
        return {"msg": "already registered"}, 200

    users.append({
        "phone": phone,
        "active": True,
        "threshold_nb": DEFAULT_THRESHOLD_NB,
        "threshold_sb": DEFAULT_THRESHOLD_SB,
        "windows": DEFAULT_WINDOWS,
        "pausedUntil": 0,
    })
    save_user_settings(users)
    return {"msg": "registered"}, 201

@app.route("/api/otp/start", methods=["POST", "OPTIONS"])
@cross_origin(origins=list(ALLOWED_ORIGINS),
              methods=["POST", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization", "content-type"],
              max_age=600)
def otp_start():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(silent=True) or {}
    raw = data.get("phone")
    if not raw:
        abort(400, "phone is required")
    try:
        phone = normalize_phone(raw)
    except ValueError:
        # Soft success to avoid user enumeration
        return jsonify({"ok": True, "status": "sent"}), 200

    # ⬇️ NEW: enforce CA mobile/voip before we ever send OTP
    try:
        client = Client(ACCOUNT_SID, AUTH_TOKEN)
        _assert_canadian_mobile(client, phone)
    except Exception:
        return jsonify({"ok": True, "status": "sent"}), 200  # pretend sent; do not actually send

    if not any(u["phone"] == phone for u in get_user_settings()):
        return jsonify({"ok": True, "status": "sent"}), 200
    ok, status2 = otp_issue_and_send(phone)
    if not ok and status2 == "cooldown":
        return jsonify({"ok": True, "status": "cooldown"}), 200
    if not ok and status2 == "too_many_attempts":
        return jsonify({"ok": False, "error": "locked"}), 429
    return jsonify({"ok": True, "status": "sent"}), 200

@app.route("/api/otp/verify", methods=["POST", "OPTIONS"])
@cross_origin(origins=list(ALLOWED_ORIGINS),
              methods=["POST", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization", "content-type"],
              max_age=600)
def otp_verify():
    if request.method == "OPTIONS":
        return ("", 204)
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

@app.route("/api/user/settings", methods=["GET", "POST", "OPTIONS"])
@cross_origin(origins=list(ALLOWED_ORIGINS),
              methods=["GET", "POST", "OPTIONS"],
              allow_headers=["Content-Type", "Authorization", "content-type"],
              max_age=600)
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
            "threshold_nb": user.get("threshold_nb", DEFAULT_THRESHOLD_NB),
            "threshold_sb": user.get("threshold_sb", DEFAULT_THRESHOLD_SB),
            "windows": user.get("windows", DEFAULT_WINDOWS)
        })
    data = request.get_json(silent=True) or {}
    if "active" in data:
        user["active"] = bool(data["active"])
        if user["active"]:
            user["pausedUntil"] = 0
    if "threshold_nb" in data:
        try:
            user["threshold_nb"] = int(data["threshold_nb"])
        except Exception:
            return jsonify({"ok": False, "error": "invalid_threshold_nb"}), 400
    if "threshold_sb" in data:
        try:
            user["threshold_sb"] = int(data["threshold_sb"])
        except Exception:
            return jsonify({"ok": False, "error": "invalid_threshold_sb"}), 400
    if "threshold" in data:
        # Backward compatibility: set both thresholds
        try:
            val = int(data["threshold"])
            user["threshold_nb"] = val
            user["threshold_sb"] = val
        except Exception:
            return jsonify({"ok": False, "error": "invalid_threshold"}), 400
    if "windows" in data:
        try:
            user["windows"] = parse_windows(data["windows"]) if isinstance(data["windows"], str) else data["windows"]
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
    save_user_settings(users)
    return jsonify({"ok": True, "settings": user}), 200

# ---- Twilio inbound SMS ----------------------------------------------------
@app.route("/sms", methods=["POST"], strict_slashes=False)
def sms_webhook():
    if TWILIO_VALIDATE and not _twilio_signature_ok(request):
        return Response("Forbidden", status=403)

    resp = MessagingResponse()
    try:
        from_number = request.form.get("From", "").strip()
        if not from_number:
            abort(400)

        body_raw = request.form.get("Body", "").strip()
        parts    = body_raw.upper().split() if body_raw else ["HELP"]
        if parts:
            parts[0] = re.sub(r"[^A-Z]", "", parts[0])
        args = parts[1:]

        try:
            users = get_user_settings()
        except Exception:
            users = []
        user = next((u for u in users if u["phone"] == from_number), None)
        if not user:
            user = {
                "phone": from_number,
                "active": True,
                "threshold_nb": DEFAULT_THRESHOLD_NB,
                "threshold_sb": DEFAULT_THRESHOLD_SB,
                "windows": DEFAULT_WINDOWS,
                "pausedUntil": 0,
            }
            users.append(user)

        now_sec = int(time.time())

        if parts[0] == "PAUSE":
            user["pausedUntil"] = now_sec + 3600  # 1 hour
            try:
                save_user_settings(users)
            except Exception:
                pass
            resp.message("⏸️ Paused for 1 hour. Send REACTIVATE to resume sooner.")
            return Response(str(resp), mimetype="application/xml")

        if parts[0] == "DEACTIVATE":
            user["active"] = False
            try:
                save_user_settings(users)
            except Exception:
                pass
            resp.message("🔕 Alerts deactivated. Send REACTIVATE to turn them back on.")
            return Response(str(resp), mimetype="application/xml")

        if parts[0] == "REACTIVATE":
            user["active"] = True
            user["pausedUntil"] = 0
            try:
                save_user_settings(users)
            except Exception:
                pass
            resp.message("🔔 Alerts reactivated.")
            return Response(str(resp), mimetype="application/xml")

        if parts[0] == "STATUS":
            msg: str
            try:
                tc = _require_table_client(STATE_TABLE)
                ent = tc.get_entity(partition_key="state", row_key="latest")
                data = json.loads(ent.get("data", "{}") or "{}")
                poll = data.get("poll", data)
                nb_delay = poll["NB"]["delay"]
                sb_delay = poll["SB"]["delay"]
                msg = (
                    "🚦 Lions Gate update\n"
                    f"Northbound delay: {nb_delay}m\n"
                    f"Southbound delay: {sb_delay}m"
                )
            except Exception:
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

        if parts[0] == "THRESHOLD":
            if len(args) == 2 and args[0] in ("NB", "SB") and args[1].isdigit():
                val = int(args[1])
                if args[0] == "NB":
                    user["threshold_nb"] = val
                else:
                    user["threshold_sb"] = val
                try:
                    save_user_settings(users)
                except Exception:
                    pass
                resp.message(f"✅ {args[0]} threshold set to {val} minutes.")
            elif len(args) == 1 and args[0].isdigit():
                val = int(args[0])
                user["threshold_nb"] = val
                user["threshold_sb"] = val
                try:
                    save_user_settings(users)
                except Exception:
                    pass
                resp.message(f"✅ Threshold set to {val} minutes for NB and SB.")
            else:
                resp.message("❌ Use THRESHOLD NB|SB <minutes> or THRESHOLD <minutes>.")
        elif parts[0] == "WINDOW" and args:
            try:
                user["windows"] = parse_windows(" ".join(args))
                try:
                    save_user_settings(users)
                except Exception:
                    pass
                win_str = ", ".join(f"{w['start']}-{w['end']} {w['dir']}" for w in user["windows"])
                resp.message(f"✅ Windows set to {win_str}")
            except ValueError:
                resp.message("❌ Invalid format. Use: WINDOW HH:MM-HH:MM DIR[,HH:MM-HH:MM DIR]")
        elif parts[0] in ("LIST", "HELP"):
            resp.message("Commands: STATUS | THRESHOLD NB/SB n | WINDOW HH:MM-HH:MM DIR[,HH:MM-HH:MM DIR] | PAUSE | DEACTIVATE | REACTIVATE")
        else:
            resp.message("Unknown command. Send HELP for options.")

    except Exception:
        resp.message("⚠️ Error processing request.")
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


@app.route("/dev/sms", methods=["POST"])
def dev_sms():
    to = request.form.get("to", "").strip()
    body = request.form.get("body", "BridgeDelay test")
    try:
        sid = send_sms(body, normalize_phone(to))
        return {"ok": True, "sid": sid}, 200
    except Exception as e:
        import traceback
        return {"ok": False, "error": str(e), "trace": traceback.format_exc()}, 500

@app.route("/dev/showkey")
def dev_showkey():
    import os
    return {"GOOGLE_MAPS_API_KEY": os.getenv("GOOGLE_MAPS_API_KEY")}

import os
import time
import json
from datetime import datetime
from typing import Dict, Any

import requests
from twilio.rest import Client

# routes api
GOOGLE_KEY = os.getenv("GOOGLE_MAPS_API_KEY")
ROUTES_URL = "https://routes.googleapis.com/directions/v2:computeRouteMatrix"
HEADERS = {
    "Content-Type": "application/json",
    "X-Goog-Api-Key": GOOGLE_KEY,
    "X-Goog-FieldMask": "originIndex,destinationIndex,duration,staticDuration",
}

# coords
        #  NB is northbound (to north van), SB is southbound (to downtown)
NB_START = (49.283296, -123.119276)  # downtown starting from apple store
NB_END   = (49.324653, -123.130173)  # north shore off‑ramp
SB_START = (49.324432, -123.122765)  # north shore on‑ramp
SB_END   = (49.292738, -123.133985)  # downtown off‑ramp

# twilio vars
ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
AUTH_TOKEN  = os.getenv("TWILIO_AUTH_TOKEN")
FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER")
TO_NUMBERS  = os.getenv("TWILIO_TO_NUMBERS", "")

# persistence
STATE_FILE = "last_status.json"

# ---------------------------------------------------------------------------
# Helper funcs
# ---------------------------------------------------------------------------

def _latlng(pair):
    lat, lng = pair
    return {"latLng": {"latitude": lat, "longitude": lng}}


def get_delays() -> Dict[str, Dict[str, int]]:
    """Return live, base, delay minutes for NB & SB."""
    body: Dict[str, Any] = {
        "origins": [
            {"waypoint": {"location": _latlng(NB_START)}},  # origin0 = NB start
            {"waypoint": {"location": _latlng(SB_START)}},  # origin1 = SB start
        ],
        "destinations": [
            {"waypoint": {"location": _latlng(NB_END)}},    # dest0 = NB end
            {"waypoint": {"location": _latlng(SB_END)}},    # dest1 = SB end
        ],
        "travelMode": "DRIVE",
        "routingPreference": "TRAFFIC_AWARE_OPTIMAL",
    }

    r = requests.post(ROUTES_URL, headers=HEADERS, json=body, timeout=10)
    r.raise_for_status()
    matrix = r.json()  # order: (0,0) (0,1) (1,0) (1,1)

    def to_min(d: str) -> float:
        return float(d.rstrip("s")) / 60.0

    nb_elem = matrix[0]   # origin0 → dest0  (NB)
    sb_elem = matrix[3]   # origin1 → dest1  (SB)

    def build(elem):
        live  = to_min(elem["duration"])
        base  = to_min(elem["staticDuration"])
        delay = live - base
        return {"live": round(live), "base": round(base), "delay": round(delay)}

    return {"NB": build(nb_elem), "SB": build(sb_elem)}


# persistence helpers

def load_snapshot():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_snapshot(snap):
    with open(STATE_FILE, "w") as f:
        json.dump(snap, f)


# twilio helpers

def send_sms(body: str, to: str) -> str:
    client = Client(ACCOUNT_SID, AUTH_TOKEN)
    msg = client.messages.create(body=body, from_=FROM_NUMBER, to=to)
    return msg.sid


# user settings

def load_user_settings():
    try:
        with open("user_settings.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def get_user_settings():
    settings = load_user_settings()
    if settings:
        return settings
    # fallback to env list
    users = []
    for num in TO_NUMBERS.split(","):
        num = num.strip()
        if num:
            users.append({
                "phone": num,
                "threshold": 0,
                "windows": [{"start": "00:00", "end": "23:59"}],
            })
    return users


# --- business logic ---------------------------------------------------------

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

    users = get_user_settings()
    now = datetime.now().strftime("%H:%M")
    for u in users:
        thr = u["threshold"]
        if nb_s["delay"] < thr and sb_s["delay"] < thr:
            continue
        if not within_window(now, u["windows"]):
            continue
        sid = send_sms(body, u["phone"])
        print(f"🔔 Sent to {u['phone']}: {sid}")


# main loop (5 mins  intervals)
if __name__ == "__main__":
    required = (
        "GOOGLE_MAPS_API_KEY",
        "TWILIO_ACCOUNT_SID",
        "TWILIO_AUTH_TOKEN",
        "TWILIO_FROM_NUMBER",
        "TWILIO_TO_NUMBERS",
    )
    missing = [v for v in required if not os.environ.get(v)]
    if missing:
        print("⚠️ Missing env vars:", ", ".join(missing))
        exit(1)

    print("▶️ Bridge monitor started – polling every 5 min …")
    while True:
        try:
            check_and_notify()
        except Exception as e:
            print("❌ Error during check:", e)
        time.sleep(300)   # ← 5 minutes

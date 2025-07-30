# -*- coding: utf-8 -*-
"""
BridgeDelay – Google Routes edition
----------------------------------
Replaces the old GIF‑OCR scraper with a direct call to Google Maps Routes API.

• Polls once a minute (while‑loop at bottom) – keep or switch to Azure Functions.
• Sends SMS via Twilio when either north‑bound or south‑bound *severity bucket*
  changes, respecting each user’s threshold + time windows.

ENV VARS required (set in Azure App Service / Function Configuration or .env):
  GOOGLE_MAPS_API_KEY  – Routes API key (restricted to Routes API + your IPs)
  TWILIO_ACCOUNT_SID   – Twilio credentials
  TWILIO_AUTH_TOKEN
  TWILIO_FROM_NUMBER   – e.g. +15551234567 (must be a Twilio‑verified sender)
  TWILIO_TO_NUMBERS    – coma‑separated list of fallback numbers if no
                          per‑user settings file exists

Optional local JSON files created at runtime:
  last_status.json     – persists last NB/SB delays so we only notify on change
  user_settings.json   – opt‑in thresholds & time‑windows per user
"""

import os
import time
import json
from datetime import datetime
import re
from typing import Dict, Any

import requests
from twilio.rest import Client

# ── Google Routes API config ────────────────────────────────────────────────
GOOGLE_KEY = os.environ.get("GOOGLE_MAPS_API_KEY")
ROUTES_URL = "https://routes.googleapis.com/directions/v2:computeRouteMatrix"
HEADERS = {
    "Content-Type": "application/json",
    "X-Goog-Api-Key": GOOGLE_KEY,
    # ask only for the fields we need – smaller, cheaper responses
    "X-Goog-FieldMask": "originIndex,destinationIndex,duration,staticDuration",
}

# Lions Gate Bridge coords  (lat, lng)
SOUTH_END = (49.313217, -123.140648)  # Stanley Park / Prospect Point
NORTH_END = (49.316400, -123.130000)  # North Van exit (example)

# ── Twilio config ───────────────────────────────────────────────────────────
ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER")
TO_NUMBERS = os.environ.get("TWILIO_TO_NUMBERS", "")

# ── Persistence ─────────────────────────────────────────────────────────────
STATE_FILE = "last_status.json"

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _latlng(pair):
    lat, lng = pair
    return {"latLng": {"latitude": lat, "longitude": lng}}


def get_delays() -> Dict[str, int]:
    """Return current delays in minutes for both travel directions.

    Returns
    -------
    {"NB": minutes, "SB": minutes}
    """
    body: Dict[str, Any] = {
        "origins": [
            {"waypoint": {"location": _latlng(SOUTH_END)}},  # origin0 (south)
            {"waypoint": {"location": _latlng(NORTH_END)}},  # origin1 (north)
        ],
        "destinations": [
            {"waypoint": {"location": _latlng(NORTH_END)}},  # dest0 (north)
            {"waypoint": {"location": _latlng(SOUTH_END)}},  # dest1 (south)
        ],
        "travelMode": "DRIVE",
        "routingPreference": "TRAFFIC_AWARE_OPTIMAL",
    }

    r = requests.post(ROUTES_URL, headers=HEADERS, json=body, timeout=10)
    r.raise_for_status()
    matrix = r.json()  # four entries: (0,0) (0,1) (1,0) (1,1)

    def to_minutes(google_duration: str) -> float:
        return float(google_duration.rstrip("s")) / 60.0

    # south -> north (north‑bound)
    nb_elem = matrix[0]
    # north -> south (south‑bound)
    sb_elem = matrix[3]

    nb_delay = to_minutes(nb_elem["duration"]) - to_minutes(nb_elem["staticDuration"])
    sb_delay = to_minutes(sb_elem["duration"]) - to_minutes(sb_elem["staticDuration"])

    return {"NB": round(nb_delay), "SB": round(sb_delay)}


# --- persistence helpers ----------------------------------------------------

def load_last_snapshot() -> Dict[str, int]:
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_snapshot(snapshot: Dict[str, int]):
    with open(STATE_FILE, "w") as f:
        json.dump(snapshot, f)


# --- Twilio helpers ---------------------------------------------------------

def send_sms(body: str, to: str) -> str:
    client = Client(ACCOUNT_SID, AUTH_TOKEN)
    msg = client.messages.create(body=body, from_=FROM_NUMBER, to=to)
    return msg.sid


# --- user settings ----------------------------------------------------------

def load_user_settings():
    try:
        with open("user_settings.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def get_user_settings():
    # First try file, else fall back to env list with default prefs
    settings = load_user_settings()
    if settings:
        return settings

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


def within_any_window(now: str, windows):
    return any(w["start"] <= now <= w["end"] for w in windows)


def check_and_notify():
    # 1. Current snapshot
    current = get_delays()  # {"NB": x, "SB": y}
    nb_delay, sb_delay = current["NB"], current["SB"]
    nb_sev = severity_level(nb_delay)
    sb_sev = severity_level(sb_delay)

    # 2. Previous snapshot
    previous = load_last_snapshot()  # possibly empty {}
    old_nb_sev = severity_level(previous.get("NB", -1)) if previous else None
    old_sb_sev = severity_level(previous.get("SB", -1)) if previous else None

    # 3. Skip if neither direction changed bucket
    if nb_sev == old_nb_sev and sb_sev == old_sb_sev:
        print("No severity change; skipping.")
        return

    # 4. Save new state
    save_snapshot(current)

    # 5. Compose message
    body = (
        f"🚦 Lions Gate delay update\n"
        f"NB: {nb_delay} min (sev {nb_sev}) | SB: {sb_delay} min (sev {sb_sev})"
    )

    # 6. Notify users respecting prefs
    users = get_user_settings()
    now = datetime.now().strftime("%H:%M")
    for user in users:
        phone     = user["phone"]
        threshold = user["threshold"]
        windows   = user["windows"]

        if nb_delay < threshold and sb_delay < threshold:
            continue
        if not within_any_window(now, windows):
            continue

        sid = send_sms(body, phone)
        print(f"🔔 Sent to {phone}: {sid}")


# --- main loop --------------------------------------------------------------
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

    print("▶️  Bridge monitor started – polling every 60 s…")
    while True:
        try:
            check_and_notify()
        except Exception as e:
            print("❌ Error during check:", e)
        time.sleep(60)

import os, time, json
from dotenv import load_dotenv
import requests
from io import BytesIO
from PIL import Image
import pytesseract
from twilio.rest import Client
import re
from datetime import datetime



load_dotenv()  # load your .env

# ── Config from ENV ─────────────────────────────────────────────────────────
IMAGE_URL   = os.environ.get("IMAGE_URL")
ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
AUTH_TOKEN  = os.environ.get("TWILIO_AUTH_TOKEN")
FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER")
TO_NUMBERS  = os.environ.get("TWILIO_TO_NUMBERS", "")

# Where we persist last-seen text
STATE_FILE = "last_status.json"

# ── Helpers ──────────────────────────────────────────────────────────────────
def load_last_text():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f).get("last_text", "")
    except FileNotFoundError:
        return ""

def save_last_text(text: str):
    with open(STATE_FILE, "w") as f:
        json.dump({"last_text": text}, f)

def fetch_image(url: str) -> Image.Image:
    resp = requests.get(url)
    resp.raise_for_status()
    return Image.open(BytesIO(resp.content))

def extract_text(img: Image.Image) -> str:
    # B/W + whitelist digits & ":" to eliminate "@"
    bw = img.convert("L").point(lambda x: 0 if x < 140 else 255, "1")
    cfg = r"--oem 3 --psm 7 -c tessedit_char_whitelist=0123456789:"
    return pytesseract.image_to_string(bw, config=cfg).replace("@", "0").strip()

def send_sms_to_all(body: str) -> list[str]:
    client = Client(ACCOUNT_SID, AUTH_TOKEN)
    recipients = [n.strip() for n in TO_NUMBERS.split(",") if n.strip()]
    sids = []
    for to in recipients:
        msg = client.messages.create(
            body=body,
            from_=FROM_NUMBER,
            to=to
        )
        sids.append(msg.sid)
    return sids

def parse_delay(text):
    match = re.search(r"(\d+)", text)
    if match:
        return int(match.group(1))
    return None

def severity_level(delay: int) -> int:
    if delay <= 5:
        return 0
    elif 5 < delay <= 15:
        return 1
    elif 15 < delay <= 30:
        return 2
    else:
        return 3

def get_user_settings():
    """
    Return a list of user‐preference dicts:
      - phone (str)
      - threshold (int, min delay to alert)
      - windows (list of {start,end} in "HH:MM")
    For now, we’ll fall back to TWILIO_TO_NUMBERS env var, full‐day window, zero threshold.
    """
    numbers = os.environ.get("TWILIO_TO_NUMBERS", "")
    users = []
    for num in numbers.split(","):
        num = num.strip()
        if not num:
            continue
        users.append({
            "phone": num,
            "threshold": 0,
            "windows": [{"start": "00:00", "end": "23:59"}]
        })
    return users

def send_sms_to_user(body: str, to: str) -> str:
    """
    Send one SMS to a single user.
    """
    client = Client(ACCOUNT_SID, AUTH_TOKEN)
    msg = client.messages.create(
        body=body,
        from_=FROM_NUMBER,
        to=to
    )
    return msg.sid

def load_user_settings():
    try:
        with open("user_settings.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []



# ── The core check ────────────────────────────────────────────────────────────
def check_and_notify():
    last = load_last_text()
    new  = extract_text(fetch_image(IMAGE_URL))

    # Parse out the numeric delay
    new_delay = parse_delay(new)
    if new_delay is None:
        print("⚠️ Couldn’t extract a number from OCR:", new)
        return

    # Compute the new severity bucket
    new_sev = severity_level(new_delay)
    print(f"Parsed delay = {new_delay} min → severity {new_sev}")

    # Parse and bucket the old value
    old_delay = parse_delay(last)
    old_sev   = severity_level(old_delay) if old_delay is not None else None

    # Skip if severity didn’t change
    if new_sev == old_sev:
        print(f"No severity change (still {new_sev}); skipping.")
        return

    # Persist the new status and notify everyone
    save_last_text(new)
    body = f"🚨 Severity changed: was {old_sev}, now {new_sev} (delay {new_delay} min)"
        # Load per-user preferences
    users = get_user_settings()

    # Current time as "HH:MM"
    now = datetime.now().strftime("%H:%M")

    # Loop through each user and apply their threshold & windows
    for user in users:
        phone     = user["phone"]
        threshold = user["threshold"]
        windows   = user["windows"]

        # 1️⃣ Skip if below their personal threshold
        if new_delay < threshold:
            continue

        # 2️⃣ Skip if current time not in any of their windows
        in_window = any(
            win["start"] <= now <= win["end"]
            for win in windows
        )
        if not in_window:
            continue

        # 3️⃣ Send a personalized SMS
        sid = send_sms_to_user(body, phone)
        print(f"🔔 Sent to {phone}: {sid}")



# ── Run forever, polling once a minute ───────────────────────────────────────
if __name__ == "__main__":
    # sanity checks
    for var in ("IMAGE_URL","TWILIO_ACCOUNT_SID","TWILIO_AUTH_TOKEN","TWILIO_FROM_NUMBER","TWILIO_TO_NUMBERS"):
        if not os.environ.get(var):
            print(f"⚠️ Missing env var {var}; exiting.")
            exit(1)

    print("▶️  Starting monitor, polling every 60s…")
    while True:
        try:
            check_and_notify()
        except Exception as e:
            print("❌ Error during check:", e)
        time.sleep(60)

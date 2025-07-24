import os
import json
from flask import Flask, request, Response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.twiml.messaging_response import MessagingResponse
from main import (
    load_user_settings,
    save_user_settings,
    parse_windows,
    fetch_image,
    extract_text,
    parse_delay,
    severity_level,
    IMAGE_URL
)

# map severity → colored circle
SEV_EMOJI = {
    0: "🟢",
    1: "🟡",
    2: "🟠",
    3: "🔴",
}

# Basic user account storage
USER_DB = "accounts.json"


def load_accounts():
    try:
        with open(USER_DB, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def save_accounts(data) -> None:
    with open(USER_DB, "w") as f:
        json.dump(data, f, indent=2)



app = Flask(__name__)


@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json() or request.form
    if "email" not in data:
        return jsonify({"error": "Email required"}), 400

    accounts = load_accounts()
    if any(u["email"] == data["email"] for u in accounts):
        return jsonify({"error": "Email already exists"}), 400

    account = {
        "email": data["email"],
        "first": data.get("first", ""),
        "last": data.get("last", ""),
        "phone": data.get("phone", ""),
    }

    if "pass" in data:
        account["password"] = generate_password_hash(data["pass"])
    accounts.append(account)
    save_accounts(accounts)
    return jsonify({"status": "ok"})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or request.form
    email = data.get("email")
    pw = data.get("pass")
    if not email or not pw:
        return jsonify({"error": "Missing credentials"}), 400

    accounts = load_accounts()
    user = next((u for u in accounts if u["email"] == email), None)
    if not user or not check_password_hash(user["password"], pw):
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"status": "ok"})

@app.route("/sms", methods=["POST"])
def sms_webhook():
    # 1) Get sender and text
    from_number = request.form.get("From")
    body        = request.form.get("Body", "").strip()

    # 2) Load or init user prefs
    users = load_user_settings()
    user = next((u for u in users if u["phone"] == from_number), None)
    if not user:
        user = {
            "phone": from_number,
            "threshold": 0,
            "windows": [{"start": "00:00", "end": "23:59"}]
        }
        users.append(user)

    # 3) Split into command + args
    parts = body.upper().split(maxsplit=1)
    resp  = MessagingResponse()

    # ➤ STATUS: report the live delay regardless of threshold
    if parts[0] == "STATUS":
        try:
            img   = fetch_image(IMAGE_URL)
            raw_text = extract_text(img)
            delay = parse_delay(raw_text)
            if delay is None:
                resp.message("⚠️ Couldn’t parse delay right now.")
            else:
                sev = severity_level(delay)
                emoji = SEV_EMOJI.get(sev, "❓")
                resp.message(f"{emoji} Current delay: {delay} min (severity {sev})")
        except Exception:
            resp.message("⚠️ Could not fetch status right now.")
        return Response(str(resp), mimetype="application/xml")


    # 4a) THRESHOLD command
    if parts[0] == "THRESHOLD" and len(parts) == 2 and parts[1].isdigit():
        new_thr = int(parts[1])
        user["threshold"] = new_thr
        save_user_settings(users)
        resp.message(f"✅ Threshold set to {new_thr} minutes.")

    # 4b) WINDOW command
    elif parts[0] == "WINDOW" and len(parts) == 2:
        try:
            new_wins = parse_windows(parts[1])
            user["windows"] = new_wins
            save_user_settings(users)
            # echo back the ranges
            win_str = ", ".join(f"{w['start']}-{w['end']}" for w in new_wins)
            resp.message(f"✅ Windows set to {win_str}")
        except Exception:
            resp.message("❌ Invalid format. Use: WINDOW HH:MM-HH:MM[,HH:MM-HH:MM]")

    elif parts[0] in ("LIST", "HELP"):
        resp.message(
            "Available commands:\n"
            "• THRESHOLD <minutes>   Set your alert threshold\n"
            "• WINDOW <HH:MM-HH:MM>[,<HH:MM-HH:MM>]   Set up to one or two notify windows\n"
            "• STATUS   Get the current bridge delay\n"
            "• LIST or HELP   Show this message\n"
        )
        return Response(str(resp), mimetype="application/xml")

    elif parts[0] == "RAW":
        try:
            img = fetch_image(IMAGE_URL)
            raw = extract_text(img)
            snippet = raw[:150] + ("…" if len(raw) > 150 else "")
            resp.message(f"🔍 OCR raw: {snippet}")
        except Exception as e:
            # 1) Log full error server‐side
            print("🔴 RAW handler error:", e)
            # 2) Echo error back so you see it in the SMS
            resp.message(f"⚠️ OCR error: {e}")
        return Response(str(resp), mimetype="application/xml")

    # 4c) Unknown command
    else:
        resp.message(
            "❓ Commands:\n"
            "• THRESHOLD:  (Adjust alert threshold) \n"
            "• WINDOW:  (Adjust notification window) \n"
            "• STATUS:  (Get current bridge delay) \n"
            "• LIST or HELP:  (Full list of commands and how to format them)\n"
        )


    # 5) Send TwiML back
    return Response(str(resp), mimetype="application/xml")


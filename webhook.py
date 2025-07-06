import os
import json
from flask import Flask, request, Response
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



app = Flask(__name__)

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
            # Trim to 150 chars so SMS doesn’t truncate
            snippet = raw[:150] + ("…" if len(raw) > 150 else "")
            resp.message(f"🔍 OCR raw: {snippet}")
        except Exception:
            resp.message("⚠️ Error fetching OCR text.")
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

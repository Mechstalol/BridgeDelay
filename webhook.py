import os
import json
from flask import Flask, request, Response, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.twiml.messaging_response import MessagingResponse
from main import (              # ⟵ only this import line changed
    load_user_settings,
    save_user_settings,
    parse_windows,
    get_delays,                 # NEW
    severity_level              # unchanged
)

# map severity → colored circle
SEV_EMOJI = {0: "🟢", 1: "🟡", 2: "🟠", 3: "🔴"}

# Basic user account storage
USER_DB = "accounts.json"

def load_accounts():
    try:
        with open(USER_DB, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_accounts(data):
    with open(USER_DB, "w") as f:
        json.dump(data, f, indent=2)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# -------------------------------------------------------------------
#  REST API  (signup / login)
# -------------------------------------------------------------------
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json() or request.form
    if "email" not in data:
        return jsonify({"error": "Email required"}), 400
    accounts = load_accounts()
    if any(u["email"] == data["email"] for u in accounts):
        return jsonify({"error": "Email already exists"}), 400
    account = {
        "email":  data["email"],
        "first":  data.get("first", ""),
        "last":   data.get("last", ""),
        "phone":  data.get("phone", "")
    }
    if "pass" in data:
        account["password"] = generate_password_hash(data["pass"])
    accounts.append(account)
    save_accounts(accounts)
    return jsonify({"status": "ok"})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or request.form
    email, pw = data.get("email"), data.get("pass")
    if not email or not pw:
        return jsonify({"error": "Missing credentials"}), 400
    user = next((u for u in load_accounts() if u["email"] == email), None)
    if not user or not check_password_hash(user["password"], pw):
        return jsonify({"error": "Invalid credentials"}), 401
    return jsonify({"status": "ok"})

# -------------------------------------------------------------------
#  Twilio SMS webhook
# -------------------------------------------------------------------
def _format_status_block(d, emoji):
    """NB/SB one-liner."""
    return f"{emoji} {d['live']}m (base {d['base']} +{d['delay']})"

@app.route("/sms", methods=["POST"])
def sms_webhook():
    # 1) Sender + body
    from_number = request.form.get("From")
    body        = request.form.get("Body", "").strip()

    # 2) Load (or init) user prefs
    users = load_user_settings()
    user  = next((u for u in users if u["phone"] == from_number), None)
    if not user:
        user = {
            "phone":     from_number,
            "threshold": 0,
            "windows":   [{"start": "00:00", "end": "23:59"}]
        }
        users.append(user)

    # 3) Split cmd + args
    parts = body.upper().split(maxsplit=1)
    cmd   = parts[0]
    resp  = MessagingResponse()

    # ---------- STATUS --------------------------------------------------
    if cmd == "STATUS":
        try:
            delays = get_delays()              # {"NB": {...}, "SB": {...}}
            nb, sb = delays["NB"], delays["SB"]
            sev_nb = severity_level(nb["delay"])
            sev_sb = severity_level(sb["delay"])
            msg = (
                "NB " + _format_status_block(nb, SEV_EMOJI[sev_nb]) + "\n" +
                "SB " + _format_status_block(sb, SEV_EMOJI[sev_sb])
            )
            resp.message(msg)
        except Exception:
            resp.message("⚠️ Couldn’t fetch status right now.")
        return Response(str(resp), mimetype="application/xml")

    # ---------- THRESHOLD n --------------------------------------------
    if cmd == "THRESHOLD" and len(parts) == 2 and parts[1].isdigit():
        new_thr = int(parts[1])
        user["threshold"] = new_thr
        save_user_settings(users)
        resp.message(f"✅ Threshold set to {new_thr} minutes.")

    # ---------- WINDOW ranges ------------------------------------------
    elif cmd == "WINDOW" and len(parts) == 2:
        try:
            new_wins = parse_windows(parts[1])
            user["windows"] = new_wins
            save_user_settings(users)
            win_str = ", ".join(f"{w['start']}-{w['end']}" for w in new_wins)
            resp.message(f"✅ Windows set to {win_str}")
        except Exception:
            resp.message("❌ Invalid format. Use: WINDOW HH:MM-HH:MM[,HH:MM-HH:MM]")

    # ---------- RAW (debug) --------------------------------------------
    elif cmd == "RAW":
        try:
            resp.message("🔍 " + json.dumps(get_delays()))
        except Exception as e:
            print("RAW handler error:", e)
            resp.message(f"⚠️ {e}")
        return Response(str(resp), mimetype="application/xml")

    # ---------- HELP / LIST -------------------------------------------
    elif cmd in ("LIST", "HELP"):
        resp.message(
            "Available commands:\n"
            "• THRESHOLD <minutes>   Set alert threshold\n"
            "• WINDOW <HH:MM-HH:MM>[,<HH:MM-HH:MM>]   Set up to two windows\n"
            "• STATUS                Get current bridge delay\n"
            "• LIST or HELP          Show this message\n"
        )
        return Response(str(resp), mimetype="application/xml")

    # ---------- Unknown cmd -------------------------------------------
    else:
        resp.message(
            "❓ Commands:\n"
            "• THRESHOLD, WINDOW, STATUS, LIST/HELP"
        )

    # 5) Send TwiML
    return Response(str(resp), mimetype="application/xml")

# BridgeDelay

A simple monitor that polls Google Maps for Lions Gate Bridge travel times and
sends SMS alerts when delay severity changes or the delay jumps by at least 15
minutes since the last alert. It also exposes a Twilio SMS webhook so users can
adjust alert preferences or query the current status on demand. By default, the
app sends southbound alerts in the morning (06:30–08:30) and northbound alerts
in the evening (16:30–19:30). The first alert after each window starts reminds
you to reply "PAUSE" if you need to silence notifications.

## Environment variables

Set the following variables before running the app:

- `GOOGLE_MAPS_API_KEY` – Google Maps Routes API key used for delay lookups.
- `TWILIO_ACCOUNT_SID` – Twilio account SID used to send SMS.
- `TWILIO_AUTH_TOKEN` – Twilio auth token used to authenticate API requests.
- `TWILIO_FROM_NUMBER` – The Twilio phone number that sends the alerts.
- `JWT_SECRET`/`OTP_SIGNING_KEY` – Secret used to sign OTP login tokens.
- `ENABLE_POLLING` – Set to `0` to disable the background polling thread.
- `POLL_INTERVAL` – Interval in seconds between delay checks. Defaults to
  `300` seconds. Setting it to `0` also disables polling. The thread starts
  automatically on the first request.
- `NOTIFY_MIN_STEP` – Minimum change in delay (minutes) from the last message
  before another alert is sent for the same direction. Defaults to `15`.

## Running locally

Install requirements and then run the web server and poller. The poller checks
Google Maps every five minutes and must run continuously alongside the web
server.

```bash
pip install -r requirements.txt

# Terminal 1 – background poller
python bridge_app.py --poll

# Terminal 2 – Flask web server
gunicorn --bind 0.0.0.0:8000 bridge_app:app
```

Alternatively, run the helper script which starts both components for you:

```bash
./run.sh
```

## Docker build and deployment

Build the image:

```bash
docker build -t bridgedelay .
```

Run it with the required environment configured. The container starts the
poller and serves the webhook on port 8000 (mapped below to host port 80):

```bash
docker run -p 80:8000 \
  -e GOOGLE_MAPS_API_KEY=... \
  -e TWILIO_ACCOUNT_SID=... \
  -e TWILIO_AUTH_TOKEN=... \
  -e TWILIO_FROM_NUMBER=... \
  -e JWT_SECRET=... \
  bridgedelay
```

## Usage examples

Send `STATUS` to the Twilio number to receive the current delay. Adjust your
alert threshold with `THRESHOLD <minutes>` or define time windows and
directions with `WINDOW HH:MM-HH:MM DIR[,HH:MM-HH:MM DIR]`. Use `LIST` or `HELP`
for a summary of available commands.

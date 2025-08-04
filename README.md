# BridgeDelay

A simple monitor that polls Google Maps for Lions Gate Bridge travel times and
sends SMS alerts when delay severity changes. It also exposes a Twilio SMS
webhook so users can adjust alert preferences or query the current status on
demand.

## Environment variables

Set the following variables before running the app:

- `GOOGLE_MAPS_API_KEY` – Google Maps Routes API key used for delay lookups.
- `TWILIO_ACCOUNT_SID` – Twilio account SID used to send SMS.
- `TWILIO_AUTH_TOKEN` – Twilio auth token.
- `TWILIO_FROM_NUMBER` – The Twilio phone number that sends the alerts.
 codex/add-background-job-for-notifications
- `TWILIO_TO_NUMBERS` – Comma-separated list of recipient numbers for the
  monitor when running without per-user settings.
- `ENABLE_POLLING` – Set to `0` to disable the background polling thread
  (defaults to enabled).
- `POLL_INTERVAL` – Interval in seconds between delay checks. Defaults to
  `300` seconds. Setting it to `0` also disables polling.
 codex/add-background-job-for-notifications
=======

- `TWILIO_TO_NUMBERS` – Optional comma-separated list of recipient numbers for
  the monitor when running without per-user settings.
 main
 main

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
  -e TWILIO_TO_NUMBERS=... \
  bridgedelay
```

## Usage examples

Send `STATUS` to the Twilio number to receive the current delay. Adjust your
alert threshold with `THRESHOLD <minutes>` or define time windows with
`WINDOW HH:MM-HH:MM[,HH:MM-HH:MM]`. Use `LIST` or `HELP` for a summary of
available commands.

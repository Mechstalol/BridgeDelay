# BridgeDelay

A simple monitor that checks a live image for the current delay time and
sends SMS alerts when the delay severity changes. It also exposes a Twilio
SMS webhook so users can adjust their alert preferences or query the
current status on demand.

## Environment variables

The application expects the following variables to be defined:

- `IMAGE_URL` – URL of the image containing the delay text.
- `TWILIO_ACCOUNT_SID` – Twilio account SID used to send SMS.
- `TWILIO_AUTH_TOKEN` – Twilio auth token.
- `TWILIO_FROM_NUMBER` – The Twilio phone number that sends the alerts.
- `TWILIO_TO_NUMBERS` – Comma-separated list of recipient numbers for the
  monitor when running without per-user settings.
- `ENABLE_POLLING` – Set to `0` to disable the background polling thread.
- `POLL_INTERVAL` – Interval in seconds between delay checks. Defaults to
  `300` seconds. Setting it to `0` also disables polling.
  The thread starts automatically on the first request.

## Running locally

Install the requirements and run the monitor directly:

```bash
pip install -r requirements.txt
python main.py
```

Alternatively run the helper script which installs dependencies and then
launches the monitor:

```bash
./run.sh
```

## Docker build and deployment

Build the image:

```bash
docker build -t bridgedelay .
```

Run it with the required environment configured and expose port 80 for the
webhook:

```bash
docker run -p 80:80 \
  -e IMAGE_URL=... \
  -e TWILIO_ACCOUNT_SID=... \
  -e TWILIO_AUTH_TOKEN=... \
  -e TWILIO_FROM_NUMBER=... \
  -e TWILIO_TO_NUMBERS=... \
  bridgedelay
```

This launches the delay monitor in the background and serves the Twilio
webhook on port 80 using Gunicorn as specified in the Dockerfile.

## Usage examples

Send `STATUS` to the Twilio number to receive the current delay. Adjust your
alert threshold with `THRESHOLD <minutes>` or define time windows with
`WINDOW HH:MM-HH:MM[,HH:MM-HH:MM]`. Use `LIST` or `HELP` for a summary of
available commands.

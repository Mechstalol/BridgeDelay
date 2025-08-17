#!/usr/bin/env bash
set -euo pipefail

PORT_TO_BIND="${WEBSITES_PORT:-${PORT:-8000}}"

# 1) Start the polling loop in the background
if [[ "${ENABLE_POLLING:-1}" != "0" ]]; then
  echo "[run.sh] launching poller (interval: ${POLL_INTERVAL:-300}s)"
  # -u: unbuffered so logs show up immediately in Log Stream
  python -u bridge_app.py --poll &
fi

# 2) Run gunicorn (single worker to avoid double-sends from multiple workers)
: "${WEB_CONCURRENCY:=1}"
echo "[run.sh] starting gunicorn on ${PORT_TO_BIND} (workers=${WEB_CONCURRENCY})"
exec gunicorn \
  --bind "0.0.0.0:${PORT_TO_BIND}" \
  --workers "${WEB_CONCURRENCY}" \
  --log-level info \
  bridge_app:app

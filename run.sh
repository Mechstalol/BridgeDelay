#!/usr/bin/env bash
set -euo pipefail

PORT_TO_BIND="${WEBSITES_PORT:-${PORT:-8000}}"

# Start one dedicated poller process
if [[ "${ENABLE_POLLING:-1}" != "0" ]]; then
  echo "[run.sh] launching poller (interval: ${POLL_INTERVAL:-300}s)"
  python -u bridge_app.py --poll &
  # Make sure the in-app poller is off so we never double-send
  export ENABLE_POLLING=0
fi

# One worker prevents duplicate sends
export WEB_CONCURRENCY="${WEB_CONCURRENCY:-1}"
echo "[run.sh] starting gunicorn on ${PORT_TO_BIND} (workers=${WEB_CONCURRENCY})"
exec gunicorn \
  --bind "0.0.0.0:${PORT_TO_BIND}" \
  --workers "${WEB_CONCURRENCY}" \
  --log-level info \
  bridge_app:app

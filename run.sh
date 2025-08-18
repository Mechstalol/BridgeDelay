#!/usr/bin/env bash
set -euo pipefail

PORT_TO_BIND="${WEBSITES_PORT:-${PORT:-8000}}"

# Start the dedicated poller *once*
if [[ "${ENABLE_POLLING:-1}" != "0" ]]; then
  echo "[run.sh] launching poller (interval: ${POLL_INTERVAL:-300}s)"
  python -u bridge_app.py --poll &
  # Disable the Flask in-app poller so we don't run two pollers
  export ENABLE_POLLING=0
fi

# Single worker → no duplicate sends
export WEB_CONCURRENCY="${WEB_CONCURRENCY:-1}"
echo "[run.sh] starting gunicorn on ${PORT_TO_BIND} (workers=${WEB_CONCURRENCY})"
exec gunicorn \
  --bind "0.0.0.0:${PORT_TO_BIND}" \
  --workers "${WEB_CONCURRENCY}" \
  --log-level info \
  bridge_app:app

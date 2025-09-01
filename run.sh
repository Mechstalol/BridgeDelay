#!/usr/bin/env bash
set -euo pipefail

PORT_TO_BIND="${WEBSITES_PORT:-${PORT:-8000}}"

poller_pid=""
gunicorn_pid=""

cleanup() {
  if [[ -n "${gunicorn_pid}" ]]; then
    kill "${gunicorn_pid}" 2>/dev/null || true
    wait "${gunicorn_pid}" 2>/dev/null || true
  fi
  if [[ -n "${poller_pid}" ]]; then
    echo "[run.sh] stopping poller"
    kill "${poller_pid}" 2>/dev/null || true
    wait "${poller_pid}" 2>/dev/null || true
  fi
}

trap cleanup TERM INT

# Start the polling loop in the background (single instance)
if [[ "${ENABLE_POLLING:-1}" != "0" ]]; then
  echo "[run.sh] launching poller (interval: ${POLL_INTERVAL:-300}s)"
  python -u bridge_app.py --poll &
  poller_pid=$!
fi

# One worker avoids duplicate sends
: "${WEB_CONCURRENCY:=1}"
echo "[run.sh] starting gunicorn on ${PORT_TO_BIND} (workers=${WEB_CONCURRENCY})"
gunicorn \
  --bind "0.0.0.0:${PORT_TO_BIND}" \
  --workers "${WEB_CONCURRENCY}" \
  --log-level info \
  bridge_app:app &
gunicorn_pid=$!

wait "${gunicorn_pid}"
exit_code=$?

cleanup

exit "$exit_code"

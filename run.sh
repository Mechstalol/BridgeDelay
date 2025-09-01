#!/usr/bin/env bash
set -euo pipefail

PORT_TO_BIND="${WEBSITES_PORT:-${PORT:-8000}}"

poller_pid=""
gunicorn_pid=""
shutdown_requested=0

cleanup() {
  shutdown_requested=1
  if [[ -n "${gunicorn_pid}" ]]; then
    kill "${gunicorn_pid}" 2>/dev/null || true
    wait "${gunicorn_pid}" 2>/dev/null || true
    gunicorn_pid=""
  fi
  if [[ -n "${poller_pid}" ]]; then
    echo "[run.sh] stopping poller"
    kill "${poller_pid}" 2>/dev/null || true
    wait "${poller_pid}" 2>/dev/null || true
    poller_pid=""
  fi
}

trap cleanup TERM INT

start_poller() {
  if [[ "${ENABLE_POLLING:-1}" != "0" ]]; then
    echo "[run.sh] launching poller (interval: ${POLL_INTERVAL:-300}s)"
    python -u bridge_app.py --poll &
    poller_pid=$!
  fi
}

start_gunicorn() {
  echo "[run.sh] starting gunicorn on ${PORT_TO_BIND} (workers=${WEB_CONCURRENCY})"
  gunicorn \
    --bind "0.0.0.0:${PORT_TO_BIND}" \
    --workers "${WEB_CONCURRENCY}" \
    --log-level info \
    bridge_app:app &
  gunicorn_pid=$!
}

# One worker avoids duplicate sends
: "${WEB_CONCURRENCY:=1}"

start_poller

# Restart gunicorn automatically if it exits unexpectedly
while true; do
  start_gunicorn
  wait "${gunicorn_pid}"
  exit_code=$?
  if [[ "${shutdown_requested}" -eq 1 ]]; then
    break
  fi
  echo "[run.sh] gunicorn exited with code ${exit_code}, restarting..."
  sleep 1
done

cleanup
exit "$exit_code"

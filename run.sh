#!/usr/bin/env bash
set -e
exec gunicorn --bind 0.0.0.0:${WEBSITES_PORT:-${PORT:-8000}} --log-level debug bridge_app:app

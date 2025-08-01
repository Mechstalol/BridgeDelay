#!/usr/bin/env bash
set -e
python -u bridge_app.py --poll &
exec gunicorn --bind 0.0.0.0:${PORT:-8000} --log-level debug bridge_app:app

#!/usr/bin/env bash
set -e

# Launch Flask app via Gunicorn on the port Azure probes (8000)
exec gunicorn --bind 0.0.0.0:${PORT:-8000} … bridge_app:app

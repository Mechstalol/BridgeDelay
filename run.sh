#!/usr/bin/env bash
set -e

# Launch Flask app via Gunicorn on the port Azure probes (8000)
exec gunicorn --bind 0.0.0.0:8000 --log-level debug bridge_app:app

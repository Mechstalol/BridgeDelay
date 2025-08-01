#!/usr/bin/env bash
set -e

# 1️⃣ Create and activate virtual environment
python -m venv venv
source venv/bin/activate

# 2️⃣ Install Python deps
pip install --no-cache-dir -r requirements.txt

# 3️⃣ Run the monitor
python bridge_app.py


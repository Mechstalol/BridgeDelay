# 1) Base
FROM python:3.11-slim

# 2) (Optional) system utils
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

# 3) App
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir gunicorn
COPY . .

# 4) Expose app port and start
EXPOSE 8000
ENV PORT=8000
CMD ["gunicorn", "-k", "gthread", "--threads", "4", "--workers", "2", "--timeout", "120", "--bind", "0.0.0.0:8000", "bridge_app:app"]

# 1) Base
FROM python:3.11-slim

# 2) Minimal OS deps
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

# 3) App
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir gunicorn
COPY . .

# 4) Expose and start through run.sh
EXPOSE 8000
ENV PORT=8000
CMD ["bash", "-lc", "./run.sh"]

# ── 1️⃣ Base image ──────────────────────────────────────────────
FROM python:3.11-slim

# ── 2️⃣ System packages: Tesseract + SSH ────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tesseract-ocr libtesseract-dev libleptonica-dev pkg-config \
        openssh-server && \
    rm -rf /var/lib/apt/lists/*

# ── 3️⃣ Configure SSH (root pwd = docker, listen on 2222) ──────
RUN mkdir /run/sshd && \
    echo 'root:docker' | chpasswd && \
    sed -i \
        -e 's/^#\?Port .*/Port 2222/' \
        -e 's/^#\?PermitRootLogin .*/PermitRootLogin yes/' \
        -e 's/^#\?UseDNS .*/UseDNS no/' \
        -e '$aClientAliveInterval 120' \
        /etc/ssh/sshd_config

# ── 4️⃣ App directory ──────────────────────────────────────────
WORKDIR /app

# ── 5️⃣ Python deps ────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── 6️⃣ Copy source code ───────────────────────────────────────
COPY . .

# ── 7️⃣ Expose ports (80 = web API, 2222 = SSH tunnel) ─────────
EXPOSE 80 2222

# ── 8️⃣ CMD: monitor + sshd + gunicorn ─────────────────────────
CMD ["bash","-c", "\
      python -u main.py & \
      /usr/sbin/sshd -D -p 2222 & \
      exec gunicorn --bind 0.0.0.0:${PORT:-80} webhook:app" ]

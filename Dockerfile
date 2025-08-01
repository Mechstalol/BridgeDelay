# ── 1️⃣ Base image ──────────────────────────────────────────────
FROM python:3.11-slim

# ── 2️⃣ System packages: Tesseract + SSH (unchanged) ───────────
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
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir gunicorn     # guarantee gunicorn

# ── 6️⃣ Copy source code ───────────────────────────────────────
COPY . .

# ── 7️⃣ Copy + make run.sh executable ──────────────────────────
COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

# ── 8️⃣ Expose ports ───────────────────────────────────────────
EXPOSE 8000 2222

# ── 9️⃣ Start everything via run.sh (variable expands inside) ──
CMD ["sh", "-c", "./run.sh"]

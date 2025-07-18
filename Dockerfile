# ── 1️⃣ Base image ──────────────────────────────────────────────
FROM python:3.11-slim

# ── 2️⃣ System packages: Tesseract + SSH ────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tesseract-ocr libtesseract-dev libleptonica-dev pkg-config \
        openssh-server && \
    rm -rf /var/lib/apt/lists/*

# ── 3️⃣ Configure SSH (port 2222, root pwd = docker) ───────────
RUN mkdir /run/sshd && \
    echo 'root:docker' | chpasswd && \
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

# ── 4️⃣ App directory ──────────────────────────────────────────
WORKDIR /app

# ── 5️⃣ Python deps ────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── 6️⃣ Copy source code ───────────────────────────────────────
COPY . .

# ── 7️⃣ Expose ports (80 = web, 2222 = SSH) ────────────────────
EXPOSE 80
EXPOSE 2222

# ── 8️⃣ Single CMD: monitor + sshd + gunicorn ──────────────────
CMD ["bash","-c", "\
      python -u main.py & \
      /usr/sbin/sshd -D & \
      exec gunicorn --bind 0.0.0.0:${PORT:-80} webhook:app" ]

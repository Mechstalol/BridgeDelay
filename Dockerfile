# 1️⃣ Base image with Python
FROM python:3.11-slim

# 2️⃣ Install system deps (Tesseract OCR + its libs)
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       tesseract-ocr libtesseract-dev libleptonica-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*

# 3️⃣ Create app directory
WORKDIR /app

# 4️⃣ Copy and install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5️⃣ Copy the rest of your code
COPY . .

# 6️⃣ Expose port 80 for App Service
EXPOSE 80

# 7️⃣ Launch both your monitor and webhook
CMD ["bash","-c", \
     "python main.py & \
      exec gunicorn --bind 0.0.0.0:${PORT:-80} webhook:app"]

FROM python:3.10-slim

# Stabilniejsze logi + brak pyc
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# LibreOffice lubi zapisywać cache/config w HOME — w kontenerze ustawiamy na /tmp
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp \
    XDG_CONFIG_HOME=/tmp

WORKDIR /app

# System deps: LibreOffice + fonty (żeby PDF wyglądał sensownie) + kilka bibliotek pod headless
RUN apt-get update && apt-get install -y --no-install-recommends \
    libreoffice \
    libreoffice-calc \
    fontconfig \
    fonts-dejavu-core \
    fonts-liberation \
    ca-certificates \
    libcups2 \
    libnss3 \
    libxinerama1 \
    libxrender1 \
    libxext6 \
    libsm6 \
    libice6 \
  && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Railway zwykle ustawia PORT w env — nie trzymaj na sztywno 8000
EXPOSE 8000
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]

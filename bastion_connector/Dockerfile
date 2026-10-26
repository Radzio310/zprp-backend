# bastion-connector: OSOBNA usluga Railway (Root Directory = zprp-backend/bastion_connector).
# Obraz Playwrighta ma Chromium i zaleznosci systemowe; wersja musi pasowac do playwright== w requirements.txt.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Stan (zaszyfrowany) lezy na wolumenie Railway zamontowanym w /data.
ENV BASTION_DATA_DIR=/data PYTHONUNBUFFERED=1
RUN mkdir -p /data

EXPOSE 8000
# Railway ustawia PORT. Jedna replika (stan na wolumenie, bilety i blokady w pamieci procesu).
CMD ["sh", "-c", "uvicorn connector.app:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips=*"]

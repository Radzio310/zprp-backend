# 1. Wybieramy lekki obraz Pythona
FROM python:3.10-slim

# 2. Ustawiamy katalog roboczy wewnątrz kontenera
WORKDIR /app

# ✅ MINIMUM pod LibreOffice (soffice) + fonty
# - libreoffice + libreoffice-calc: konwersja XLSX->PDF
# - fontconfig + fonts-dejavu-core: żeby PDF nie był "pusty"/z krzakami
# - ca-certificates: często potrzebne do normalnych requestów TLS
RUN apt-get update && apt-get install -y --no-install-recommends \
    libreoffice \
    libreoffice-calc \
    fontconfig \
    fonts-dejavu-core \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# ✅ LibreOffice lubi pisać cache/config w HOME – ustawiamy na /tmp (bez wpływu na serwer)
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp \
    XDG_CONFIG_HOME=/tmp

# 3. Kopiujemy tylko plik z zależnościami i instalujemy
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Kopiujemy cały kod aplikacji
COPY . .

# 5. Otwieramy port 8000 (ten, na którym działa Uvicorn)
EXPOSE 8000

# 6. Domyślna komenda startowa (BEZ ZMIAN)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

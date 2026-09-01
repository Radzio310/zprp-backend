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
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    ffmpeg \
    postgresql-client \
  && rm -rf /var/lib/apt/lists/*

# ✅ LibreOffice lubi pisać cache/config w HOME – ustawiamy na /tmp (bez wpływu na serwer)
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp \
    XDG_CONFIG_HOME=/tmp

# 3. Kopiujemy tylko plik z zależnościami i instalujemy
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ✅ Font symboli - bez niego protokół drukuje pustą ramkę zamiast znaku
# „K w kółku" przy niewykorzystanym rzucie karnym.
#
# Sprawdzone (fontTools, cmap): U+24C0 NIE MA ani DejaVu (Sans/Serif, wszystkie
# odmiany), ani Times New Roman z szablonu, ani Liberation, którym LibreOffice
# go zastępuje, ani GNU FreeFont, ani Noto Sans/Serif/Symbols2. Ma go dopiero
# Noto Sans Symbols (v1) i dlatego leży w repozytorium - pakiet apt z Noto
# ciągnie kilkadziesiąt megabajtów po jeden glif, a jego zawartość zależy od
# wydania Debiana.
#
# LibreOffice dobiera go automatycznie: znak, którego nie ma font komórki,
# bierze przez fontconfig z dowolnego zainstalowanego. Stąd `fc-cache`.
COPY app/fonts/NotoSansSymbols-Regular.ttf /usr/local/share/fonts/
RUN fc-cache -f

# 4. Kopiujemy cały kod aplikacji
COPY . .

# 5. Otwieramy port 8000 (ten, na którym działa Uvicorn)
EXPOSE 8000

# 6. Domyślna komenda startowa (BEZ ZMIAN)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

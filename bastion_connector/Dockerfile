# bastion-connector: OSOBNA usluga Railway (Root Directory = zprp-backend/bastion_connector).
# Obraz Playwrighta ma Chromium i zaleznosci systemowe; wersja musi pasowac do playwright== w requirements.txt.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

# Prawdziwa przegladarka z oknem (headful) na wirtualnym ekranie Xvfb: headless Chromium ma w UA
# "HeadlessChrome" i hCaptcha Discorda zapetla sie na nim. Bez wtyczek "stealth" i podrabiania
# odciskow - jestesmy zwykla przegladarka, captche rozwiazuje czlowiek w oknie.
# apt jest idempotentny: jesli obraz ma juz xvfb, nic sie nie zmieni.
RUN apt-get update  && apt-get install -y --no-install-recommends xvfb xauth  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Stan (zaszyfrowany) lezy na wolumenie Railway zamontowanym w /data.
ENV BASTION_DATA_DIR=/data PYTHONUNBUFFERED=1 BASTION_HEADFUL=true
RUN mkdir -p /data

EXPOSE 8000
# Railway ustawia PORT. Jedna replika (stan na wolumenie, bilety i blokady w pamieci procesu).
# Xvfb w tle, uvicorn przez exec jako PID 1 (dostaje SIGTERM od Railway). xvfb-run jako PID 1 zawisa
# na czekaniu na SIGUSR1 od Xvfb - sprawdzone lokalnie. Chromium startuje dopiero przy probie logowania,
# wiec Xvfb zdazy wstac.
CMD ["sh", "-c", "Xvfb :99 -screen 0 1280x800x24 -nolisten tcp >/dev/null 2>&1 & export DISPLAY=:99; exec uvicorn connector.app:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips=*"]

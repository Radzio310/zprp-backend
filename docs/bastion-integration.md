# Handball Bastion w Mentorze - Etap 0 (bramka techniczna)

Stan na 26.10.2026. To jest minimalny pionowy test, nie wdrożona integracja. Specyfikacja: handoff
`Documents/Codex/2026-10-26/.../outputs/handoff.md` (rozdz. 4, 5, 7, 12, 13, 16). Decyzje: pamięć `bastion-mentor-decyzje`.

## 1. Architektura

```
przeglądarka (BAZA) --HTTPS/WSS--> bastion-connector (osobny serwis Railway, Playwright + Chromium)
        ^                               |  izolowany kontekst na próbę logowania, klatki CDP (screencast)
        | embed Bunny (Player.js)       |  stan sesji: AES-GCM na wolumenie /data
zprp-backend (FastAPI, bez przeglądarki) --Bearer BASTION_CONNECTOR_TOKEN--> connector  (Etap 1+)
                                        |
                                        +--> portal.handball-bastion.pl (GET /api/game-context z sesją)
```

- Kod: `zprp-backend/bastion_connector/` (własny `Dockerfile`, `requirements.txt`, testy, `static/test.html`).
  FastAPI `zprp-backend` nie dostaje Playwrighta ani Chromium.
- **Widok logowania**: Chromium serwerowy -> `Page.startScreencast` (JPEG) -> binarne ramki WSS; wejście
  (mysz, kółko, klawisze, wklejanie) -> `Input.dispatchMouseEvent/KeyEvent`, `Input.insertText`. Bez noVNC,
  bez publicznego CDP (CDP żyje tylko w procesie connectora).
- **Bilet wejścia**: HMAC-SHA256 (`BASTION_TICKET_SECRET`), przypięty do `judge_id` i `attempt_id`, ważny 60 s,
  jednorazowy (rejestr nonce w pamięci). Jedzie w pierwszej wiadomości WSS (`{"type":"auth","ticket":...}`),
  nie w adresie URL. Origin sprawdzany przy handshake (`BASTION_ALLOWED_ORIGINS`), zły Origin = zamknięcie 4403.
  Rozłączenie widoku nie jest ani sukcesem, ani anulowaniem; próba wygasa po `BASTION_LOGIN_ATTEMPT_TTL_SECONDS`.
- **Próby**: scope `default` albo `personal` (klucz połączenia `default` / `personal-<judge_id>`), jedna aktywna
  próba na połączenie, limit globalny `BASTION_MAX_ACTIVE_LOGINS`. Każda próba = nowy, izolowany kontekst; zapisany
  stan działającej sesji nie jest dotykany, dopóki weryfikacja nie przejdzie (wtedy atomowa wymiana, `generation+1`).
- **Weryfikacja**: connector sam co 3 s woła `GET /api/game-context?bunny_item_id=<probe>` z kontekstu próby, gdy
  strona jest na hoście portalu. 200 albo 403 = zalogowano (403 = konto bez dostępu do meczu probnego), 401 = jeszcze
  nie. Sukces wyłącznie ze stanu connectora, nigdy z zamknięcia okna.
- **Stan**: `storage_state` Playwrighta okrojony do hosta portalu (cookie domen stosujących się do portalu i
  localStorage jego originu; sesja Discorda NIE jest zapisywana), zaszyfrowany AES-256-GCM (AAD = klucz połączenia),
  plik `<data>/states/<klucz>.enc`, zapis atomowy. Rotacja: nowy `BASTION_SECRETS_KEY`, stary w
  `BASTION_SECRETS_KEY_PREVIOUS`; odczyt przepisuje plik nowym kluczem. Profil = jeden plik + `asyncio.Lock` na
  klucz (connector musi działać jako **jedna replika**).
- **Odczyt z zapisanego stanu** (`GET /playback`) nie używa Chromium: `playwright.request.new_context(storage_state)`.
  Błędy: 401 -> `BASTION_AUTH_REQUIRED` (409, stan nie jest kasowany), 403 -> `BASTION_RESOURCE_FORBIDDEN`,
  429 -> `BASTION_RATE_LIMITED`, timeout/5xx -> `BASTION_UNAVAILABLE` (503, to NIE dowód wygaśnięcia).
- **expires_at = null** zawsze, dopóki TTL sesji Bastionu nie jest znany. Status pokazuje tylko obserwowane metadane
  cookie (liczba, sesyjne, najwcześniejsze/najpóźniejsze wygaśnięcie) i `last_validated_at`. Termin z adresu embed
  (`expires`/`token_expires`/`exp`) jest zwracany tylko, jeśli adres go ma.
- **Embed**: adres musi być https, bez userinfo/portu, a host kończyć się sufiksem z `BASTION_EMBED_HOST_SUFFIXES`
  (domyślnie `mediadelivery.net`, DO POTWIERDZENIA pierwszą próbą). Inaczej `BASTION_EMBED_HOST_NOT_ALLOWED` z nazwą
  hosta w `detail`. Nie omijamy X-Frame-Options, CSP ani referera.
- **Nawigacja Chromium**: blokada schematów innych niż http(s) i adresów prywatnych/lokalnych (warstwa dodatkowa,
  bez ochrony przed DNS rebinding).
- Adres embed jest wrażliwy: `Cache-Control: no-store`, nie trafia do logów (skrypty drukują host i skrót).

## 2. Trasy connectora

Wszystkie z `Authorization: Bearer BASTION_CONNECTOR_TOKEN`, poza WSS.

| Trasa | Zachowanie |
|---|---|
| `GET /health` | żywotność, stan przeglądarki |
| `POST /attempts` `{scope, judge_id, probe_bunny_item_id?}` | tworzy próbę, zwraca `id`, `ticket`, `ws_path` |
| `GET /attempts/{id}`, `POST .../cancel`, `POST .../ticket` | stan, anulowanie, nowy bilet |
| `WSS /ws/login/{id}` | klatki JPEG (binarne) + wejście (JSON), bilet w 1. wiadomości |
| `GET /playback?scope&judge_id&bunny_item_id` (lub `game_url`) | game-context z zapisanej sesji, `embed_url` |
| `GET /connections/status`, `DELETE /connections` | metadane (bez sekretów), usunięcie stanu |
| `GET /test` | techniczna strona testowa (tylko gdy `BASTION_TEST_PAGE=true`) |

`judge_id` ustala backend BAZY z prawdziwej sesji (`base_actor`), nigdy z `act_as` (Etap 1).

## 3. Zmienne (`bastion_connector/.env.example`, bez sekretów)

`BASTION_PORTAL_BASE_URL`, `BASTION_SECRETS_KEY`, `BASTION_SECRETS_KEY_PREVIOUS`, `BASTION_CONNECTOR_TOKEN`,
`BASTION_TICKET_SECRET`, `BASTION_ALLOWED_ORIGINS`, `BASTION_LOGIN_ATTEMPT_TTL_SECONDS`, `BASTION_TICKET_TTL_SECONDS`,
`BASTION_MAX_ACTIVE_LOGINS`, `BASTION_EMBED_HOST_SUFFIXES`, `BASTION_PROBE_BUNNY_ITEM_ID`, `BASTION_DATA_DIR`,
`BASTION_TEST_PAGE`, `BASTION_HEADFUL`, `BASTION_CHROMIUM_PATH` (tylko lokalnie). Connector nie startuje, gdy token
lub sekret biletów ma < 32 znaki; bez poprawnego `BASTION_SECRETS_KEY` nie da się utworzyć magazynu.
Obraz Docker uruchamia Chromium z oknem pod Xvfb (`xvfb-run`, `BASTION_HEADFUL=true` domyślnie): headless ma w UA
"HeadlessChrome" i hCaptcha Discorda się na nim zapętla. Bez wtyczek stealth; captchę rozwiązuje człowiek w oknie.

## 4. Uruchomienie lokalne

```
cd zprp-backend/bastion_connector
pip install -r requirements.txt && python -m playwright install chromium
python -m pytest -q                       # testy jednostkowe (38)
# sekrety wygeneruj lokalnie, nie wklejaj ich do repo:
export BASTION_SECRETS_KEY=$(python -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
export BASTION_CONNECTOR_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(40))")
export BASTION_TICKET_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(40))")
export BASTION_ALLOWED_ORIGINS=http://127.0.0.1:8770 BASTION_DATA_DIR=./.data BASTION_PROBE_BUNNY_ITEM_ID=5632 BASTION_TEST_PAGE=true
python -m uvicorn connector.app:app --port 8770
# strona testowa: http://127.0.0.1:8770/test  (token wklejasz w polu; zostaje w pamięci karty)
python scripts/e0_local_probe.py --out <katalog>            # zrzuty bez poświadczeń
BASTION_CONNECTOR_TOKEN=... python scripts/e0_restart_test.py --scope default --judge tester1
```

## 5. Railway (przygotowane, NIE wdrożone)

1. Nowy serwis z tego samego repo, **Root Directory** `bastion_connector` (używa jego `Dockerfile`).
2. Wolumen zamontowany w `/data` (`BASTION_DATA_DIR=/data`, ustawione w obrazie). Jedna replika.
3. Zmienne z sekcji 3; `BASTION_ALLOWED_ORIGINS` = `https://bazapodreka.app` oraz publiczny adres samego connectora
   (strona `/test`); na czas prób `BASTION_TEST_PAGE=true`, po próbach wyłączyć.
4. Healthcheck `/health`. Zasoby: Chromium potrzebuje ok. 0,5-1 GB RAM na aktywną próbę logowania (szacunek do
   zmierzenia na Railway). Poza próbą logowania Chromium nie działa (odczyt idzie przez `APIRequest`).
5. Strona osadzenia Bunny: `BAZA_web/public/bastion-test.html` (po wdrożeniu BAZA_web: `https://bazapodreka.app/bastion-test`;
   czy trasa jest serwowana mimo przepisań Vercela - do sprawdzenia przy wdrożeniu).

## 6. Procedura prób z człowiekiem

Przygotowanie: connector na Railway, otwórz `https://<connector>/test`, wpisz token. `bunny_item_id` = 5632.

**P1. Logowanie z MFA (default).** Scope `default`, judge `tester1` -> "Rozpocznij logowanie" -> w oknie klikasz
"Zaloguj przez Discord", wpisujesz dane i kod MFA na prawdziwej stronie Discorda -> status ma przejść w `succeeded`
(sam, po weryfikacji `game-context`). Zapisz: czy Discord prosił o CAPTCHA/kod/QR, czy klawiatura i wklejanie działają,
czy po powrocie widać portal zalogowany. Klucz dostępu (WebAuthn) lokalnego komputera nie będzie dostępny - użyj hasła
+ kodu albo QR z telefonu.

**P2. Playback.** "Sprawdź playback": oczekiwane `code=OK`, `video_state`, `game_context_keys`. Zanotuj, czy `expires_at` jest znane.

**P3. Restart.** `python scripts/e0_restart_test.py --url https://<connector> --scope default --judge tester1` -> po fazie 1
zrestartuj usługę w Railway (Redeploy) -> Enter. Oczekiwane: "stan odtworzony, embed_url uzyskany ponownie". Zapisz też
wynik po 1 h, 24 h i 7 dniach (`/connections/status` + `/playback`) - tak ustalimy realny TTL.

**P4. Inne IP (kluczowe).** Na stronie `https://bazapodreka.app/bastion-test` podaj adres connectora i token -> "Pobierz
embed i załaduj" -> "Sekwencja Player.js". Zrób to z komputera w innej sieci **i** z telefonu na LTE (Wi-Fi wyłączone).
Adres Bunny został wydany dla IP serwera Railway; sprawdzamy, czy gra u użytkownika. Zapisz: czy iframe się ładuje, czy
`Player.js ready`, `supports` (zwłaszcza `setPlaybackRate`), czy po seek 600 `getCurrentTime` ≈ 603+. Jeśli nie gra: zapisz
dokładny komunikat/status z konsoli. Nie zdejmujemy nagłówków ani nie podrabiamy referera.

**P5. Ponowne uzyskanie embed.** Po > 2 h (lub po wygaśnięciu) powtórz "Pobierz embed" bez ponownego logowania.

**P6. Dwa konta osobiste.** Scope `personal`: judge `osoba1` loguje się kontem A, judge `osoba2` kontem B (druga karta).
Sprawdź `/connections/status?scope=personal&judge_id=osoba1` i `osoba2` oraz `/playback` dla każdego: każde zwraca
tylko własne konto; usunięcie `osoba1` (`Rozłącz`) nie rusza `osoba2`. Zanotuj, czy konto z dostępem do 5632 różni się
od konta bez dostępu (oczekiwane 403 `BASTION_RESOURCE_FORBIDDEN`, bez utraty sesji).

**P7. Wylogowanie/cofnięcie dostępu.** Wyloguj się z Bastionu w zwykłej przeglądarce / odłącz aplikację w Discordzie, potem
`/playback`: czy 401 pojawia się od razu, czy sesja serwerowa nadal działa.

Nie tworzymy klipów w Bastionie (Etap 4).

## 7. Wyniki

Wyniki lokalne uzyskane 26.10.2026 na Windows 11, Python 3.14, Playwright 1.63 (klient) z Chromium headless shell 149
(przeglądarki 1243 nie dało się pobrać w tym środowisku, użyto zainstalowanego 1228 przez `BASTION_CHROMIUM_PATH`).

| Próba | Status | Wynik / uwagi |
|---|---|---|
| Testy jednostkowe: szyfrowanie stanu, rotacja klucza, izolacja połączeń, bilety, walidacja URL/embed/Origin | zweryfikowane | 38 testów przechodzi |
| Start connectora, `/health`, autoryzacja tokenem (401 bez tokenu) | zweryfikowane (lokalnie) | |
| Próba logowania + screencast CDP przez WSS: strona logowania Bastionu | zweryfikowane (lokalnie) | 21-34 klatek w 6 s, strona widoczna, przycisk "Zaloguj przez Discord" |
| Kliknięcie "Zaloguj przez Discord" przez kanał wejścia (bez wpisywania danych) | zweryfikowane (lokalnie) | po ok. 10-25 s widać formularz Discorda (e-mail/hasło, kod QR, link do klucza dostępu); headless Chromium nie zablokowany, brak CAPTCHA na tym etapie |
| Bilet: ponowne użycie / zły Origin | zweryfikowane (lokalnie) | odrzucone (HTTP 403 przy handshake) |
| `GET /api/game-context` bez sesji (po stronie connectora, `APIRequest`) | zweryfikowane (lokalnie) | 401 -> `BASTION_AUTH_REQUIRED` |
| Zapisany stan po restarcie procesu (stan syntetyczny, fałszywe cookie) | zweryfikowane (lokalnie) | odtworzony, 401 rozpoznane jako `BASTION_AUTH_REQUIRED` (409), stan nie skasowany; to NIE dowodzi trwałości prawdziwej sesji |
| Logowanie z kodem MFA, wejście klawiaturą i wklejanie w widoku | **zweryfikowane (Railway, 27.10)** | P1: `succeeded` po 61 s, portal "Witaj, Radosław Witkowicz!". Wymagało: Chromium z oknem pod Xvfb (headless = pętla hCaptcha), znaki przez `insertText`, brak WebAuthn zgłaszany Discordowi |
| `game-context` z prawdziwą sesją, `embed_url` dla 5632 i host embed | **zweryfikowane (Railway, 27.10)** | P2: HTTP 200 `OK`, `video_state=READY`, klucze game-context: assistant, audiences, bunny_item_id, crew, extra_people_max, match, nav, video, viewer. Adres embed ważny ok. 2 h (`expires_at` = +7200 s) |
| Prawdziwa sesja po restarcie (Railway) | czeka na człowieka | P3 |
| Embed Bunny na domenie BAZY, inne IP (komputer + LTE) | czeka na człowieka | P4 |
| Ponowne uzyskanie embed po wygaśnięciu | czeka na człowieka | P5 |
| Dwa konta osobiste, izolacja | czeka na człowieka (logika kluczy i AAD: zweryfikowana testami) | P6 |
| TTL sesji, zachowanie po wylogowaniu/cofnięciu dostępu | częściowo: zapisane 1 ciasteczko sesji Bastionu z terminem +7 dni (604 800 s od logowania). To termin ciasteczka, nie potwierdzony czas sesji po stronie serwera, więc `expires_at` zostaje `null` | P3 (1 h / 24 h / 7 dni), P7 |
| Build obrazu Docker i start na Railway | **zweryfikowane (27.10)** | obraz z Xvfb (commit 332d846) działa na Railway |
| Tożsamość konta (`external_identity_id`) | otwarte | brak znanego endpointu; do ustalenia przy P1 (np. strona profilu) |

## 8. Ryzyka i otwarte kwestie

- Trwałość sesji Bastionu nieznana; może wymagać cyklicznego logowania przez człowieka (MFA nie omijamy).
- Discord może na IP centrum danych (Railway) żądać CAPTCHA/weryfikacji częściej niż lokalnie.
- Adres Bunny wydany dla IP serwera może nie grać u użytkownika (P4). Jeśli nie, potrzebna współpraca po stronie Bastionu;
  alternatywa to tylko klipy MP4 (Etap 4) bez odtwarzania pełnych meczów.
- Dozwolony host embed jest założeniem (`mediadelivery.net`), do potwierdzenia.
- Ograniczone do jednej repliki (bilety i blokady w pamięci); skalowanie wymaga przeniesienia ich do Postgresa (Etap 1+).
- Okrojenie stanu do domeny portalu zakłada, że sesja Bastionu to cookie własne portalu. Jeśli P1 pokaże, że
  `game-context` po restarcie wymaga czegoś jeszcze (np. cookie Discorda), trzeba jawnie rozszerzyć zakres i opisać go w UI.
- Widok obsługuje jedną kartę przeglądarki serwerowej (OAuth w tej samej karcie); popup `window.open` strony nie byłby widoczny.

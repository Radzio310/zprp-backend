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
| `GET /games/search?scope&judge_id&q&limit&offset&season_id&video` | Meczoteka: portal `GET /api/games` sesją (publiczny game_library.js: items[{bunny_item_id, game_code, date, home_team, away_team, type_name, series, score{full_home,full_away}, video_state, video_coverage}], paging{total,has_more}); zwraca `{games:[{bunny_item_id,title,home,away,date,competition,code,score,video_state,video_coverage,thumbnail:null,duration_s:null}],total,has_more}`; kształt z JS, do potwierdzenia na żywo (/test, karta M) |
| `GET /playback?scope&judge_id&bunny_item_id` (lub `game_url`) | game-context z zapisanej sesji, `embed_url` |
| `GET /connections/status`, `DELETE /connections` | metadane (bez sekretów), usunięcie stanu |
| `POST /probe/clip` `{scope, judge_id, bunny_item_id, start_s, end_s}` | P8: jedno zlecenie cięcia (prywatny klip), zwraca zdalne `remote_id` i kod; 202 = `needs_reconciliation` |
| `GET /probe/clip/{id}?scope&judge_id` | P8: `clip-context` (m.in. `download_available`) |
| `POST /probe/clip/{id}/download?scope&judge_id` | P8: pobranie do katalogu tymczasowego, ffprobe, SHA-256, skasowanie pliku; zwraca metadane |
| `POST /clips` `{scope, judge_id, bunny_item_id, start_s, end_s, fingerprint, correlation}` | Etap 4: produkcyjne zlecenie, idempotentne po odcisku (ksiega `clip_jobs.json`), 202 = `needs_reconciliation` bez ponowien |
| `GET /clips/{remote_id}?scope&judge_id` | Etap 4: stan (`ready` = `download_available`), tylko dla klipu tego polaczenia |
| `POST /clips/{remote_id}/download-url?scope&judge_id` | Etap 4: krotko zyjacy podpisany adres po walidacji hostow; plik pobiera BAZA bez ciasteczek |
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
| Prawdziwa sesja po restarcie (Railway) | **zweryfikowane (27.10)** | P3: redeploy po zmianie zmiennej, bez ponownego logowania `/playback` = 200 OK. Do powtórzenia po 24 h i 7 dniach (TTL) |
| Embed Bunny na domenie BAZY, inne IP (komputer + LTE) | **zweryfikowane (telefon, sieć komórkowa, 27.10)** | P4: origin `https://www.bazapodreka.app` (dopisany do `BASTION_ALLOWED_ORIGINS`), embed z `iframe.mediadelivery.net`, Player.js ready po 2 s, film gra, seek 600 -> 602,26 s i 603,08 s, czas trwania 6795,1 s. `setPlaybackRate`: false, `setMuted`: false - tempa i wyciszenia pełnego meczu nie sterujemy z zewnątrz. Adres wydany dla IP Railway gra z innego IP. Komputer w innej sieci: do zrobienia przy okazji |
| Ponowne uzyskanie embed po wygaśnięciu | czeka na człowieka | P5 |
| Dwa konta osobiste, izolacja | czeka na człowieka (logika kluczy i AAD: zweryfikowana testami) | P6 |
| TTL sesji, zachowanie po wylogowaniu/cofnięciu dostępu | częściowo: zapisane 1 ciasteczko sesji Bastionu z terminem +7 dni (604 800 s od logowania). To termin ciasteczka, nie potwierdzony czas sesji po stronie serwera, więc `expires_at` zostaje `null` | P3 (1 h / 24 h / 7 dni), P7 |
| Build obrazu Docker i start na Railway | **zweryfikowane (27.10)** | obraz z Xvfb (commit 332d846) działa na Railway |
| Cięcie klipu 628-638 s w 5632, pobranie MP4, ffprobe, SHA-256 (P8) | **zweryfikowane (Railway, 27.10)** | zlecenie 200, zdalne id 1665, kod 8GGB8, prywatne (ONLY_ME), wysłano 10:28-10:38. Gotowe po ok. 90 s (`download_available`). Pobranie z `handball-bastion-2026-2027.b-cdn.net` (0 przekierowań, bez ciasteczek): 5 224 410 B, `video/mp4`, h264 1280×720 + aac, 10,02 s (różnica 0,02 s). SHA-256 `bef6e787…728a` identyczne z testem z handoffu: cięcie Bastionu jest deterministyczne. Plik skasowany |
| Tożsamość konta (`external_identity_id`) | **wdrożone, do potwierdzenia na Railway** | Z `viewer` w game-context: pole id, jeśli jest, inaczej odcisk `viewer.display_name` (`dn:<sha256[:16]>`; publiczne skrypty portalu czytają tylko `display_name`). `GET /connections/check` zwraca `viewer_keys` pośrednio w `identity_source`; kształt `viewer` sprawdzić na żywo |
| Meczoteka `GET /games/search` (q=LCM/32, scope default) | **zweryfikowane (Railway, 28.10)** | 1 wynik: `{bunny_item_id:5632, home:"AZS AGH Kraków", away:"ENERGA GWARDIA Koszalin", date:"2026-10-10 19:00:00" (czas polski, bez strefy, spacja zamiast T), competition:"Liga Centralna Mężczyzn", code:"LCM/32" (pisownia ZPRP co do litery), score:"37:32", video_state:"READY", video_coverage:2}`. Zaraz potem `/playback` 5632 = 200 OK (wyszukiwanie nie psuje sesji). Na tym kształcie stoi ocena pewności Archiwisty (`app/mentor_bastion_search.py`, mentor-panel 8.10) |

### Meczoteka po sędzi (Trybuna, 28.10.2026, do potwierdzenia próbą)

`GET /games/search` przyjmuje też `referee` (imię i nazwisko, do 80 znaków) oraz `referee_param` (nazwa parametru portalu: `q|referee|referees|referee_name|judge|sedzia`, domyślnie `q`). Wiersz wyniku ma `referees: [{name, id}]` (tolerancyjny parser pól o nazwie z `referee`/`judge`/`sedzi`) a odpowiedź `row_keys` (nazwy pól pierwszego wiersza portalu). Właściciel potwierdził, że portal szuka po imieniu i nazwisku sędziego; NIEZNANE jest dokładne pole, więc backend używa `REFEREE_PARAM` (`app/mentor_bastion_search.py`, domyślnie `q`). Próba (po wdrożeniu connectora z tą zmianą; skrypt tylko do odczytu `scripts/probe_meczoteka_referee.py`, uruchamiany w kontenerze `zprp-backend`):

```
$b = [Convert]::ToBase64String([IO.File]::ReadAllBytes("scripts\probe_meczoteka_referee.py"))
railway ssh -s zprp-backend "echo $b | base64 -d | python - 'Jan Kowalski'"
```

Wynik pokazuje dla każdego parametru liczbę wyników, `row_keys` i sędziów z pierwszej kasety. Parametr, który zwęża listę do meczów tego sędziego, wpisujemy w `REFEREE_PARAM`; jeśli żaden nie zawęża, szukanie po sędzi działa przez `q` (nazwisko jako zwykły tekst) i filtr po stronie BAZY (`referees` w wierszach), a pole z obsadą dopisujemy do `parse_referees` w `bastion_connector/connector/bastion.py`.

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


## 10. Kontrakt klipów Bastionu (P8)

Źródło: publiczne skrypty portalu `GET /static/game.js` i `/static/clip.js` (pobrane bez logowania 27.10.2026). Strony `/game`
i `/clip` bez sesji dają 303 na `/auth/login`, ale skrypty są publiczne. To **wewnętrzne API portalu**; walidacja po stronie
serwera nie jest potwierdzona, dopóki P8 nie przejdzie na koncie.

**`POST /api/game-submit`** (JSON, sesja, `credentials: include`):

```text
{ bunny_item_id: <int>,
  clips: [ {                       # 1..10 elementów (MAX_CLIPS)
    clipNumber: 1,
    startTime: "10:28",            # "m:ss" albo "h:mm:ss", całe sekundy (regex ^([0-9]{1,2}:)?[0-9]{1,2}:[0-9]{2}$)
    endTime:   "10:38",
    privateId: null,               # opcjonalne, <= 20 znaków
    audience_group_id: null,       # null = tylko ja (ONLY_ME); audience_crew / audience_extra_ids pomijamy
    comment: "BAZA test P8",       # WYMAGANE, 1..300 znaków (to jedyny tekst klipu, nie ma osobnego tytułu)
    situationType: "NORMAL",       # WYMAGANE: NORMAL | TRAINING | CURIOSITY | NEEDS_ANALYSIS
    videoTags: ["PLAY_ON"] } ] }   # WYMAGANE 1..5 z 22 kluczy (PENALTY, ADVANTAGE, ... PLAY_ON, ... VR)
```

Odpowiedź sukcesu (z `showSuccessState`): `{clip_codes: [...], clip_ids: [...], addressees: [...]}`. Błędy w skrypcie: 401
(brak logowania), 403 (brak uprawnień), 422 (walidacja), inne = komunikat `message`. Skrypt klienta wymusza czas 2-300 s
(`MIN_DIFF_SECONDS`, `MAX_DIFF_SECONDS`) i tylko całe sekundy (`dataset.seconds` jest całkowite).
Jest też `supersedes_clip_id` (ponowne cięcie, jeden klip); nie używamy. Brak idempotencji i brak pola korelacji,
więc po timeoucie nie wiemy, czy klip powstał.

**`GET /api/clip-context?clip_id=<int>`** -> `{clip: {clip_code, time_start_sec, time_end_sec, situation_type, video_tags,
description, private_id}, download_available: bool, is_owner, ...}`. 401/403/404 jak wyżej. `download_available=true` oznacza
zapisany plik. Z odpowiedzi bierzemy tylko pola potrzebne do próby (bez opisów, osób, komentarzy).

**`GET /api/clip/{id}/download`** -> 302 do podpisanego adresu Bunny z wymuszonym pobraniem (z komentarza w `clip.js`).
Host przekierowania **nieznany do P8**; lista dozwolonych sufiksów: `b-cdn.net, mediadelivery.net, bunnycdn.com`
(`BASTION_DOWNLOAD_HOST_SUFFIXES`). Inny host = błąd `DOWNLOAD_HOST_NOT_ALLOWED` z nazwą hosta w `detail` (po ocenie dopisz sufiks).

**Co robi connector:**

1. `POST /probe/clip`: zakres musi być całkowity, 2-300 s (inaczej 400 `BAD_RANGE`, ułamki 422; nic nie jest zaokrąglane).
   Wpis w księdze (`<BASTION_DATA_DIR>/clip_jobs.json`, odcisk = połączenie + film + zakres) powstaje **przed** POST-em.
   Odpowiedź zawiera `sent` (dokładnie wysłane `startTime`/`endTime`, tytuł, typ, tagi, odbiorca).
2. Timeout, błąd sieci, 5xx albo sukces bez dokładnie jednego `clip_ids` -> `needs_reconciliation` (HTTP 202), **zero ponowień**.
   Ten sam zakres drugi raz -> 409 `CLIP_ALREADY_SUBMITTED` (bez drugiego POST), także po restarcie. Odrzucenie 4xx = `failed`, można poprawić i ponowić.
   Rozstrzygnięcie ręczne: lista klipów w portalu Bastionu.
3. `GET /probe/clip/{id}` i `POST .../download` działają tylko dla klipów utworzonych przez ten connector (`CLIP_UNKNOWN`).
4. Pobranie: sesja połączenia tylko do pierwszego żądania `/api/clip/{id}/download` (bez podążania za przekierowaniem). Podpisany
   adres pobiera **osobny klient httpx**: bez ciasteczek i nagłówków autoryzacji, bez `trust_env`, `https` bez userinfo i portu,
   host na liście sufiksów, literały IP odrzucane, nazwa musi się rozwiązać wyłącznie na adresy publiczne, każde przekierowanie
   (maks. 3) przechodzi te same kontrole, strumień do katalogu tymczasowego z limitem `BASTION_MAX_DOWNLOAD_MB` (domyślnie 200).
   Potem `ffprobe` (czas, rozdzielczość, kodeki, obecność obrazu), SHA-256, i katalog zawsze jest kasowany. Ograniczenie: DNS jest
   sprawdzany przed połączeniem, nie przypięty do gniazda (DNS rebinding nie jest wykluczony; to próba, nie produkcja).
5. `ffmpeg` (zawiera `ffprobe`) jest w obrazie (Dockerfile).

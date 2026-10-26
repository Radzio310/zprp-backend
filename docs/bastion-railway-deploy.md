# Wdrożenie bastion-connector na Railway (etap 0, bramka techniczna)

Dla wykonawcy wdrożenia (człowiek albo asystent z dostępem do Railway i GitHuba).
Kontekst techniczny: `docs/bastion-integration.md` (architektura, procedura prób P1-P7, tabela wyników).

## 0. Co stawiamy i czego NIE ruszamy

- Nowa, osobna usługa **bastion-connector** w tym samym projekcie Railway co istniejąca usługa backendu BAZY
  (`zprp-backend-production.up.railway.app`).
- Kod: repo `github.com/Radzio310/zprp-backend`, gałąź `master`, katalog `bastion_connector/`.
- To serwis z przeglądarką Chromium (Playwright). Loguje się do Handball Bastion przez Discord, a człowiek
  przechodzi logowanie przez stronę `/test`. Trzyma zaszyfrowaną sesję na wolumenie.
- **Nie zmieniaj** istniejącej usługi backendu, jej zmiennych, Dockerfile w korzeniu repo, bazy danych ani domen.
  Backend BAZY na etapie 0 nie rozmawia jeszcze z connectorem. Nie dodawaj mu żadnych zmiennych `BASTION_*`.
- Nie twórz klipów w Bastionie i nie zmieniaj kodu aplikacji. Jeśli build nie przechodzi, napraw minimalnie i opisz
  zmianę w commicie (patrz §6).

## 1. Usługa

1. Railway, projekt backendu BAZY: **New -> GitHub Repo -> Radzio310/zprp-backend**.
2. Nazwa usługi: `bastion-connector`.
3. Settings -> Source:
   - **Root Directory:** `bastion_connector`
   - **Branch:** `master`
   - **Watch Paths:** `bastion_connector/**`, żeby usługa nie przebudowywała się przy każdej zmianie backendu.
4. Settings -> Build: builder **Dockerfile** (plik `bastion_connector/Dockerfile`, obraz
   `mcr.microsoft.com/playwright/python:v1.63.0-noble`). Wersja obrazu musi być równa `playwright==1.63.0`
   z `bastion_connector/requirements.txt`. Gdy obrazu nie ma, użyj najbliższej istniejącej wersji 1.6x
   i ustaw TĘ SAMĄ wersję w requirements.txt.
5. Settings -> Deploy:
   - **Replicas: 1.** Dokładnie jedna, bo bilety i blokady profili są w pamięci procesu.
   - **Healthcheck Path:** `/health`, timeout 120 s (pierwszy start Chromium trwa).
   - **Restart Policy:** On Failure.
   - Start Command zostaw pusty, bo CMD jest w Dockerfile (uvicorn na `$PORT`).
6. Zasoby: co najmniej **1 GB RAM**, zalecane 2 GB (Chromium z dwoma kontekstami).
7. **Wolumen:** Settings -> Volumes -> Add Volume, Mount Path **`/data`**, 1 GB wystarczy.
   Bez wolumenu sesja ginie przy każdym redeployu, a wtedy próba P3 nie ma sensu.
8. Networking: **Generate Domain** (publiczny HTTPS, np. `bastion-connector-production.up.railway.app`).
   Zapisz ten adres, to `<CONNECTOR>` w dalszych krokach.

## 2. Zmienne usługi bastion-connector

Ustaw w Settings -> Variables usługi **bastion-connector**, nigdzie indziej.

| Zmienna | Wartość | Sekret? |
|---|---|---|
| `BASTION_PORTAL_BASE_URL` | `https://portal.handball-bastion.pl` | nie |
| `BASTION_SECRETS_KEY` | wygeneruj, patrz niżej (32 bajty base64) | **TAK** |
| `BASTION_SECRETS_KEY_PREVIOUS` | puste | - |
| `BASTION_CONNECTOR_TOKEN` | wygeneruj, losowy, min. 32 znaki | **TAK** |
| `BASTION_TICKET_SECRET` | wygeneruj, losowy, min. 32 znaki, INNY niż token | **TAK** |
| `BASTION_ALLOWED_ORIGINS` | `https://bazapodreka.app,https://<CONNECTOR>` | nie |
| `BASTION_LOGIN_ATTEMPT_TTL_SECONDS` | `600` | nie |
| `BASTION_TICKET_TTL_SECONDS` | `60` | nie |
| `BASTION_MAX_ACTIVE_LOGINS` | `2` | nie |
| `BASTION_EMBED_HOST_SUFFIXES` | `mediadelivery.net` | nie |
| `BASTION_PROBE_BUNNY_ITEM_ID` | `5632` | nie |
| `BASTION_DATA_DIR` | `/data` (Dockerfile też to ustawia) | nie |
| `BASTION_TEST_PAGE` | `true` tylko na czas prób P1-P7, potem `false` | nie |
| `BASTION_HEADFUL` | nie ustawiaj (tylko lokalnie) | - |
| `BASTION_CHROMIUM_PATH` | nie ustawiaj (obraz ma Chromium) | - |

Generowanie wartości, każda inna:

```bash
# BASTION_SECRETS_KEY
python -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
# BASTION_CONNECTOR_TOKEN i BASTION_TICKET_SECRET (dwa osobne uruchomienia)
python -c "import secrets;print(secrets.token_urlsafe(48))"
```

Zasady:
- Sekretów nie wpisuj do repo, commitów, logów, czatu ani zrzutów ekranu. Ustawia się je tylko w Railway.
- `BASTION_CONNECTOR_TOKEN` przekaż właścicielowi bezpiecznie (menedżer haseł). Wpisuje go na stronach testowych.
- `BASTION_SECRETS_KEY` po pierwszym logowaniu NIE zmieniaj bez rotacji. Stary klucz musi trafić do
  `BASTION_SECRETS_KEY_PREVIOUS`, inaczej zapisana sesja jest nie do odczytania.
- **Żadnych danych logowania Discord/Bastion w zmiennych.** Sesję domyślną tworzy człowiek, logując się
  interaktywnie na `/test` (P1).

## 3. Weryfikacja po wdrożeniu (bez logowania)

1. Logi deployu: uvicorn nasłuchuje, brak błędów importu i startu Chromium.
2. `GET https://<CONNECTOR>/health` -> `{"ok": true, "browser": ...}`. `browser` może być `false`, dopóki nikt nie
   zaczął próby (Chromium startuje leniwie). Ważne jest `ok: true`.
3. Bez tokenu: `GET https://<CONNECTOR>/connections/status?scope=default` -> 401 albo 403 (trasa chroniona).
4. `https://<CONNECTOR>/test` otwiera stronę techniczną (gdy `BASTION_TEST_PAGE=true`).
5. Na `/test`: wpisz token, scope `default`, judge `tester1` -> "Rozpocznij logowanie". W oknie powinien pojawić się
   obraz strony logowania Bastionu z przyciskiem "Zaloguj przez Discord". **Dalej nie loguj się. Logowanie robi właściciel.**
   Potem "Anuluj".
6. `https://bazapodreka.app/bastion-test` (BAZA_web, Vercel) ma się otworzyć. Jeśli zwraca stronę główną BAZY zamiast
   strony testowej, zgłoś to właścicielowi. W repo BAZA_web plik to `public/bastion-test.html`, a w `vercel.json` jest
   `cleanUrls` i ogólne przepisanie `/(.*)`. Nie zmieniaj BAZA_web bez zgody właściciela.

## 4. Co robi właściciel po wdrożeniu

Procedura P1-P7 w `docs/bastion-integration.md` §6. Najważniejsze: P1 (logowanie z kodem MFA), P3 (restart przez
Redeploy, sesja ma przetrwać dzięki wolumenowi), P4 (`bazapodreka.app/bastion-test` z telefonu na LTE).
Wyniki trafiają do tabeli w §7 tamtego dokumentu.

## 5. Typowe problemy

| Objaw | Przyczyna i działanie |
|---|---|
| Build: brak obrazu `playwright/python:v1.63.0-noble` | Dobierz istniejący tag 1.6x i tę samą wersję `playwright==` w requirements.txt. |
| Start: `Executable doesn't exist` | Wersja pakietu `playwright` != wersja obrazu. Wyrównaj. |
| Crash Chromium, OOM | Zwiększ RAM do 2 GB. `--disable-dev-shm-usage` jest już w kodzie. |
| Healthcheck nie przechodzi | Sprawdź, czy uvicorn słucha na `$PORT` (CMD w Dockerfile), i wydłuż timeout. |
| WSS widoku logowania odrzucony | Brak Originu strony w `BASTION_ALLOWED_ORIGINS` (pełny adres z https, bez ukośnika na końcu). |
| `/playback` z bazapodreka.app: błąd CORS | Jak wyżej, `https://bazapodreka.app` musi być w `BASTION_ALLOWED_ORIGINS`. |
| Sesja znika po redeployu | Brak wolumenu w `/data` albo zmieniony `BASTION_SECRETS_KEY`. |
| Discord pokazuje CAPTCHA | Normalne na IP serwerowni. Człowiek ją rozwiązuje w oknie. Zanotuj w wynikach P1. |

## 6. Zasady dla wykonawcy

- Nie wyłączaj zabezpieczeń (CSP, X-Frame-Options, Origin, tokeny). Nie podrabiaj referera ani nagłówków.
- Nie wystawiaj CDP ani panelu przeglądarki. Jedyne publiczne wejście to HTTPS usługi.
- Zmiany kodu tylko wtedy, gdy blokują build albo start: minimalne, w `bastion_connector/`, osobny commit z opisem,
  testy `cd bastion_connector && python -m pytest -q` mają przechodzić.
- Na koniec raport dla właściciela: adres `<CONNECTOR>`, wynik `/health`, wynik kroków §3.1-§3.6, czy wolumen
  jest podpięty, ile RAM, gdzie bezpiecznie przekazano token. Bez wartości sekretów w raporcie.

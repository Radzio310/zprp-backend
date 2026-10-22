# Publiczna hurtownia rozgrywek ZPRP

## Cel i zakres

Moduł `app/zprp_public` pobiera wyłącznie publiczne dane z
`https://rozgrywki.zprp.pl/api/`, normalizuje je w obecnej bazie backendu i
udostępnia frontendowi stabilne API pod `/api/v1/handball`.

Domyślny zakres to bieżący i poprzedni sezon. Starszy sezon można zaimportować
świadomie przez zadanie `historical`; nie jest cyklicznie odpytywany.

Zbierane są:

- sezony, wojewódzkie związki, kluby, dane kontaktowe i licencje;
- drużyny, kategorie, płeć, składy i pozycje zawodników;
- rozgrywki, rundy, kolejki, mecze, wyniki i statusy;
- składy meczowe, bramki i kary zawodników oraz obsada/staff meczu;
- tabele ligowe i klasyfikacje strzelców;
- historia zmian oraz deduplikowane, skompresowane migawki źródła.

## Prywatność

Pełna data urodzenia i status badań są usuwane rekurencyjnie jeszcze przed
zapisem. Nie trafiają także do surowych migawek. Z daty urodzenia zachowywany
jest wyłącznie rok. Zdjęcie zawodnika może być przechowywane i zwracane, zgodnie
z przyjętą decyzją. Surowe migawki nie są wystawione przez publiczne API BAZY.

## Model danych

Moduł tworzy wydzielone tabele z prefiksem `zprp_public_`:

| Obszar | Tabele |
| --- | --- |
| katalog | `seasons`, `associations`, `clubs`, `club_licenses`, `teams` |
| osoby i składy | `players`, `team_rosters` |
| rozgrywki | `competitions`, `rounds`, `matchdays`, `matches` |
| protokół meczu | `match_players`, `match_staff` |
| statystyki | `standings`, `scorers` |
| audyt i synchronizacja | `raw_snapshots`, `changes`, `sync_runs`, `sync_state` |

Klucze źródłowe ZPRP są zachowywane jako tekst, żeby nie utracić wiodących zer
i nie uzależniać schematu od zmiany formatu identyfikatora po stronie źródła.
Aktualny rekord jest trzymany w tabeli domenowej, każda rzeczywista zmiana jest
opisywana w `changes`, a identyczna migawka nie jest zapisywana drugi raz.

## Harmonogram i ochrona wydajności

Scheduler działa w tle tego samego procesu FastAPI:

| Cykl | Częstotliwość | Zakres |
| --- | --- | --- |
| `live` | co 2 minuty | jedno zbiorcze zapytanie terminarza bieżącego sezonu; szczegóły tylko dla meczów od 12 h przed do 4 h po terminie, maks. 40 |
| `clubs` | co 15 minut | mała partia klubów (24) i składów (40), rotacyjnie |
| `details` | co 15 minut | uzupełnianie maks. 60 brakujących szczegółów meczów |
| `catalog` | co 24 godziny | pełne drzewo bieżącego sezonu, tabele i strzelcy; poprzedni sezon tylko do pierwszego kompletnego importu |
| `cleanup` | co 24 godziny | usunięcie migawek starszych niż retencja, domyślnie 90 dni |

Klient źródła ma maksymalnie 3 równoległe żądania, co najmniej 180 ms odstępu
między ich rozpoczęciem, timeout i ponowienia z narastającym opóźnieniem. Partie
można zmniejszyć zmiennymi środowiskowymi. Unikalny `cycle_key` zapobiega
podwójnemu wykonaniu na wielu replikach. Nieudany cykl można ponowić, a cykl bez
heartbeat przez 45 minut jest uznawany za przerwany i przejmowany ponownie.

## Konfiguracja

Rekomendowane wartości są już w `.env.example`:

```dotenv
ZPRP_PUBLIC_SYNC_ENABLED=true
ZPRP_PUBLIC_API_CONCURRENCY=3
ZPRP_PUBLIC_API_MIN_INTERVAL=0.18
ZPRP_PUBLIC_API_TIMEOUT=25
ZPRP_PUBLIC_API_RETRIES=2
ZPRP_PUBLIC_START_DELAY_SECONDS=30
ZPRP_PUBLIC_CLUB_BATCH=24
ZPRP_PUBLIC_ROSTER_BATCH=40
ZPRP_PUBLIC_DETAILS_BATCH=60
ZPRP_PUBLIC_RAW_RETENTION_DAYS=90
POD_REKA_DISCORD_WEBHOOK_URL=
POD_REKA_DISCORD_DEDUP_SECONDS=1800
```

Webhook Discord jest sekretem produkcyjnym i nie może trafić do repozytorium,
logów ani odpowiedzi API. Alarm zawiera tylko rodzaj procesu, identyfikator
przebiegu i liczbę błędów — bez treści błędu, danych źródłowych i URL webhooka.
Powtarzające się alarmy są wyciszane, a pierwszy udany przebieg po awarii wysyła
krótką informację o odzyskaniu sprawności.

Przy pierwszym wdrożeniu tabele zostaną utworzone przez istniejące
`metadata.create_all`. Import startuje po opóźnieniu i działa w tle, więc nie
blokuje uruchomienia API. Na pierwsze wdrożenie warto obserwować
`/api/v1/handball/sync/status` oraz obciążenie bazy; w razie potrzeby najpierw
zmniejszyć trzy wielkości partii, a dopiero później równoległość.

## API dla aplikacji

Najważniejsze endpointy:

- `GET /api/v1/handball/health`
- transmisje meczów (`/matches/{id}/streams`, `/streams/now`, `/competitions/{id}/streams`,
  `/clubs/{id}/streams`) — osobny kontrakt: `docs/streams.md`
- `GET /api/v1/handball/portal/overview` — lekki agregat Centrum dnia
- `GET /api/v1/handball/seasons?include_historical=false`
- `GET /api/v1/handball/associations`
- `GET /api/v1/handball/clubs` i `GET /clubs/{club_id}`
- `GET /api/v1/handball/teams/{team_id}?season_id=...`
- `GET /api/v1/handball/competitions` i `GET /competitions/{competition_id}`
- `GET /api/v1/handball/competitions/{competition_id}/standings`
- `GET /api/v1/handball/competitions/{competition_id}/scorers`
- `GET /api/v1/handball/matches` i `GET /matches/{match_id}`
- `GET /api/v1/handball/players` i `GET /players/{player_id}`
- `GET /api/v1/handball/search?q=...`
- `GET /api/v1/handball/changes?since=...`
- `GET /api/v1/handball/sync/status`

### Bilans bez remisów (Z / Zk / Pk / P)

Piłka ręczna nie zna remisu: równy wynik rozstrzygają rzuty karne. Kody wyniku
drużyny (`match_rules.side_result`): `W` zwycięstwo, `WK` zwycięstwo po karnych,
`LK` porażka po karnych, `L` porażka (walkower = W/L); punkty 3/2/1/0.
Pola dodane obok starych (zgodność):

- `stats` klubu/drużyny i `metrics` porównywarki: `record {w, wk, lk, l}`,
  `form_detail`, płaskie `wins_regular`/`wins_shootout`/`losses_shootout`/`losses_regular`
  (to one są metrykami `/compare`). `wins`/`losses` liczą też karne,
  `draws` = tylko równy wynik bez serii karnych w danych (zwykle 0).
- wiersze tabeli (`/competitions/{id}/standings`, `standings` w overview):
  `record {w, wk, lk, l, source}` albo `null`. `source`: `zprp` (kolumny karnych
  w wierszu pokaz_tabela.php albo brak karnych), `matches` (policzone z meczów
  drużyny w rozgrywkach), `points` (rozkład „Remisów” z punktów 3/2/1/0).
  Kolumny `wins`/`draws`/`losses` są wprost ze źródła (mecze z karnymi źródło
  liczy jako „Remisy” albo wlicza do W/L - `record` rozstrzyga oba przypadki).
- `/teams/{id}/season-chart`: `rounds[].result_detail`, `rounds[].decided_by`, `record`.
- `/h2h`: `balance.a_wins_shootout`/`b_wins_shootout`, `balance.a_record`/`b_record`.

Endpointy administracyjne są chronione istniejącą bramką administratora:

- `POST /admin/handball-sync/run` — `catalog`, `live`, `clubs`, `details`,
  `cleanup` albo `historical`; dla `historical` wymagany jest `season_id`;
- `GET /admin/handball-sync/runs` — historia i diagnostyka przebiegów.

## Plan frontu — BAZA (mobile)

Nie należy zastępować `app/(tabs)/stats.tsx`, bo to obecne statystyki osobiste
sędziego. Publiczne rozgrywki powinny dostać własną trasę i wspólny klient API:

1. Dodać `utils/handballPublicApi.ts`: typy, parametry filtrów, timeout,
   anulowanie zapytań i prosty cache bieżącego sezonu.
2. Dodać trasę `app/rozgrywki.tsx` oraz katalog
   `components/handball/` z ekranami: start/wyszukiwarka, rozgrywki, terminarz,
   tabela, strzelcy, klub, drużyna/skład, zawodnik i mecz.
3. W `app/(tabs)/more.tsx` dodać pełnoszeroki kafel „Rozgrywki ZPRP” obok
   istniejących modułów ZPRP. Kafel prowadzi przez `router.push('/rozgrywki')` i
   nie wymaga konta ZPRP.
4. Stan filtrów trzymać w URL/parametrach trasy: sezon, związek, kategoria,
   płeć, rozgrywki. Domyślnie otwierać bieżący sezon; poprzedni pokazywać w
   selektorze, starsze dopiero po wybraniu „Pokaż archiwalne”.
5. Użyć `changes` do cichego odświeżania widocznego meczu/tabeli, nie odpytywać
   źródła ZPRP z telefonu. Przy braku sieci pokazać ostatnią odpowiedź cache z
   datą aktualizacji.

Proponowana kolejność ekranów MVP: wyszukiwanie i lista rozgrywek → terminarz i
szczegóły meczu → tabela i strzelcy → klub/drużyna/skład → profil zawodnika.

## Plan frontu — BAZA_Web

Istniejące `components/zprp/ZprpVip*` korzystają z poświadczeń i dotychczasowych
endpointów. Nie należy ich przepinać bezpośrednio. Nowy moduł powinien być
publiczny i równolegle migrować użyteczne widoki:

1. Dodać `utils/handballPublicApi.ts` oraz `components/handball/`.
2. Utworzyć `app/rozgrywki.tsx` jako responsywny portal z bocznymi filtrami na
   szerokim ekranie i filtrem modalnym na telefonie.
3. W pierwszej wersji przenieść samą warstwę prezentacji z
   `components/zprp/stats/LeagueTablesSubTab.tsx`, `TopScorersSubTab.tsx`,
   `TeamStatsSubTab.tsx` i `PlayerMatchesSubTab.tsx`; źródłem ma być wyłącznie
   nowe API, bez `callBackendWithEncryptedCreds`.
4. Punkt wejścia dodać jako nowy `TileKey` i kafel w
   `app/(tabs)/index.tsx`; nie dokładać czwartej stałej pozycji do ciasnego
   dolnego menu w `app/(tabs)/_layout.tsx`.
5. Na desktopie pokazać równolegle tabelę i ostatnie/następne mecze; na mobile
   przełączać je segmentami. Każdy widok pokazuje `updated_at` i stan synchronizacji.

## BAZA pod RĘKĄ: raporty, Strefa trenera i Talenty

Funkcje produktowe są odseparowane od hurtowni w tabelach `pod_reka_*`. Import
publiczny nie może nadpisać zgłoszenia, sesji ani raportu.

Publiczne endpointy produktu:

- `POST /api/v1/pod-reka/reports` — migawka albo raport live;
- `GET /api/v1/pod-reka/reports/{report_id}` — trwały link publiczny;
- `DELETE /api/v1/pod-reka/reports/{report_id}` — usunięcie tokenem właściciela;
- `GET /api/v1/pod-reka/talents` — wyłącznie zatwierdzone i opublikowane pola,
  z filtrami drużyny, kategorii, pozycji, ręki dominującej i wzrostu.
- `POST /api/v1/pod-reka/push-subscriptions` — zapis zgody przeglądarki wraz z
  tematami; odpowiedź zwraca jednorazowy token do późniejszego usunięcia;
- `DELETE /api/v1/pod-reka/push-subscriptions/{id}` — odwołanie subskrypcji
  tokenem przekazanym w `X-Subscription-Token`.

Katalog sportowy udostępnia również paginowane `GET /api/v1/handball/teams`
oraz `GET /api/v1/handball/club-licenses`. Szczegóły klubu zwracają jego
drużyny i licencje, ale celowo nie zawierają adresu, e-maila ani telefonów.

Strefa trenera:

- `POST /api/v1/pod-reka/auth/login` loguje serwer-serwer do `baza.zprp.pl`,
  odczytuje konto i listę drużyn, po czym natychmiast odrzuca hasło;
- `GET /api/v1/pod-reka/auth/me` oraz `POST /auth/logout` zarządzają nieprzenośną
  sesją 12-godzinną;
- `GET /trainer/roster`, `/trainer/templates` i `/trainer/talents` zwracają tylko
  zakres potwierdzonego klubu;
- `POST /trainer/talents`, `PATCH /trainer/talents/{id}` oraz
  `POST /trainer/talents/{id}/submit` realizują szkic i wysłanie.

Zakres konta jest wyliczany wyłącznie po stronie serwera i ponownie sprawdzany
co godzinę. Identyfikator drużyny przesłany przez frontend zawsze podlega
porównaniu z sesją oraz aktywnym składem. Cookie sesji jest `HttpOnly`, `Secure`
w produkcji i chronione tokenem CSRF. Zaszyfrowane ciasteczka źródłowe służą
wyłącznie do godzinnego odświeżenia zakresu; hasło nie jest zapisywane. Próby
logowania są ograniczone czasowo.

Administracja:

- `GET /admin/pod-reka/overview` — raporty, aktywne sesje, szablony i statusy;
- `GET /admin/pod-reka/talents` — kolejka weryfikacji;
- `POST /admin/pod-reka/templates` — wersjonowane formularze;
- `PATCH /admin/pod-reka/talents/{id}` — do poprawy, weryfikacja, akceptacja,
  publikacja i archiwizacja wraz z listą publicznych pól.

Centrum dowodzenia pokazuje również, czy kanał alarmowy Discord jest
skonfigurowany, ale nigdy nie zwraca jego adresu.

Pełna data urodzenia, PESEL, badania, kontakt, dane dokumentowe i prywatna ocena
nie są zwracane publicznie. Każda zmiana workflow trafia do audytu.

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
```

Przy pierwszym wdrożeniu tabele zostaną utworzone przez istniejące
`metadata.create_all`. Import startuje po opóźnieniu i działa w tle, więc nie
blokuje uruchomienia API. Na pierwsze wdrożenie warto obserwować
`/api/v1/handball/sync/status` oraz obciążenie bazy; w razie potrzeby najpierw
zmniejszyć trzy wielkości partii, a dopiero później równoległość.

## API dla aplikacji

Najważniejsze endpointy:

- `GET /api/v1/handball/health`
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

## Następna faza: panel zdolnych zawodników

Obecny model przygotowuje identyfikatory zawodnika, drużyny, klubu, sezonu i
kategorii, ale nie miesza publicznych danych ze zgłoszeniami. W kolejnej fazie
należy dodać osobne tabele aplikacyjne: profile trenerskie, powiązania trenera z
drużyną, nabory/kryteria, zgłoszenia, decyzje i audyt. Tożsamość trenera powinna
być potwierdzana serwer-serwer przez `baza.zprp.pl`, a dostęp ograniczony do
przypisanej drużyny i kategorii wiekowej. Pełna data urodzenia i status badań
nie powinny być automatycznie kopiowane z publicznej hurtowni także w tej fazie.

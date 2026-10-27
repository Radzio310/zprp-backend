# Statystyki ogólnopolskie (`/statystyki`) - kontrakt API

Ekran „Statystyki" portalu BAZA pod Ręką i karta podglądu na „Dziś".
Wszystko publiczne, tylko odczyt, prefiks `/api/v1/handball/stats`.
Kod: `app/zprp_public/stats.py` (baza, pamięć, pętla w tle),
`app/zprp_public/stats_rules.py` (czyste reguły meczów/zawodników, szablony
ciekawostek), `app/zprp_public/stats_proel_rules.py` (czyste reguły protokołów ProEl).

API jest **addytywne**: nowe pola mogą dochodzić, istniejące nie zmieniają znaczenia.
Klient ma ignorować nieznane pola i znosić `null` w polach opisanych jako „albo null".

## Zakres (jeden pasek filtrów)

Każda trasa poza `/stats/filters` przyjmuje ten sam zestaw parametrów i liczy
WSZYSTKIE swoje sekcje dokładnie dla tego zakresu. Puste = bez filtra.

| parametr | wartości | znaczenie |
|---|---|---|
| `season_id` | id z `/stats/filters` | domyślnie bieżący sezon |
| `gender` | `M` \| `K` \| `X` | płeć rozgrywek (`competition.gender`) |
| `category` | klucz kategorii (tabela niżej), można kilka po przecinku | klasa rozgrywek |
| `age` | `1`..`5` | kategoria wiekowa ZPRP: 1 seniorzy, 2 juniorzy, 3 juniorzy mł., 4 młodzicy, 5 dzieci |
| `level` | `central` \| `district` | szczebel |
| `province` | slug województwa (`slaskie`, `mazowieckie`, …), można kilka po przecinku | województwo |

Nieznana wartość parametru = 422 (FastAPI) albo pusty wynik (nieznany slug) - nigdy 500.
Odpowiedź każdej trasy ma `scope` (zakres po normalizacji, z rozwiązanym `season_id`).

### Klucze kategorii (`category`)

Jak `components/pod-reka/match/category.ts` w BAZA_web (ta sama kolejność reguł na nazwie
rozgrywek), plus zapas z kategorii wiekowej ZPRP, gdy nazwa nic nie mówi:

| klucz | etykieta | | klucz | etykieta |
|---|---|---|---|---|
| `OS` | Superliga | | `J` | Juniorzy |
| `LC` | Liga Centralna | | `Jm` | Juniorzy mł. |
| `I` | I liga | | `Ml` | Młodzicy |
| `II` | II liga | | `Ml1213` | Dzieci |
| `III` | III liga | | `MP` | Mistrzostwa Polski |
| `S` | Seniorzy - inne ligi | | `PP` | Puchar Polski |
| `OTHER` | Pozostałe rozgrywki | | `SP` | Superpuchar |

`S` = nazwa bez klasy ligi, ale ZPRP mówi „seniorzy" (ligi okręgowe/wojewódzkie).
Etykiety przychodzą też w `/stats/filters` - klient nie musi ich trzymać.

### Szczebel i województwo

* **central**: kategoria `OS`, `LC`, `I`, `II`, `MP`, `PP`, `SP` albo rozgrywki bez
  województwa (związek „centralny"/departament). Reszta = **district**.
* **Województwo meczu**: rozgrywki okręgowe - województwo związku prowadzącego;
  centralne - województwo klubu GOSPODARZA (związek klubu). Nieustalone = `unknown`
  (nie przechodzi filtra `province`, ale jest w `/stats/geo`, więc suma województw = całość).
* **Województwo zawodnika i drużyny**: województwo WŁASNEGO klubu (zapas: województwo
  rozgrywek okręgowych). Dlatego w meczu centralnym gość z innego województwa liczy
  się do swojego województwa w rankingach zawodników/drużyn, a mecz - do gospodarza.

## Wspólne kształty

`MatchRef` (karta meczu w rekordach i listach):

```json
{"match_id": "123", "home_team_name": "…", "away_team_name": "…",
 "home_team_id": "…", "away_team_id": "…", "home_club_id": "…", "away_club_id": "…",
 "home_logo_url": "https://…|null", "away_logo_url": "…|null",
 "score_home": 31, "score_away": 29, "shootout_home": null, "shootout_away": null,
 "halftime_home": 15, "halftime_away": 14,
 "scheduled_at": "2026-10-25T18:00:00", "competition_id": "…", "competition_name": "…",
 "category": "OS", "province": "slaskie", "score_source": "zprp|proel|proel_live"}
```

`PlayerRef`: `{"player_id", "first_name", "last_name", "photo_url", "team_id",
"team_name", "club_id", "club_logo_url"}` - zawsze z publicznych tabel ZPRP
(po korektach admina). Nigdy nazwisk z ProEla.

`TeamRef`: `{"team_id", "team_name", "club_id", "club_logo_url", "province"}`.

Procenty to liczby 0-100 z jednym miejscem po przecinku albo `null`, gdy nie ma z czego liczyć.
Średnie z dwoma miejscami. Daty: `scheduled_at` = naiwny czas warszawski (jak w całym API),
`generated_at` = ISO z offsetem UTC.

Każda odpowiedź ma: `generated_at`, `next_refresh_s` (po ilu sekundach warto zapytać
ponownie), `snapshot_at` (chwila zbudowania migawki sezonu, ISO), `scope`,
`season` (`{season_id, name}` albo null).

## Pamięć podręczna i koszt

| trasa | TTL odpowiedzi | źródło |
|---|---|---|
| `/stats/filters` | 15 min | migawka sezonu |
| `/stats/today` | 25 s | świeże zapytanie o dzisiejsze mecze + ProEl (bloby czytane tylko po zmianie) |
| `/stats/season`, `/geo`, `/trends`, `/proel` | 10 min | migawka sezonu w pamięci |

Migawka sezonu (mecze sezonu w zwartej postaci, sumy zawodników na drużynę i rozgrywki,
wielkie występy, streszczenia protokołów ProEl) buduje się w tle co 15 min dla bieżącego
sezonu (inne sezony - przy pierwszym pytaniu, potem 15 min). Streszczenia protokołów ProEl
leżą trwale w `zprp_public_stats_snapshots` (klucz `proel:<numer>`), więc restart nie czyta
wszystkich blobów od nowa. Obliczenia CPU idą w wątku (`asyncio.to_thread`), nie na pętli.

## `GET /stats/filters?season_id=`

```json
{"generated_at": "…", "next_refresh_s": 900,
 "season": {"season_id": "…", "name": "2026/2027"},
 "seasons": [{"season_id": "…", "name": "…", "start_year": 2026, "active": true, "current": true}],
 "genders": [{"key": "M", "label": "Mężczyźni", "matches": 9123}],
 "categories": [{"key": "OS", "label": "Superliga", "matches": 182, "level": "central"}],
 "ages": [{"key": "1", "label": "Seniorzy", "matches": 4000}],
 "levels": [{"key": "central", "label": "Centralne", "matches": 1200}, {"key": "district", "label": "Okręgowe", "matches": 21000}],
 "provinces": [{"key": "slaskie", "label": "śląskie", "matches": 2500, "clubs": 80}],
 "defaults": {"season_id": "…"}}
```

Liczniki `matches` = wszystkie mecze sezonu w danej wartości (bez innych filtrów).
Wartości z zerem nie wracają (poza województwami - zawsze 16).

## `GET /stats/today?{zakres}`

„Dziś na żywo" - doba warszawska. Odświeżać co `next_refresh_s` (25 s).

```json
{"date": "2026-10-26", "weekday": 0,
 "counts": {"total": 212, "played": 120, "live": 14, "upcoming": 70, "pending": 6,
            "no_hour": 3, "withdrawn": 2},
 "goals": {"total": 6123, "final": 5800, "live": 323, "avg_per_match": 48.33,
           "sources": {"zprp": 110, "proel": 10, "proel_live": 14}},
 "highest_scoring": "MatchRef + total|null",
 "biggest_win": "MatchRef + margin|null",
 "top_scorers": [{"player": "PlayerRef|null", "number": 7, "team_name": "…", "goals": 14,
                  "penalty_goals": 3, "match": "MatchRef", "source": "zprp|proel"}],
 "discipline": {"two_minutes": 300, "red_cards": 6, "warnings": 210, "matches_counted": 130},
 "goals_by_hour": [{"hour": 10, "matches": 12, "goals": 540, "played": 9, "live": 2}],
 "comparison": {
   "weekday_avg": {"weekday": 0, "days": 7, "matches": 35.4, "goals": 1600.2, "avg_goals": 45.2},
   "yesterday": {"date": "2026-10-25", "matches": 260, "played": 255, "goals": 12000, "avg_goals": 47.06},
   "delta_avg_goals": 3.1},
 "ticker": [{"match": "MatchRef", "side": "home", "kind": "goal|seven_goal", "minute": 43,
             "clock": "42:17", "half": 2, "score": {"home": 21, "away": 19}, "number": 7,
             "player": "PlayerRef|null", "at": "2026-10-26T17:42:10+00:00", "live": true}],
 "live": ["MatchRef + {live_score: {home, away}, minute, clock: \"25:00\", phase: \"live\"}"],
 "by_category": [{"key": "OS", "label": "Superliga", "matches": 6, "played": 2, "live": 1, "goals": 120}],
 "by_province": [{"key": "slaskie", "label": "śląskie", "matches": 30, "played": 12, "live": 2, "goals": 600}]}
```

Reguły:
* Mecz liczy się do `played`, gdy ma wynik końcowy z ZPRP albo z zakończonego protokołu
  ProEl (zapas `proel_cards`, `score_source: "proel"`); `live` = protokół w toku
  (start + leasing albo świeży zapis, jak `/live`); `upcoming` = przed nami (reguła 3 h,
  bez godziny do końca doby); `pending` = po terminie bez wyniku; `no_hour` = 00:00
  bez godziny z ProEla (podzbiór `upcoming`/`pending`).
* Bramki: JEDNO źródło na mecz - wynik ZPRP, inaczej wynik zakończonego protokołu,
  inaczej bieżący wynik meczu w toku. Bez podwójnego liczenia. `avg_per_match` tylko
  z meczów zakończonych.
* Strzelcy dnia i kary: skład ZPRP, gdy jego bramki zgadzają się z wynikiem; inaczej
  protokół ProEl (numery przypisane do publicznych zawodników ZPRP tą samą regułą co
  zapasowy skład meczu); bez dopasowania `player: null` + `number`.
* `goals_by_hour` - godzina ROZPOCZĘCIA meczu (bramki meczu idą do jego godziny);
  `played` / `live` - ile meczów tej godziny ma wynik / trwa (reszta = przed nami albo po terminie).
* `ticker` - ostatnie bramki z protokołów meczów w toku i zakończonych przed chwilą,
  najnowsze pierwsze (max 30). `at` to szacunek: chwila zapisu protokołu minus czas
  gry od bramki. `minute` = minuta gry (1-60+).
* `comparison.weekday_avg` - średnia z dni sezonu przed dziś o tym samym dniu tygodnia,
  w których odbył się co najmniej jeden mecz (w tym samym zakresie).

## `GET /stats/season?{zakres}`

```json
{"totals": {"matches": 21000, "played": 9000, "remaining": 11800, "walkovers": 40,
            "goals": 430000, "avg_goals": 47.8, "avg_home_goals": 24.6, "avg_away_goals": 23.2,
            "teams": 3100, "clubs": 610, "players": 41000, "referees": 900},
 "results": {"decided": 8950, "home_w": 4300, "home_wk": 200, "away_wk": 180, "away_w": 4270,
             "home_win_pct": 50.3, "away_win_pct": 49.7, "shootout_pct": 4.2, "unresolved": 10},
 "halftime": {"matches": 7000, "leader_win_pct": 78.1, "trailer_win_pct": 17.0, "level_at_ht": 600},
 "attendance": {"matches": 500, "total": 120000, "avg": 240, "top": ["MatchRef + spectators"]} ,
 "goals_histogram": [{"goals": 41, "matches": 210}],
 "margin_histogram": [{"margin": 1, "matches": 900}],
 "top_scorers": [{"player": "PlayerRef", "goals": 180, "matches": 12, "per_match": 15.0,
                  "penalty_goals": 30, "penalty_attempts": 36, "two_minutes": 3}],
 "top_scorers_avg": ["… jak wyżej, min. 5 meczów, sort per_match"],
 "top_seven_m": ["… sort penalty_goals"],
 "teams_attack": [{"team": "TeamRef", "competition_name": "…", "matches": 10,
                   "goals_for": 350, "goals_against": 250, "gf_pm": 35.0, "ga_pm": 25.0}],
 "teams_defense": ["… sort ga_pm rosnąco"],
 "teams_scatter": [{"team_id": "…", "name": "…", "matches": 10, "gf_pm": 35.0, "ga_pm": 25.0}],
 "win_streaks": [{"team": "TeamRef", "length": 9, "current": true, "from": "2026-09-05", "to": "2026-10-25",
                  "form": ["L", "W", "WK", "W", "…"], "form_streak": [1, 9]}],
 "discipline": {"two_minutes": 30000, "red_cards": 400, "warnings": 20000, "two_min_per_match": 6.1,
                "matches_with_lineups": 4900,
                "teams_two_min": [{"team": "TeamRef", "two_minutes": 60, "matches": 10, "per_match": 6.0}],
                "teams_red": [{"team": "TeamRef", "red_cards": 5, "matches": 10}]},
 "biggest_wins": ["MatchRef + margin"],
 "highest_scoring": ["MatchRef + total"]}
```

Reguły: wynik bez remisów (`W`/`WK`/`LK`/`L`, `match_rules.side_result`); walkower
liczy się do bilansu (`decided`), ale NIE do bramek, średnich, histogramów i rekordów.
`unresolved` = równy wynik bez serii karnych w danych. `attendance` = null, gdy
żaden mecz nie ma widzów. Ranking średniej: min. 5 meczów; ataku/obrony: min. 3 mecze.
Strzelcy z publicznych składów meczów (suma po drużynach zawodnika w zakresie).
Kary drużyn - suma kar zawodników ze składów (bez osób towarzyszących).
`win_streaks`: zwycięstwa W i WK, mecze drużyny w zakresie chronologicznie; `form` = okno wyników
drużyny (max 12, chronologicznie: dwa mecze przed serią, seria, dalsze mecze), `form_streak` = położenie
serii w oknie `[od, do]` włącznie. `teams_scatter` = mapa ataku i obrony: drużyny z min. 3 meczami
(max 300, najwięcej meczów), bramki zdobyte / stracone na mecz.

## `GET /stats/geo?{zakres}`

```json
{"provinces": [{"key": "slaskie", "label": "śląskie", "matches": 2500, "played": 1100,
                "goals": 52000, "avg_goals": 47.3, "home_win_pct": 52.0, "share_pct": 12.0,
                "clubs": 80, "teams": 300, "players": 4100, "referees": 90}],
 "unknown": {"matches": 3, "...": "…"},
 "matrix": {"categories": ["OS", "J"], "genders": ["M", "K"],
            "rows": [{"key": "slaskie", "by_category": {"J": {"matches": 300, "goals": 9000, "avg_goals": 48.1}},
                      "by_gender": {"M": {"matches": 1300, "goals": 30000, "avg_goals": 47.0}}}]},
 "levels": {"central": {"matches": 1200, "played": 600, "goals": 33000, "avg_goals": 55.0,
                        "home_win_pct": 56.0, "shootout_pct": 6.0, "two_min_per_match": 7.2},
            "district": {"...": "…"}},
 "totals": {"matches": 21000, "played": 9000, "goals": 430000}}
```

Suma `matches`/`played`/`goals` po `provinces` + `unknown` = `totals`. Kluby, drużyny
i zawodnicy - wg województwa własnego klubu; sędziowie - wg województwa meczów, które
prowadzili (sędzia z meczami w dwóch województwach jest w obu).
Filtr `province` zawęża listę do wskazanych województw (reszta pól liczona normalnie).

## `GET /stats/trends?{zakres}`

```json
{"weekly": [{"week_start": "2026-09-07", "matches": 900, "goals": 43000, "avg_goals": 47.8, "home_win_pct": 51.0}],
 "cumulative": {"total_goals": 430000,
                "daily": [{"date": "2026-09-06", "goals": 9000, "cumulative": 9000}],
                "milestones": [{"goals": 100000, "date": "2026-10-04", "match": "MatchRef"}],
                "next_milestone": {"goals": 500000, "remaining": 70000, "rate_per_day": 4100.5,
                                   "projected_date": "2026-11-12"}},
 "records": [{"kind": "highest_scoring_match", "title": "Najwięcej bramek w meczu", "value": 88,
              "unit": "bramek", "match": "MatchRef|null", "player": "PlayerRef|null",
              "side": "home|away|null", "minute": null, "detail": "…|null", "source": "zprp|proel"}],
 "facts": [{"kind": "goals_per_minute", "text": "W tym sezonie pada średnio 1,6 bramki na minutę gry.",
            "value": 1.6, "match_id": null}]}
```

`records.kind` (pojawiają się tylko, gdy da się je policzyć): `highest_scoring_match`,
`biggest_win`, `most_goals_team`, `top_individual_game`, `most_seven_m_game`,
`highest_attendance`, oraz z ProEla: `fastest_goal` (`minute` + `detail` „0:23"),
`biggest_comeback` (odrobiona strata), `most_goals_5min` (bramki jednej drużyny
w 5 minutach gry), `longest_run` (bramki z rzędu), `latest_winner` (najpóźniejsza
decydująca bramka). Kamienie milowe: 1 000, 5 000, 10 000, 25 000, 50 000, 100 000,
potem co 100 000; `match` = mecz, w którym padła bramka nr N (kolejność: dzień, godzina,
id meczu). Prognoza: tempo z ostatnich 28 dni (null, gdy tempo 0).
`facts` - gotowe zdania po polsku (szablony w `stats_rules.FACT_TEMPLATES`), max 12,
kolejność = ciekawość; `kind` stały, do ikon.

## `GET /stats/proel?{zakres}`

Tylko publiczne protokoły ProEl (bez testów i szkoleń) zakończone/zatwierdzone,
powiązane z meczem ZPRP z zakresu. Zero danych osobowych - wyłącznie zdarzenia.

```json
{"coverage": {"protocols": 800, "played_matches": 9000, "pct": 8.9, "timed": 790, "no_clock": 10,
              "by_category": [{"key": "OS", "label": "Superliga", "protocols": 90, "played": 100, "pct": 90.0}]},
 "goals_by_minute": [{"minute": 1, "goals": 410}],
 "halves": {"first": 18000, "second": 19500, "second_pct": 52.0},
 "goals_by_5min": [{"from": 0, "to": 5, "goals": 2900}],
 "last5_share_pct": 9.6, "first5_share_pct": 7.1,
 "sevens": {"attempts": 4000, "goals": 3000, "pct": 75.0, "per_match": 5.0},
 "suspensions": {"count": 5000, "per_match": 6.2, "pp_goals": 3100, "sh_goals": 900,
                 "pp_goal_pct": 8.3, "pp_per_match": 3.9, "window_own": 0.71, "window_opp": 1.12},
 "timeouts": {"count": 2100, "per_match": 2.6, "before_diff": -0.9, "after_diff": 0.4,
              "avg_swing": 1.3, "positive_pct": 58.0},
 "comebacks": {"matches": 120, "pct": 15.0, "biggest": "{match: MatchRef, side, deficit}|null",
               "top": ["{match: MatchRef, side, deficit} - max 3, największa odrobiona strata"]},
 "lead_changes_avg": 2.4, "ties_avg": 3.1,
 "first_goal_winner_pct": 58.0, "halftime_leader_win_pct": 77.0,
 "longest_runs": [{"match": "MatchRef", "side": "home", "goals": 9, "from_minute": 12, "to_minute": 21}],
 "best_5min": [{"match": "MatchRef", "side": "away", "goals": 7, "from_minute": 51}],
 "matches": 800}
```

Reguły (jak `analysis.ts` zakładki Statystyki meczu): minuta = `floor(t / długość meczu × 60) + 1`
(połowy 20/25 min skalowane do 60); kara (2 min, czerwona, niebieska, Kd) osłabia na
2 minuty; bramka w przewadze = rywal ma więcej osób na ławce kar; `window_own/opp` = średnio
bramek ukaranej drużyny / rywala w 2 minutach po karze; czas drużyny: bilans 5 min
przed i po (`swing` = po − przed); powrót = zwycięzca przegrywał ≥ 3 bramkami;
serie od 3 bramek z rzędu. Wynik meczu do „kto wygrał": wynik ZPRP, a bez niego protokół.

Protokół zakończony, którego wyniku ZPRP jeszcze nie ma, też wchodzi do `/stats/proel`
(i rekordów ProEl) - wtedy jego `MatchRef` ma wynik z protokołu i `score_source: "proel"`.
Sekcje `/season`, `/geo`, `/trends` (poza rekordami ProEl) liczą wyłącznie wyniki ZPRP.

### Ograniczenia danych ProEl

* Pokrycie = tylko mecze prowadzone w aplikacji BAZA (ProEl) z publicznym protokołem
  zakończonym albo zatwierdzonym; testy, szkolenia (`T-…`) i ćwiczenia nigdy. Udział
  podaje `coverage.pct` (całość i per kategoria) - klient powinien go pokazać przy wykresach.
* Protokół łączy się z meczem ZPRP po `zprp_match_id` (z wiersza albo `matchConfig.matchId`),
  a bez niego po numerze meczu i dniu z protokołu. Niepołączony protokół nie liczy się nigdzie.
* Minuta to czas gry z protokołu; dla połów 20/25 min histogram jest skalowany do 60.
* Czas gry 00:00 = zegar stał. Zdarzenie z czasem ≤ 0 nie wchodzi do statystyk CZASU
  (minuty, pierwsze/ostatnie 5 minut, przewaga i okna kar, efekt czasu drużyny, najlepsze
  5 minut, serie z minutami, najszybsza i decydująca bramka). Protokół z co najmniej 3
  zdarzeniami na 00:00 (albo ze wszystkimi bramkami na 00:00) to „bez zegara”
  (`coverage.no_clock`, reszta = `coverage.timed`): wypada ze statystyk czasu w całości,
  a zostaje w tym, co wynika z kolejności bramek (kto pierwszy, zmiany prowadzenia,
  remisy, powroty, prowadzenie do przerwy, karne, liczba kar i czasów).
  `per_match` kar/czasów dzieli przez wszystkie protokoły, przewagę i efekty czasu przez
  `timed`. Najszybsza bramka meczu: co najmniej 5 s (`stats_proel_rules.FASTEST_MIN_MS`).
  Zmiana reguł = `stats_proel_rules.VERSION` + 1: zapisane streszczenia liczą się od nowa.
  Dogrywki (rzadkie, puchary) wpadają do ostatniego przedziału.
* `ticker.at` jest szacunkiem (zapis protokołu − czas gry od bramki, + 10 min przerwy dla
  bramek z 1. połowy oglądanych w 2.). Kolejność między meczami może się minimalnie różnić.

## Wydajność (pomiar 26.10.2026, Postgres 16 lokalnie, 1 rdzeń Pythona)

Zasiane: 20 000 meczów sezonu (~280 tys. wierszy składów, 54 tys. sum zawodnik-drużyna-rozgrywki),
1 500 protokołów ProEl po ~110 zdarzeń, 460 meczów „dziś" w tym 40 protokołów w toku.

| krok | 20 tys. meczów | 40 tys. meczów |
|---|---|---|
| migawka sezonu (SQL + budowa w wątku) | 1,2 s (SQL 0,3-0,4 s) | 1,9 s (SQL 0,65 s) |
| `/season` bez filtrów, pierwszy raz po migawce | 0,46-0,55 s | 0,57-0,7 s |
| `/geo` bez filtrów | 0,16-0,2 s | 0,27-0,35 s |
| `/trends` (sezon i ProEl z pamięci) | 0,11 s | 0,25 s |
| `/proel` | 35 ms | < 50 ms |
| sekcja z filtrem (kategoria, województwo, szczebel) | 35-200 ms | 50-190 ms |
| każda sekcja z pamięci (10 min) | < 1 ms | < 1 ms |
| `/today`: baza dnia (co 20 s) / inny zakres z tej samej bazy | 0,25-0,8 s / 25 ms | 0,55-1,1 s / 50-80 ms |
| streszczenia ProEl: 600 nowych blobów (tylko w tle) / restart z tabeli | 1,8 s / 0,05 s | - |

Pamięć migawki: ~24 MB dla 20 tys. meczów (szczyt budowy ~100 MB, chwilowo); w pamięci
najwyżej 2 sezony. Bieżący sezon rozgrzewa pętla w tle (`run_stats_scheduler`, start po
90 s, potem co 15 min), więc użytkownik dostaje gotowe odpowiedzi; inny sezon - przy
pierwszym pytaniu ok. 1,5-2,5 s, potem z pamięci.

Zmienne środowiskowe: `STATS_DISABLED=1` (pętla nie startuje; trasy liczą na żądanie),
`STATS_INTERVAL_SECONDS` (900), `STATS_START_DELAY_SECONDS` (90),
`STATS_PROEL_PER_CYCLE` (600 blobów na cykl). Indeks: `ix_zprp_public_matches_season_sched`
(`season_id, scheduled_at`) zakładany przy starcie w `app/db.py`.

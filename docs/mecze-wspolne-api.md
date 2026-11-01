# Mecze wspólne i ręczne podpięcie ProEla - kontrakt API

Stan: 31.10.2026. Kod: `app/shared_matches.py`, `app/shared_match_pair.py`, `app/shared_match_rules.py`,
`app/shared_match_notify.py`, `app/mentor_proel_link.py`, tabele `app/shared_match_tables.py`. Decyzje właściciela:
pamięć `mecze-reczne-wspolne-decyzje`.

## 0. Zasady wspólne

- **Tożsamość:** `Authorization: Bearer <JWT BAZY>` (aplikacja) albo ciasteczko sesji `baza_mentor_session` + `X-CSRF-Token`
  przy zapisach (BAZA_web) - ta sama zależność co panel Mentor (`base_actor`). Wszystkie trasy sędziowskie wymagają claimu `judge_id`.
- **Koperta błędu** (`main.py`): `{"error": {code,message,...}, "code": "...", "message": "...", ...pola dodatkowe}`. Klient czyta
  w kolejności `detail` -> `detail.message` -> `error` -> `error.message` -> `message`, jak `serverMessage()`; kod to `code`.
- **Dostęp:** wyłącznie członkowie meczu (twórca jest członkiem). Obcy dostaje `404 MATCH_NOT_FOUND`, jakby meczu nie było. Admin
  nie ma dostępu do cudzych meczów wspólnych. Egzekwowane na serwerze.
- **Wersja (`rev`):** liczba całkowita, rośnie o 1 przy KAŻDYM zapisie treści (dane, wynik, obsada, powiązania ZPRP/ProEl, usunięcie).
  Zapis treści wymaga `base_rev` (wersja, którą klient widział). Niezgodny -> `409 REV_CONFLICT` (kształt niżej). Zapisy osobiste
  (ukryj, przywróć, statystyki) `rev` nie zmieniają i `base_rev` nie wymagają.
- **Identyfikatory:** mecz = `id` (uuid hex, 32 znaki). Karta w panelu pary = `my:<id>` (pole `card_id`).
- **Wynik ręczny nigdy nie idzie do ZPRP** - moduł nie wywołuje ZPRP w ogóle. `zprp_match_id` to tylko wskaźnik.
- **Role obsady (`role`):** `sedzia1`, `sedzia2`, `czas`, `sekretarz`, `delegat`. Limit obsady: 12 osób.
- **Czas:** `match_at` przyjmowany jako ISO 8601; bez strefy = czas polski. Odpowiedzi niosą UTC (`...Z`/`+00:00`).
  Klucz dnia (`date_key`) liczony po polsku.

### Błąd 409 `REV_CONFLICT`
```json
{"error": {...}, "code": "REV_CONFLICT", "message": "Ktoś zmienił ten mecz, zanim zapisałeś(aś)...",
 "rev": 7, "base_rev": 5, "current": { /* pełna odpowiedź GET /shared-matches/{id} z aktualnymi danymi */ }}
```
Klient pokazuje różnicę (`current.match`, `current.log[0]` - kto i co zmienił) i prosi o decyzję; po decyzji powtarza zapis z
`base_rev = rev`. Serwer niczego nie scala ani nie nadpisuje.

## A. Mecze wspólne (`/shared-matches`)

### Kształty
**match**: `id, card_id, creator_id, creator_name, rev, code, competition, home_name, away_name, match_at, date_key, hall, city,
zprp_match_id, proel_key, result, extra, local_id (tylko twórca), created_at, updated_at, updated_by, updated_by_name`.
`result` = `null` albo `{score_home, score_away, half_home, half_away, by, by_name, at}` (kto i kiedy wpisał).
**crew[]**: `{id (member_id), judge_id|null, manual (true = wpis ręczny bez konta, bez dostępu), name, photo_url, role, role_label, added_by, added_at}`.
**my**: `{member_id, role, hidden, hidden_at, counts_in_stats, added_by, added_by_name}` (tylko własny stan; cudzych ukryć/flag nie widać).
**detail** (odpowiedź szczegółu i większości zapisów): `{match, crew[], my, can:{edit,delete,remove_members,hide}, log[], rev}`.
`log[]`: `{id, rev, actor_id, actor_name, at, action, changes:[{field,from,to}]}`, najnowsze pierwsze (do 60).
Akcje dziennika: `create, edit, result, result_clear, crew_add, crew_edit, crew_remove, join, zprp_link, proel_link, delete`.

### Trasy

| Metoda i ścieżka | Body / query | Odpowiedź | Błędy |
|---|---|---|---|
| `GET /shared-matches?include_hidden=false&limit=300` | - | `{matches:[{match,crew,my}], count, hidden_count}` (bez usuniętych; ukryte tylko z `include_hidden=true`) | 401 |
| `GET /shared-matches/{id}` | - | detail | 404 `MATCH_NOT_FOUND`, 410 `MATCH_DELETED` (członek, mecz usunięty) |
| `POST /shared-matches` | `CreateBody` (niżej) | `{ok, existing, skipped[], ...detail}`; przy idempotentnym trafieniu `existing:true`; gdy lokalny mecz był już usunięty przez twórcę: `{ok, existing:true, deleted:true, id}` | 409 `DUPLICATE_MATCH`, 422 `VALIDATION`/`NOT_APP_USER`/`MANUAL_NAME_REQUIRED` |
| `PUT /shared-matches/{id}` | `{base_rev, code?, competition?, home_name?, away_name?, match_at?, hall?, city?, extra?}` (tylko wysłane pola) | `{ok, unchanged, ...detail}` | 409 `REV_CONFLICT`, 422 `BASE_REV_REQUIRED`, 404 |
| `DELETE /shared-matches/{id}?base_rev=` | `base_rev` opcjonalny | `{ok, deleted:true}`; reszta obsady dostaje push i przy następnym odczycie 410 | 403 `CREATOR_ONLY`, 409 (gdy podano `base_rev`) |
| `PUT /shared-matches/{id}/result` | `{base_rev, score_home, score_away, half_home?, half_away?}` albo `{base_rev, clear:true}` | `{ok, unchanged, ...detail}` (`match.result.by/at`) | 409, 422 (oba wyniki wymagane, 0-199) |
| `POST /shared-matches/{id}/crew` | `{base_rev, add:[{judge_id? , name?, role}]}` | `{ok, unchanged, skipped[], ...detail}`; `skipped[]`: `{judge_id, reason: ALREADY_MEMBER\|BLOCKED}` | 409 `ADD_BLOCKED` (gdy nikogo nie dodano z powodu blokady), 422 `NOT_APP_USER` (`judge_ids[]`), 422 `MANUAL_NAME_REQUIRED`, 409 `REV_CONFLICT` |
| `PUT /shared-matches/{id}/crew/{member_id}` | `{base_rev, role?, name?}` | `{ok, unchanged, ...detail}` | 403 `NOT_ALLOWED`, 404 `MEMBER_NOT_FOUND`, 409 |
| `DELETE /shared-matches/{id}/crew/{member_id}?base_rev=` | `base_rev` wymagany | `{ok, ...detail}`; usunięty sędzia z aplikacji dostaje push | 403 `CREATOR_ONLY` (nie-twórca), 403 `CREATOR_STAYS` (twórca nie usunie siebie), 409 |
| `POST /shared-matches/{id}/hide` | `{block_adder?: bool}` (body opcjonalne) | `{ok, hidden:true, blocked_via: judge_id\|null}`. `block_adder` = „nie dodawaj mnie więcej przez tę osobę" (osoba z `my.added_by`) | 404 |
| `POST /shared-matches/{id}/restore` | - | `{ok, hidden:false}` | 404 |
| `PUT /shared-matches/{id}/stats` | `{counts_in_stats: bool}` | `{ok, counts_in_stats}` (per członek, domyślnie false, `rev` bez zmian) | 404 |
| `PUT /shared-matches/{id}/zprp` | `{base_rev, zprp_match_id: "123456"\|null}` | `{ok, unchanged, ...detail}` | 422 (tylko liczbowe IdZawody), 409 |
| `PUT /shared-matches/{id}/proel` | `{base_rev, proel_key: "OSK/12"\|"T-XXXXXXXX/NUM"\|null}` | `{ok, unchanged, ...detail}`. Wołać automatycznie, gdy ktoś prowadzi ProEla z meczu wspólnego. To wskaźnik: nic nie zapisuje w `proel_matches`. | 403 `PROEL_SCOPE` (cudze szkolenie), 409 |
| `POST /shared-matches/join` | `{match_id, role, home_name, away_name, match_at}` | `{ok, joined, already_member, ...detail}`. Dozwolone tylko dla duplikatu (serwer porównuje drużyny+datę; samo `zprp_match_id` NIE wystarcza). `role` jest wymagana; zajęta rola sędziowska (sędzia 1/2) nie jest przejmowana. Twórca dostaje push `joined` i może usunąć dołączonego z obsady. Ukryty członek dostaje przywrócenie | 403 `NOT_A_DUPLICATE`, 404, 409 `ROLE_TAKEN`, 422 `ROLE_REQUIRED` |
| `POST /shared-matches/{id}/repeat` | `{match_at, code?, copy_crew=true, force=false}` | `{ok, existing:false, skipped[], ...detail}` nowego meczu | 409 `DUPLICATE_MATCH`, 422 |
| `GET /shared-matches/blocks` | - | `{blocks:[{via_judge_id, via_name, created_at}]}` | |
| `DELETE /shared-matches/blocks/{via_judge_id}` | - | `{ok}` | |
| `GET /shared-matches/users/search?q=&limit=10` | `q` min. 2 znaki: imię/nazwisko (tokeny AND, bez wieloznaczników) albo dokładny numer sędziego | `{users:[{judge_id,name,photo_url,province}]}` - tylko konta z aplikacji (`login_records`), bez siebie. Limit 60 zapytań/min na konto (pamięć procesu) | 429 `RATE_LIMITED` |
| `GET /shared-matches/users/suggestions?limit=8` | - | `{suggestions:[{judge_id,name,photo_url,reason: partner\|frequent\|recent, reasons[], shared_count}]}` | |

**CreateBody:** `{local_id?, code?, competition?, home_name?, away_name?, match_at?, hall?, city?, zprp_match_id?, proel_key?,
my_role="sedzia1", crew:[{judge_id?|name?, role}], counts_in_stats=false, extra?, result?:{score_home,score_away,half_home?,half_away?}, force=false}`.

- `local_id`: ten sam twórca + ten sam `local_id` = ten sam mecz (migracja lokalnych meczów idempotentna, także przy równoległych
  wywołaniach). Usunięty wcześniej mecz nie wraca (`deleted:true`) - klient usuwa lokalną kopię.
- Duplikat (bez `force`): te same drużyny (bez względu na kolejność, wielkość liter i ogonki) i ta sama data (dzień polski).
  Samo `zprp_match_id` nie wystarcza (nie ujawnia meczu bez zgodności drużyn i daty). Odpowiedź: `409 DUPLICATE_MATCH`, `can_join:true`,
  `duplicates:[{id, home_name, away_name, match_at, creator_name, already_member, hidden}]` - nie-członek dostaje tylko to minimum;
  `code`, `hall` i `crew` dochodzą wyłącznie, gdy pytający już jest członkiem. Klient pyta „ten mecz już istnieje, dołączyć?":
  „Dołącz" -> `POST /shared-matches/join`, „Utwórz drugi" -> powtórka z `force:true`.
- `crew[]` bez `judge_id` = wpis ręczny (sam podpis, bez dostępu, wymaga `name`). Z `judge_id` - tylko użytkownik aplikacji
  (inaczej 422 `NOT_APP_USER`). Osoba z blokadą względem twórcy trafia do `skipped[]` z `reason:"BLOCKED"` (klient to pokazuje).
- Wynik (`result`) przy migracji: autorem wyniku zostaje twórca, czas = chwila utworzenia.
- Mecz testowy nigdy nie jest wysyłany (decyzja: tylko lokalnie).

### Powtórz mecz
Kopiuje drużyny, rozgrywki, halę, miasto, `extra` i (opcjonalnie) obsadę z własną rolą powtarzającego. Kod: kolejny numer serii
(`EHF/1` -> `EHF/2`, `EHF 3` -> `EHF 4`, `EHF` -> `EHF/2`; zajęte numery z moich meczów są pomijane; kod będący samym numerem zostaje
pusty). NIE kopiuje wyniku, powiązań ZPRP/ProEl ani flagi statystyk. Autorem kopii jest powtarzający.

### Push (FCM, `kind: "shared_match"`)
Dane: `type, kind=shared_match, event=added|removed|deleted, matchId, tag, notificationTag, notificationColor`. Przełącznik w telefonie:
`notificationTypes.sharedMatch` (brak pola = zgoda; `app/push/preferences.py`). Autor zmiany nie dostaje własnego pusha.
- `added` - po dodaniu do obsady (utworzenie, dodanie przez członka, powtórka): tytuł „Dodano Cię do meczu".
- `removed` - twórca usunął Cię z obsady: „Usunięto Cię z obsady meczu".
- `deleted` - twórca usunął mecz u wszystkich: „Mecz został usunięty" (reszta obsady).
Dołączenie przez duplikat nie wysyła pusha.

## B. Panel mentorski (`/mentor-panel`)

### Mecz wspólny jako karta pary
Jeśli OBAJ sędziowie pary są w obsadzie meczu wspólnego jako `sedzia1`/`sedzia2`, mecz jest kartą na liście pary (te same trasy
`/mentor-panel/pairs/{pair_id}/matches...`), z `match_id = "my:<id>"`. Karta niesie: `shared:true`, `origin_kind:"shared"`,
`shared_id`, `shared_rev`, `zprp_match_id`, `proel_key`, `result_by`, `result_at`, `source` jest usuwane jak przy innych kartach.
Flagi, nagrania, klipy, wątki pary działają na tym id bez zmian. Ukrycie meczu u jednego członka nie usuwa karty z panelu pary.
Każda zmiana meczu wspólnego (dane, wynik, obsada, powiązania, usunięcie) zrzuca pamięć kart pary i podbija `rev` panelu
(`GET .../changes` długim pollem informuje klientów).

### Ręczne podpięcie ProEla do DOWOLNEJ karty pary
Tylko odczyt; nie zapisuje nic w `proel_matches`, nie daje praw zapisu. Pierwszeństwo przed automatem. Prawo: `video`
(para, mentorzy, admin; panel włączony).

| Metoda i ścieżka | Body / query | Odpowiedź | Błędy |
|---|---|---|---|
| `GET /mentor-panel/pairs/{pair_id}/proel/search?q=&number=&team=&date=&kind=all&limit=20` | `date=RRRR-MM-DD` (dzień polski); `kind=all\|official\|training`; `limit` 1-30 | `{results:[{key, kind, official, number, status, home, away, date, score_home, score_away, events, zprp_match_id, promoted_to, updated_at}], count, limit}` | 403 `NO_ACCESS`/`PANEL_DISABLED`, 422 (data) |
| `GET .../matches/{match_id}/proel-link` | - | `{link: null\|{key, kind, number, linked_by, linked_by_name, linked_at, manual:true, resolved_key, preview:{...jak wynik wyszukiwania}}, match_id}` | 404 `MATCH_NOT_FOUND` |
| `PUT .../matches/{match_id}/proel-link` | `{proel_key}` (PEŁNY klucz z wyniku wyszukiwania) | `{ok, via:"pair", match_id, link, rev}`; dla karty `tr_` `{ok, via:"trybuna", result}` (deleguje do `PUT .../trybuna/matches/{id}/links`) | 404 `PROEL_NOT_FOUND`, 403 `PROEL_SCOPE` |
| `DELETE .../matches/{match_id}/proel-link` | - | `{ok, via, match_id, link:null, rev}`; karta wraca do automatu | |

- **Zakres:** mecz oficjalny - dowolny. Szkoleniowy (`T-XXXXXXXX/NUMER`) - tylko taki, który napisał (`doc_writer_judge`) któryś
  z sędziów TEJ pary (własny lub partnera). Egzekwowane przy wyszukiwaniu, przy podpinaniu i przy odczycie osi.
- **Klucz:** numer meczu nie jest kluczem między sezonami, więc podpięcie idzie po pełnym kluczu; podgląd niesie datę i drużyny.
  Wyszukiwanie: wartości jako parametry SQL, `%` i `_` nie działają jak wieloznaczniki; data szuka okna +-1 dzień w UTC i
  rozstrzyga dokładnie po dniu polskim.
- **Karta pary dostaje:** `has_proel:true` oraz `proel_link: {key, kind, number, linked_by, linked_at, manual:true}|null`.
- **Oś czasu (`GET .../matches/{id}` -> `timeline`):** kolejność źródeł: ręczne podpięcie > `proel_key` meczu wspólnego/Trybuny >
  automat (ID ZPRP + numer meczu). Podpięty klucz jest zaufany (zgodność IdZawody nie jest sprawdzana - to świadomy wybór).
  Klucz szkoleniowy z `promoted_to` jest rozwiązywany do oficjalnego. Zdarzenia: bez serii rzutów karnych.
- **Trybuna** (`tr_`) działa jak dotąd; podpięcie z panelu przechodzi przez tę samą logikę (`put_links`).
- `GET /proel/` i `GET /proel/{numer}` nie są zawężone.

## C. Wdrożenie (kolejność)
1. Railway: deploy backendu (nowe tabele powstają przez `metadata.create_all` przy starcie - bez migracji ręcznej; żadnej kolumny
   w istniejącej tabeli nie dodano).
2. Dopiero potem build aplikacji i BAZA_web (stary backend nie zna tras `/shared-matches`).
3. Nowy klucz preferencji `sharedMatch` - aplikacja dopisuje przełącznik w ustawieniach powiadomień (do tego czasu zgoda domyślna).

- Karta w panelu pary po powiązaniu z ZPRP: ten sam mecz nie jest dwiema kartami. Główna jest karta ZPRP; gdy dane pary (flagi,
  klipy, wątki, wgrane, oceny, nagrania, podpięcie ProEla) wiszą pod `my:<id>`, a pod numerem ZPRP ich nie ma, główną zostaje karta `my:`.
  Gdy dane są po obu stronach, zostają obie karty (nic nie jest scalane na siłę). `GET .../matches/my:<id>` działa dalej też po scaleniu.

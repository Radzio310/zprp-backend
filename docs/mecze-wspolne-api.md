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
**match**: `id, card_id, creator_id, creator_name, rev, code, competition, home_name, away_name, match_at, date_key, hall, city, match_kind, age_group,
zprp_match_id, proel_key, key_stem, result, extra, local_id (tylko twórca), created_at, updated_at, updated_by, updated_by_name`.
`result` = `null` albo `{score_home, score_away, half_home, half_away, by, by_name, at}` (kto i kiedy wpisał).
**crew[]**: `{id (member_id), judge_id|null, manual (true = wpis ręczny bez konta, bez dostępu), name, photo_url, role, role_label, added_by, added_at}`.
**my**: `{member_id, role, hidden, hidden_at, counts_in_stats, kind_stats_applied, added_by, added_by_name}` (tylko własny stan; cudzych ukryć/flag nie widać).
**detail** (odpowiedź szczegółu i większości zapisów): `{match, crew[], my, can:{edit,delete,remove_members,hide}, log[], rev}`.
`log[]`: `{id, rev, actor_id, actor_name, at, action, changes:[{field,from,to}]}`, najnowsze pierwsze (do 60).
Akcje dziennika: `create, edit, result, result_clear, crew_add, crew_edit, crew_remove, join, zprp_link, proel_link, lineup, delete`.

### Trasy

| Metoda i ścieżka | Body / query | Odpowiedź | Błędy |
|---|---|---|---|
| `GET /shared-matches?include_hidden=false&limit=300` | - | `{matches:[{match,crew,my}], count, hidden_count}` (bez usuniętych; ukryte tylko z `include_hidden=true`) | 401 |
| `GET /shared-matches/{id}` | - | detail | 404 `MATCH_NOT_FOUND`, 410 `MATCH_DELETED` (członek, mecz usunięty) |
| `POST /shared-matches` | `CreateBody` (niżej) | `{ok, existing, skipped[], ...detail}`; przy idempotentnym trafieniu `existing:true`; gdy lokalny mecz był już usunięty przez twórcę: `{ok, existing:true, deleted:true, id}` | 409 `DUPLICATE_MATCH`, 422 `VALIDATION`/`NOT_APP_USER`/`MANUAL_NAME_REQUIRED` |
| `PUT /shared-matches/{id}` | `{base_rev, code?, competition?, home_name?, away_name?, match_at?, hall?, city?, match_kind?, age_group?, extra?}` (tylko wysłane pola) | `{ok, unchanged, ...detail}` | 409 `REV_CONFLICT`, 422 `BASE_REV_REQUIRED`, 404 |
| `DELETE /shared-matches/{id}?base_rev=` | `base_rev` opcjonalny | `{ok, deleted:true}`; reszta obsady dostaje push i przy następnym odczycie 410 | 403 `CREATOR_ONLY`, 409 (gdy podano `base_rev`) |
| `PUT /shared-matches/{id}/result` | `{base_rev, score_home, score_away, half_home?, half_away?}` albo `{base_rev, clear:true}` | `{ok, unchanged, ...detail}` (`match.result.by/at`) | 409, 422 (oba wyniki wymagane, 0-199) |
| `POST /shared-matches/{id}/crew` | `{base_rev, add:[{judge_id? , name?, role}]}` | `{ok, unchanged, skipped[], ...detail}`; `skipped[]`: `{judge_id, reason: ALREADY_MEMBER\|BLOCKED}` | 409 `ADD_BLOCKED` (gdy nikogo nie dodano z powodu blokady), 422 `NOT_APP_USER` (`judge_ids[]`), 422 `MANUAL_NAME_REQUIRED`, 409 `REV_CONFLICT` |
| `PUT /shared-matches/{id}/crew/{member_id}` | `{base_rev, role?, name?}` | `{ok, unchanged, ...detail}` | 403 `NOT_ALLOWED`, 404 `MEMBER_NOT_FOUND`, 409 |
| `DELETE /shared-matches/{id}/crew/{member_id}?base_rev=` | `base_rev` wymagany | `{ok, ...detail}`; usunięty sędzia z aplikacji dostaje push | 403 `CREATOR_ONLY` (nie-twórca), 403 `CREATOR_STAYS` (twórca nie usunie siebie), 409 |
| `POST /shared-matches/{id}/hide` | `{block_adder?: bool}` (body opcjonalne) | `{ok, hidden:true, blocked_via: judge_id\|null}`. `block_adder` = „nie dodawaj mnie więcej przez tę osobę" (osoba z `my.added_by`) | 404 |
| `POST /shared-matches/{id}/restore` | - | `{ok, hidden:false}` | 404 |
| `PUT /shared-matches/{id}/stats` | `{counts_in_stats: bool}` | `{ok, counts_in_stats}` (per członek, domyślnie false, `rev` bez zmian) | 404 |
| `PUT /shared-matches/{id}/lineup` | `{base_rev, lineup}`; `lineup:null` kasuje skład (kształt w sekcji Wczytaj składy) | `{ok, unchanged, ...detail}` (`match.extra.lineup`) | 404 (obcy), 409 `REV_CONFLICT`, 422 `BASE_REV_REQUIRED` albo `VALIDATION` |
| `PUT /shared-matches/{id}/zprp` | `{base_rev, zprp_match_id: "123456"\|null}` | `{ok, unchanged, ...detail}` | 422 (tylko liczbowe IdZawody), 409 |
| `PUT /shared-matches/{id}/proel` | `{base_rev, proel_key: "OSK/12"\|"M-XXXXXXXX/EHF/1"\|"T-XXXXXXXX/NUM"\|null}` | `{ok, unchanged, ...detail}`. Wołać automatycznie, gdy ktoś prowadzi ProEla z meczu wspólnego. To wskaźnik: nic nie zapisuje w `proel_matches`. | 403 `PROEL_SCOPE` (cudze szkolenie), 422 `PROEL_KEY_FOREIGN` (klucz `M-` z cudzą tuleją), 409 |
| `POST /shared-matches/join` | `{match_id, role, home_name, away_name, match_at}` | `{ok, joined, already_member, ...detail}`. Dozwolone tylko dla duplikatu (serwer porównuje drużyny+datę; samo `zprp_match_id` NIE wystarcza). `role` jest wymagana; zajęta rola sędziowska (sędzia 1/2) nie jest przejmowana. Twórca dostaje push `joined` i może usunąć dołączonego z obsady. Ukryty członek dostaje przywrócenie | 403 `NOT_A_DUPLICATE`, 404, 409 `ROLE_TAKEN`, 422 `ROLE_REQUIRED` |
| `GET /shared-matches/blocks` | - | `{blocks:[{via_judge_id, via_name, created_at}]}` | |
| `DELETE /shared-matches/blocks/{via_judge_id}` | - | `{ok}` | |
| `GET /shared-matches/users/search?q=&limit=10` | `q` min. 2 znaki: imię/nazwisko (tokeny AND, bez wieloznaczników) albo dokładny numer sędziego | `{users:[{judge_id,name,photo_url,province}]}` - tylko konta z aplikacji (`login_records`), bez siebie. `photo_url` jak w obsadzie: z konta, a gdy puste, z listy sędziów okręgu. Limit 60 zapytań/min na konto (pamięć procesu) | 429 `RATE_LIMITED` |
| `GET /shared-matches/users/suggestions?limit=8` | - | `{suggestions:[{judge_id,name,photo_url,reason: partner\|frequent\|recent, reasons[], shared_count}]}` | |

**CreateBody:** `{local_id?, code?, competition?, home_name?, away_name?, match_at?, hall?, city?, match_kind?, age_group?, zprp_match_id?, proel_key?,
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

### Rodzaj meczu (02.11.2026)
`match_kind`: `miedzypanstwowy` | `miedzynarodowy` | `zwykly` (świadome „Nie traktuj tak tego meczu") | `null` (nikt nie rozstrzygnął).
`age_group`: `seniorzy` | `mlodziez` | `null`. Oba pola są treścią meczu: wspólne dla obsady, zapis z `base_rev`, wchodzą do dziennika.
Inna wartość = 422 `VALIDATION`. Serwer niczego nie wnioskuje z nazw drużyn; sugestię liczy aplikacja.

Statystyki: oznaczenie meczu jako międzypaństwowy albo międzynarodowy włącza `counts_in_stats` każdemu członkowi RAZ
(`kind_stats_applied`). Później dodany członek też dostaje włączone. `PUT .../stats` stawia ten znacznik, więc ręczne wyłączenie
zostaje przy ponownym oznaczeniu. Odznaczenie nie włącza i nie wyłącza. Twórca przy `POST` decyduje sam przez `counts_in_stats`.

Łączenie rozliczenia w serię jest osobiste i serwer go nie zna (magazyn na telefonie).

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
1. Railway: kolumny match_kind, age_group, kind_stats_applied dokłada blok ALTER w app/db.py, a stawki ensure_intl_categories przy starcie. Deploy backendu (nowe tabele powstają przez `metadata.create_all` przy starcie; kolumna `shared_matches.proel_stem`
   w istniejącej już tabeli dochodzi linią `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` w bloku migracji na końcu `app/db.py`).
2. Dopiero potem build aplikacji i BAZA_web (stary backend nie zna tras `/shared-matches`).
3. Nowy klucz preferencji `sharedMatch` - aplikacja dopisuje przełącznik w ustawieniach powiadomień (do tego czasu zgoda domyślna).

- Karta w panelu pary po powiązaniu z ZPRP: ten sam mecz nie jest dwiema kartami. Główna jest karta ZPRP; gdy dane pary (flagi,
  klipy, wątki, wgrane, oceny, nagrania, podpięcie ProEla) wiszą pod `my:<id>`, a pod numerem ZPRP ich nie ma, główną zostaje karta `my:`.
  Gdy dane są po obu stronach, zostają obie karty (nic nie jest scalane na siłę). `GET .../matches/my:<id>` działa dalej też po scaleniu.

## Wczytaj składy (02.11.2026)

Kod: `app/lineup_read.py` (trasy), `app/lineup_read_rules.py` (normalizacja, walidacja, limity), `app/lineup_pdf_parse.py` (PDF z tekstem),
`app/lineup_vision.py` (zdjęcie/skan przez OpenAI), `app/lineup_read_quota.py` + tabela `lineup_read_usage` (licznik dobowy). Decyzje:
pamięć `wczytaj-sklady-decyzje`. Klauzula RODO v5 (OpenAI, dane osób trzecich, plik niezapisywany).

**Zasady:** zalogowany sędzia (JWT aplikacji, `base_actor`), nie admin. Plik żyje wyłącznie w pamięci serwera (nie jest zapisywany,
w logach są same liczby, bez nazwisk i treści). Sam odczyt NICZEGO nie zapisuje, nie łączy z ZPRP i nie dopisuje sędziów: aplikacja
pokazuje ekran zatwierdzenia, a dopiero potem woła `PUT /shared-matches/{id}/lineup`. Nieczytelne pole = `null`, nigdy zgadywanie.

### `POST /matches/lineup/read` (multipart, pole `files`, 1-4 plików)
- Typ po pierwszych bajtach (nagłówek klienta i rozszerzenie są ignorowane): PDF, JPEG, PNG. HEIC jest rozpoznawany i odrzucany
  jasnym kodem `HEIC_UNSUPPORTED` (Pillow w backendzie nie czyta HEIC: aplikacja ma wysłać JPEG, skaner dokumentów daje JPEG).
- Limity: obraz 12 MB, PDF 16 MB, razem najwyżej 4 strony (zdjęcie = 1 strona, PDF liczy strony). Walidacja całego żądania idzie
  PRZED zużyciem limitu dobowego.
- PDF z warstwą tekstową (>= 400 znaków na stronę): parser regułami PyMuPDF, bez AI. Zdjęcie albo skan bez tekstu: model z wizją
  (domyślnie `gpt-4o`, env `OPENAI_LINEUP_MODEL`, klucz `OPENAI_API_KEY`), JSON schema strict, temperature 0, wszystkie strony w jednym
  zapytaniu, obraz zmniejszony do 2000 px i bez EXIF. PDF z tekstem, ale bez tabel "A (nazwa)" i "B (nazwa)", też próbuje wizji.
- Limity dobowe na konto (dzień polski, trwałe w bazie): **20 odczytów AI**, **300 odczytów PDF-ów z tekstem** (bezpiecznik). Błąd
  dostawcy (5xx) oddaje miejsce w limicie; `NOT_A_PROTOCOL` go nie oddaje.

**Odpowiedź 200:**
```json
{"ok": true, "source": "pdf_text|vision|mixed", "pages": 1,
 "header": {"match_number": "JmK/7", "zprp_match_id": "207457"|null, "home_name": "...", "away_name": "...", "date": "2026-10-31",
            "time": "18:00", "hall": "...", "address": "...",
            "competition": {"stage": ["I LIGA"], "sex": "M", "age": ["SENIORZY"]}|null},
 "home": {"name": "...", "players": [{"number": 7|null, "clashed_number": 7?, "name": "NAZWISKO Imię"|null, "surname": "...", "given": "...",
                                      "confidence": 0.98, "checked": true|false|null, "source": "pdf_text|vision"}],
          "staff": [{"slot": "A".."E"|null, "name": "NAZWISKO Imię", "surname": "...", "given": "...", "function": "TRENER B"|null,
                     "license": "B 0544/2026"|null, "license_category": "B"|null, "license_number": "0544/2026"|null,
                     "confidence": 0.95, "source": "..."}]},
 "away": {"...": "jak home"},
 "officials": [{"role": "sedzia1|sedzia2|czas|sekretarz|delegat", "name": "NAZWISKO Imię"}],
 "warnings": [{"code": "DUPLICATE_NUMBER", "team": "home", "number": 7, "rows": [0, 3]}],
 "unreadable": [{"team": "home", "kind": "player|staff", "index": 2, "field": "number|name|function"}],
 "checks_detectable": true|null, "low_confidence_count": 3,
 "quota": {"ai_used": 4, "ai_limit": 20}|null}
```
Kody ostrzeżeń: `DUPLICATE_NUMBER`, `DUPLICATE_PLAYER`, `EMPTY_TEAM`, `TOO_MANY_ROWS`.

- `home` = tabela z nagłówkiem "A (nazwa)", `away` = "B (nazwa)", niezależnie od położenia (wiązanie po nagłówku, nie po pozycji).
- `confidence` 0-1 dla CAŁEGO wiersza; poniżej 0.7 aplikacja oznacza wiersz jako niepewny. PDF z tekstem daje 0.98/0.95, zdjęcie: ocena
  modelu (przy braku numeru lub nazwiska maks. 0.4, przy niejednoznacznym nazwisku maks. 0.6). Zdjęcie krzywe albo z odręcznymi
  dopiskami: bez gwarancji, ale pewność wiersza jest uczciwa.
- **Numer 1-99.** Powtórzony w składzie: pierwszy zostaje, kolejny dostaje `number: null` i `clashed_number` (aplikacja mapuje to na
  `number: 0` + `clashedNumber`, jak `rosterToCards`) oraz ostrzeżenie `DUPLICATE_NUMBER`. `unreadable` nie wymienia numeru zdjętego
  przez duplikat (jest wyjaśniony ostrzeżeniem).
- **Nazwisko:** `NAZWISKO Imię`, nazwisko wielkimi literami i w całości (`VAN DER BERG`, `NOWAK-KOWALSKA`); kolejność "Imię NAZWISKO"
  jest odwracana. Nazwa z cyfrą, znakami specjalnymi, polecenie z obrazu itp. daje `null` (whitelista znaków) i nie przechodzi dalej.
- **Osoby A-E:** litera slotu (przyklejona w PDF-ie: "A.NAZWISKO") NIE jest częścią nazwiska. `function` osobno (`TRENER B`,
  `OSOBA TOWARZYSZĄCA`), `license` w formacie `NNNN/RR` lub `NNNN/RRRR` z opcjonalnym prefiksem kategorii (`B 0544/2026`, `0404/18`).
- **`checked`** (zielony ptaszek przy zawodniku, osobne oznaczenie "z protokołu", NIE badania ZPRP/WZPR): w PDF-ie to mały obrazek
  w wierszu na lewo od numeru; zielony = `true`, czerwony = `false`, wiersz bez znaczka gdy na stronie są znaczki innych = `false`.
  Gdy na stronie nie ma żadnego znacznika (inny szablon), `checked` jest `null` i `checks_detectable: null` (nie twierdzimy, że nikt
  nie ma ptaszka). Ze zdjęcia `checked` to ocena modelu (`true`/`false`/`null`), nie pewnik.
- **`header.competition`** (kratki "x": rozgrywki, płeć, kategoria wieku): tylko z PDF-a z tekstem, gdzie "x" to znak tekstu stojący
  przed etykietą; ze zdjęcia i gdy nic nie wykryto: `null`.
- **`zprp_match_id`** tylko gdy same cyfry (`IdZawody:`); "JmK/7" to numer meczu (`match_number`, wielkość liter jak wydrukowano, to
  nie klucz). `officials` i dane meczu to podpowiedź: nic nie wpisuje się samo, a dane meczu aplikacja wstawia tylko do pustych pól.

**Błędy** (koperta `{"error":..., "code":..., "message":...}`, klient czyta jak `serverMessage()`):
`NO_FILE`, `EMPTY_FILE`, `TOO_MANY_FILES`, `TOO_MANY_PAGES`, `PDF_UNREADABLE`, `PDF_ENCRYPTED`, `IMAGE_UNREADABLE`, `IMAGE_TOO_LARGE` 422;
`UNSUPPORTED_TYPE`, `HEIC_UNSUPPORTED` 415; `FILE_TOO_LARGE` 413; `NOT_A_PROTOCOL` 422 (plik nie jest protokołem ZPRP, np. krajobraz);
`AI_LIMIT_REACHED` 429 (`limit`, `used`) i `READ_LIMIT_REACHED` 429; `AI_NOT_CONFIGURED` 503 (brak klucza OpenAI, PDF z tekstem nadal
działa); `AI_FAILED`, `AI_BAD_RESPONSE`, `AI_TRUNCATED` 502 (bez treści błędu dostawcy).

### `GET /matches/lineup/zprp-check?zprp_match_id=&home_name=&away_name=&date=RRRR-MM-DD`
Czy mecz o tym IdZawody istnieje w ZPRP i czy drużyny oraz data zgadzają się z meczem ręcznym. Źródła: `zprp_public_matches`, a gdy
brak, `province_matches` (nazwy ze `state_json`). Odpowiedź: `{found, verdict: match|swapped|mismatch|not_found, home_ok, away_ok,
date_ok, swapped, match: {zprp_match_id, home_name, away_name, date, time, competition, match_code}}`. `swapped` = gospodarz i gość
zamienieni. Drużyny porównywane bez wielkości liter, ogonków i interpunkcji (drugi zespół klubu, "... II", to nie ten sam zespół).
**Nic nie łączy**: po decyzji użytkownika aplikacja woła istniejące `PUT /shared-matches/{id}/zprp`. 422 `VALIDATION` dla nie-liczbowego id.

### `PUT /shared-matches/{id}/lineup` - zapis składu we wspólnym meczu
Body `{base_rev, lineup}`; `lineup` = obiekt jak niżej albo `null` (kasuje). Zapis w `match.extra.lineup`, reszta `extra` zostaje.
```json
{"home": {"name": "...", "players": [{"number": 7|null, "name": "NAZWISKO Imię"|null, "checked": true, "confidence": 0.9}],
          "staff": [{"slot": "A", "name": "NAZWISKO Imię", "function": "TRENER B"|null, "license": "B 0544/2026"|null}]},
 "away": {"...": "jak home"}, "source": "pdf_text", "read_at": "2026-11-02"}
```
(`checked`, `confidence`, `source`, `read_at` opcjonalne.)
- Każdy członek meczu (twórca też); obcy dostaje `404 MATCH_NOT_FOUND`, jak przy każdej trasie meczu. Wymaga `base_rev` (`422
  BASE_REV_REQUIRED`, `409 REV_CONFLICT` z `current`), rośnie `rev`, `unchanged:true` przy identycznym składzie.
- Walidacja ta sama co przy odczycie (numer 1-99 albo null, nazwisko whitelistą znaków, licencja wzorcem, do 30 zawodników i 5 osób na
  drużynę): zły kształt daje `422 VALIDATION`. Ten sam kontroler stoi na ogólnym `PUT /shared-matches/{id}` z `extra.lineup`.
- Rozmiar: skład 2x16 zawodników + 10 osób to ok. 5 kB (limit składu 12 kB w ramach limitu `extra` 20 kB).
- Dziennik: akcja `lineup`, `changes:[{field:"lineup", from, to}]` z SAMYMI LICZBAMI ("16+16 zawodników, 10 os."), bez nazwisk.
  Push nie jest wysyłany (a gdyby kiedyś był: bez nazwisk).
- Skład widzą wyłącznie członkowie: jest w `match.extra` tylko w `GET /shared-matches` i `GET /shared-matches/{id}` (oba za członkostwem).
  Nie ma go w odpowiedzi `409 DUPLICATE_MATCH`, w kartach panelu pary ani w danych publicznych ZPRP.
- "Powtórz mecz" kopiuje `extra` razem ze składem (decyzja: domyślnie przepisuje).

### Wdrożenie
1. Railway: nowa tabela `lineup_read_usage` powstaje przez `metadata.create_all` przy starcie (bez ALTER). `OPENAI_API_KEY` już jest
   (faktury, narzędzie admina); opcjonalnie `OPENAI_LINEUP_MODEL`.
2. Deploy backendu, dopiero potem build aplikacji z klauzulą v5 i funkcją "Wczytaj składy" (stary backend nie zna tras).
3. Przed buildem właściciel akceptuje tekst klauzuli v5 (`BAZA/utils/privacyConsent.ts`, `CLAUSE_CHANGES[5]`).

## Powtórz mecz

Nie ma osobnej trasy. Aplikacja otwiera kreator z danymi meczu (następny numer serii i termin to sugestie), a kopia idzie zwykłym `POST /shared-matches`, więc ma tę samą ochronę przed duplikatem i ten sam zapis obsady. Wynik i powiązania ZPRP/ProEl się nie kopiują.

## Klucz protokołu ProEla meczu ręcznego (`M-`)

Numer meczu ręcznego ("EHF/1") wpisują sędziowie sami, więc dwa różne mecze o tym numerze trafiały w jeden wiersz
`proel_matches`. Protokół meczu ręcznego leży pod kluczem `M-<TULEJA>/<NUMER>` (np. `M-KDL2W2JS/EHF/1`, całość wielkimi literami).
Mecz POZOSTAJE oficjalny (nie jest `T-`, nie znika z listy oficjalnych), a ekrany pokazują sam numer.

- **Tuleja (8 znaków)** jest jedna na mecz wspólny i ta sama u całej obsady: serwer zapisuje ją przy tworzeniu meczu
  (`shared_matches.proel_stem`) i oddaje w `match.key_stem` oraz na karcie pary (`key_stem`). Liczy się ze skrótu
  `(creator_id, local_id)` (`app/proel_match_key.py:stem_from_local`, w aplikacji `utils/sharedProelKey.ts`; wektory testowe po obu
  stronach), a bez `local_id` z początku id serwera. Dzięki temu telefon twórcy zna klucz ZANIM mecz dotrze na serwer (start offline).
  Wiersz sprzed kolumny (pusta) ma tuleję = pierwsze 8 znaków id (`stem_of_row`).
- **Pierwszeństwo klucza już użytego:** wskaźnik `proel_key` (serwer) i `shared_proel_want` (telefon) wygrywają z wyliczeniem;
  to także goły numer sprzed zmiany. Protokoły zapisane pod gołym numerem zostają tam, gdzie są.
- **Mecz połączony z prawdziwym IdZawody** (i bez użytego klucza) leży pod numerem jak każdy mecz z rozgrywek.
- **Prywatność:** wiersz `M-` bez numerycznego `zprp_match_id` nie wchodzi do publicznych zestawień (live, statystyki ZPRP;
  `public_rows_clause`), a wyszukiwarka panelu pary pokazuje go tylko temu, kto go zapisał (jak `T-`).
- **ZPRP:** backend nie wysyła niczego do ZPRP z `proel_matches`; aplikacja nie pisze do ZPRP z meczu `M-` bez IdZawody
  (`mayWriteToZprp`).
- **Oś czasu w panelu:** gdy wskaźnik jeszcze nie dotarł z telefonu, serwer sam składa `M-<key_stem>/<match_code>` i używa go,
  jeśli taki protokół istnieje.

## Wiązanie nazwisk z kontami (`app/shared_match_link.py`)

Mecz zmigrowany ze starego `myMatches.json` niesie obsadę jako same nazwiska, więc drugi sędzia jest wpisem ręcznym
(`judge_id = NULL`) i nie widzi meczu, a panel Mentor go pomija (karta `my:` wymaga OBU sędziów jako kont). Serwer wiąże taki wpis
z kontem aplikacji (`login_records`) sam, ale tylko przy dokładnym, jednoznacznym dopasowaniu:

- imię i nazwisko po normalizacji (`person_name_key`: polskie znaki, wielkość liter, dowolna kolejność członów; inicjał i Jr/Sr
  rozróżniają), co najmniej dwa człony,
- dokładnie JEDNO konto z takim kluczem (dwa konta o tym nazwisku = bez wiązania),
- konto nie jest już w obsadzie tego meczu i nie ma blokady „nie dodawaj mnie przez tę osobę" względem autora wpisu.

Wiązanie jest idempotentne (UPDATE warunkowy `judge_id IS NULL`, wyścig wygrywa pierwsze wywołanie) i nigdy nie psuje odczytu
(błąd tylko do logu). Skutek to zwykła zmiana obsady: `rev` rośnie, wpis `crew_edit` w dzienniku (`actor_id` pusty), odświeżenie
paneli par i push „Dodano Cię do meczu" (z wyjątkiem osoby, która wywołała odczyt). Wołane przy: tworzeniu meczu, dodaniu i edycji
wpisu ręcznego, odczycie listy i szczegółów przez członka (`link_matches`), wejściu konta do aplikacji (`link_for_account`, odwrotny
kierunek) oraz budowie kart pary (`repair_pair`). Gdy nazwisko nie pasuje (inna pisownia, dwa konta), aplikacja pokazuje
wskazówkę „Wybierz X z listy" (`SharedCrewLinkHint`) i otwiera wybór osoby dla tej roli.


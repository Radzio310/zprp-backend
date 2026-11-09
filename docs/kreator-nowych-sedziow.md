# Kreator nowych sędziów na baza.zprp.pl (09.11.2026)

Panel okręgowy BAZA_web → **Lista sędziów okręgowych** → kafel „Dodaj nowego sędziego na baza.zprp.pl”.
Kreator zakłada osoby na baza.zprp.pl formularzem `?a=sedzia&b=dodaj` (jak przycisk NOWY w zakładce
„Sędziowie i Delegaci”) – ręcznie albo grupowo z pliku – i składa mail do ZPRP z prośbą o konta do logowania.

Kod: `app/referee_onboarding.py` (trasy), `app/referee_onboarding_rules.py` (reguły, test
`tests/test_referee_onboarding_rules.py`), `app/referee_onboarding_excel.py` (pliki),
`app/referee_onboarding_tables.py` (historia). Front: `BAZA_web/components/referee-onboarding/`.

## Dostęp

Wszystkie trasy: JWT + uprawnienie panelu `province_judges` dla okręgu z żądania
(`panel_read_gate`, jak zapis w rejestrze sędziów). Trasy rozmawiające z ZPRP dostają dodatkowo
zaszyfrowany RSA login i hasło do baza.zprp.pl (`username`, `password`, jak `/zprp/sedziowie/*`).
Osoby zakłada konto ZPRP użytkownika – musi mieć opcję NOWY (sprawdza `/probe`); województwo
bierze ZPRP z konta (ukryte pole `woj`).

## Trasy (`/province_referees/onboarding`)

| Trasa | Wejście | Wyjście |
|---|---|---|
| `POST /probe` | `{province, username, password}` | `{can_create, new_button, reason, woj_code, woj_name, known_people}` |
| `POST /parse?province=` | multipart `file` (.xlsx/.xlsm/.xls/.csv/.tsv) | `{file_name, kind, sheets:[{name, hidden, rows:[{row, hidden, cells[]}], hidden_rows, hidden_columns, truncated}]}` |
| `POST /check` | `{province, username, password, people:[{key, first_name, last_name, birth_date, …}]}` | `{results:{key:{status, blocking, matches:[{nr, relation, name, birth_date, source}]}}}` |
| `POST /create` | `{province, username, password, person, force, source, batch_id}` | `{status, nr, message, duplicate?, errors?, record?}` |
| `GET /history?province=` | – | `{items:[record]}` |
| `POST /history/mailed` | `{province, ids}` | `{ok}` |
| `POST /history/remove` | `{province, ids}` | `{ok}` – usuwa tylko z historii BAZY, nie z ZPRP |

`/parse` oddaje surowe komórki (daty `RRRR-MM-DD`, liczby całkowite bez `.0`) i znacznik `hidden`
(wiersz ukryty, zwinięty lub odfiltrowany). Rozpoznanie kolumn, normalizacja i walidacja są w kreatorze.

`status` duplikatu: `exact` (imię, nazwisko i data urodzenia), `probable` (imię i nazwisko, daty nie
odczytano) – oba **blokują** (`blocking`), kreator pozwala świadomie wymusić (`force`); `namesake`
(inna data urodzenia) i `similar` (literówka, zamiana imienia z nazwiskiem, człon nazwiska) tylko
ostrzegają. Źródła: lista z selecta „Dwójka sędziowska z” na stronie dodawania, rejestr okręgu
BAZY (`province_judges`, `province_settlement_judges`), data urodzenia z karty edycji ZPRP.

`status` zapisu: `created` (z `nr`), `unconfirmed` (ZPRP przyjął formularz, ale nie pokazał numeru –
wpis trafia do historii do sprawdzenia), `error` (formularz wrócił z danymi, `message` z ZPRP),
`duplicate` (drugie sprawdzenie tuż przed zapisem), `invalid` (pola wymagane / znaki spoza iso-8859-2).
`/create` zakłada **jedną** osobę – kreator woła ją po kolei, żeby pokazywać postęp na żywo.

## Dane

Tabela `province_referee_onboarding`: okręg, `nr_sedzia`, status, imię, nazwisko, płeć, rok urodzenia,
miasto, email, role, źródło, `batch_id`, kto i kiedy założył, kiedy oznaczono mail. Bez PESEL-u
(służy tylko walidacji w przeglądarce), adresu i telefonu.

## Decyzje właściciela (09.11.2026)

- Para sędziowska nie jest wskazywana przy zakładaniu; domyślna rola: Sędzia.
- Ukryte wiersze pliku domyślnie pomijane, kreator pyta, czy je wziąć.
- Duplikat w ZPRP blokuje z ręcznym obejściem.
- PESEL tylko do walidacji, nigdzie nie zapisywany ani nie wysyłany w mailu.
- Historia wspólna dla okręgu; adres maila do ZPRP wpisywany i pamiętany w przeglądarce.

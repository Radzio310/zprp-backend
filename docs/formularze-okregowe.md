# Formularze okręgowe — kontrakt (źródło prawdy)

Wspólny kontrakt dla trzech repozytoriów:

- `zprp-backend` (serwer, ten plik),
- `BAZA` (aplikacja: panel okręgowy → „Więcej” → kafelek **Formularze**),
- `BAZA_web` (strona `https://www.bazapodreka.app/f/<kod>`).

Zmiana kształtu pola wymaga zmiany TEGO pliku i wszystkich trzech stron.

## 1. Idea

Jeden silnik i dwa rodzaje formularza (`kind`):

| kind | Co to jest | Przykład |
|---|---|---|
| `list` | **Lista deklaracji.** Wiersze to sędziowie z listy, kolumny ustawia twórca. | Wigilia sędziowska: Będę/Nie będę, Wpłata (sędzia zgłasza, komisja potwierdza), Menu |
| `form` | **Formularz** jak w Communio: sekcje, pytania, logika „przejdź do sekcji”. | Ankieta po szkoleniu, zgłoszenie na turniej |

Formularz jest niezależny. Można go **spiąć z wydarzeniem okręgowym** (`event_id`). Wtedy kolumna statusu formularza **zastępuje RSVP wydarzenia** (szczegóły w §8).

## 2. Role (trzy kręgi + zarządzający)

Każdy krąg opisuje obiekt `Target`, ten sam co w wydarzeniach (`province_event_rules.invited_ids`):

```ts
type Target = {
  include_all?: boolean;
  include_badges?: string[];   // nazwy badży okręgowych
  exclude_badges?: string[];
  include_ids?: string[];      // judge_id dopisani ręcznie
  exclude_ids?: string[];      // judge_id wykluczeni ręcznie
};
type Audience = {
  participants: Target & { open?: boolean }; // „na liście” — deklarują i odpowiadają
  observers: Target;                         // widzą listę i wyniki (bez edycji)
  managers: Target;                          // zarządzają (domyślnie badż „Komisja sędziowska”)
};
```

- **Zarządzający:**
  - autor formularza zawsze;
  - admin aplikacji (`is_admin`) zawsze;
  - komisja sędziowska okręgu zawsze (ta sama reguła co `can_manage` w wydarzeniach);
  - do tego osoby z `audience.managers`.
- **Tworzyć formularze** mogą: admin oraz komisja okręgu (`can_manage(who, province)`).
- `participants.open = true` jest dozwolone tylko dla `kind = "form"` przy włączonym webie. Na webie odpowiada wtedy każdy z linkiem, wpisując imię i nazwisko (`guest_name`).
- Pustego `participants` (bez kryteriów) **nie** traktujemy jak „wszyscy”. Inaczej niż w starych wydarzeniach, edytor wymaga wyboru.
- Liczy się na żywo z `province_judges` okręgu, z tą samą listą nieaktywnych co wydarzenia.
- Kto nie jest uczestnikiem, obserwatorem ani zarządzającym, dostaje **404**: nie widzi nawet tytułu.

## 3. Model danych (serwer)

Tabele leżą w `app/district_forms_tables.py` (`define_tables(metadata)`, wzór: `exam_public_tables.py`). Brak Alembica: nowe kolumny dopisujemy przez `MIGRATIONS` jako `ALTER ... IF NOT EXISTS`.

### `district_forms`

| kolumna | typ | uwagi |
|---|---|---|
| id | str(16) PK | `secrets.token_hex(8)` |
| province | str | kanoniczny (`SLASKIE`) |
| kind | str | `list` \| `form` |
| title | str(160) | |
| description | text null | |
| cover_json | JSON null | `{tone:"gold"\|"red"\|"blue"\|"green"\|"violet"\|"slate", emoji?:string}` |
| schema_json | JSON | §4 (list) albo §5 (form) |
| settings_json | JSON | §6 |
| audience_json | JSON | `Audience` |
| event_id | int null | spięcie z `province_events.id` |
| web_enabled | bool | domyślnie **false** |
| web_code | str(8) unique null | alfabet bez 0/O/1/l/i (jak `exam_public_rules.CODE_ALPHABET`). Raz nadany zostaje. |
| created_by | str | judge_id |
| created_at, updated_at | timestamptz | |
| published_at | timestamptz null | NULL = szkic |
| closes_at | timestamptz null | termin |
| closed_at | timestamptz null | ręczne zamknięcie |
| archived_at, deleted_at | timestamptz null | kosz 30 dni |
| rev | int | rośnie przy każdej zmianie definicji. Klient wysyła `If-Match: <rev>`, przy niezgodności serwer odpowiada 409 `stale`. |

### `district_form_entries` (wiersz listy albo odpowiedź formularza)

| kolumna | typ | uwagi |
|---|---|---|
| id | int PK | |
| form_id | str FK | |
| judge_id | str null | NULL tylko dla gościa formularza otwartego |
| guest_name | str null | |
| cells_json | JSON | `kind=list`: `{[columnId]: Cell}` |
| answers_json | JSON | `kind=form`: `{[questionId]: any}` (kształt jak w Communio) |
| verified | bool | **true**, gdy właściciel zapisał w aplikacji albo na webie po logowaniu QR |
| self_source | str null | ostatnie źródło zapisu właściciela: `app` \| `web_qr` \| `web` |
| web_device | str null | `device_id` przeglądarki, która ostatnio zapisała anonimowo |
| web_at | timestamptz null | czas ostatniego anonimowego zapisu z weba |
| web_review | bool | true = wpis z weba czeka na potwierdzenie „To ja” w aplikacji |
| client_id | str null | idempotencja (unikalny w obrębie formularza) |
| fill_seconds | int null | |
| submitted_at, updated_at | timestamptz | |

Unikalność: (`form_id`, `judge_id`) dla wierszy sędziów.

```ts
type Cell = {
  v: any;                    // wartość (typ zależy od kolumny, §4)
  src: "app" | "web_qr" | "web" | "manager";
  by: string | null;         // judge_id autora zmiany (null = anonimowy web)
  at: string;                // ISO
};
```

### `district_form_log` (historia każdej zmiany komórki lub odpowiedzi)

`id, form_id, entry_id, owner_judge_id, column_id (null = cała odpowiedź formularza), old_json, new_json, actor_judge_id null, source, ip, user_agent, device_id, geo_json, created_at`

`geo_json` ma postać `{lat, lon, acc}`, `{denied:true}` albo null.

### `district_form_pairs` (logowanie QR na webie, wzór: `exam_web`)

`code (PK, 8 znaków), poll_token_hash, form_id, status (pending|approved|expired|used), judge_id null, created_at, expires_at (5 min), ip, user_agent`

### `district_form_notifications` (dziennik wysyłek, deduplikacja)

`form_id, judge_id, kind, slot, sent_at`. Unikalność na (`form_id`, `judge_id`, `kind`, `slot`).

- Wartości `kind`: `published`, `reminder`, `manual`, `web_review`, `deadline_today`.
- Zasada jak w wydarzeniach: najpierw wiersz w dzienniku, potem push.

### Pliki (pytanie typu `file` w `kind=form`)

Te same mechanizmy, z których korzystają plakaty i ilustracje wydarzeń.

## 4. Schemat listy (`kind = "list"`)

```ts
type ListSchema = { columns: Column[] };          // 1..20 kolumn
type Column = {
  id: string;                                      // stabilne, [a-z0-9_-]{1,24}
  type: "status" | "check" | "confirm" | "choice" | "number" | "text";
  title: string;                                   // ≤ 60
  hint?: string;                                   // ≤ 200, podpowiedź pod nagłówkiem
  editor: "self" | "managers" | "self_confirm";   // kto wpisuje; self_confirm tylko dla confirm
  visibility: "all" | "self" | "managers";        // kto widzi wartość innych (§7)
  required?: boolean;                              // liczy się do „wypełnione”
  lock_after_deadline?: boolean;                   // domyślnie true; dla confirm domyślnie false
  options?: Option[];                              // status (2..5), choice (2..20)
  multi?: boolean;                                 // choice
  amount?: number | null;                          // confirm: kwota w zł (np. 80)
  min?: number; max?: number; integer?: boolean;   // number
  max_length?: number;                             // text (≤ 500)
};
type Option = { id: string; label: string; tone?: "positive" | "negative" | "neutral" | "warning" };
```

Wartości `Cell.v` według typu kolumny:

| type | v | „brak” |
|---|---|---|
| status | `option.id` | `null` = **Brak głosu** (domyślnie) |
| check | `true` | `null`/`false` |
| confirm | `"declared"` (sędzia: „Zapłaciłem”) albo `"confirmed"` (zarządzający: „Otrzymano”) | `null` |
| choice | `option.id` albo `option.id[]` przy `multi` | `null` |
| number | number | `null` |
| text | string | `null` |

Zasady:

- **Kolumna `status`:** najwyżej jedna na liście. Domyślne opcje to `yes` „Będę” (positive) i `no` „Nie będę” (negative); można dodać np. `maybe` „Może” (warning).
- **Kolumna `confirm`** to maszyna stanów:
  - Sędzia (przy `editor = "self_confirm"`) może przejść `null ↔ declared`. Gdy wartość to `confirmed`, nie może jej zmienić (403 `confirmed_locked`).
  - Zarządzający może ustawić dowolny stan: `null`, `declared` albo `confirmed`.
  - Przy `editor = "managers"` kolumnę zmienia tylko zarządzający.
  - Przy `editor = "self"` sędzia sam przechodzi aż do `confirmed`. Stan pośredni jest wtedy zbędny, ale dozwolony.
- **Uprawnienia do kolumny:** `editor = "self"` oznacza, że wpisuje sędzia, a zarządzający też może poprawić. `editor = "managers"` oznacza, że wpisuje tylko zarządzający.
- **„Wypełnione” dla sędziego:** ma wartość w kolumnie `status`, jeśli taka istnieje. Bez kolumny statusu: w każdej kolumnie `required`, którą może edytować. Bez statusu i bez wymaganych kolumn sędziego: jakakolwiek wartość w kolumnie, którą może edytować. Tylko niewypełnieni dostają przypomnienia.

## 5. Schemat formularza (`kind = "form"`)

Port 1:1 z `Communio_serwer/app/form_schemas.py` + `app/forms.py`:

- sekcje i pytania, logika `next`/`logic` tylko w przód;
- typy pytań: `short_text, long_text, single, multi, dropdown, scale, rating, number, date, time, datetime, email, phone, pesel, postal, file, grid`;
- limity i komunikaty walidacji jak w Communio;
- przy zapisie serwer liczy trasę przez sekcje i wycina odpowiedzi z pominiętych sekcji;
- pytanie ma opcjonalnie `image` (token pliku z `POST /district-forms/{id}/uploads?purpose=question`) i `image_url` (≤ 500 znaków, `https://…`, `/district-forms/…` albo `/static/…`). Serwer przechowuje `image_url` z zapisu, a w odpowiedziach (`FormDetail.schema`, `PublicForm.schema`) i tak wylicza go z tokenu: w aplikacji `/district-forms/{id}/files/{token}` (z tokenem sędziego), na webie `/public/forms/{code}/files/{token}` (otwarta ścieżka, tylko obrazy pytań, nigdy pliki odpowiedzi).

Plik: `app/district_form_schema.py` (czysta logika + testy, wzór: `*_rules.py`).

## 6. Ustawienia (`settings_json`)

```ts
type Settings = {
  // wspólne
  roster_visible?: boolean;            // list: uczestnicy widzą w aplikacji całą listę (kolumny visibility=all). Domyślnie false (widzą tylko siebie)
  reminders?: "off" | "gentle" | "standard" | "intense";   // domyślnie "standard"
  home_prompt?: boolean;               // karta „Czeka na Ciebie” na panelu + okno <72 h. Domyślnie true
  confirmation?: string | null;        // komunikat po wysłaniu (≤ 300)
  // form
  anonymous?: boolean;                 // zamrażane po pierwszej odpowiedzi; zakazane przy participants.open=false && web
  allow_edit?: boolean;                // edycja odpowiedzi do terminu (domyślnie true)
  results_visibility?: "managers" | "observers" | "participants"; // participants = tylko agregaty (jak „everyone” w Communio)
  fill_mode?: "steps" | "scroll";
};
```

Przypomnienia: offsety przed `closes_at`, tylko dla niewypełnionych uczestników.

| preset | offsety |
|---|---|
| gentle | 1 dzień |
| standard | 3 dni, 1 dzień, 3 h |
| intense | 7 dni, 3 dni, 1 dzień, 6 h, 2 h |

- Na start formularza (publikacja) wychodzi zawsze push `published` do uczestników.
- **Cisza nocna 21:00–8:00 (Europe/Warsaw):** slot wypadający w nocy przesuwamy na 8:00, chyba że termin minie wcześniej. Wtedy wysyłamy o 20:30 poprzedniego wieczoru.
- Sweep idzie w pętli `run_event_reminder_sweep` (`province_events.py`), z deduplikacją w `district_form_notifications`.
- Preferencja push: `preference_key="province_events"`, chyba że w `app/push/preferences.py` jest stosowniejszy klucz.

## 7. Widoczność

| Kto | lista (`kind=list`) | formularz (`kind=form`) |
|---|---|---|
| uczestnik | swój wiersz (wszystkie kolumny poza `visibility=managers`). Przy `roster_visible` także cudze wiersze, tylko kolumny `visibility=all`. | swoja odpowiedź. Agregaty, jeśli `results_visibility=participants`. |
| obserwator | wszystkie wiersze, kolumny `all` i `self` (bez `managers`), tylko odczyt | agregaty (`/stats`), a pełne odpowiedzi przy `results_visibility ∈ {observers, participants}` |
| zarządzający | wszystko, edycja, historia, eksport, push | wszystko |
| web anonimowy | całą listę z kolumnami `visibility=all` i kolumnami edytowalnymi przez sędziego (`editor ∈ self, self_confirm`) | listę imion do wybrania siebie (bez treści odpowiedzi) albo pole „Imię i nazwisko” przy `participants.open` |

Kolumny `visibility=self` przy anonimowym webie: pokazujemy tylko, czy wiersz ma wartość (np. ✓), nie samą wartość. Wyjątek: `status` jest zawsze jawny na webie, bo to sedno listy.

## 8. Spięcie z wydarzeniem okręgowym

- `district_forms.event_id`. Formularz ustawia powiązanie w kreatorze; jedno wydarzenie ma najwyżej jeden formularz.
- Gdy wydarzenie ma formularz z kolumną `status`:
  - **Zaproszeni na wydarzenie = uczestnicy formularza.** Przy zapisie formularza serwer kopiuje `participants` do `data_json.target`, `include_ids` i `exclude_ids` wydarzenia.
  - **RSVP wydarzenia = kolumna statusu.**
    - `yes` → RSVP „yes”, `no` → „no”, `maybe` i inne → brak RSVP.
    - `POST /province-events/:id/rsvp` przy spiętym formularzu zapisuje do kolumny statusu (źródło `app`) i odwrotnie. Jedna prawda: status w formularzu. Endpointy RSVP i feed wydarzeń czytają z formularza.
  - Przypomnienie RSVP z wydarzenia jest wyłączone, bo formularz ma własne.
  - Feed wydarzeń i `/item/:id` dokładają `form: {id, kind, title, closes_at, web_enabled, my_status, filled, counts:{yes,no,none,...}}`.
- **Bez spięcia:** akcja „Zaproś z wyników”, czyli `POST /district-forms/{id}/invite-to-event` z `{event_id, filter}`. Dopisuje pasujących do `include_ids` wydarzenia, bez dubli, i zwraca liczbę dopisanych.

## 9. Źródła zapisu i blokady (najważniejsze reguły)

| Źródło | Kto | Co może |
|---|---|---|
| `app` | właściciel w aplikacji (JWT bez `scope`) | swój wiersz, kolumny `self`/`self_confirm`; ustawia `verified=true`, czyści `web_review` |
| `web_qr` | właściciel na webie po logowaniu QR (JWT `scope:"form-web"`) | to samo co `app` (ustawia `verified=true`) |
| `web` | ktokolwiek z linkiem, bez logowania | dowolny wiersz **niezweryfikowany**, kolumny `self`/`self_confirm`; nigdy `managers` |
| `manager` | zarządzający (app albo web_qr) | wszystkie wiersze i kolumny; nie zmienia `verified` |

Reguły:

1. **Twarda blokada.** Wiersz z `verified=true` odrzuca zapis `web`: **423** `{"error":"verified_lock","message":"Ten sędzia potwierdził wybór w aplikacji."}`.
2. **Miękka blokada (tylko sugestia).** Wiersz z zapisem `web` z innego `device_id` (`web_device ≠ device_id`) i bez `force:true` dostaje **409** `{"error":"soft_claimed","at":"<web_at>","message":"..."}`. Web pyta „To już zaznaczono … z innego urządzenia. Na pewno to Ty?”, a po potwierdzeniu ponawia z `force:true`.
3. **Ślad.** Każdy zapis `web` trafia do logu z `ip` (pierwszy z `X-Forwarded-For`, inaczej `request.client.host`), `user_agent`, `device_id` i `geo` (jeśli przeglądarka dała zgodę).
4. **„To Ty?”.** Każdy zapis `web` w cudzym wierszu ustawia `web_review=true` i wysyła właścicielowi push (dedup: 1 na 30 min na wiersz):
   - tytuł: „Zaznaczono Cię przez stronę”;
   - treść: „{tytuł}: {opis zmiany}. To Ty? Potwierdź albo popraw w aplikacji.”;
   - dane: `{type:"district_form", formId, action:"review_web"}`.

   W aplikacji `POST /district-forms/{id}/me/confirm` ustawia `verified=true` i `web_review=false` bez zmiany wartości. Zwykły zapis `app` robi to samo.
5. **Termin.** Po `closes_at` (albo po `closed_at`) zapisy `app`/`web_qr`/`web` w kolumnach z `lock_after_deadline` dostają **409** `closed`. Zarządzający mogą dalej edytować. Kolumny `confirm` domyślnie zostają otwarte.
6. **Web wyłączony.** `web_enabled=false`: publiczne endpointy zwracają tylko `{web_enabled:false, title}`, a każdy zapis dostaje 403 `web_disabled`.

## 10. API (aplikacja i web po QR) — prefiks `/district-forms`

Uwierzytelnianie przez `get_jwt_payload`; identyfikator i okręg sędziego pochodzą z tokenu i `province_judges`, jak `market_actor`. Token `scope:"form-web"` wpuszczamy **tylko** pod `/district-forms/` (`_SCOPE_PREFIXES` w `deps.py`). Błędy w kopercie `{"error": code, "message": "po polsku"}`.

```ts
type FormRole = "manager" | "observer" | "participant";
type FormSummary = {
  id: string; kind: "list" | "form"; title: string; description: string | null;
  cover: { tone: string; emoji?: string } | null;
  status: "draft" | "open" | "closed" | "archived" | "trash";
  closes_at: string | null; published_at: string | null; created_at: string;
  created_by: { judge_id: string; name: string };
  event: { id: number; name: string; event_date: string } | null;
  web_enabled: boolean; web_url: string | null;   // https://www.bazapodreka.app/f/<kod>
  roles: FormRole[];                               // moje role
  me: { participant: boolean; filled: boolean; status: string | null; web_review: boolean } ;
  counts: { participants: number; filled: number; status?: Record<string, number> };
  rev: number;
};
type FormDetail = FormSummary & {
  schema: ListSchema | FormSchema;
  settings: Settings;
  audience: Audience;                              // tylko dla manager; inni dostają null
  my_entry: Entry | null;
  can: { manage: boolean; respond: boolean; view_rows: boolean; view_results: boolean; edit_after_deadline: boolean };
};
type Entry = {
  judge_id: string | null; name: string; guest_name?: string | null; photo_url?: string | null; badges?: string[];
  cells: Record<string, Cell>;                     // list (przefiltrowane wg widoczności)
  answers?: Record<string, any>;                   // form (gdy wolno)
  verified: boolean; self_source: string | null; web_review: boolean; web_at: string | null;
  filled: boolean; updated_at: string | null; submitted_at: string | null;
};
```

| Metoda i ścieżka | Kto | Opis |
|---|---|---|
| `GET /district-forms?scope=todo\|active\|manage\|drafts\|closed\|archived\|trash` | zalogowany | `{forms: FormSummary[], can_create: boolean}`. `todo` = jestem uczestnikiem, otwarte, niewypełnione albo `web_review`. |
| `GET /district-forms/pending` | zalogowany | Na kartę panelu: `{forms: Array<FormSummary & {status_column: Column \| null}>}`, posortowane wg terminu. |
| `GET /district-forms/templates` | twórca | Gotowe szablony `{id,title,kind,description,schema,settings}` (§13). |
| `GET /district-forms/people` | twórca/zarządzający | `{judges:[{judge_id,name,photo_url,badges}], badges:[{name,color?,icon?}]}` do edytora odbiorców (okręg z tokenu). |
| `GET /district-forms/info/recall` | komisja okręgu, admin | `{items:[{form_id,form_title,event,at,block}]}`: bloki `payment`/`place`/`contact` z list okręgu (bez kosza, najnowsze pierwsze, do 120) - podpowiedzi kreatora; scala je klient (przelew po numerze konta). |
| `POST /district-forms/audience/preview` | twórca | `{audience}` → `{participants:n, observers:n, managers:n, sample:[name]}` |
| `POST /district-forms` | twórca | Body `{kind,title,description?,cover?,schema,settings?,audience,closes_at?,event_id?,publish?:boolean,template_id?}` → `FormDetail` |
| `GET /district-forms/{id}` | role | `FormDetail` |
| `GET /district-forms/by-code/{code}` | zalogowany | `{id}` (link `/f/<kod>` otwarty w aplikacji) |
| `PATCH /district-forms/{id}` + `If-Match` | manager | Te same pola co POST, częściowo. Zmiana `kind` jest zakazana. Usunięcie kolumny zostawia dane w logu. → `FormDetail` |
| `POST /district-forms/{id}/publish` · `/close` · `/reopen` · `/archive` · `/unarchive` · `/restore` · `DELETE /district-forms/{id}` | manager | `/reopen` przyjmuje opcjonalnie `{closes_at}`. → `FormDetail` |
| `POST /district-forms/{id}/duplicate` | manager | `{title?, closes_at?}` → nowy szkic (bez odpowiedzi) |
| `PUT /district-forms/{id}/me` | uczestnik | list: `{cells:{[colId]: v}}`; form: `{answers, client_id, fill_seconds?}` → `{entry: Entry}`. Źródło `app` albo `web_qr` (wg scope). |
| `POST /district-forms/{id}/me/confirm` | uczestnik | „To ja” po zapisie z weba → `{entry}` |
| `GET /district-forms/{id}/rows?q=&filter=` | manager/obserwator/uczestnik przy roster_visible | `{rows: Entry[], columns: Column[]}`. Wszyscy uczestnicy, także z pustym wierszem (`cells:{}`). `filter` = JSON `{[colId]: v \| "none"}`. |
| `PATCH /district-forms/{id}/rows/{judge_id}` | manager | `{cells:{[colId]: v}}` → `{entry}` |
| `POST /district-forms/{id}/rows/bulk` | manager | `{judge_ids:[], column_id, value}` → `{updated:n}` |
| `GET /district-forms/{id}/log?judge_id=&limit=` | manager | `{items:[{id, owner:{judge_id,name}, column_id, column_title, old, new, source, actor:{judge_id,name}\|null, ip, user_agent, device_id, geo, created_at}]}` |
| `GET /district-forms/{id}/stats` | wg §7 | §11 |
| `GET /district-forms/{id}/responses` | manager (form) | `{responses: Entry[]}` (bez `judge_id`/`name` przy anonymous) |
| `GET /district-forms/{id}/export?format=xlsx\|csv\|pdf` | manager | `{url, filename}`. Plik do pobrania przez `/district-forms/file/{token}` (otwarta ścieżka, jak `/province-events/pdf/{token}`, ważna 15 min). |
| `POST /district-forms/{id}/remind` | manager | `{judge_ids?: string[], filter?: {...}, only_unfilled?: boolean, title?: string, body?: string}` → `{sent_to:n, devices:n}`. Limit: 1 na 10 min na formularz (429 `rate_limited` z `retry_at`). |
| `POST /district-forms/{id}/web` | manager | `{enabled:boolean}` → `{web_enabled, web_code, web_url}` |
| `POST /district-forms/{id}/invite-to-event` | manager | `{event_id, filter}` → `{added:n}` |
| `POST /district-forms/{id}/uploads?purpose=question\|answer` · `GET /district-forms/{id}/files/{token}` | wg Communio | pliki (form) |
| `POST /district-forms/pair/{code}/approve` | zalogowany w aplikacji | Telefon zatwierdza logowanie przeglądarki → `{ok:true, form:{id,title}}` |

## 11. Statystyki (`GET /district-forms/{id}/stats`)

```ts
type ListStats = {
  kind: "list";
  participants: number; filled: number;
  sources: { app: number; web_qr: number; web: number; manager: number };
  web_review: number;                                         // czeka na „To ja”
  timeline: Array<{ date: string; filled: number }>;          // narastająco, dziennie
  columns: Array<
    | { id: string; type: "status" | "choice"; counts: Record<string, number>; none: number }
    | { id: string; type: "check"; yes: number; no: number }
    | { id: string; type: "confirm"; none: number; declared: number; confirmed: number;
        amount: number | null; expected_total: number | null; declared_total: number | null; confirmed_total: number | null }
    | { id: string; type: "number"; count: number; sum: number; avg: number | null; min: number | null; max: number | null }
    | { id: string; type: "text"; count: number }
  >;
};
```

Dla kolumny `confirm` z kwotą:

- `expected_total = amount × (liczba wierszy ze statusem positive, a gdy nie ma kolumny statusu: wszyscy uczestnicy)`;
- `declared_total = amount × (declared + confirmed)`;
- `confirmed_total = amount × confirmed`.

`kind=form`: kształt jak `Communio_serwer/app/form_stats.py`, z dodatkiem `participants`, `filled` i `timeline`:

```ts
type FormStats = {
  kind: "form";
  participants: number; filled: number;       // uczestnicy z listy i ilu z nich odpowiedziało
  guests: number; total: number;              // odpowiedzi gości (participants.open) i wszystkie odpowiedzi
  last_at: string | null;
  timeline: Array<{ date: string; filled: number }>;
  questions: FormQuestionStat[];              // element jak Communio `FormQuestionStat` (question_id, kind, answered, ...)
  hidden_question_ids: string[];              // pytania z danymi osobowymi - bez wyniku
  median_fill_seconds: number | null;
};
```

## 12. Publiczny web (bez logowania) — prefiks `/public/forms`

Ścieżki dopisane do `OPEN_PATTERNS` w `client_key_rules.py` (web i tak wysyła `X-Baza-Key`). Limit: 30 zapisów na minutę na IP i 20 kodów QR na 10 minut na IP (`AttemptLimiter`, jak `/exam-web/qr` i `client-errors`; slowapi nie jest w repo używany na trasach). Przekroczenie: 429 `rate_limited` z nagłówkiem `Retry-After`.

| Metoda i ścieżka | Opis |
|---|---|
| `GET /public/forms/{code}` | `PublicForm` (niżej). Przy `web_enabled=false` → `{web_enabled:false, title}`. Nieznany kod → 404. |
| `PUT /public/forms/{code}/rows/{judge_id}` | Body `{cells:{[colId]:v}, device_id, geo?: {lat,lon,acc} \| {denied:true}, force?: boolean}` → `{row: PublicRow}`. Błędy: 423 `verified_lock`, 409 `soft_claimed`, 409 `closed`, 403 `web_disabled`, 403 `column_forbidden`, 404 `not_participant`. |
| `PUT /public/forms/{code}/responses` | form: `{judge_id? \| guest_name?, answers, client_id, device_id, geo?, force?}` → `{ok:true, confirmation, submitted_at, row}`. Te same zasady blokad co dla wierszy: dla `judge_id` blokada verified/soft, dla otwartego formularza zapis jako gość. |
| `POST /public/forms/{code}/qr` | → `{pair_code, poll_token, qr_url:"https://www.bazapodreka.app/f/p/<pair_code>", expires_at}` |
| `GET /public/forms/qr/{pair_code}?poll_token=&wait=20` | Long-poll → `{status:"pending"\|"approved"\|"expired", token?, judge:{judge_id,name}?, form_id?}`. `token` to JWT `scope:"form-web"` z `judge_id`, `form_id` i ważnością 12 h. |

Po zalogowaniu QR web używa zwykłych endpointów `/district-forms/...` z tym tokenem. Zarządzający dostaje na komputerze pełną tabelę; uczestnik edytuje tylko swój wiersz, ze źródłem `web_qr`.

```ts
type PublicForm = {
  web_enabled: true;
  id: string; kind: "list" | "form"; title: string; description: string | null; cover: {...} | null;
  closes_at: string | null; closed: boolean;
  province_label: string;                    // np. "Śląskie"
  columns?: Column[];                        // list: kolumny widoczne na webie (§7), z editor
  schema?: FormSchema;                       // form
  open?: boolean;                            // form z participants.open
  fill_mode?: "steps" | "scroll";            // form: z settings.fill_mode
  confirmation?: string | null;              // form: komunikat po wysłaniu (settings.confirmation)
  rows?: PublicRow[];                        // list: wszyscy uczestnicy; form: lista imion (bez odpowiedzi)
  counts: { participants: number; filled: number; status?: Record<string, number> };
  privacy_note: string;                      // tekst RODO do pokazania przy pierwszym zapisie
};
type PublicRow = {
  judge_id: string; name: string; photo_url: string | null;
  cells: Record<string, { v: any; src: string; at: string } | { set: true }>; // {set:true} dla visibility=self
  verified: boolean;                          // twarda kłódka
  web_claimed: { at: string } | null;         // ostatni zapis z weba (sugestia blokady)
  filled: boolean;
};
```

**Linki.** `https://www.bazapodreka.app/f/<kod>` (formularz) i `https://www.bazapodreka.app/f/p/<pair_code>` (zatwierdzenie logowania QR).

- iOS i Android otwierają je w aplikacji, gdy jest zainstalowana.
- Serwer dopisuje ścieżki `/f/*` do `/.well-known/apple-app-site-association` w `app/event_links.py`.
- Aplikacja dopisuje intent filter z `pathPrefix "/f/"` dla `WEB_LINK_HOST`.
- Bez aplikacji link ląduje na webie.

## 13. Szablony (serwer, stałe w kodzie)

1. **Impreza z wpłatą** (`list`): status Będę/Nie będę; `confirm` „Wpłata” (`self_confirm`, kwota do ustawienia); `choice` „Menu” (mięsne/wegetariańskie); `number` „Osoby towarzyszące” (0–3).
2. **Składka** (`list`): `confirm` „Składka” (`self_confirm`).
3. **Zebranie / szkolenie** (`list`): status Będę/Nie będę/Może; `text` „Uwagi”.
4. **Lista obecności z potwierdzeniem** (`list`): status; `check` „Obecny” (`managers`, `visibility=all`).
5. **Ankieta po szkoleniu** (`form`): skala, wybór, tekst.
6. **Zgłoszenie** (`form`): dane kontaktowe, wybór terminu, uwagi.

## 14. Eksport

- **xlsx (openpyxl):**
  - arkusz „Lista” albo „Odpowiedzi”: nagłówek z tytułem, terminem i datą eksportu; kolorowe statusy (zielony, czerwony, szary); kolumna „Źródło” (Aplikacja / Web QR / Web / Komisja);
  - arkusz „Podsumowanie”: liczby, kwoty i procenty.
- **CSV:** średnik, UTF-8 z BOM.
- **PDF (WeasyPrint):** lista do druku, czyli tabela z polami do odhaczenia, podsumowanie i kwoty na górze, stopka z datą. Wzór: PDF obecności wydarzeń.

## 15. Testy serwera (minimum)

- czyste reguły (`district_forms_rules.py`): widoczność kolumn, maszyna `confirm`, blokady 423/409, termin, wypełnienie, presety przypomnień i cisza nocna, statystyki i kwoty, odbiorcy;
- walidacja schematu listy i formularza (port testów Communio);
- wiring: router zamontowany, ścieżki publiczne w `OPEN_PATTERNS`, scope `form-web`, AASA zawiera `/f/`.

## 16. Uzupełnienia z implementacji serwera (10.11.2026)

Dopisane przy budowie serwera. Kształty z §1–§14 bez zmian; poniższe pola i trasy są DODATKOWE.

**Pliki serwera:** `district_forms_tables.py` (tabele), `district_forms_rules.py` (reguły bez bazy), `district_form_schema.py` (schemat listy i formularza, port Communio), `district_form_templates.py` (§13), `district_forms_service.py` (baza, powiadomienia, spięcie z wydarzeniem, `sweep_district_forms(now)`), `district_forms.py` (trasy `/district-forms`), `district_forms_public.py` (trasy `/public/forms`), `district_form_export.py` (§14).

**Model danych (dodatki):**

- `district_forms.created_by_name` (nazwisko twórcy w chwili utworzenia);
- `district_form_pairs.judge_name`;
- `district_form_notifications` ma `id` (PK), `title`, `body` – treść pusha trafia też do skrzynki w aplikacji;
- nowa tabela `district_form_uploads`: `token (PK, 16 hex), form_id, judge_id, purpose (question|answer), name, mime, size_bytes, created_at`. Pliki leżą POZA publicznym `static` (`$RAILWAY_VOLUME_MOUNT_PATH/private/district-forms/<form_id>/<token>`), wydaje je tylko `GET /district-forms/{id}/files/{token}` po sprawdzeniu ról. Limit 10 MB; przy pytaniu tylko obraz.
- indeks unikalny `uq_district_forms_event` (jedno wydarzenie – jeden żywy formularz) przez `MIGRATIONS`.

**Skrzynka w aplikacji:** `GET /district-forms/inbox?installation_id=&limit=` (bez tokenu, tożsamość z rekordu urządzenia – jak `/push/match-events` i `/mentor-evaluations/requests/inbox`). Zwraca `{items: ServerMatchNotification[]}`: `id: "district-form:<n>"`, `event_type: "district_form"`, `match_code: null`, `data_json: {type:"district_form", kind:"district_form", formId, action, notice}`. `action`: `open` (published), `fill` (reminder, manual, deadline_today), `review_web` (web_review). Aplikacja dokłada to źródło w `fetchServerMatchNotifications` obok skrzynki mentora (starszy serwer zwróci 404 – brak źródła nie może wyłączyć reszty).

**Dane pusha:** `{type:"district_form", kind:"district_form", formId, action, notice, province}`; `preference_key="province_events"`, `app_variant="baza"`.

**Filtry wierszy** (`/rows?filter=`, `/remind`, `/invite-to-event`): poza `{[colId]: v | "none" | v[]}` także `_filled`, `_web_review`, `_verified` (true/false). Filtr działa tylko na kolumnach, które pytający widzi.

**Drobne pola:**

- `FormSummary.counts.guests` – liczba odpowiedzi gości przy `participants.open`;
- `FormDetail.web_code` – tylko dla zarządzających;
- `GET /district-forms/people` i `POST /district-forms/audience/preview` przyjmują opcjonalnie `province` (admin) i `form_id` (zarządzający spoza komisji edytuje odbiorców swojego formularza); podgląd zwraca też `open`;
- `POST /district-forms/{id}/remind`: `only_unfilled` domyślnie `true`, gdy nie podano `judge_ids`; przy limicie 429 niesie `retry_at` i `Retry-After`;
- `PUT /public/forms/{code}/responses` → `{ok:true, submitted_at, confirmation, row: PublicRow | null}`;
- `PATCH` bez nagłówka `If-Match` jest przyjmowany (zgodność); niezgodny `If-Match` → 409 `stale` z `rev`. `rev` rośnie też przy publikacji, zamknięciu, archiwum, koszu i przełączeniu webu;
- token `form-web` działa tylko na trasach `/district-forms/{form_id}/...` formularza, dla którego go wydano (inne → 403 `form_web_scope`); trasy listy, tworzenia, `pair/approve`, `by-code` są tylko dla aplikacji (403 `app_only`);
- `deadline_today` jest zarezerwowany – przejście wysyła dziś tylko sloty presetów.

**Kody błędów** (`{"error", "message", ...}`): `not_found` 404, `forbidden` 403, `not_participant` 403/404, `column_forbidden` 403, `confirmed_locked` 403, `web_disabled` 403, `verified_lock` 423, `soft_claimed` 409 (+`at`), `closed` 409, `draft` 409, `stale` 409, `event_linked` 409, `already_answered` 409, `client_conflict` 409, `anonymous_frozen` 409, `column_type_locked` 409, `rate_limited` 429, `bad_*`/`invalid_answers` 400 (`invalid_answers` niesie `errors: {questionId: zdanie}`), `trash_expired` 410.

**Wydarzenie przy spiętej liście:** `POST /province-events/:id/rsvp` zapisuje status formularza (źródło `app`), termin odpowiedzi to termin formularza, a odmowy formularza wracają do starej aplikacji jako zwykłe 409 ze zdaniem. Status jest też kopiowany do `province_event_responses` (dla czytników spoza modułu); powód „Nie będę” przy spiętej liście nie jest zapisywany. Feed i `/item/:id` mają zawsze klucz `form` (`null`, gdy brak spięcia); obiekt formularza ma dodatkowo `status` i `status_column`.

## 17. Bloki informacyjne (nad i pod formularzem)

Każdy formularz (`list` i `form`) może mieć dwie strefy bloków: **nad** formularzem i **pod** nim. Twórca składa je w kreatorze w kroku „Informacje”:

- dodaje blok jednym tapnięciem z arkusza typów;
- przesuwa bloki w górę i w dół oraz między strefami;
- widzi podgląd na żywo.

Bloki pokazują się:

- w aplikacji: uczestnikowi i obserwatorowi na ekranie formularza, zarządzającemu w podglądzie i w zakładce Ustawienia;
- na stronie `/f/<kod>`: także przy wyłączonym webie, na karcie „tylko w aplikacji”, ale tylko bloki `countdown` i `text`;
- na ekranie „Czeka na Ciebie” i w oknie <72 h: tylko pierwszy blok `countdown`.

### Model

Nowa kolumna `district_forms.info_json` (JSON, domyślnie `{"above":[],"below":[]}`), dodawana przez `MIGRATIONS`.

```ts
type FormInfo = { above: InfoBlock[]; below: InfoBlock[] };   // każda strefa ≤ 12 bloków
type InfoBlock =
  | { id: string; type: "text";      title?: string; body: string }                       // body ≤ 3000
  | { id: string; type: "callout";   tone: "info" | "warning" | "success" | "danger"; title?: string; body: string }  // ≤ 600
  | { id: string; type: "countdown"; title?: string; target: "deadline" | "event" | "date";
      date?: string;                 // ISO, wymagane przy target="date"
      done_label?: string;           // np. „Zapisy zamknięte”; domyślnie zależne od celu
      show_date?: boolean }          // pokaż pod licznikiem datę, np. „wt 9.12, 23:59”; domyślnie true
  | { id: string; type: "payment";   title?: string;                                      // domyślnie „Dane do przelewu”
      recipient: string;             // ≤ 70
      account: string;               // NRB: serwer zapisuje 26 cyfr bez spacji, z poprawną sumą kontrolną IBAN PL
      transfer_title: string;        // szablon ≤ 140, symbole: {imie_nazwisko} {imie} {nazwisko} {numer_sedziego}
      amount?: number | null;        // zł (np. 80); albo:
      amount_column?: string | null; // id kolumny confirm z kwotą; brane z niej
      confirm_column?: string | null;// id kolumny confirm: blok pokazuje jej stan i przycisk „Zapłaciłem”
      address?: string;              // ≤ 140
      bank_qr?: boolean;             // kod QR do aplikacji banku (domyślnie true)
      note?: string }                // ≤ 300
  | { id: string; type: "copy";      title?: string; items: Array<{ id: string; label: string; value: string; mono?: boolean }> } // 1..10 pozycji, value ≤ 300
  | { id: string; type: "place";     title?: string; name: string; address?: string; lat?: number; lon?: number; note?: string }
  | { id: string; type: "contact";   title?: string; people: Array<{ id: string; name: string; role?: string; phone?: string; email?: string }> } // 1..6 osób
  | { id: string; type: "links";     title?: string; items: Array<{ id: string; label: string; url: string }> };          // 1..6, tylko https
```

Bloki niosą tylko treść. Nie mają nadtytułów (zakaz z CLAUDE.md BAZA): `title` to zwykły tytuł bloku i jest opcjonalny.

### Serwer

- **Walidacja i czyszczenie:** `clean_info(raw, schema)` w `district_forms_rules.py` albo w osobnym `district_form_info.py`, z testami.
  - Przycina teksty i usuwa nieznane typy.
  - Odrzuca `target:"event"` bez `event_id`: 400 `bad_info` z `errors: {blockId: zdanie}`.
  - Sprawdza NRB (26 cyfr, `PL` + mod 97 == 1) i `amount_column`/`confirm_column` (musi istnieć kolumna typu `confirm`).
  - Linki przyjmuje tylko z `https://`.
- **Gdzie trafia `info`:** do `POST`/`PATCH` `/district-forms` (pole `info`), `FormDetail.info`, `PublicForm.info` (zawsze; przy `web_enabled:false` tylko `countdown` i `text`), `/pending` (`info_countdown`: pierwszy blok `countdown` albo null) i do `duplicate`.
- **`resolved_at` (ISO albo null) w każdym bloku `countdown` w odpowiedziach**, wyliczane z celu:
  - `deadline` → `closes_at`;
  - `event` → początek spiętego wydarzenia;
  - `date` → `date`.

  Klient odlicza tylko do `resolved_at`.
- **`payment` w odpowiedziach** dostaje `resolved_amount` (number albo null): `amount` albo `amount` z kolumny `amount_column`.
- **`FormDetail.viewer`** = `{judge_id, name, first_name, last_name}`. Imię i nazwisko z `province_judges.full_name`; kolejność ustalić z danych, a gdy niejasna: `first_name = ""`, `last_name = name`.
- **Szablon „Impreza z wpłatą”** dostaje bloki:
  - nad: `countdown` (deadline, tytuł „Do końca zapisów”) i `payment` (puste konto, `transfer_title` „{tytuł formularza} – {imie_nazwisko}”, `amount_column` = kolumna wpłaty, `confirm_column` = ta sama);
  - pod: `contact` (pusty, do uzupełnienia).

  Szablon „Zebranie / szkolenie” dostaje `countdown` (event) i `place`.

### Klienci (aplikacja i web)

- **`text`:** proste formatowanie, czyli `**pogrubienie**`, nowe linie i listy `- `. Adresy `https://`, telefony i e-maile są klikalne.
- **`callout`:** kolorowa ramka według `tone`.
- **`countdown`:**
  - Kafle dni / godz. / min / sek z poprawną odmianą, jak licznik najbliższego meczu (`components/home/CountdownTile.tsx` w BAZA; na webie odpowiednik CSS).
  - Pod licznikiem data, jeśli `show_date`.
  - Po czasie: `done_label`, domyślnie dla celu `deadline` „Termin minął”, dla `event` „Wydarzenie trwa albo minęło”.
  - Zegar we własnym komponencie, żeby nie przerysowywać całego ekranu. Zatrzymany, gdy ekran nie jest widoczny.
- **`payment`:**
  - Wiersze Odbiorca / Numer konta (formatowany `12 3456 7890 …`) / Tytuł przelewu (szablon wypełniony danymi oglądającego) / Kwota / Adres.
  - Każdy wiersz z przyciskiem **Kopiuj** i potwierdzeniem „Skopiowano”; numer konta kopiujemy bez spacji. Jest też „Kopiuj wszystko”.
  - Przy `bank_qr`: kod QR w standardzie ZBP „Skanuj i zapłać”, opisany niżej.
  - Przy `confirm_column`: stan wpłaty uczestnika (Nie zapłacono / Zapłaciłem / Otrzymano ✓) i przycisk „Zapłaciłem”, który zapisuje kolumnę tak jak wiersz uczestnika.
  - Na anonimowym webie tytuł personalizuje się dopiero po wybraniu siebie z listy albo po zalogowaniu QR. Wcześniej symbol zamienia się na „[imię i nazwisko]”, a przycisk „Zapłaciłem” jest ukryty.
- **`copy`:** etykieta, wartość (`mono` = krój o stałej szerokości) i Kopiuj.
- **`place`:** nazwa, adres, „Otwórz w mapach” (współrzędne albo wyszukanie adresu).
- **`contact`:** osoby z przyciskami Zadzwoń / Napisz.
- **`links`:** przyciski otwierające adresy.

**Kod QR przelewu (rekomendacja ZBP, standard 2D)** to jeden napis z polami rozdzielonymi `|`:

`{NIP odbiorcy albo pusty}|PL|{NRB 26 cyfr}|{kwota w groszach, 6 cyfr z zerami}|{nazwa odbiorcy ≤ 20 znaków}|{tytuł ≤ 32 znaki}|||`

Przykład: 80 zł → `008000`. Brak kwoty → `000000`. Tytuł i nazwę przycinamy oraz usuwamy z nich `|`. Pod kodem: „Zeskanuj w aplikacji banku (Skanuj i zapłać)”.

### Uzupełnienia z implementacji serwera (§17)

Logika: `app/district_form_info.py` (testy: `tests/test_district_form_info.py`). Kształty jak wyżej, poniżej doprecyzowania:

- **Identyfikatory:** blok bez `id` (albo z powtórzonym) dostaje `b<n>`, pozycje `copy`/`contact`/`links` – `c<n>`/`p<n>`/`l<n>`. Identyfikatory bloków są unikalne w obu strefach razem (`errors` są po nich).
- **Limity bez wartości w kontrakcie:** `title` ≤ 80, `done_label` ≤ 60, etykiety ≤ 60, `place.name` ≤ 120, `place.address` ≤ 200, `contact.name` ≤ 80, `role` ≤ 60, `url` ≤ 500. `place` przyjmuje `lat` i `lon` tylko parą.
- **Kwota:** `resolved_amount` = `amount`, a gdy go brak – `amount` kolumny `amount_column`. Kolumna musi być typu `confirm` (formularz `kind=form` nie ma kolumn, więc przy nim `amount_column`/`confirm_column` to błąd).
- **PATCH:** bloki są sprawdzane od nowa także przy zmianie `schema` albo `event_id` bez pola `info`. Np. odpięcie wydarzenia przy liczniku `target:"event"` daje 400 `bad_info` – klient zmienia licznik w tym samym żądaniu. Każda zmiana `info` podbija `rev`.
- **Szablon bez kreatora** (`POST` z `template_id` i bez `info`):
  - puste bloki do uzupełnienia (`payment` bez konta lub odbiorcy, `contact` bez osób, `place` bez nazwy) odpadają;
  - licznik `event` bez spiętego wydarzenia liczy do `deadline`;
  - tytuł przelewu zaczynający się od nazwy szablonu dostaje tytuł formularza.

  `GET /district-forms/templates` oddaje bloki szablonu w całości (pole `info`), więc kreator może je wypełnić.
- **Szablony:**
  - „Impreza z wpłatą”: `transfer_title` „Impreza z wpłatą – {imie_nazwisko}” (po utworzeniu: tytuł formularza), `amount_column` i `confirm_column` = `payment`;
  - „Zebranie / szkolenie”: licznik „Do rozpoczęcia” (`event`) i `place` „Miejsce”.
- **`duplicate`:** kopiuje bloki. Kopia nie ma wydarzenia, więc licznik `event` przechodzi na `deadline`.
- **Odpowiedzi:**
  - `PublicForm` przy `web_enabled:false` ma kształt `{web_enabled:false, title, info}`, a w `info` tylko `countdown` i `text`;
  - `/pending`: `info_countdown` to pierwszy licznik z `resolved_at`, albo `null`.
- **`viewer`:**
  - nazwisko WERSALIKAMI w `full_name` (zapis ZPRP „NOWAK Jan”) rozstrzyga kolejność: wersaliki to `last_name`, reszta to `first_name`;
  - bez wersalików: `first_name = ""`, `last_name = name`;
  - `name` to nazwisko z tokenu i z listy sędziów, a przy jego braku `judge_id`.
- **Eksport:** pierwszy blok `payment` z kontem dopisuje do arkusza „Podsumowanie” wiersze Odbiorca przelewu / Numer konta (`12 3456 …`) / Tytuł przelewu / Kwota przelewu. Do nagłówka PDF trafiają odbiorca, konto i tytuł.
- **Migracja:** `ALTER TABLE district_forms ADD COLUMN IF NOT EXISTS info_json JSONB DEFAULT '{"above":[],"below":[]}'`. Stare wiersze z `NULL` czytamy jako puste strefy.

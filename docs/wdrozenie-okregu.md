# Wdrożenie okręgu - specyfikacja (27.11.2026)

Jeden plik, ta sama treść w trzech repo: `BAZA_web/docs/wdrozenie-okregu.md`,
`zprp-backend/docs/wdrozenie-okregu.md`, `BAZA/docs/claude/wdrozenie-okregu.md`.
Zmieniasz jeden, przenieś zmianę do pozostałych.

## 1. Po co

Film „Panel okręgowy” (v7) kończy się mapą: „Kolejne 14 okręgów? Czekamy.”
Ta strona jest jego drugą połową. Okręg wchodzi na **bazapodreka.app/okreg/start**,
widzi na mapie Polski, gdzie BAZA już działa, wpisuje kod od admina i sam wgrywa
wszystko, czego panel potrzebuje. Admin dostaje powiadomienia w BAZA, przegląda,
zatwierdza i włącza okręg.

Trzy grupy odbiorców:
1. **Każdy** (bez kodu): mapa, stan okręgów, wybór funkcji, które go interesują, i cena.
2. **Okręg z kodem**: stół okręgu, czyli konta, pliki i ludzie, z widocznym skutkiem każdej rzeczy.
3. **Admin** (BAZA, telefon): powiadomienia, sejf haseł, przegląd plików, zatwierdzenia, kody.

## 2. Decyzje właściciela (nie dopytywać)

| Temat | Decyzja |
|---|---|
| Hasła ZPRP (konto odczytu i konto komisyjne) | **Szyfrowany sejf.** Hasło szyfrowane w przeglądarce kluczem publicznym admina. Serwer trzyma tylko szyfrogram. Odszyfrowanie tylko w BAZA na telefonie admina. Admin sam wkleja do Railway. Zasada „hasła ZPRP tylko w zmiennych Railway” zostaje. |
| Ryczałty i tabela odległości | **Plik ALBO edytor.** Plik (PDF, XLSX, CSV, zdjęcie) idzie do przeglądu i przepisania. Edytor na stronie daje od razu poprawny JSON. W obu drogach admin zatwierdza, zanim cokolwiek trafi do `okreg_rates` lub `okreg_distances`. |
| Dodatki | Tylko **ludzie i uprawnienia**: opiekun panelu, komisja z prawami, masterzy, mentorzy i delegaci. Bez płatnika, dokumentów i formalności. |
| Kod | **Jeden kod na okręg, wiele osób.** Każdy wchodzący podpisuje się imieniem i nazwiskiem, historia pokazuje, kto co wgrał. Admin unieważnia kod i wydaje nowy. |
| Mapa | Wypełnienie województwa zależne od postępu, **publicznie** (bez nazwisk). |
| Wybór funkcji | Każdy może wyklikać funkcje. Wybór przestawia listę potrzebnych rzeczy i liczy cenę z cennika `/okreg` (`components/pod-reka/screens/district/pricing.ts`). |
| Admin | Push w BAZA przy każdym wgraniu i pominięciu. Ekran „Wdrożenia okręgów” w panelu admina. |
| Styl | Mega top poziom, lekko. **Zero kafelków i checkboxów.** Świetnie na telefonie i komputerze. |

## 3. Co okręg dostarcza: klucze

Każda pozycja to **klucz**. Wgrany klucz zapala funkcje okręgu. Klucz `skippable`
można świadomie pominąć, a strona mówi wprost, co przez to zgaśnie albo czym to zastąpimy.

| Klucz (`key`) | Co to jest | Forma | Zapala | Pominąć? | Gdzie ląduje po zatwierdzeniu |
|---|---|---|---|---|---|
| `zprp_sync` | Konto ZPRP do odczytu (monitor) | login + hasło do sejfu | Terminarz okręgu, powiadomienia o obsadach, kalendarz, statystyki, synchronizacja | nie | admin wkleja do Railway: `ZPRP_SYNC_<SUF>_USERNAME/_PASSWORD` (`app/zprp_accounts.py`, `PROVINCE_ENV_SUFFIXES`) |
| `zprp_assign` | Konto komisyjne ZPRP z zapisem (jak `ks_slzpr`) | login + hasło do sejfu ALBO „to samo co odczyt” | Obsada z wysyłką do ZPRP, akceptacja wymian z giełdy, logowanie panelu kodem QR | nie | Railway `ZPRP_ASSIGN_<SUF>_*` + `province_module_config.assign_account_mode` (`own` / `same_as_sync`) |
| `rates` | Ryczałty okręgowe z datą obowiązywania | plik albo edytor | Rozliczenia, rachunki sędziowskie, „Moje rozliczenie” | nie | `okreg_rates` (wersje, `POST /admin/okreg_rates/{province}/versions`, `app/admin.py` ~778-912). Format treści: patrz `app/settlement_rates.py`. |
| `distances` | Tabela odległości między miastami | plik albo edytor | Kilometry z tabeli okręgu w rachunkach | **tak**: kilometry liczy wtedy pomiar Google (`city_distances`) | `okreg_distances` (`PUT /admin/okreg_distances/{province}`, `app/admin.py` ~1064). JSON: `validFrom`, `cities`, `edges` (pełna macierz par, kontrola w `app/distance_table_seed.py`) |
| `keeper` | Opiekun panelu: imię, nazwisko, telefon, e-mail | formularz | Kontakt admina z okręgiem | nie | tylko w stanie wdrożenia |
| `commission` | Skład komisji z prawami: obsada, rozliczenia, admin okręgu | lista osób: imię, nazwisko, login ZPRP, prawa | Dostęp do panelu webowego i panelu okręgowego w BAZA | nie | `baza_vips` (`app/db.py` ~3279, `app/province_panel_access.py`, UI admina `BAZA/components/admin/BazaVipsManagerModal.tsx`) |
| `masters` | Masterzy: ogłoszenia, kalendarz, nauczanie (egzaminy), mecze | wybór sędziów okręgu | Ogłoszenia, kalendarz okręgu, egzaminy | **tak**: robi to wtedy komisja | `news_masters`, `calendar_masters`, `teach_masters`, `match_masters` (`/admin/masters`, `app/admin.py` ~514-590) |
| `mentors` | Mentorzy i delegaci | wybór sędziów okręgu | Oceny młodych, para mentor z delegatem, Panel Mentor | **tak** | istniejące tabele mentoringu (agent ustala, `grep -rn mentor app/db.py`) |

### Moduły cennika a klucze

`pricing.ts` ma `rdzen` + `ModuleKey = obsada | rozliczenia | statystyki | rozwoj | egzaminy`.

| Moduł | Wymaga kluczy |
|---|---|
| rdzeń | `zprp_sync`, `keeper`, `commission` |
| obsada | `zprp_assign` |
| rozliczenia | `rates` (+ `distances` opcjonalnie) |
| statystyki | nic ponad rdzeń |
| rozwoj | `mentors` |
| egzaminy | `masters` (nauczanie) |

Wybór funkcji zmienia **listę kluczy** na stole i **cenę**. Klucz modułu niewybranego
chowa się do „poza zakresem”, ale nie znika.

### Postęp (wypełnienie na mapie)

`progress` w zakresie 0-100 liczy serwer z wag kluczy w zakresie okręgu. Proponowane wagi: `zprp_sync` 20,
`zprp_assign` 20, `rates` 20, `commission` 15, `keeper` 5, `distances` 10, `masters` 5,
`mentors` 5. Wagi normalizujesz do wybranych modułów.

Mnożnik statusu: `missing` 0, `submitted` 0.6, `in_review` 0.6, `active` 1, `skipped` 1, `rejected` 0.
Pominięty klucz rysujemy na mapie innym deseniem (kreskowanie), a nie pustką.

Etap okręgu:
- `waiting`: brak kodu albo nikt nie wszedł;
- `in_progress`: od pierwszego wejścia;
- `ready`: wszystko `active` albo `skipped`, czeka na włączenie;
- `live`: `active_provinces` włączone.

## 4. Kontrakt API (zprp-backend)

Nowy moduł `app/district_onboarding.py` + router. Tabele w `app/db.py` w stylu istniejących
(SQLAlchemy Core `Table`, tworzone przy starcie jak reszta). **Nie zakładaj katalogu `api/` w BAZA_web.**

### Tabele

- `district_onboarding`:
  - `province` (PK, klucz jak `SLASKIE`);
  - `code_hash` (sha256 kodu z pieprzem z env);
  - `code_version`, `code_issued_at`, `code_revoked`;
  - `modules` (JSONB, wybrane moduły);
  - `items` (JSONB: `{key: {status, updated_at, by, note, skip_reason, draft}}`);
  - `progress`, `stage`, `updated_at`.
- `district_onboarding_events`:
  - `id`, `province`, `at`, `by` (podpis), `key`;
  - `action` (`opened`, `submitted`, `skipped`, `unskipped`, `approved`, `rejected`, `commented`, `code_rotated`, `modules_changed`);
  - `payload` (JSONB, **nigdy sekrety**).
- `district_onboarding_files`:
  - `id`, `province`, `key`, `filename`, `mime`, `size`, `sha256`, `uploaded_by`, `uploaded_at`, oraz przechowywanie (bajty albo odnośnik).
  - Użyj istniejącego mechanizmu przechowywania plików w projekcie. Sprawdź, jak robią to zgłoszenia ze zdjęciami i załączniki, i nie wymyślaj nowego.
  - Limit 15 MB. Typy: pdf, xlsx, xls, csv, jpg, png, heic, webp.
- `sealed_secrets`:
  - `id`, `province`, `key` (`zprp_sync` / `zprp_assign`), `login` (jawny);
  - `ciphertext`, `alg`, `key_id`, `created_at`, `created_by`;
  - `consumed_at`: admin oznacza „wklejone do Railway”, a szyfrogram jest wtedy kasowany.
- `onboarding_sealing_keys`: `key_id`, `public_key`, `created_at`, `revoked_at` (klucz publiczny admina).

### Kod

- 8 znaków z alfabetu bez dwuznacznych (`ABCDEFGHJKLMNPQRSTUVWXYZ23456789`), pokazywany jako `WK7Q-3MPX`.
- Serwer trzyma tylko hash. Admin widzi kod **raz**, przy wydaniu, z przyciskiem udostępnienia.
- Link: `https://www.bazapodreka.app/okreg/start#WK7Q3MPX`. Kod jest we fragmencie (`#`), więc nie leci do serwera ani do logów.
- Wejście kodem zwraca **token sesji** (HMAC, 12 h, z `province` i `code_version`). Rotacja kodu unieważnia stare tokeny.
- Limit prób: 5 na minutę na IP, po 20 nieudanych blokada IP na 1 h. Błędny kod nie zdradza, czy okręg istnieje.

### Endpointy publiczne (bez logowania)

Dopisz je do listy ścieżek klucza `www` w `CLIENT_KEYS` (`app/client_key_rules.py`), tak jak `/public/baza-stats`.

- `GET /public/onboarding/map` zwraca `[{province, stage, progress, lit: [moduły zapalone], skipped: [klucze], updated_at}]`. Bez nazwisk, bez plików.
- `POST /public/onboarding/enter` z `{code, name}` zwraca `{token, province, label}`.
- `GET /public/onboarding/sealing-key` zwraca `{key_id, public_key}`.

### Endpointy okręgu (nagłówek `X-Onboarding-Token`)

- `GET /onboarding/state`:
  - zwraca `{province, modules, items, progress, stage, events (ostatnie 50)}`;
  - pole `draft` jest tylko u kluczy z edytora.
- `PUT /onboarding/modules`: `{modules}`.
- `POST /onboarding/secret` z `{key, login, ciphertext, key_id, same_as_sync?}`:
  - status klucza przechodzi na `submitted`;
  - push do admina.
- `POST /onboarding/file` (multipart: `key`, `file`).
- `PUT /onboarding/draft/{key}`: JSON z edytora. Walidacja kompletności jest taka sama jak przy zatwierdzaniu.
- `PUT /onboarding/people/{key}` dla `keeper`, `commission`, `masters` i `mentors`.
- `POST /onboarding/skip/{key}` z `{reason?}`, oraz `POST /onboarding/unskip/{key}`.
- `GET /onboarding/judges?q=`: sędziowie TEGO okręgu (imię, nazwisko, id), od 3 znaków. Służy do wyboru masterów i mentorów.

Każdy zapis:
- dopisuje zdarzenie z podpisem (`by` = imię z wejścia);
- przelicza `progress` i `stage`;
- woła `notify_admins(kind="district_onboarding", ...)` z `app/admin_alerts.py`. Ta funkcja nigdy nie rzuca, ma deduplikację i dane do deep-linku.
- **Łącz powiadomienia**: jeden push na okręg na 10 minut, z liczbą zmian.

### Endpointy admina (`/admin`, istniejący `admin_write_guard`)

- `GET /admin/onboarding`: wszystkie okręgi.
- `GET /admin/onboarding/{province}`: pełny stan, pliki, sekrety (tylko metadane i szyfrogram).
- `POST /admin/onboarding/{province}/code`: wydaje nowy kod (zwraca go raz) i unieważnia stary.
- `POST /admin/onboarding/{province}/approve/{key}`:
  - dla `rates` i `distances` publikuje szkic przez istniejące funkcje `okreg_rates` i `okreg_distances` (nie duplikuj logiki wersjonowania);
  - dla `commission` zakłada lub aktualizuje `baza_vips`;
  - dla `masters` zapisuje masterów;
  - dla sekretów: tylko status.
- `POST /admin/onboarding/{province}/reject/{key}` z `{note}`. Okręg widzi notatkę przy kluczu.
- `POST /admin/onboarding/{province}/draft/{key}`: admin sam wpisuje szkic, gdy przepisuje plik.
- `POST /admin/onboarding/secrets/{id}/consumed`: kasuje szyfrogram.
- `PUT /admin/onboarding/sealing-key`: rejestruje nowy klucz publiczny.
- `POST /admin/onboarding/{province}/go-live`: włącza `active_provinces` i moduły z `province_modules`.

### Sejf: kryptografia

- **NaCl sealed box** (X25519 + XSalsa20-Poly1305): `tweetnacl` + `tweetnacl-sealedbox-js` (czysty JS). Działa w przeglądarce i w Hermesie, bez natywnych modułów.
- Parę kluczy generuje BAZA na telefonie admina. Klucz prywatny leży w `expo-secure-store` i nigdy nie opuszcza telefonu. Publiczny idzie na serwer.
- Strona szyfruje `{"login","password"}`, a serwer nigdy nie widzi jawnego hasła. W logach i zdarzeniach nie może być szyfrogramu ani hasła.
- Zgubiony telefon oznacza nowy klucz. Stare szyfrogramy są wtedy nieczytelne, a okręg wpisuje hasło jeszcze raz. Strona mówi o tym uczciwie.

### Blokery wielookręgowości (etap 0, przed pierwszym nowym okręgiem)

- `app/distance_table_seed.py:17` i `main.py` ~1309: seed tabeli tylko dla Śląska. Musi zostać, ale nie może blokować innych okręgów.
- `app/joomla_tables_sync.py`: na sztywno `SLASKIE` i slzpr.com.pl. Zostaw jako funkcję tylko dla Śląska i niech nie zakłada jednego okręgu gdzie indziej.
- `app/archive_rules.py:301` `_STATIC_WZPR`: sprawdź, czy dla nowych okręgów numer z listy rozgrywek działa.
- `app/match_market_rules.py` ~806 `DEFAULT_MANAGED_PREFIXES`: II ligi tylko dla 5 okręgów. Nowy okręg ma działać z pustą listą.
- `app/district_payer.py:41`: skrót tylko „ŚlZPR”. Inne okręgi dostają „Okręg X”. Zostaw, tylko sprawdź.
- `app/exam_live_brand.py`, `app/exam_print_theme.py`: barwy okręgów w kodzie. Sprawdź, czy brak barwy ma bezpieczny zapas.
- `BAZA/app/(silesia)`: sprawdź, czy treść nie zakłada Śląska dla innych okręgów.

Etap 0 to **sprawdzenie i raport**. Poprawiasz tylko to, co by się wywaliło. Nie przepisuj działającego Śląska.

## 5. Strona: bazapodreka.app/okreg/start (BAZA_web)

Trasa `app/(portal)/okreg/start.tsx` (albo `okreg-start.tsx`, jeśli `okreg.tsx` koliduje z katalogiem).
⚠ Sprawdź `vercel.json`: każda nowa trasa, która nie jest plikiem eksportu, potrzebuje rewrite. Stan na żywo z `/public/baza-stats` jest już w
`components/pod-reka/screens/district/districts.ts`. Bazuj na:
- `components/pod-reka/screens/map/polandGeo.ts` (`VOIVODESHIPS`, `POLAND_SCENE`);
- `map/canvas/geoPaths.ts`;
- `components/settlements/provinceLogo` (herby);
- `BAZA/components/admin/provinceColors.ts` (barwy z herbów; przenieś albo zduplikuj mały słownik).

Strona `/okreg` dostaje wyraźne wejście: „Wasz okręg startuje? Wejdź z kodem”.

### Scena 1. Mapa „Kolejne okręgi”

- Ciemna, ciepła noc, ta sama paleta co film i Pod Ręką.
- Polska z 16 województw. Każde to **szklane naczynie**, które napełnia się od dołu barwą z herbu okręgu do poziomu `progress`.
  - Powierzchnia ma delikatną falę: SVG `clipPath` + jedna pętla rAF, tylko gdy mapa jest widoczna.
  - Przy `prefers-reduced-motion` fala stoi.
- `live`: pełne naczynie, herb lekko świeci nad województwem, cienka złota obwódka.
- `in_progress`: poziom + liczba procent przy herbie. Pominięte klucze rysujemy kreskowaniem w cieczy.
- `waiting`: ciemne szkło, herb w półcieniu.
- Licznik w nagłówku: „Działa w 2 okręgach. Kolejne 14? Czekamy.” Liczby żywe, z poprawną odmianą liczebników.
- Najechanie lub dotknięcie województwa:
  - herb się unosi, sąsiednie województwa przygasają;
  - panel okręgu pokazuje etap, ostatnią aktywność („wczoraj”) i zapalone funkcje jako małe świecące ikony;
  - przycisk „Mam kod”.
- Telefon: mapa na całą szerokość, panel okręgu wjeżdża od dołu jako arkusz.
- Bez kodu poniżej mapy jest **wybór funkcji** (scena 4).

### Scena 2. Kod

- Wybrane województwo przybliża się płynnie (FLIP z mapy) i staje się tłem.
- Na środku **tablica wyników**: 8 klapek, jak w hali. Wpisywane znaki przeskakują klapką. Wklejenie całego kodu przelatuje kaskadą. Kod z `#` w adresie wpisuje się sam.
- Dobry kod: tablica gaśnie, a naczynie województwa nalewa się do aktualnego poziomu. Potem jedno pytanie: „Jak się podpiszesz?” (imię i nazwisko, zapamiętane w `localStorage`).
- Zły kod: tablica krótko drży i podaje jedno zdanie przyczyny. Przy blokadzie mówi, kiedy można spróbować znów.

### Scena 3. Stół okręgu

To serce strony.

- Komputer:
  - z lewej **pionowa szyna** z kluczami: gradient przez barwy kluczy, przystanki-kropki, nazwa i jednozdaniowy skutek;
  - z prawej **tablica funkcji**: sylwetki 12 funkcji z filmu (Obsada z zapisem w ZPRP, Ocena młodego, Statystyki młodego, Ryczałt + kilometry = rachunek, Moje rozliczenie, Moje statystyki, Egzamin, Teczka komisji, Wydarzenia z kodem QR, Ogłoszenia, Giełda, Kalendarz).
- Każda funkcja jest połączona cienką nitką z kluczami, których potrzebuje.
- Wgrany klucz wysyła iskrę po nitce, a funkcja **zapala się** (z ciemnej sylwetki w barwny podgląd).
- Telefon: tablica funkcji to poziomy pasek u góry, który zapala się tak samo, a pod nim szyna kluczy.
- Mini mapa w rogu: naczynie tego województwa z aktualnym poziomem.

Otwarcie klucza: na komputerze treść rozwija się w miejscu na szynie (bez modali centralnych), a na telefonie jako arkusz od dołu (260 ms easeOut). W środku:

- **Sejf** (`zprp_sync`, `zprp_assign`):
  - dwa pola: login, hasło;
  - po „Zamknij w sejfie” znaki hasła rozsypują się w szyfr (glify) i wpadają do zamka. To widoczny dowód, że hasła nie widzi nikt poza adminem.
  - Jedno zdanie: „Hasło szyfrujemy na tym urządzeniu. Odczyta je tylko administrator BAZY.”
  - Przy `zprp_assign` dodatkowo przełącznik dwóch stanów „Osobne konto / To samo co odczyt” jako segment, nie przełącznik systemowy.
- **Plik** (`rates`, `distances`):
  - cały stół staje się strefą upuszczenia, a plik wpada do szczeliny klucza;
  - pod spodem druga droga: „Wolę wpisać”.
  - Po wgraniu status „W przeglądzie”. Gdy admin przepisze plik, okręg widzi **podgląd tabeli do zatwierdzenia** („Zgadza się” albo „Popraw”).
- **Edytor**:
  - arkusz w stylu BAZA, poruszanie strzałkami, Enter i Tab;
  - **wklejanie wprost z Excela** (TSV ze schowka): wielki skrót, bo okręgi mają to w Excelu;
  - ryczałty: wiersze to kategorie lub klasy rozgrywek, kolumny to role (wg formatu `settlement_rates.py`), plus data obowiązywania;
  - odległości: lista miast, a trójkąt macierzy uzupełnia się z symetrii; licznik brakujących par i podświetlenie pustych.
- **Ludzie**:
  - wpis imienia i nazwiska z podpowiedzią z sędziów okręgu (`/onboarding/judges`);
  - osoba pojawia się jako żeton z herbem okręgu;
  - prawa (obsada, rozliczenia, admin) to trzy małe świecące glify na żetonie, zapalane dotknięciem. Żadnych checkboxów.
- **Pomiń**:
  - klucz zsuwa się z szyny do tacki „Na później” na dole;
  - funkcje, które zależą tylko od niego, przygasają z podpisem, np. „Bez tabeli kilometry policzymy z map Google”;
  - z tacki wraca jednym gestem.

Na górze stołu zostaje jedno zdanie stanu, np. „Brakuje 2 kluczy do obsady” albo „Gotowe. Czekamy na włączenie.” Bez paska postępu (postęp pokazuje naczynie). Historia „Kto co wgrał” jest zwijaną osią czasu pod szyną.

### Scena 4. Wybór funkcji (dla każdego)

- Te same 12 funkcji jako pas dużych kart sceny, z krótkimi pętlami wyciętymi z filmu (webm/mp4, po 2-3 s, bez dźwięku, `preload="none"`, odtwarzane w kadrze).
- Dotknięcie **zapala** funkcję: barwa, delikatny dźwięk wizualny (błysk), bez ptaszków.
- Obok, przyklejone na komputerze i jako dolny pasek na telefonie:
  - „Wasz zakres”: lista kluczy, które będą potrzebne (te same klucze co na stole, wygaszone);
  - cena z `price()` w `pricing.ts`, z liczbą sędziów do ustawienia.
- Z kodem wybór zapisuje się jako `modules` okręgu. Bez kodu zostaje tylko w `localStorage`, a przycisk „Mam kod” przenosi go na stół.

### Zasady (twarde, z pamięci właściciela)

- Pisz po polsku z polskimi znakami.
- Nigdy długich myślników (U+2014 i U+2013), zawsze `-`. Dotyczy UI, komentarzy i dokumentów.
- Zero kafelków w kafelkach, zero checkboxów i systemowych przełączników, zero `Alert`.
- Zero blobów jako ozdoby tła, tylko płynne gradienty.
- Zero nadtytułów: bez numerów rozdziałów i kapitalikowych kickerów nad tytułami. Sam tytuł, ewentualnie podtytuł.
- Liczebniki się odmieniają: 1 okręg, 2 okręgi, 5 okręgów.
- Animacje bez sprężyn: `timing` z `easeOut`. Lekko, bez ciężkich bibliotek.
- Tytuły i główne przyciski w Fontastique (`VoiceText` / tak jak reszta Pod Ręką), dane w Geist.
- Odmowa nigdy nie jest cicha: wygaszony element, toast albo pełny komunikat z wyjściem.
- React Native Web, pułapki:
  - `flex: 0` z szerokością zeruje element, używaj `flexShrink: 0`;
  - każdy `View` ma `z-index: 0`, więc nakładki sprawdzaj `elementFromPoint`;
  - przyciski nie mają `flex` we własnym stylu;
  - obrócony tekst potrzebuje `flexShrink: 0`.
- Jasny i ciemny motyw czytelne. Telefon 375 px i komputer 1440 px oba „wow”.
- RODO: na publicznej mapie żadnych nazwisk, a nazwiska tylko po kodzie.

## 6. BAZA (aplikacja): admin

- **Powiadomienie** `district_onboarding`: tytuł „Okręg pomorski: 3 nowe rzeczy”, treść „Ryczałty (plik), konto odczytu, 2 osoby komisji”. Deep-link do ekranu okręgu, przez istniejący mechanizm deep-linków powiadomień admina.
- **Ekran „Wdrożenia okręgów”** w panelu admina:
  - mapa-lista 16 okręgów z tym samym naczyniem postępu;
  - ekran okręgu:
    - oś czasu zdarzeń;
    - klucze ze statusem i akcjami: Zatwierdź, Odrzuć z notatką, Wpisz szkic, Podgląd pliku;
    - sejf: „Odszyfruj” (biometria przez `expo-local-authentication`, jeśli jest w projekcie), potem login i hasło z przyciskami „Kopiuj” i nazwą zmiennej Railway, a na końcu „Wklejone do Railway”, które kasuje szyfrogram;
    - kod: „Wydaj nowy kod”, pokazany raz, z udostępnieniem linku i kodem QR (`BAZA/docs` lub memory: kody QR BAZY);
    - „Włącz okręg” (go-live), gdy etap `ready`.
- Pierwsze wejście generuje parę kluczy sejfu i rejestruje klucz publiczny. W ustawieniach jest „Nowy klucz sejfu”.
- Zasady BAZA z `BAZA/CLAUDE.md`:
  - jeden modal naraz na iOS (`afterModalDismiss`);
  - arkusze GlassSheet;
  - zero `elevation`;
  - zero sprężyn.
- `tsc` w BAZA: `NODE_OPTIONS=--max-old-space-size=8192 npx tsc --noEmit` i sprawdź, czy nie ma „heap out of memory” (inaczej 0 błędów kłamie).

## 7. Etapy i kryteria końca

| Etap | Repo | Koniec, gdy |
|---|---|---|
| 0. Blokery | zprp-backend, BAZA | raport w `docs/wdrozenie-okregu-blokery.md` + poprawki tylko tego, co by padło |
| 1. Serwer | zprp-backend | tabele, endpointy, sejf (tylko szyfrogram), przeliczanie postępu, push. Testy pytest (`tests/test_district_onboarding.py`): kod, limit prób, rotacja, postęp, approve publikuje wersję `okreg_rates`, brak sekretów w zdarzeniach |
| 2. Strona | BAZA_web | sceny 1-4 działają na `/okreg/start` z prawdziwym API. Tryb podglądu z danymi przykładowymi (`?demo=1`), gdy serwer nie ma jeszcze endpointów. `tsc` czysty. Zrzuty 375 px i 1440 px, jasny i ciemny motyw. |
| 3. Admin | BAZA | ekran wdrożeń, sejf z odszyfrowaniem, powiadomienie z deep-linkiem, wydanie kodu. `tsc` czysty. |

Każde repo: osobna gałąź `wdrozenie-okregu` i PR do `master`. **Nie scalać i nie pchać na master**, bo master BAZA_web wdraża Vercel, a master backendu idzie na produkcję.

## 8. Ustalenia z realizacji (etap 1)

Kod: `app/district_onboarding_rules.py` (reguły), `app/district_onboarding.py` (trasy),
`app/district_onboarding_tables.py` (tabele). Testy: `tests/test_district_onboarding.py`.

- Klucz okręgu w nowych tabelach i w API: kanoniczny (`SLASKIE`, `KUJAWSKO_POMORSKIE`).
  Do starych tabel (`okreg_rates`, `okreg_distances`, mastersi, `active_provinces`, `baza_vips`)
  serwer pisze nazwą wyświetlaną (`ŚLĄSKIE`), tak jak robi to aplikacja.
- Trasy admina wymagają tokenu administratora ZAWSZE (`require_app_admin`), także odczyty i także
  przed `ADMIN_WRITE_STRICT`. Sam `admin_write_guard` zostawia odczyty otwarte, a tu leżą nazwiska i szyfrogramy.
- Wejście: `POST /public/onboarding/enter` z dobrym kodem i bez podpisu zwraca
  `{need_name: true, province, label}`; z podpisem zwraca token. Błędy mają `detail.message`,
  limit prób dodatkowo `detail.retry_after` (sekundy).
- `PUT /onboarding/draft/{key}` zapisuje szkic zawsze (autozapis edytora) i oddaje `errors`.
  Status `submitted` dopiero przy komplecie. Potwierdzenie szkicu admina („Zgadza się”) to ten sam PUT.
- Plik: status `in_review`. Szkic admina: `in_review` + `draft_by_admin: true`, okręg widzi podgląd.
- Kształt szkiców: ryczałty `{validFrom, content: {rola: {kategoria: kwota}}}` (role i kategorie:
  `RATE_ROLES`, `RATE_CATEGORIES`), odległości `{validFrom, cities, edges: [{from, to, distance_km}]}`.
- Ludzie: `PUT /onboarding/people/keeper` z `{person}`, pozostałe z `{people: [...]}`. Komisja:
  `login`, `rights` z `assignments | settlements | admin`. Masterzy: `judge_id`, `kinds`. Mentorzy: `role`.
- Zatwierdzenie `mentors` i `keeper` to sam status (pary mentoringu potrzebują młodego sędziego,
  zakłada je komisja w BAZA). `zprp_assign` ustawia `province_module_config.assign_account_mode`.
- `GET /onboarding/state` i stan admina niosą też `label`, `lit`, `missing`, `scope`, `files`, `catalog`
  (nazwy i skutki kluczy z serwera, jedno źródło dla strony i aplikacji).
- Plik dla admina: `GET /admin/onboarding/{province}/files/{id}`. Unieważnienie bez nowego kodu:
  `POST /admin/onboarding/{province}/code/revoke`.
- Push: rodzaj `district_onboarding`, tytuł „🗺️ Okręg pomorski: 3 nowe rzeczy”, dane
  `{alertKind, province, screen: "district_onboarding", changes}`. Pierwsza zmiana po ciszy idzie od razu,
  kolejne zbierają się do 10 minut (pamięć procesu; restart gubi najwyżej jedną paczkę).
- Zmienne Railway (opcjonalne): `ONBOARDING_CODE_PEPPER`, `ONBOARDING_TOKEN_SECRET`.
  Bez nich serwer wyprowadza je z `SECRET_KEY`.
- `CLIENT_KEYS` to zmienna Railway, nie kod: klucz strony, jeśli jest zawężony, potrzebuje
  dopisania `|/public/onboarding|/onboarding`.

### Etap 2 i 3 (strona i aplikacja)

- Strona: `BAZA_web/components/pod-reka/screens/onboarding/` (czysty DOM jak `/okreg`), trasa `app/(okreg)/okreg/start.tsx`,
  pętle z filmu w `public/okreg/petle/`. Podgląd `?demo=1` działa bez serwera.
- BAZA: `components/admin/DistrictOnboardingManager.tsx` (Panel admina › Okręg › „Wdrożenia okręgów”),
  sejf w `utils/onboardingVault.ts`. Pierwsze wejście zakłada klucz sejfu, gdy serwer nie ma żadnego;
  gdy sejf ma klucz innego telefonu, ekran mówi to wprost i daje „Przejmij sejf na ten telefon”.
  „Nowy klucz sejfu” stoi na karcie sejfu w tym ekranie, nie w ustawieniach aplikacji.
- Deep-link powiadomienia: `alertKind = district_onboarding`, okręg z `ref` (`POMORSKIE:<czas>:<liczba>`),
  bez zmian w mechanizmie odsyłaczy.


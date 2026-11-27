# Blokery wielookręgowości - wynik etapu 0 (27.11.2026)

Sprawdzone pod kątem nowego okręgu (np. POMORSKIE) włączonego w `active_provinces` i `province_modules`. Nic nie rzuca wyjątku ani nie zwraca 500, więc kod nie wymagał poprawek. Zostają miejsca, które zakładają Śląsk i są do odnotowania.

| Miejsce | Werdykt | Co się dzieje dla nowego okręgu | Poprawka |
|---|---|---|---|
| `app/distance_table_seed.py:17`, `main.py` ~1309 | OK | Seed dotyka wyłącznie wiersza `ŚLĄSKIE` w `okreg_distances`, jest w `try/except` i nie czyta innych okręgów. Tabela nowego okręgu przychodzi przez `PUT /admin/okreg_distances/{province}`, a bez niej kilometry liczy Google. | brak |
| `app/joomla_tables_sync.py` | RYZYKO | Moduł jest w całości śląski (`PROVINCE = "SLASKIE"`, slzpr.com.pl) i nie przyjmuje okręgu. Pętla w `main.py` publikuje tylko Śląsk, a panel webowy (`BAZA_web/.../TableOfficialsTab.tsx`) pokazuje historię i „Sprawdź teraz” tylko przy `isSilesia`. Inny okręg nic nie psuje. Uwaga: `POST /province/tables-publication/check-now` wymaga tylko zalogowania, więc sędzia z innego okręgu może ręcznie odpalić śląską publikację (bez szkody, publikacja jest deterministyczna i zależy od odcisku danych). | brak (do rozważenia: bramka uprawnień Śląska na `check-now`) |
| `app/archive_rules.py:301` `_STATIC_WZPR` | OK | `resolve_wzpr_code` najpierw dopasowuje okręg po `NazwaWZPR` z listy rozgrywek (pole niesie nazwę województwa, np. „POMORSKIE”), dopiero potem sięga do słownika przez `.get`. Brak okręgu w słowniku daje `None` i pusty wynik, bez wyjątku. Sprawdzone: POMORSKIE dostaje numer z listy. | brak |
| `app/match_market_rules.py` ~806 `DEFAULT_MANAGED_PREFIXES` | OK | `managed_prefixes_for` używa `.get(key, ())`, więc okręg bez wpisu ma pustą listę. POMORSKIE ma już domyślnie `IIM2`, `IIK2` (to samo co `utils/provinceTravel.ts`). Okręg może to nadpisać w panelu, także pustą listą. | brak |
| `app/district_payer.py:41` | OK | Skrót tylko dla Śląska („ŚlZPR”). Inne okręgi dostają „Okręg POMORSKIE”, nazwę zmienia panel klubów (`province_clubs.display_name` dla `OKREG`). | brak |
| `app/exam_live_brand.py` | OK | `PROVINCE_COLORS` zna wszystkie 16 województw, każde ma herb w `app/exam_live_img/okregi/`. Okręg spoza słownika przechodzi na barwy i herb ZPRP (`kind = "zprp"`), bez `KeyError`. | brak |
| `app/exam_print_theme.py` | OK | `province_theme` bierze barwy przez `.get`, a brak daje czerwień ZPRP. | brak |
| `BAZA/app/(silesia)` (ekrany) | OK | Ekrany nie mają na sztywno Śląska w treści. Nazwa, herb i barwy idą z okręgu użytkownika (`provinceLogo`, `provinceTabPalette` z zapasem, `prettyProvince`). Jedyna wzmianka to komentarz w `unavailability.tsx`. | brak |
| `BAZA/components/silesia/YoungRefereeMatchRatingsModal.tsx:485, 903, 1598` | RYZYKO | Bez okręgu w profilu (`initialProvince` puste) moduł ocen młodych pyta o `ŚLĄSKIE`. Sędzia z nowego okręgu ma okręg w profilu, więc dostaje swój. | brak |
| `BAZA/components/silesia/ProvinceTravelStatsModal.tsx:212, 276` | RYZYKO | Domyślny wybór okręgu to Śląsk tylko wtedy, gdy profil nie ma województwa. POMORSKIE jest na liście i wybiera się samo. | brak |
| `BAZA/components/MatchDetailsScreen.tsx:1015`, `components/RyczaltStats.tsx:809`, `components/silesia/MyTravelDistancesModal.tsx` | RYZYKO | Kilometry w aplikacji: najpierw tabela okręgu użytkownika, potem zawsze tabela śląska jako zapas („Tabela śląska (zapas)” w `TravelSeasonMatchList.tsx:147`), potem tabela krajowa. Dla nowego okręgu zapas trafi tylko przy parze miast obecnej w tabeli śląskiej (wyjazd na Śląsk). Serwer tego zapasu nie ma. | brak (przy wdrożeniu: zapas śląski tylko dla Śląska albo dla meczu na Śląsku) |
| `app/province_settlement_periods.py:41` | OK | Domyślne okresy rozliczeń tylko dla Śląska. Inny okręg dostaje pustą listę, czyli tryb miesięczny. | brak |
| `app/province_settlement_pdf.py:66` `ORG_DETAILS` | OK | Papier firmowy (pełna nazwa i adres) tylko dla Śląska, inne okręgi przez `.get` dostają samą nazwę. | brak |
| `app/settlement_rates.py:402` `TRIPLE_TABLE_PROVINCES` | OK | Potrójny ryczałt stolikowego tylko na Śląsku, inne okręgi go nie widzą. | brak |
| `app/province_judge_status_rules.py:24` `SEED_ACTIVE` | OK | Stan początkowy listy aktywnych sędziów tylko dla Śląska i Dolnego Śląska. Nowy okręg zaczyna od pustego stanu. | brak |
| `app/sms_config_rules.py:52` `DEFAULTS`, `app/province_club_budgets_rules.py:40` `DEFAULT_BUDGETS` | OK | Czytane przez `.get` albo pętlą po kluczach. Nowy okręg nie ma ustawień domyślnych. | brak |
| Przegląd `grep -rn "SLASKIE\|ŚLĄSKIE\|slzpr" app` | OK | Słowniki okręgów są czytane przez `.get` albo strzeżone wcześniej (`zprp_accounts.env_var_names`, `settlement_province.spellings`). `raise` dla okręgu dotyczy tylko nazw spoza 16 województw („Nieznane województwo”). | brak |

Weryfikacja: reguły (`resolve_wzpr_code`, `managed_prefixes_for`, `default_label`, `palette_for`, `crest_data_uri`, `province_theme`) uruchomione dla POMORSKIE, ŁÓDZKIE, WARMIŃSKO-MAZURSKIE, ŚWIĘTOKRZYSKIE, Kujawsko-Pomorskie, nazwy obcej i pustej. Wszystkie bez wyjątku.

## Do zrobienia przy wdrożeniu pierwszego okręgu

- Railway: `ZPRP_SYNC_<SUF>_USERNAME` i `ZPRP_SYNC_<SUF>_PASSWORD` (np. `ZPRP_SYNC_POMORSKIE_*`), przyrostek z `app/zprp_accounts.py` `PROVINCE_ENV_SUFFIXES`.
- Railway: `ZPRP_ASSIGN_<SUF>_USERNAME` i `_PASSWORD` albo `province_module_config.assign_account_mode = same_as_sync`.
- Ligi powierzone: potwierdzić z okręgiem domyślne `IIM2`, `IIK2` dla POMORSKIE albo ustawić listę w panelu (pusta lista = okręg nie prowadzi II ligi).
- Ryczałty: pierwsza wersja w `okreg_rates` (`POST /admin/okreg_rates/{province}/versions`).
- Odległości: tabela w `okreg_distances` albo świadomie pomiar Google.
- Okresy rozliczeń: jeśli okręg płaci w okresach, a nie miesiącach, ustawić je w panelu.
- Płatnik-okręg: nadać skrót związku w panelu klubów, jeśli okręg nie chce „Okręg POMORSKIE”.
- Papier firmowy rozliczeń: pełna nazwa i adres związku w `ORG_DETAILS` (`app/province_settlement_pdf.py`), inaczej nagłówek ma samą nazwę.
- Lista aktywnych sędziów: stan początkowy ustawia komisja w panelu (nie ma seeda).
- SMS: konfiguracja okręgu w panelu (brak ustawień domyślnych).

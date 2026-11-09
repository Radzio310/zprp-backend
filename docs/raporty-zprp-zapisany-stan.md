# Raporty i podsumowania ZPRP – zapisany stan okręgu (10.11.2026)

Zakładki BAZA_web „Raporty i podsumowania ZPRP” (Terminarz, Rozgrywki, Statystyki, Sędziowie i delegaci)
przy wejściu pokazują ostatni zapisany stan okręgu zamiast logować się do baza.zprp.pl za każdym razem.
Odświeżenie (↻ / „Odśwież” przy znaczniku „Stan z …”) pobiera dane z ZPRP i zapisuje je jako nowy stan
**dla całego okręgu**.

Kod: `app/zprp_report_snapshots.py` (trasy, zapis, automat), `app/zprp_report_snapshot_rules.py`
(reguły, test `tests/test_zprp_report_snapshot_rules.py`), `app/zprp_report_snapshot_tables.py`
(tabela `zprp_report_snapshots`). Front: `utils/zprpReportSnapshots.ts`, `components/zprp/SnapshotNote.tsx`.

## Skąd stan

| Rodzaj | Kształt jak trasa | Automat (okręgi z kontem `ZPRP_SYNC_*`) |
|---|---|---|
| `officials` | `/zprp/sedziowie/scrape` | co 2 h – zapisuje synchronizacja niedyspozycji (`province_offtime_sync`), zero dodatkowych logowań |
| `schedule_meta`, `schedule_full` | `/zprp/terminarz/meta`, `/scrape` | nocą (3–6) raz na dobę, bieżący sezon |
| `competitions_meta`, `competitions_lite` | `/zprp/rozgrywki/meta`, `/scrape_lite` | nocą, najnowszy sezon |
| `stats_table`, `stats_teams`, `stats_scorers` | `/zprp/statystyki/tabela`, `/druzyn`, `/strzelec` | nocą, domyślne rozgrywki (klucz pusty) |
| `schedule_slim`, statystyki innych rozgrywek | jw. | tylko ręcznie – po pierwszym pobraniu widzi je cały okręg |

Pierwszy nocny przebieg rusza ok. 10 min po starcie serwera, gdy okręg nie ma jeszcze żadnego stanu
automatycznego. Po nieudanej próbie kolejna najwcześniej po 6 h. Wyłączenie: `ZPRP_REPORT_SNAPSHOTS=0`.
Okręgi bez konta na serwerze mają tylko stany z ręcznych odświeżeń.

## Trasy (`/zprp/reports`, JWT)

- `GET /snapshot?province=&kind=&key=` → `{fetched_at, source: auto|manual, fetched_by, stale, payload}` albo 404.
- `GET /snapshots?province=` → spis bez danych.
- `POST /snapshot {province, kind, key, payload}` → zapis ręczny (nadpisuje stan okręgu).

Dostęp: administrator aplikacji – każdy okręg; konto VIP – okręg własny albo z `provinces` w uprawnieniach.
Front zapisuje stan tylko, gdy oglądany okręg to okręg konta (`vipReadProvince`), bo trasy `/zprp/*`
pobierają dane okręgu loginu ZPRP. Klucze: sezon; `sezon::kategoria::rozgrywki` (wycinek terminarza);
`sezon::rozgrywki` (statystyki, pusty = domyślne).

## Decyzje właściciela (10.11.2026)

Wszystkie cztery zakładki; automat z istniejącej synchronizacji (sędziowie co 2 h, reszta raz na dobę);
ręczne odświeżenie nadpisuje stan dla całego okręgu; okręgi bez konta – ostatnie ręczne pobranie.

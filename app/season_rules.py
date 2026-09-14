"""Sezon rozgrywkowy - JEDNA reguła dla całego backendu.

GRANICA JEST SIERPNIOWA. Mecz z 29.08.2026 należy do sezonu 2026/2027, bo
pierwsze mecze i przydziały pojawiają się w bazie związku już w sierpniu.
Do 14.09.2026 reguła żyła w dwóch kopiach i obie łamały sezon we WRZEŚNIU:
`season_of` w `app/match_bombs_rules.py` (rejestr bomb, statystyki ProEla) i
`season_of` w `app/settlement_seasons.py` (rozliczenia okręgu, zakres
odświeżania). Sierpniowe mecze wpadały przez to do poprzedniego sezonu -
w rejestrze, w statystykach i w rozliczeniach naraz.

DWA KSZTAŁTY TEJ SAMEJ ODPOWIEDZI, bo tak są używane:
  * `season_start_year` - liczba (2026), po której da się sortować,
  * `season_label_full` - „2026/2027", tekst, który przyjeżdża z ZPRP,
  * `season_label_short` - „2026/27", etykieta na przełączniku.

CZEGO TO NIE OBEJMUJE. Oceny młodych sędziów mają WŁASNĄ, wrześniową granicę
(`BAZA/utils/youngRefereeSeasons.ts`, decyzja z 12.09.2026) i tak ma zostać:
tam liczy się sezon szkoleniowy, a nie identyfikator rozgrywek. Bliźniak tej
reguły po stronie aplikacji: `BAZA/utils/zprpSeason.ts`.

MODUŁ-LIŚĆ: bez bazy i bez sieci, żeby reguła miała test.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Optional, Union

#: Miesiąc otwierający sezon (1-12). Sierpień - patrz nagłówek.
SEASON_START_MONTH = 8

DateLike = Optional[Union[date, datetime]]


def season_start_year(when: DateLike) -> Optional[int]:
    """Rok, w którym zaczął się sezon obejmujący tę datę. `None` bez daty.

    `None`, a nie „bieżący sezon": wpis bez daty nie wiadomo, gdzie należy,
    a zgadywanie przestawiłoby go w cudzym zestawieniu.
    """
    if not isinstance(when, (date, datetime)):
        return None
    return when.year if when.month >= SEASON_START_MONTH else when.year - 1


def season_label_full(year: Any) -> str:
    """„2026/2027" - postać, w której sezon przyjeżdża z ZPRP."""
    try:
        start = int(year)
    except (TypeError, ValueError):
        return ""
    return f"{start}/{start + 1}"


def season_label_short(year: Any) -> str:
    """„2026/27" - etykieta na przełączniku, ta sama co w aplikacji."""
    try:
        start = int(year)
    except (TypeError, ValueError):
        return ""
    return f"{start}/{str((start + 1) % 100).zfill(2)}"

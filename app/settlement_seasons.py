"""
Ktore sezony pobierac przy odswiezaniu danych okregu (statystyki, rozliczenia).

Regula uzytkownika (10.09.2026):
  - PIERWSZE odswiezenie w historii okregu wczytuje WSZYSTKIE dostepne sezony,
    od poczatku - jednorazowo;
  - potem kazde odswiezenie (takze dobowe) pobiera TYLKO biezacy sezon;
  - reczne puszczenie z panelu sprawdza, czy kazdy sezon byl chociaz raz
    pobrany w calosci, i nadrabia te, ktorych nie byl - zeby sedziowie
    widzieli pelne dane wstecz.

„Pobrany w calosci" = przebieg przeszedl liste meczow WSZYSTKICH sedziow dla
tego sezonu bez bledu. Rejestr tego trzyma `province_settlement_seasons`.

Sezon liczymy jak w statystykach: od wrzesnia (`2026/2027` = 1.09.2026 -
31.08.2027). To ta sama regula, ktora `/province/stats/me` przypisuje mecz do
sezonu, wiec zakres odswiezenia i ekran mowia o tych samych meczach.

MODUL-LISC - bez bazy i sieci, zeby regula miala test.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Iterable, Optional, Union

_SEASON_RE = re.compile(r"(\d{4})\s*[/-]\s*(\d{2,4})")


def season_of(when: Optional[Union[date, datetime]]) -> str:
    """Sezon meczu: `2026/2027` od wrzesnia 2026. Brak daty = pusty napis."""
    if when is None:
        return ""
    year = when.year if when.month >= 9 else when.year - 1
    return f"{year}/{year + 1}"


def normalize_season_label(text: object) -> str:
    """
    Etykieta sezonu z listy ZPRP do postaci `RRRR/RRRR`.

    Przyjmuje `2026/2027`, `2026/27`, `Sezon 2026-2027`. Wszystko, co nie jest
    para kolejnych lat, to pusty napis - lepiej pominac niz pobrac zle.
    """
    match = _SEASON_RE.search(str(text or ""))
    if not match:
        return ""
    first = int(match.group(1))
    tail = match.group(2)
    if len(tail) == 4:
        ok = int(tail) == first + 1
    else:
        # „1999/00": dwie cyfry to koncowka roku NASTEPNEGO, takze na przelomie wieku.
        ok = len(tail) == 2 and int(tail) == (first + 1) % 100
    return f"{first}/{first + 1}" if ok else ""


def plan_seasons(
    *,
    available: Iterable[object],
    completed: Iterable[str],
    current: str,
    full_check: bool,
) -> list[str]:
    """
    Sezony do pobrania w tym przebiegu - najnowszy pierwszy.

    - nic jeszcze nie pobrano w calosci -> wszystkie dostepne + biezacy,
    - reczne sprawdzenie -> dostepne, ktorych nie pobrano w calosci + biezacy,
    - poza tym -> sam biezacy.

    Sezonow „z przyszlosci" (ZPRP potrafi zalozyc nastepny sezon wczesniej)
    nie pobieramy - nie ma w nich jeszcze czego liczyc.
    """
    avail = {normalize_season_label(item) for item in available} - {""}
    done = {s for s in (normalize_season_label(c) for c in completed) if s}

    if not done:
        wanted = avail | {current}
    elif full_check:
        wanted = {s for s in avail if s not in done} | {current}
    else:
        wanted = {current}

    return sorted((s for s in wanted if s and s <= current), reverse=True)


def in_scope(
    when: Optional[Union[date, datetime]],
    scope: Optional[Iterable[str]],
    *,
    current: str,
) -> bool:
    """
    Czy mecz nalezy do zakresu przebiegu. `scope=None` = wszystko.

    Mecz bez daty liczymy do biezacego sezonu - to zwykle swiezo dopisany
    mecz, a nie historia.
    """
    if scope is None:
        return True
    return (season_of(when) or current) in set(scope)

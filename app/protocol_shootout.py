"""Seria rzutów karnych w protokole - kolejność i wiersze, bez arkusza.

Wydzielone z `app/results.py` z tego samego powodu co leasing i klucz meczu:
tamten moduł ciągnie `app.db`, więc test wymagałby żywej bazy. A tutaj chodzi
o wydruk, który sędzia podpisuje - każdy oddany rzut MUSI się w nim znaleźć,
w tej kolejności, w której padł.

Reguła kolejności jest lustrem `getTeamForShotIndex` z aplikacji
(`components/PenaltyShootoutModal.tsx`):

    cykl = shotIndex // 10          → co PIĘĆ serii zmienia się drużyna zaczynająca
    zaczyna = starter, gdy cykl parzysty; przeciwna, gdy nieparzysty

Poprzednia wersja liczyła to w arkuszu przełącznikiem `flip = not flip`
odpalanym dla KAŻDEJ serii z przedziału 6-10 zamiast raz na pięć - przez co
serie 7 i 9 wychodziły w drukowanym protokole odwrócone, a od serii 11 wszystko
było zamienione na stałe. Tu reguła jest wyliczana wprost i ma testy.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

#: Ile serii mieści się w jednym cyklu, po którym drużyny zamieniają się
#: kolejnością. Wynika z regulaminu, nie z szablonu.
SERIES_PER_CYCLE = 5

Team = str  # "host" | "guest"


def _other(team: Team) -> Team:
    return "guest" if team == "host" else "host"


def first_team_of_series(series_no: int, starter: Team) -> Team:
    """Kto wykonuje PIERWSZY rzut w danej serii (numerowanej od 1)."""
    cycle = (max(1, int(series_no)) - 1) // SERIES_PER_CYCLE
    return starter if cycle % 2 == 0 else _other(starter)


def _shot(arr: Sequence[Any], idx: int) -> Optional[Dict[str, Any]]:
    if idx < 0 or idx >= len(arr):
        return None
    x = arr[idx]
    return x if isinstance(x, dict) else None


def shootout_rows(
    shots: Dict[str, Any] | None,
    starter: Team = "guest",
) -> List[Dict[str, str]]:
    """Wiersze strony „RZUTY KARNE", po dwa na serię, w kolejności wykonania.

    Każdy wiersz to gotowy komplet napisów: numer serii, numer zawodnika po
    swojej stronie, „--" po drugiej i wynik po tym rzucie. Pudło zostawia wynik
    pusty (`--`), tak jak w formularzu związku - liczy się to, co zmienia stan.

    Wiersze powstają dla KAŻDEJ serii, w której któraś z drużyn ma zapisany
    rzut. Drużyna, która w danej serii nie strzelała (bo seria rozstrzygnęła
    mecz wcześniej), dostaje wiersz z samymi kreskami - jej rubryka w protokole
    ma zostać pusta, a nie zniknąć razem z numerem serii.
    """
    data = shots or {}
    host_arr = data.get("host") or []
    guest_arr = data.get("guest") or []
    series_count = max(len(host_arr), len(guest_arr))
    if series_count <= 0:
        return []

    starter = "host" if str(starter) == "host" else "guest"

    rows: List[Dict[str, str]] = []
    host_score = 0
    guest_score = 0

    for series_no in range(1, series_count + 1):
        idx = series_no - 1
        first = first_team_of_series(series_no, starter)

        for team in (first, _other(first)):
            arr = host_arr if team == "host" else guest_arr
            sh = _shot(arr, idx)
            player = sh.get("player") if sh else None
            try:
                result = int(sh.get("result") or 0) if sh else 0
            except (TypeError, ValueError):
                result = 0

            if result == 1:
                if team == "host":
                    host_score += 1
                else:
                    guest_score += 1
                score_host = str(host_score)
                score_guest = str(guest_score)
            else:
                score_host = "--"
                score_guest = "--"

            number = "--" if player is None else str(player)
            rows.append(
                {
                    "series": str(series_no),
                    "host": number if team == "host" else "--",
                    "guest": number if team == "guest" else "--",
                    "score_host": score_host,
                    "score_guest": score_guest,
                }
            )

    return rows


def recorded_shot_count(shots: Dict[str, Any] | None) -> int:
    """Ile rzutów faktycznie oddano - miara kontrolna dla wydruku.

    Wydruk gubiący ostatni rzut wygląda dokładnie jak wydruk kompletny, więc
    generator porównuje tę liczbę z liczbą wypełnionych wierszy i krzyczy do
    logu, gdy się nie zgadza.
    """
    data = shots or {}
    total = 0
    for side in ("host", "guest"):
        for x in data.get(side) or []:
            if isinstance(x, dict) and x.get("player") is not None:
                total += 1
    return total

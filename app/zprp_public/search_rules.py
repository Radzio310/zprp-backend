"""Szukanie po numerze meczu - reguły czyste (bez bazy).

Numer to np. "S/JmM/13", "P/JK/6", "ICM/32". Wielkość liter w numerach ma znaczenie
(JmK != JMK), więc przy kilku trafieniach pokazujemy wszystkie: najpierw te z dokładnie
tą samą pisownią, potem różniące się tylko wielkością liter, na końcu prefiksy.
Mała "l" i wielkie "I" wyglądają tak samo, więc "lcm/32" bywa "ICM/32" - próbujemy obu.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime
from typing import Any, Iterable, Optional

_NUMBER_RE = re.compile(r"^[A-Za-z]{1,6}\s*\d{1,5}$")


def fold(text: Any) -> str:
    """Małe litery, bez ogonków, bez spacji: klucz porównania numerów."""
    s = unicodedata.normalize("NFKD", str(text or "").replace("ł", "l").replace("Ł", "L"))
    s = "".join(c for c in s if not unicodedata.combining(c))
    return re.sub(r"\s+", "", s).lower()


def tidy(raw: str) -> str:
    """Fraza z usuniętymi spacjami wokół "/" i na brzegach (wielkość liter zostaje)."""
    s = re.sub(r"\s*/\s*", "/", str(raw or "").strip())
    return re.sub(r"\s+", " ", s)


def looks_like_number(raw: str) -> bool:
    s = tidy(raw)
    if "/" in s:
        return len(s) >= 3 and any(ch.isalnum() for ch in s)
    return bool(_NUMBER_RE.match(s))


def _swap_li(s: str) -> str:
    """l <-> i w części literowej przed pierwszą cyfrą/ukośnikiem (cały numer bywa wpisany małymi)."""
    out, in_letters = [], True
    for ch in s:
        if ch.isdigit() or ch == "/":
            in_letters = False
        if in_letters and ch.lower() in ("l", "i"):
            out.append("i" if ch.lower() == "l" else "l")
        else:
            out.append(ch)
    return "".join(out)


def variants(raw: str) -> list[str]:
    """Klucze (fold) do szukania prefiksu: najpierw wpisany, potem z zamianą l<->I."""
    base = fold(tidy(raw))
    keys = [base]
    swapped = fold(_swap_li(tidy(raw)))
    if swapped != base:
        keys.append(swapped)
    return keys


def rank(rows: Iterable[dict], raw: str, now: Optional[datetime] = None, current_season: Optional[str] = None) -> list[dict]:
    """Kolejność: dokładna pisownia, ten sam numer (inna wielkość liter), prefiks; potem
    wariant l<->I za wpisanym; w grupie bieżący sezon i najbliższy w czasie."""
    now = now or datetime.now()
    q = tidy(raw)
    keys = variants(raw)

    def when_gap(r: dict) -> float:
        t = r.get("scheduled_at") or r.get("played_at")
        if not isinstance(t, datetime):
            return float("inf")
        t = t.replace(tzinfo=None)
        return abs((t - now).total_seconds())

    def key(r: dict):
        code = str(r.get("match_code") or "")
        f = fold(code)
        if code == q:
            tier = 0
        elif f == keys[0]:
            tier = 1
        elif f.startswith(keys[0]):
            tier = 2
        elif f in keys[1:]:
            tier = 3
        else:
            tier = 4
        season_rank = 0 if current_season and r.get("season_id") == current_season else 1
        return (tier, season_rank, when_gap(r), code)

    return sorted(rows, key=key)

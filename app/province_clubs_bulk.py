"""
Panel klubow - akcje grupowe.

Lisc bez bazy i bez HTTP: tylko regula, co wolno zrobic jednym kliknieciem dla
wielu klubow naraz. Warstwa HTTP (`province_clubs`) zamienia ValueError na 400.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Iterable, Optional

#: Tyle klubow przyjmuje jedna akcja grupowa. Okreg ma ich od kilkudziesieciu
#: do kilkuset - wiecej to juz pomylka w zaznaczeniu, a nie praca.
BULK_LIMIT = 500


def clean_club_ids(raw: Optional[Iterable[Any]]) -> list[str]:
    """Numery klubow z zaznaczenia: bez pustych i powtorzen, w kolejnosci klikniec."""
    out: list[str] = []
    seen: set[str] = set()
    for value in raw or []:
        club_id = str(value or "").strip()
        if club_id and club_id not in seen:
            seen.add(club_id)
            out.append(club_id)
    if not out:
        raise ValueError("Nie zaznaczono żadnego klubu")
    if len(out) > BULK_LIMIT:
        raise ValueError(f"Za dużo klubów naraz - limit to {BULK_LIMIT}")
    return out


def settles_since(settles: bool, since: Optional[date], today: date) -> Optional[date]:
    """
    Od kiedy klub NIE rozlicza sie przez okreg.

    Wlaczenie czysci date - obciazenia wracaja za caly sezon, tak samo jak przy
    pojedynczym klubie. Wylaczenie dziala od podanego dnia, a bez niego od dzis:
    historia zostaje obciazona.
    """
    if settles:
        return None
    return since or today


def parse_club_filter(raw: Optional[str]) -> Optional[set[str]]:
    """`club_ids=12,15,19` z adresu szablonu. Pusty napis znaczy „wszystkie"."""
    if not raw:
        return None
    ids = {part.strip() for part in str(raw).split(",") if part.strip()}
    return ids or None

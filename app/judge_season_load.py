"""
Ile meczów w sezonie ma sędzia - boisko i stolik osobno.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby reguła chodziła w teście.

JEDNA LICZBA W TRZECH MIEJSCACH. Liczniki przy chętnych na Giełdzie meczów,
kafle sędziów w niedyspozycjach BAZA_web i panel obsadowy (Mecze, Sędziowie)
pokazują TO SAMO - więc liczy je jedna reguła, a nie trzy. Decyzja
użytkownika z 23.09.2026.

CO SIĘ LICZY:

  * sezon BIEŻĄCY (`settlement_seasons.season_of` - ta sama granica, co
    w rozliczeniach i statystykach),
  * kubełki domyślne statystyk: mecze okręgu ORAZ stoliki ligowe
    (`settlement_buckets.DEFAULT_BUCKETS`) - boiskowy albo delegat na
    szczeblu centralnym to nie jest obciążenie okręgu,
  * rozegrane RAZEM z przyszłymi, do których sędzia jest już obsadzony -
    obsadowy pyta „ile on już ma", a nie „ile już odgwizdał". Ile z tego to
    przyszłość, niesie osobne pole dla podglądu szczegółów,
  * role: boiskowy (1. i 2. sędzia) i stolikowy (sekretarz, mierzący czas).
    Delegatury NIE wchodzą - to nie jest ani boisko, ani stolik.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping, Optional

from app import settlement_buckets as B
from app import settlement_rates as R
from app.settlement_seasons import season_of


def empty() -> dict[str, int]:
    """Licznik sędziego bez meczów - ten sam kształt co z `tally`."""
    return {"field": 0, "table": 0, "future_field": 0, "future_table": 0}


def kind_of(code: Any, role: Any) -> Optional[str]:
    """`field` / `table` albo `None`, gdy obsada nie wchodzi do licznika."""
    if B.bucket_of(code, role) not in B.DEFAULT_BUCKETS:
        return None
    text = str(role or "").strip()
    if text == R.ROLE_FIELD:
        return "field"
    if text == R.ROLE_TABLE:
        return "table"
    return None


def tally(
    rows: Iterable[Mapping[str, Any]],
    *,
    now: datetime,
    season: Optional[str] = None,
) -> dict[str, dict[str, int]]:
    """
    Liczniki wszystkich sędziów z wierszy `province_settlement_matches`.

    Wiersz potrzebuje pól `judge_id`, `match_at`, `match_code`, `role`.
    Mecz bez daty nie ma sezonu, więc do licznika nie wchodzi.
    """
    wanted = season or season_of(now)
    out: dict[str, dict[str, int]] = {}
    for row in rows:
        judge_id = str(row.get("judge_id") or "").strip()
        when = row.get("match_at")
        if not judge_id or not when or season_of(when) != wanted:
            continue
        kind = kind_of(row.get("match_code"), row.get("role"))
        if not kind:
            continue
        slot = out.setdefault(judge_id, empty())
        slot[kind] += 1
        if when > now:
            slot[f"future_{kind}"] += 1
    return out

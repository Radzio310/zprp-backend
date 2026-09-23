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


def _percentile_below(values: list[int], mine: int) -> int:
    """Jaki odsetek POZOSTAŁYCH ma mniej niż ja (0-100, zaokrąglony)."""
    if not values:
        return 0
    below = sum(1 for v in values if v < mine)
    return round(100 * below / len(values))


def _median(values: list[int]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2


def compare(counts: Mapping[str, Mapping[str, int]], judge_id: str) -> dict[str, Any]:
    """
    Sędzia na tle okręgu - osobno boisko i stolik.

    Tło to AKTYWNI sędziowie: ci, którzy w sezonie mają choć jeden mecz
    (boisko albo stolik). Zera z listy okręgu zawyżałyby każdy percentyl -
    decyzja użytkownika z 23.09.2026.

    Rozkład oddajemy jako same liczby, posortowane - bez numerów i nazwisk.
    Percentyl liczymy względem pozostałych (bez siebie), więc sędzia z
    najwięcej meczami ma 100, a nie „99 z hakiem".
    """
    me = str(judge_id or "").strip()
    active = {
        jid: c for jid, c in counts.items() if (c.get("field", 0) + c.get("table", 0)) > 0
    }
    mine = counts.get(me) or empty()
    others = [c for jid, c in active.items() if jid != me]
    out: dict[str, Any] = {"active": len(active)}
    for kind in ("field", "table"):
        values = [int(c.get(kind, 0)) for c in active.values()]
        rest = [int(c.get(kind, 0)) for c in others]
        out[kind] = {
            "mine": int(mine.get(kind, 0)),
            "median": _median(values),
            "max": max(values) if values else 0,
            "percentile": _percentile_below(rest, int(mine.get(kind, 0))),
            "distribution": sorted(values),
        }
    return out

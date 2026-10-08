"""
Okresy wypłat sędziego - sama reguła (08.10.2026).

MODUŁ-LIŚĆ: bez bazy i sieci, żeby podział sezonu miał test. Trasy
w `province_settlements` (`/me/season`).

SKĄD TO SIĘ WZIĘŁO. Okręg płaci według WŁASNYCH okresów (Śląsk: 07.09-04.10,
05.10-01.11...), a aplikacja sędziego liczyła miesiące kalendarzowe. Koszty,
podatek i próg 200 zł idą od sumy okresu, więc „netto za wrzesień" w telefonie
nie było żadną kwotą, która przychodzi na konto. Decyzja użytkownika
z 08.10.2026: sędzia widzi te same okresy co panel okręgu.

ZASADY:
  - Okres okręgu (włączony) to jeden kubełek - dokładnie ten rachunek, który
    panel drukuje na Zestawieniu.
  - Dni, których nie obejmuje żaden okres (okręg bez okresów, minione sezony,
    luka w kalendarzu okręgu), idą w miesiącach kalendarzowych przyciętych do
    luki - tak liczy panel w trybie miesięcy. Nic nie znika.
  - Podatek okresu dzielimy na mecze według brutto (`share_by_gross`) tylko
    po to, żeby ekran mógł pokazać „netto meczu". Suma udziałów = podatek
    okresu co do grosza.
"""

from __future__ import annotations

import calendar
from datetime import date, timedelta
from typing import Any, Iterable, Optional

from app.season_rules import SEASON_START_MONTH
from app.settlement_money import money

PERIOD = "period"
MONTH = "month"
GAP = "gap"


def season_span(season: int) -> tuple[date, date]:
    """Sezon (rok początku) -> pierwszy i ostatni dzień (sierpień-lipiec)."""
    start = date(int(season), SEASON_START_MONTH, 1)
    end = date(int(season) + 1, SEASON_START_MONTH, 1) - timedelta(days=1)
    return start, end


def _d(value: Any) -> Optional[date]:
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value or "")[:10])
    except ValueError:
        return None


def _month_end(day: date) -> date:
    return date(day.year, day.month, calendar.monthrange(day.year, day.month)[1])


def payout_ranges(periods: Iterable[dict], start: date, end: date) -> list[dict]:
    """
    Kubełki wypłat obejmujące [start, end] - po kolei, bez dziur i zakładek.

    `periods`: okresy okręgu (`province_settlement_periods.periods_for`).
    Okres zachodzący na zakres wchodzi CAŁY (to jeden przelew), nawet gdy
    wystaje poza sezon.
    """
    chosen: list[dict] = []
    for item in periods:
        if not item.get("enabled", True):
            continue
        a, b = _d(item.get("date_from")), _d(item.get("date_to"))
        if a is None or b is None or a > b or b < start or a > end:
            continue
        payout = _d(item.get("payout_date")) or b
        chosen.append(
            {
                "id": str(item.get("id") or ""),
                "kind": PERIOD,
                "from": a,
                "to": b,
                "year": payout.year,
                "month": payout.month,
                "payout_date": payout,
                "label": str(item.get("label") or ""),
                "period_kind": str(item.get("kind") or "regular"),
            }
        )
    chosen.sort(key=lambda x: (x["from"], x["to"]))

    covered = [(x["from"], x["to"]) for x in chosen]
    out = list(chosen)
    day = start
    while day <= end:
        hit = next((b for a, b in covered if a <= day <= b), None)
        if hit is not None:
            day = hit + timedelta(days=1)
            continue
        # Luka od `day` do najbliższego okresu albo końca miesiąca.
        nxt = min((a for a, _ in covered if a > day), default=None)
        stop = min(_month_end(day), end, (nxt - timedelta(days=1)) if nxt else end)
        full = day.day == 1 and stop == _month_end(day)
        out.append(
            {
                "id": f"m:{day.year}-{day.month:02d}" if full else f"g:{day.isoformat()}",
                "kind": MONTH if full else GAP,
                "from": day,
                "to": stop,
                "year": day.year,
                "month": day.month,
                "payout_date": None,
                "label": "",
                "period_kind": "",
            }
        )
        day = stop + timedelta(days=1)
    out.sort(key=lambda x: (x["from"], x["to"]))
    return out


def range_of(ranges: Iterable[dict], day: Optional[date]) -> Optional[dict]:
    """Kubełek, w który wpada dzień - albo None."""
    if day is None:
        return None
    return next((r for r in ranges if r["from"] <= day <= r["to"]), None)


def share_by_gross(grosses: list[float], costs: float, tax: int) -> list[tuple[float, int]]:
    """
    Koszty (z groszami) i podatek (w pełnych złotych) okresu rozdzielone na
    mecze według brutto. Reszta z zaokrągleń trafia do największych meczów,
    więc sumy zgadzają się co do grosza / złotówki.
    """
    n = len(grosses)
    if n == 0:
        return []
    total = sum(max(0.0, float(g or 0)) for g in grosses)
    if total <= 0:
        return [(0.0, 0) for _ in grosses]
    order = sorted(range(n), key=lambda i: -float(grosses[i] or 0))

    def spread(amount: float, unit: float) -> list[float]:
        units = round(amount / unit)
        raw = [units * max(0.0, float(g or 0)) / total for g in grosses]
        base = [int(x) for x in raw]
        left = units - sum(base)
        by_rest = sorted(range(n), key=lambda i: (-(raw[i] - base[i]), order.index(i)))
        for i in by_rest[: max(0, left)]:
            base[i] += 1
        return [b * unit for b in base]

    cost_parts = [money(x) for x in spread(money(costs), 0.01)]
    tax_parts = [int(round(x)) for x in spread(float(int(tax or 0)), 1.0)]
    return list(zip(cost_parts, tax_parts))

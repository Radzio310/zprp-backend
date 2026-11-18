"""Minuta meczu w zapisie piłki ręcznej (18.11.2026) - jedna reguła dla całej BAZY.

0:00-0:59 = 1', 29:30 = 30', ale koniec okresu należy do JEGO ostatniej minuty: minuta nigdy nie wychodzi poza
czas gry. W meczu 2 x 30 min 30:00 = 30', 60:00 = 60' (nie 61'); w meczu 2 x 25 min 50:00 = 50'. Dogrywka:
okresy po 5 min z tym samym sufitem. `half` rozstrzyga granicę przerwy (30:00 tuż po wznowieniu = 31').
Bez długości połowy pełna minuta (60:00, 50:00) należy do minuty, która się na niej kończy.
Lustro: BAZA_web `components/pod-reka/live/clock.ts` `minuteOf`, aplikacja `MatchScreen.logic` `matchMinuteFromMs`.
"""

from __future__ import annotations

import math
from typing import Any, Optional

MIN = 60_000
SLACK = 2_000  # zegar protokołu staje ułamek sekundy za końcem okresu (60:00,4)


def match_minute(ms: Any, half_ms: Optional[Any] = None, half: Optional[int] = None) -> int:
    try:
        t = max(0, int(ms))
    except (TypeError, ValueError):
        t = 0
    raw = t // MIN + 1
    try:
        h = int(half_ms) if half_ms else 0
    except (TypeError, ValueError):
        h = 0
    if h <= 0:
        return t // MIN if t > 0 and t % MIN == 0 else raw
    full = 2 * h
    if half == 1 or (half is None and t <= h + SLACK):
        end = h
    elif t <= full + SLACK:
        end = full
    else:
        end = full + math.ceil((t - full) / 300_000) * 300_000
    return max(1, min(raw, math.ceil(end / MIN)))

"""Pamięć podręczna odpowiedzi publicznych tras transmisji (proces, krótki TTL).

Pętla w tle czyści ją po każdej zmianie (`clear`), więc nowy live pojawia się
od razu, a w spokojne minuty portal nie pyta bazy przy każdym wejściu.
"""

from __future__ import annotations

import time
from typing import Any, Awaitable, Callable

_cache: dict[str, tuple[float, Any]] = {}
_MAX = 400


async def cached(key: str, ttl: float, factory: Callable[[], Awaitable[Any]]) -> Any:
    hit = _cache.get(key)
    now = time.monotonic()
    if hit and now - hit[0] < ttl:
        return hit[1]
    value = await factory()
    if len(_cache) > _MAX:
        _cache.clear()
    _cache[key] = (now, value)
    return value


def clear() -> None:
    _cache.clear()

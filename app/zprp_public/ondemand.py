"""Pobieranie szczegółów meczu na żądanie + czysta logika priorytetów/świeżości.

Funkcje czyste (``is_finished``, ``needs_details``, ``backfill_sort_key``,
``NegativeCache``) nie dotykają bazy ani sieci - są testowane osobno.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

log = logging.getLogger(__name__)

RECENT_WINDOW = timedelta(days=3)
STALE_AFTER = timedelta(hours=6)
BACKFILL_RECENT = timedelta(days=14)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def match_moment(played_at: datetime | None, scheduled_at: datetime | None) -> datetime | None:
    return _aware(played_at) or _aware(scheduled_at)


def is_finished(score_home: Any, played_at: datetime | None, scheduled_at: datetime | None, now: datetime) -> bool:
    """Mecz rozegrany: ma wynik albo datę rozegrania w przeszłości."""
    if score_home is not None:
        return True
    played = _aware(played_at)
    return played is not None and played <= now


def needs_details(
    details_fetched_at: datetime | None,
    finished: bool,
    moment: datetime | None,
    now: datetime,
) -> bool:
    if not finished:
        return False
    fetched = _aware(details_fetched_at)
    if fetched is None:
        return True
    moment = _aware(moment)
    if moment is not None and now - moment <= RECENT_WINDOW:
        return now - fetched > STALE_AFTER
    return False


def backfill_sort_key(
    played_at: datetime | None,
    scheduled_at: datetime | None,
    score_home: Any,
    now: datetime,
) -> tuple[int, int, float]:
    """Klucz rosnący: rozegrane z ostatnich 14 dni, potem starsze rozegrane (od najnowszych), potem reszta."""
    moment = match_moment(played_at, scheduled_at)
    ts = (moment or _EPOCH).timestamp()
    if score_home is None:
        return (2, 0, -ts)
    recent = moment is not None and now - moment <= BACKFILL_RECENT
    return (0 if recent else 1, 0, -ts)


class NegativeCache:
    """Krótkotrwała pamięć nieudanych prób (nie młotkujemy upstreamu)."""

    def __init__(self, ttl: float = 120.0, clock: Callable[[], float] = time.monotonic) -> None:
        self.ttl = ttl
        self._clock = clock
        self._until: dict[str, float] = {}

    def block(self, key: str) -> None:
        self._until[key] = self._clock() + self.ttl
        if len(self._until) > 2000:
            self.purge()

    def blocked(self, key: str) -> bool:
        until = self._until.get(key)
        if until is None:
            return False
        if self._clock() >= until:
            self._until.pop(key, None)
            return False
        return True

    def purge(self) -> None:
        now = self._clock()
        for key in [k for k, v in self._until.items() if v <= now]:
            self._until.pop(key, None)


_negative = NegativeCache(ttl=float(os.getenv("ZPRP_PUBLIC_ONDEMAND_NEG_TTL", "120")))
_locks: dict[str, asyncio.Lock] = {}
_slots = asyncio.Semaphore(max(1, int(os.getenv("ZPRP_PUBLIC_ONDEMAND_CONCURRENCY", "3"))))
_client: Any = None


def _get_client() -> Any:
    global _client
    if _client is None:
        from app.zprp_public.client import PublicZprpClient

        _client = PublicZprpClient()
    return _client


async def ensure_details(match: Any) -> bool:
    """Zwraca True, gdy szczegóły są w toku/nieaktualne i nie udało się ich pobrać (``details_pending``)."""
    now = datetime.now(timezone.utc)
    moment = match_moment(match["played_at"], match["scheduled_at"])
    finished = is_finished(match["score_home"], match["played_at"], match["scheduled_at"], now)
    if not needs_details(match["details_fetched_at"], finished, moment, now):
        return False
    match_id = str(match["match_id"])
    if _negative.blocked(match_id):
        return True
    lock = _locks.setdefault(match_id, asyncio.Lock())
    if lock.locked():
        # ktoś już pobiera - poczekaj chwilę na jego wynik
        try:
            await asyncio.wait_for(lock.acquire(), timeout=4)
            lock.release()
            return False
        except asyncio.TimeoutError:
            return True
    if _slots.locked():
        return True
    try:
        async with lock:
            async with _slots:
                from app.zprp_public.sync import Counters, _sync_match_details

                counters = Counters()
                await asyncio.wait_for(
                    _sync_match_details(_get_client(), match_id, counters),
                    timeout=float(os.getenv("ZPRP_PUBLIC_ONDEMAND_TIMEOUT", "4")),
                )
            if not counters.get("match_details"):
                _negative.block(match_id)
                return True
            return False
    except Exception as exc:  # timeout, błąd upstreamu, błąd bazy
        _negative.block(match_id)
        log.warning("[zprp_public] on-demand %s: %r", match_id, exc)
        return True
    finally:
        if not lock.locked():
            _locks.pop(match_id, None)

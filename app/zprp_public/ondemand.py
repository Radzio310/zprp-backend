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


# --- Odświeżenie meczu na żądanie (wejście na stronę meczu / profil sędziego) ---
REFRESH_MIN_INTERVAL = float(os.getenv("ZPRP_PUBLIC_REFRESH_INTERVAL", "120"))
_refreshed_at: dict[str, float] = {}
_refresh_locks: dict[str, asyncio.Lock] = {}
_OFFICIAL_COLS = ("referee_1_id", "referee_1_name", "referee_2_id", "referee_2_name", "scheduled_at",
                  "venue_name", "venue_city", "score_home", "score_away", "home_team_id", "away_team_id",
                  "home_club_id", "away_club_id", "home_team_name", "away_team_name")


async def _refresh_header(match_id: str, existing: Any) -> bool:
    """Lekkie odświeżenie: tylko nagłówek meczu (obsada, termin, hala, wynik, drużyny).
    Bez składów, migawek i gzip - żadnej ciężkiej pracy na pętli zdarzeń."""
    from app.zprp_public.client import rows
    from app.zprp_public.store import now_utc, upsert_values
    from app.zprp_public.sync import _match_values
    from app.db import zprp_public_matches as M

    payload = await _get_client().get(f"pokaz_mecze_szczegoly.php?Zawody={match_id}")
    header: dict[str, Any] = {}
    if isinstance(payload, dict):
        zero = payload.get("0")
        header = zero[0] if isinstance(zero, list) and zero and isinstance(zero[0], dict) else (zero if isinstance(zero, dict) else {})
    elif isinstance(payload, list) and payload:  # goła tablica [[{...}]]
        bucket = payload[0]
        header = bucket[0] if isinstance(bucket, list) and bucket and isinstance(bucket[0], dict) else {}
    if not header:
        return False
    keep = {c: existing[c] for c in ("season_id", "competition_id", "competition_name", "round_id", "round_name",
                                      "matchday_id", "matchday_name")}
    values = _match_values(header, **keep)
    values["details_fetched_at"] = now_utc()
    # Nie ruszamy source_hash/source_json: pełny zapis zrobi synchronizacja.
    await upsert_values(M, values, key_columns=("match_id",))
    return True


async def refresh_match(match_id: str, force: bool = False) -> dict[str, Any]:
    """Pobiera mecz z ZPRP (nie częściej niż co REFRESH_MIN_INTERVAL). Nigdy nie rzuca:
    błąd/timeout = stan z bazy. Zwraca {refreshed, changed, throttled, error}."""
    from sqlalchemy import select
    from app.db import database, zprp_public_matches as M

    match_id = str(match_id)
    now = time.monotonic()
    last = _refreshed_at.get(match_id)
    if not force and last is not None and now - last < REFRESH_MIN_INTERVAL:
        return {"refreshed": False, "changed": False, "throttled": True}
    lock = _refresh_locks.setdefault(match_id, asyncio.Lock())
    if lock.locked():
        # drugie wejście czeka na to samo pobranie zamiast robić własne
        try:
            await asyncio.wait_for(lock.acquire(), timeout=10)
            lock.release()
        except asyncio.TimeoutError:
            pass
        return {"refreshed": False, "changed": False, "throttled": True}
    try:
        async with lock:
            before = await database.fetch_one(select(M).where(M.c.match_id == match_id))
            if not before:
                return {"refreshed": False, "changed": False, "throttled": False}
            async with _slots:
                ok = await asyncio.wait_for(
                    _refresh_header(match_id, before),
                    timeout=float(os.getenv("ZPRP_PUBLIC_REFRESH_TIMEOUT", "8")),
                )
            if not ok:
                _refreshed_at[match_id] = time.monotonic() - REFRESH_MIN_INTERVAL + 20  # krótka blokada po pustej odpowiedzi
                return {"refreshed": False, "changed": False, "throttled": False, "empty": True}
            _refreshed_at[match_id] = time.monotonic()
            if len(_refreshed_at) > 5000:
                cutoff = time.monotonic() - REFRESH_MIN_INTERVAL
                for k in [k for k, v in _refreshed_at.items() if v < cutoff]:
                    _refreshed_at.pop(k, None)
            after = await database.fetch_one(select(M).where(M.c.match_id == match_id))
            changed = bool(after) and any(before[c] != after[c] for c in _OFFICIAL_COLS)
            if changed:
                try:
                    from app.zprp_public import portal

                    portal.invalidate_caches()
                except Exception:  # pragma: no cover
                    log.exception("[zprp_public] invalidate_caches")
            return {"refreshed": True, "changed": changed, "throttled": False}
    except Exception as exc:
        _refreshed_at[match_id] = time.monotonic() - REFRESH_MIN_INTERVAL + 20
        log.warning("[zprp_public] refresh %s: %r", match_id, exc)
        return {"refreshed": False, "changed": False, "throttled": False, "error": True}
    finally:
        if not lock.locked():
            _refresh_locks.pop(match_id, None)

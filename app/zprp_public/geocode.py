"""Geokoder miejscowości portalu w tle (OpenStreetMap Nominatim).

Mapa, hale, mecze i atlasy (klub, drużyna, sędzia) biorą współrzędne z jednej
funkcji: `portal_rules.resolve_city` (tabela odległości -> skorowidz GeoNames ->
ta pamięć). Tu dokładamy trzecie źródło dla nazw, których dwa pierwsze nie znają:

* `run_geocode_scheduler` - lekka pętla startowana w `main.py` (wyłącznik:
  `GEOCODE_DISABLED=1`); co cykl najwyżej `GEOCODE_BATCH` nazw, 1 zapytanie/s,
* kolejność: miasta meczów najbliższych w czasie, potem kluby, potem reszta hal,
* wynik na zawsze w `zprp_public_geocode_cache`; porażka wraca po 30 dniach,
* `cache_lookup()` - słownik w pamięci (odświeżany co 5 min) do `resolve_city`.

Bez środków województw ani innych przybliżeń: lepiej brak pinezki niż zła.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import httpx
from sqlalchemy import and_, func, insert, select, update

from app.national_place_rules import province_label
from app.zprp_public import geocode_rules as G
from app.zprp_public import portal_rules as R

log = logging.getLogger(__name__)

_CACHE_TTL = 300.0
_mem: dict[str, Any] = {"at": 0.0, "points": {}}


class TransientGeocodeError(Exception):
    """Sieć, 429 albo 5xx - nie zapisujemy porażki, przerywamy cykl."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


# ---------------------------------------------------------------------------
# Odczyt pamięci (dla resolve_city)
# ---------------------------------------------------------------------------


async def cached_points(force: bool = False) -> dict[str, dict]:
    """city_norm -> {lat, lon, name, province} (tylko trafienia)."""
    if not force and _mem["at"] and time.monotonic() - _mem["at"] < _CACHE_TTL:
        return _mem["points"]
    try:
        from app.db import database, zprp_public_geocode_cache as T

        rows = await database.fetch_all(
            select(T.c.city_norm, T.c.city, T.c.lat, T.c.lon, T.c.province)
            .where(and_(T.c.failed.is_(False), T.c.lat.is_not(None), T.c.lon.is_not(None)))
        )
        points = {
            r["city_norm"]: {"lat": float(r["lat"]), "lon": float(r["lon"]), "name": r["city"], "province": r["province"] or ""}
            for r in rows
        }
    except Exception:  # noqa: BLE001 - brak tabeli (stara baza, testy) = brak trzeciego źródła
        log.debug("Pamięć geokodera niedostępna", exc_info=True)
        points = _mem["points"]
    _mem.update(at=time.monotonic(), points=points)
    return points


async def cache_lookup() -> Callable[[str], Optional[dict]]:
    points = await cached_points()
    return points.get


def invalidate() -> None:
    _mem["at"] = 0.0


# ---------------------------------------------------------------------------
# Kandydaci
# ---------------------------------------------------------------------------


async def _candidate_rows(now: datetime) -> tuple[list[dict], list[dict], list[dict]]:
    from app.db import (
        database,
        zprp_public_associations as A,
        zprp_public_clubs as C,
        zprp_public_matches as M,
    )

    naive = now.astimezone(timezone.utc).replace(tzinfo=None) if now.tzinfo else now
    assoc_rows, club_rows, window_rows, venue_rows = await asyncio.gather(
        database.fetch_all(select(A.c.association_id, A.c.name)),
        database.fetch_all(select(C.c.club_id, C.c.city, C.c.association_id).where(C.c.archived.is_(False))),
        database.fetch_all(
            select(M.c.venue_city, M.c.scheduled_at, M.c.home_club_id)
            .where(and_(M.c.venue_city.is_not(None), M.c.scheduled_at >= naive - timedelta(days=14),
                        M.c.scheduled_at <= naive + timedelta(days=30)))
        ),
        database.fetch_all(
            select(M.c.venue_city, M.c.home_club_id, func.count().label("n"))
            .where(and_(M.c.venue_city.is_not(None), M.c.scheduled_at >= naive - timedelta(days=400)))
            .group_by(M.c.venue_city, M.c.home_club_id)
        ),
    )
    hint_of_assoc = {r["association_id"]: R.province_hint(r["name"]) for r in assoc_rows}
    club_hint = {r["club_id"]: hint_of_assoc.get(r["association_id"], "") for r in club_rows}
    matches = [{"city": r["venue_city"], "hint": club_hint.get(r["home_club_id"], ""), "scheduled_at": r["scheduled_at"]}
               for r in window_rows]
    clubs = [{"city": r["city"], "hint": club_hint.get(r["club_id"], "")} for r in club_rows if r["city"]]
    venues = [{"city": r["venue_city"], "hint": club_hint.get(r["home_club_id"], ""), "n": r["n"]} for r in venue_rows]
    return matches, clubs, venues


async def pending_candidates(now: Optional[datetime] = None) -> list[dict]:
    """Nazwy bez współrzędnych w tabeli odległości i skorowidzu, którym należy się
    (ponowne) zapytanie - w kolejności ważności."""
    from app.db import database, zprp_public_geocode_cache as T
    from app.zprp_public.portal import _gazetteer_lookup, _node_index

    now = now or _now()
    matches, clubs, venues = await _candidate_rows(now)
    ordered = G.order_candidates(matches, clubs, venues, now.replace(tzinfo=None))
    if not ordered:
        return []
    index = await _node_index()
    gazetteer = await _gazetteer_lookup()
    known = {r["city_norm"]: dict(r) for r in await database.fetch_all(select(T))}
    out = []
    for cand in ordered:
        if R.resolve_city(cand["city"], index, cand["hint"], gazetteer):
            continue
        display = R.display_city(cand["city"])
        key = G.city_norm(display)
        if not key or not G.due_for_lookup(known.get(key), now):
            continue
        out.append({**cand, "display": display, "city_norm": key, "attempts": int((known.get(key) or {}).get("attempts") or 0)})
    return out


# ---------------------------------------------------------------------------
# Zapytanie i zapis
# ---------------------------------------------------------------------------


async def lookup(client: httpx.AsyncClient, display: str, hint: str = "") -> tuple[Optional[dict], str]:
    """Nominatim dla jednej nazwy: (punkt albo None, zapytana nazwa). Wyjątek
    `TransientGeocodeError` przy sieci/429/5xx (bez zapisu porażki)."""
    state = f"województwo {province_label(hint)}" if hint and province_label(hint) else ""
    asked = display
    for name in G.query_names(display):
        asked = name
        try:
            async with G.NOMINATIM_LIMITER.slot():
                response = await client.get(G.NOMINATIM_URL, params=G.query_params(name, state),
                                            headers={"User-Agent": G.USER_AGENT})
        except httpx.HTTPError as exc:
            raise TransientGeocodeError(str(exc)) from exc
        if response.status_code == 429 or response.status_code >= 500:
            raise TransientGeocodeError(f"HTTP {response.status_code}")
        if response.status_code >= 400:
            return None, asked
        try:
            payload = response.json()
        except ValueError:
            return None, asked
        hit = G.parse_nominatim(payload, name)
        if hit:
            return hit, name
    return None, asked


async def store(key: str, city: str, hint: str, hit: Optional[dict], asked: str, attempts: int,
                now: Optional[datetime] = None) -> None:
    from app.db import database, zprp_public_geocode_cache as T

    now = now or _now()
    values = {
        "city": city, "query": asked, "looked_up_at": now, "attempts": attempts + 1, "source": "nominatim",
        "failed": hit is None,
        "lat": hit["lat"] if hit else None, "lon": hit["lon"] if hit else None,
        "province": hint or None,
        "display_name": (hit or {}).get("display_name"), "place_type": (hit or {}).get("place_type"),
    }
    exists = await database.fetch_val(select(T.c.city_norm).where(T.c.city_norm == key))
    if exists:
        await database.execute(update(T).where(T.c.city_norm == key).values(**values))
        return
    try:
        await database.execute(insert(T).values(city_norm=key, **values))
    except Exception:  # noqa: BLE001 - druga replika była szybsza: wiersz już jest
        await database.execute(update(T).where(T.c.city_norm == key).values(**values))


async def run_cycle(client: Optional[httpx.AsyncClient] = None, max_lookups: int = 60,
                    now: Optional[datetime] = None) -> dict[str, int]:
    """Jeden przebieg: najwyżej `max_lookups` nazw. Zwraca liczniki do logu."""
    candidates = await pending_candidates(now)
    stats = {"pending": len(candidates), "found": 0, "failed": 0, "transient": 0}
    if not candidates:
        return stats
    own = client is None
    client = client or httpx.AsyncClient(timeout=10.0, headers={"User-Agent": G.USER_AGENT})
    try:
        for cand in candidates[:max_lookups]:
            try:
                hit, asked = await lookup(client, cand["display"], cand["hint"])
            except TransientGeocodeError as exc:
                log.info("[geocode] przerwa: %s", exc)
                stats["transient"] += 1
                break
            await store(cand["city_norm"], cand["display"], cand["hint"], hit, asked, cand["attempts"], now)
            stats["found" if hit else "failed"] += 1
    finally:
        if own:
            await client.aclose()
    if stats["found"]:
        invalidate()
        try:
            from app.zprp_public import portal

            portal._map_cache.clear()
        except Exception:  # noqa: BLE001
            pass
    return stats


async def run_geocode_scheduler() -> None:
    """Pętla w tle. `GEOCODE_DISABLED=1` wyłącza; `GEOCODE_BATCH` (60) nazw na cykl,
    `GEOCODE_INTERVAL_SECONDS` (1800) przerwy, gdy kolejka pusta."""
    if _flag("GEOCODE_DISABLED"):
        log.info("[geocode] wyłączony przez GEOCODE_DISABLED")
        return
    await asyncio.sleep(max(5, _int_env("GEOCODE_START_DELAY_SECONDS", 120)))
    batch = max(1, _int_env("GEOCODE_BATCH", 60))
    idle = max(60, _int_env("GEOCODE_INTERVAL_SECONDS", 1800))
    while True:
        pause = idle
        try:
            stats = await run_cycle(max_lookups=batch)
            if stats["pending"]:
                log.info("[geocode] cykl: %s", stats)
            if stats["transient"]:
                pause = 3600
            elif stats["pending"] > batch:
                pause = 60
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("[geocode] błąd cyklu")
        await asyncio.sleep(pause)

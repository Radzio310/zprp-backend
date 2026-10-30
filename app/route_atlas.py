"""
Atlas tras - JEDNO trwale zrodlo odleglosci drogowych backendu, BAZA_web i BAZA.

Kazda pare miejsc mierzymy w Google RAZ (metoda bez zmian: cztery zapytania
Directions, wynik = najkrotsza, `google_route_verdict`) i zapamietujemy na
stale: km, zakodowana polilinie, zrodlo, date pomiaru i licznik uzyc.

Zasady:
  * pomiar starszy niz 6 miesiecy jest powtarzany przy nastepnym uzyciu
    (leniwie); gdy ponowny pomiar sie nie uda, oddajemy stary wynik;
  * porazki sa pamietane z terminem: blad przejsciowy 1 h (rosnie do doby),
    ZERO_RESULTS/NOT_FOUND 30 dni, brak geometrii 30 dni;
  * ta sama para pytana rownolegle = jedno zapytanie do Google;
  * rownoleglosc pomiarow ograniczona globalnie (nie na zadanie);
  * limit NOWYCH pomiarow na wywolanie (`max_new`) - zapora na rachunek.

Czesc czysta (klucze, terminy) jest w `route_atlas_rules`; magazyn jest
wymienny (`AtlasStore`), wiec serwis sprawdza sie testem bez bazy.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional, Protocol

from app import route_atlas_rules as R
from app.route_atlas_rules import Endpoint

logger = logging.getLogger(__name__)

#: Ile par mierzymy w Google naraz (4 zapytania na pare) - globalnie.
GOOGLE_PAIR_CONCURRENCY = 6


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Pair:
    origin: Endpoint
    destination: Endpoint


@dataclass
class Result:
    """Odpowiedz dla jednej pary (w kolejnosci wejscia)."""

    key: str = ""
    km: Optional[float] = None
    encoded: str = ""
    source: str = ""
    measured_at: Optional[datetime] = None
    #: trasa "Domyslna"; None = brak (stary wpis) - klient liczy ja sam
    default_km: Optional[float] = None
    default_encoded: str = ""
    #: "cached" | "measured" | "same" | "stale" | "missing"
    status: str = "missing"
    #: gdy missing: "invalid" | "no_route" | "retry_later" | "budget" | "no_key" | "error"
    reason: str = ""


class AtlasStore(Protocol):
    async def get_many(self, keys: list[str]) -> dict[str, dict]: ...
    async def failures_many(self, keys: list[str]) -> dict[str, dict]: ...
    async def upsert(self, row: dict) -> None: ...
    async def touch(self, keys: list[str], now: datetime) -> None: ...
    async def set_failure(self, key: str, kind: str, now: datetime) -> None: ...
    async def clear_failure(self, key: str) -> None: ...


# ---------------------------------------------------------------------------
# Pomiar (jedno zapytanie w locie na klucz)
# ---------------------------------------------------------------------------

_in_flight: dict[str, "asyncio.Future"] = {}
_semaphore: Optional[asyncio.Semaphore] = None
_semaphore_loop: Any = None
_shared_client: Any = None


def _gate() -> asyncio.Semaphore:
    global _semaphore, _semaphore_loop
    loop = asyncio.get_running_loop()
    if _semaphore is None or _semaphore_loop is not loop:
        _semaphore = asyncio.Semaphore(GOOGLE_PAIR_CONCURRENCY)
        _semaphore_loop = loop
    return _semaphore


def _client() -> Any:
    global _shared_client
    if _shared_client is None or getattr(_shared_client, "is_closed", False):
        from httpx import AsyncClient

        _shared_client = AsyncClient(timeout=20.0)
    return _shared_client


@dataclass
class _Outcome:
    km: Optional[float]
    encoded: str
    #: "ok" | "no_route" | "transient" | "no_key"
    kind: str
    #: trasa domyslna z pierwszego zapytania werdyktu (None = nie wiemy)
    default_km: Optional[float] = None
    default_encoded: str = ""


def _query(endpoint: Endpoint, *, with_region: bool) -> str:
    name = endpoint.name.strip() or ""
    if endpoint.address:
        name = f"{endpoint.address.strip()}, {name}" if name else endpoint.address.strip()
    if with_region and endpoint.region and name:
        name = f"{name}, {endpoint.region.strip()}"
    return name


async def _google_measure(pair: Pair, client: Any) -> _Outcome:
    from app import settlement_distances as SD

    if not SD.GOOGLE_MAPS_API_KEY:
        return _Outcome(None, "", "no_key")
    a, b = pair.origin, pair.destination
    pa = R.valid_point(a.lat, a.lon) or a.hint
    pb = R.valid_point(b.lat, b.lon) or b.hint
    origin = _query(a, with_region=False) or (f"{pa[0]},{pa[1]}" if pa else "")
    destination = _query(b, with_region=True) or (f"{pb[0]},{pb[1]}" if pb else "")
    km, encoded, definitive, default = await SD.google_route_full(
        client, origin, destination, a.region, pa, pb
    )
    if km is not None:
        return _Outcome(
            km, encoded or "", "ok",
            default_km=default[0] if default else None,
            default_encoded=(default[1] or "") if default else "",
        )
    return _Outcome(None, "", "no_route" if definitive else "transient")


Measure = Callable[[Pair, Any], Awaitable[_Outcome]]


async def _measure_shared(key: str, pair: Pair, client: Any, measure: Measure) -> _Outcome:
    """Ta sama para rownolegle = jedno zapytanie: kolejni czekaja na pierwszego."""
    existing = _in_flight.get(key)
    if existing is not None:
        return await asyncio.shield(existing)
    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()
    _in_flight[key] = future

    async def run() -> None:
        try:
            async with _gate():
                outcome = await measure(pair, client)
        except Exception as exc:  # pomiar nigdy nie wywraca wolajacego
            logger.debug("[atlas] pomiar %s: %s", key, exc)
            outcome = _Outcome(None, "", "transient")
        finally:
            _in_flight.pop(key, None)
        if not future.done():
            future.set_result(outcome)

    asyncio.ensure_future(run())
    return await asyncio.shield(future)


# ---------------------------------------------------------------------------
# Glowne wejscie
# ---------------------------------------------------------------------------

async def resolve(
    pairs: list[Pair],
    *,
    store: Optional[AtlasStore] = None,
    client: Any = None,
    max_new: Optional[int] = None,
    need_shape: bool = False,
    now: Optional[datetime] = None,
    measure: Optional[Measure] = None,
    on_progress: Optional[Callable[[int, int], Any]] = None,
) -> list[Result]:
    """
    Wynik dla kazdej pary (ta sama kolejnosc). Nie rzuca przy bledzie Google.

    * `max_new` - ile NOWYCH pomiarow wolno wykonac (None = bez limitu). Para
      doczepiona do pomiaru, ktory juz trwa, nie liczy sie do limitu.
    * `need_shape` - wiersz bez polilinii traktujemy jak brakujacy (raz na
      30 dni, potem zostaja same km).
    """
    store = store or DbStore()
    measure = measure or _google_measure
    now = now or _now()
    results: list[Result] = [Result() for _ in pairs]
    keys: list[str] = []
    for index, pair in enumerate(pairs):
        key = R.pair_key(pair.origin, pair.destination)
        keys.append(key)
        if not key:
            results[index].reason = "invalid"
            continue
        if R.endpoint_key(pair.origin) == R.endpoint_key(pair.destination):
            results[index] = Result(key=key, km=0.0, source="same-place", status="same")

    unique: dict[str, Pair] = {}
    for index, key in enumerate(keys):
        if key and results[index].status != "same":
            unique.setdefault(key, pairs[index])
    if not unique:
        return results

    rows = await store.get_many(list(unique))
    fails = await store.failures_many(list(unique))

    decided: dict[str, Result] = {}
    todo: list[str] = []
    used: list[str] = []
    for key in unique:
        row = rows.get(key)
        fail = fails.get(key)
        fail_live = bool(fail and fail["retry_after"] > now)
        blocked = fail_live and fail["kind"] in ("transient", "no_route")
        if row is not None:
            fresh = R.is_fresh(row["measured_at"], now)
            shape_ok = (not need_shape) or bool(row.get("encoded")) or (
                fail_live and fail["kind"] == "noshape"
            )
            if (fresh and shape_ok) or blocked:
                decided[key] = _from_row(key, row, "cached" if fresh else "stale")
                used.append(key)
                continue
            todo.append(key)
            continue
        if blocked:
            decided[key] = Result(
                key=key, status="missing",
                reason="no_route" if fail["kind"] == "no_route" else "retry_later",
            )
            continue
        todo.append(key)

    budget = None if max_new is None else max(0, int(max_new))
    client = client or _client()
    scheduled: list[str] = []
    for key in todo:
        if key in _in_flight:
            scheduled.append(key)
            continue
        if budget is not None and budget <= 0:
            row = rows.get(key)
            decided[key] = (
                _from_row(key, row, "stale") if row
                else Result(key=key, status="missing", reason="budget")
            )
            continue
        if budget is not None:
            budget -= 1
        scheduled.append(key)

    done = 0
    total = len(scheduled)

    async def one(key: str) -> None:
        nonlocal done
        outcome = await _measure_shared(key, unique[key], client, measure)
        decided[key] = await _settle(key, unique[key], outcome, rows.get(key), store, now, need_shape)
        if decided[key].km is not None:
            used.append(key)
        done += 1
        if on_progress is not None:
            try:
                value = on_progress(done, total)
                if asyncio.iscoroutine(value):
                    await value
            except Exception:
                pass  # postep to wygoda, nie warunek pomiaru

    if scheduled:
        await asyncio.gather(*(one(key) for key in scheduled))

    if used:
        try:
            await store.touch(used, now)
        except Exception as exc:
            logger.debug("[atlas] licznik uzyc: %s", exc)

    for index, key in enumerate(keys):
        if key and results[index].status != "same":
            results[index] = decided[key]
    return results


def _from_row(key: str, row: dict, status: str) -> Result:
    return Result(
        key=key,
        km=float(row["km"]),
        encoded=row.get("encoded") or "",
        source=row.get("source") or "",
        measured_at=row.get("measured_at"),
        default_km=float(row["default_km"]) if row.get("default_km") else None,
        default_encoded=row.get("default_polyline") or "",
        status=status,
    )


async def _settle(
    key: str, pair: Pair, outcome: _Outcome, old: Optional[dict],
    store: AtlasStore, now: datetime, need_shape: bool,
) -> Result:
    """Zapisuje wynik pomiaru (albo porazke) i sklada odpowiedz."""
    if outcome.kind == "ok" and outcome.km is not None:
        encoded = outcome.encoded or ""
        row = {
            "pair_key": key,
            "from_label": (pair.origin.name or R.endpoint_key(pair.origin))[:200],
            "to_label": (pair.destination.name or R.endpoint_key(pair.destination))[:200],
            "km": float(outcome.km),
            "encoded": encoded,
            "source": R.SOURCE_MEASURED,
            "default_km": float(outcome.default_km) if outcome.default_km else None,
            "default_polyline": (outcome.default_encoded or None) if outcome.default_km else None,
            "measured_at": now,
        }
        try:
            await store.upsert(row)
            if encoded or not need_shape:
                await store.clear_failure(key)
            else:
                await store.set_failure(key, "noshape", now)
        except Exception as exc:
            logger.warning("[atlas] zapis %s: %s", key, exc)
        return Result(
            key=key, km=row["km"], encoded=encoded, source=R.SOURCE_MEASURED,
            measured_at=now, status="measured",
            default_km=row["default_km"], default_encoded=row["default_polyline"] or "",
        )
    reason = {"no_route": "no_route", "no_key": "no_key"}.get(outcome.kind, "error")
    if outcome.kind in ("no_route", "transient"):
        try:
            await store.set_failure(key, outcome.kind, now)
        except Exception as exc:
            logger.warning("[atlas] porazka %s: %s", key, exc)
    if old is not None:
        # Ponowny pomiar sie nie udal - stary wynik lepszy niz nic.
        return _from_row(key, old, "stale")
    return Result(key=key, status="missing", reason=reason)


# ---------------------------------------------------------------------------
# Magazyn w bazie
# ---------------------------------------------------------------------------

CHUNK = 500


class DbStore:
    """`route_atlas` + `route_atlas_failures` w Postgresie."""

    async def get_many(self, keys: list[str]) -> dict[str, dict]:
        from sqlalchemy import select

        from app.db import database, route_atlas as T

        out: dict[str, dict] = {}
        for start in range(0, len(keys), CHUNK):
            rows = await database.fetch_all(
                select(T.c.pair_key, T.c.km, T.c.encoded, T.c.source, T.c.measured_at,
                       T.c.default_km, T.c.default_polyline)
                .where(T.c.pair_key.in_(keys[start:start + CHUNK]))
            )
            for r in rows:
                out[r["pair_key"]] = {
                    "km": r["km"], "encoded": r["encoded"], "source": r["source"],
                    "measured_at": r["measured_at"],
                    "default_km": r["default_km"], "default_polyline": r["default_polyline"],
                }
        return out

    async def failures_many(self, keys: list[str]) -> dict[str, dict]:
        from sqlalchemy import select

        from app.db import database, route_atlas_failures as F

        out: dict[str, dict] = {}
        for start in range(0, len(keys), CHUNK):
            rows = await database.fetch_all(
                select(F.c.pair_key, F.c.kind, F.c.attempts, F.c.retry_after)
                .where(F.c.pair_key.in_(keys[start:start + CHUNK]))
            )
            for r in rows:
                out[r["pair_key"]] = {
                    "kind": r["kind"], "attempts": r["attempts"], "retry_after": r["retry_after"],
                }
        return out

    async def upsert(self, row: dict) -> None:
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        from app.db import database, route_atlas as T

        statement = pg_insert(T).values(**row, uses=0)
        update = {k: v for k, v in row.items() if k != "pair_key"}
        await database.execute(
            statement.on_conflict_do_update(index_elements=[T.c.pair_key], set_=update)
        )

    async def touch(self, keys: list[str], now: datetime) -> None:
        from sqlalchemy import update

        from app.db import database, route_atlas as T

        for start in range(0, len(keys), CHUNK):
            await database.execute(
                update(T)
                .where(T.c.pair_key.in_(keys[start:start + CHUNK]))
                .values(uses=T.c.uses + 1, last_used_at=now)
            )

    async def set_failure(self, key: str, kind: str, now: datetime) -> None:
        from sqlalchemy import select
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        from app.db import database, route_atlas_failures as F

        attempts = 1
        if kind == "transient":
            old = await database.fetch_one(select(F.c.attempts, F.c.kind).where(F.c.pair_key == key))
            if old is not None and old["kind"] == "transient":
                attempts = int(old["attempts"] or 1) + 1
        values = {
            "kind": kind, "attempts": attempts, "checked_at": now,
            "retry_after": R.retry_after(kind, attempts, now),
        }
        await database.execute(
            pg_insert(F).values(pair_key=key, **values)
            .on_conflict_do_update(index_elements=[F.c.pair_key], set_=values)
        )

    async def clear_failure(self, key: str) -> None:
        from sqlalchemy import delete

        from app.db import database, route_atlas_failures as F

        await database.execute(delete(F).where(F.c.pair_key == key))


# ---------------------------------------------------------------------------
# Przejecie istniejacych pomiarow (bez ponownego pomiaru)
# ---------------------------------------------------------------------------

MIGRATION_MARKER = "~~migrated-v1~~"
#: Domy, ktorych stare pomiary trafily w imiennika - nie przejmujemy ich
#: (to samo robila pamiec rozliczen: `REMEASURE_ORIGINS`).
_SKIP_ORIGINS = frozenset({"naklo slaskie"})


async def migrate_legacy_once() -> dict:
    """
    `city_distances` + `city_route_shapes` + `settlement_pair_failures` -> atlas.
    Idempotentne (ON CONFLICT DO NOTHING) i jednorazowe (znacznik), uruchamiane
    w tle przy starcie. Nie usuwa niczego ze starych tabel.
    """
    from sqlalchemy import select
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.db import (
        city_distances, city_route_shapes, database, route_atlas as T,
        route_atlas_failures as F, settlement_pair_failures,
    )

    marker = await database.fetch_one(select(T.c.pair_key).where(T.c.pair_key == MIGRATION_MARKER))
    if marker is not None:
        return {"skipped": True}

    now = _now()
    shapes: dict[tuple[str, str], str] = {}
    for r in await database.fetch_all(select(city_route_shapes)):
        shapes[(r["from_key"], r["to_key"])] = r["encoded"] or ""

    atlas_rows: dict[str, dict] = {}
    for r in await database.fetch_all(select(city_distances)):
        left, right = str(r["from_key"] or ""), str(r["to_key"] or "")
        if not left or not right or r["km"] is None:
            continue
        stamp = r["updated_at"] or now
        if r["source"] == "google-shortest-r3":
            if left.split("|")[0] in _SKIP_ORIGINS:
                continue
            key, source = f"{left}>{right}", R.SOURCE_MEASURED
            encoded = shapes.get((left, right), "")
        elif r["source"] == "google":
            a, b = (left, right) if left <= right else (right, left)
            key, source, encoded = f"{a}~{b}", R.SOURCE_LEGACY, ""
        else:
            continue
        atlas_rows[key] = {
            "pair_key": key, "from_label": left[:200], "to_label": right[:200],
            "km": float(r["km"]), "encoded": encoded, "source": source, "measured_at": stamp,
        }

    failure_rows: dict[str, dict] = {}
    for r in await database.fetch_all(select(settlement_pair_failures)):
        left, right = str(r["from_key"] or ""), str(r["to_key"] or "")
        key = f"{left}>{right}"
        stamp = r["checked_at"] or now
        if r["kind"] == "nokm" and key not in atlas_rows:
            kind, until = "no_route", stamp + R.NO_ROUTE_RETRY
        elif r["kind"] == "noshape":
            kind, until = "noshape", stamp + R.NO_SHAPE_RETRY
        else:
            continue
        if until > now:
            failure_rows[key] = {
                "pair_key": key, "kind": kind, "attempts": 1, "checked_at": stamp, "retry_after": until,
            }

    values = list(atlas_rows.values())
    for start in range(0, len(values), CHUNK):
        await database.execute(
            pg_insert(T).values([{**v, "uses": 0} for v in values[start:start + CHUNK]])
            .on_conflict_do_nothing(index_elements=[T.c.pair_key])
        )
    fvalues = list(failure_rows.values())
    for start in range(0, len(fvalues), CHUNK):
        await database.execute(
            pg_insert(F).values(fvalues[start:start + CHUNK])
            .on_conflict_do_nothing(index_elements=[F.c.pair_key])
        )
    await database.execute(
        pg_insert(T).values(
            pair_key=MIGRATION_MARKER, from_label="", to_label="", km=0.0,
            source="meta", measured_at=now, uses=0,
        ).on_conflict_do_nothing(index_elements=[T.c.pair_key])
    )
    logger.info("[atlas] przejęto %d tras i %d porażek z tabel sprzed atlasu", len(values), len(fvalues))
    return {"routes": len(values), "failures": len(fvalues)}


async def run_migration_safely() -> None:
    try:
        await migrate_legacy_once()
    except Exception:
        logger.exception("[atlas] przejęcie starych pomiarów nie powiodło się")

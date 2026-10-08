"""Ogólnopolska tabela odległości z oficjalnych ryczałtów PDF ZPRP.

Telefon przekazuje wyłącznie znalezione na zalogowanej liście adresy ryczałtów
oraz zaszyfrowane poświadczenia. Endpoint rezerwuje nowe dokumenty i od razu
odpowiada 202. Logowanie, pobranie i analiza PDF odbywają się później w zadaniu
w tle - odświeżanie meczów nigdy na nie nie czeka.

PDF nie jest zapisywany na dysku. Po wydobyciu miast i kilometrów znika razem
z buforem odpowiedzi, a poświadczenia żyją tylko w pamięci jednego zadania.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import gzip
import json
import logging
import math
from typing import Any, Optional

import time

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import national_lookup_rules as NL
from app import national_route_shape as RS
from app.db import (
    database,
    national_distance_cities,
    national_distance_connections,
    national_distance_judges,
    national_distance_sources,
)
from app.deps import Settings, get_rsa_keys, get_settings
from app.national_distance_progress import routes_from_home, summarize_sources
from app.national_distance_parser import (
    ParsedSettlement,
    normalize_city_key,
    parse_settlement_pdf,
    validate_settlement_candidate,
)
from app.zprp_session import decrypt_field, login_and_client

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/national-distances", tags=["National distances"])

_MAX_BATCH = 250
_STALE_AFTER = timedelta(minutes=30)
_RETRY_AFTER = timedelta(minutes=5)
_MAX_ATTEMPTS = 3
_bg_tasks: set[asyncio.Task] = set()
_harvest_slots = asyncio.Semaphore(2)
_geocode_lock = asyncio.Lock()
_last_geocode_at = 0.0


class SettlementCandidate(BaseModel):
    url: str = Field(min_length=8, max_length=500)
    settlement_id: Optional[str] = None
    match_id: Optional[str] = None
    match_code: Optional[str] = Field(default=None, max_length=80)
    judge_city: Optional[str] = Field(default=None, max_length=120)
    venue_city: Optional[str] = Field(default=None, max_length=120)


class HarvestRequest(BaseModel):
    username: str
    password: str
    judge_id: str
    links: list[SettlementCandidate] = Field(default_factory=list, max_length=_MAX_BATCH)
    #: Pełne pobranie wszystkich sezonów sędziego. Po udanym odszyfrowaniu
    #: serwer zapisuje wtedy sędziego jako „tabela zbudowana" - także przy
    #: pustej liście albo samych znanych ryczałtach.
    full: bool = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)


def _validated_candidate(candidate: SettlementCandidate) -> dict[str, str]:
    return validate_settlement_candidate(
        url=candidate.url,
        settlement_id_hint=candidate.settlement_id,
        match_id_hint=candidate.match_id,
        match_code=candidate.match_code,
        judge_city=candidate.judge_city,
        venue_city=candidate.venue_city,
    )


def _as_utc(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


async def _reserve(candidate: dict[str, str]) -> bool:
    key = candidate["source_key"]
    row = await database.fetch_one(
        select(national_distance_sources).where(
            national_distance_sources.c.source_key == key,
        )
    )
    now = _now()
    if row:
        state = str(row["status"] or "")
        attempts = int(row["attempts"] or 0)
        updated = _as_utc(row["updated_at"])
        if state == "done" or attempts >= _MAX_ATTEMPTS:
            return False
        age = now - updated if updated else _STALE_AFTER
        if state in {"queued", "processing"} and age < _STALE_AFTER:
            return False
        if state == "failed" and age < _RETRY_AFTER:
            return False
        await database.execute(
            update(national_distance_sources)
            .where(national_distance_sources.c.source_key == key)
            .values(status="queued", error=None, updated_at=now)
        )
        return True

    try:
        await database.execute(
            insert(national_distance_sources).values(
                source_key=key,
                settlement_id=candidate["settlement_id"],
                match_id=candidate["match_id"],
                match_code=candidate["match_code"] or None,
                status="queued",
                attempts=0,
                created_at=now,
                updated_at=now,
            )
        )
        return True
    except Exception:  # wyścig dwóch telefonów z tym samym dokumentem
        return False


async def _geocode_city(name: str) -> Optional[tuple[float, float]]:
    global _last_geocode_at
    try:
        async with _geocode_lock:
            loop = asyncio.get_running_loop()
            pause = 1.05 - (loop.time() - _last_geocode_at)
            if pause > 0:
                await asyncio.sleep(pause)
            async with httpx.AsyncClient(
                timeout=8.0,
                headers={"User-Agent": "BAZA-ZPRP-national-distances/1.0"},
            ) as client:
                try:
                    response = await client.get(
                        "https://nominatim.openstreetmap.org/search",
                        params={
                            "q": f"{name}, Polska",
                            "format": "jsonv2",
                            "limit": 1,
                            "countrycodes": "pl",
                        },
                    )
                finally:
                    _last_geocode_at = loop.time()
                response.raise_for_status()
                items = response.json()
                if not isinstance(items, list) or not items:
                    return None
                lat = float(items[0]["lat"])
                lon = float(items[0]["lon"])
                if not (48.7 <= lat <= 55.2 and 13.8 <= lon <= 24.5):
                    return None
                return lat, lon
    except Exception:
        logger.info("Geokodowanie miejscowości %s nie powiodło się", name)
        return None


async def _route_geometry(
    a: tuple[float, float],
    b: tuple[float, float],
) -> Optional[list[list[float]]]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"https://router.project-osrm.org/route/v1/driving/"
                f"{a[1]},{a[0]};{b[1]},{b[0]}",
                params={"overview": "full", "geometries": "geojson"},
            )
            response.raise_for_status()
            coordinates = response.json()["routes"][0]["geometry"]["coordinates"]
            if not isinstance(coordinates, list) or len(coordinates) < 2:
                return None
            # Telefon nie potrzebuje kilku tysięcy punktów autostrady. Zachowujemy
            # kształt, ale ograniczamy payload do ok. 140 węzłów.
            step = max(1, math.ceil(len(coordinates) / 140))
            slim = coordinates[::step]
            if slim[-1] != coordinates[-1]:
                slim.append(coordinates[-1])
            return [[round(float(lon), 5), round(float(lat), 5)] for lon, lat in slim]
    except Exception:
        logger.info("Geometria trasy OSRM chwilowo niedostępna")
        return None


async def _city_row(key: str):
    return await database.fetch_one(
        select(national_distance_cities).where(national_distance_cities.c.city_key == key)
    )


async def _ensure_city(
    name: str,
) -> tuple[str, Optional[tuple[float, float]], bool]:
    """Zwraca klucz, punkt oraz informację, czy wykonano zapytanie Nominatim."""
    key = normalize_city_key(name)
    if not key:
        raise ValueError("Pusta nazwa miejscowości")
    row = await _city_row(key)
    now = _now()
    if row:
        await database.execute(
            update(national_distance_cities)
            .where(national_distance_cities.c.city_key == key)
            .values(
                name=name,
                observations=int(row["observations"] or 0) + 1,
                updated_at=now,
            )
        )
        if row["latitude"] is not None and row["longitude"] is not None:
            return key, (float(row["latitude"]), float(row["longitude"])), False
    else:
        await database.execute(
            insert(national_distance_cities).values(
                city_key=key,
                name=name,
                observations=1,
                created_at=now,
                updated_at=now,
            )
        )

    point = await _geocode_city(name)
    if point:
        await database.execute(
            update(national_distance_cities)
            .where(national_distance_cities.c.city_key == key)
            .values(latitude=point[0], longitude=point[1], updated_at=_now())
        )
    return key, point, True


async def _store_connection(
    parsed: ParsedSettlement,
    candidate: dict[str, str],
) -> None:
    first = (normalize_city_key(parsed.judge_city), parsed.judge_city)
    second = (normalize_city_key(parsed.venue_city), parsed.venue_city)
    if not first[0] or not second[0] or first[0] == second[0]:
        raise ValueError("Ryczałt nie tworzy połączenia między dwiema miejscowościami")
    if first[0] > second[0]:
        first, second = second, first

    a_key, a_point, _ = await _ensure_city(first[1])
    b_key, b_point, _ = await _ensure_city(second[1])

    existing = await database.fetch_one(
        select(national_distance_connections).where(
            national_distance_connections.c.city_a_key == a_key,
            national_distance_connections.c.city_b_key == b_key,
        )
    )
    geometry = existing["route_geometry"] if existing else None
    if not geometry and a_point and b_point:
        geometry = await _route_geometry(a_point, b_point)

    now = _now()
    if existing:
        observations = int(existing["observations"] or 0) + 1
        distance_sum = int(existing["distance_sum"] or existing["distance_km"] or 0)
        distance_sum += parsed.one_way_km
        # Oficjalne PDF-y zwykle są identyczne. Średnia zaokrąglona stabilizuje
        # sporadyczne różnice 1 km bez tworzenia dwóch kierunków tej samej trasy.
        distance_km = int(round(distance_sum / observations))
        await database.execute(
            update(national_distance_connections)
            .where(
                national_distance_connections.c.city_a_key == a_key,
                national_distance_connections.c.city_b_key == b_key,
            )
            .values(
                city_a_name=first[1],
                city_b_name=second[1],
                distance_km=distance_km,
                distance_sum=distance_sum,
                observations=observations,
                route_geometry=geometry,
                last_match_id=candidate["match_id"],
                last_source_key=candidate["source_key"],
                updated_at=now,
            )
        )
    else:
        await database.execute(
            insert(national_distance_connections).values(
                city_a_key=a_key,
                city_b_key=b_key,
                city_a_name=first[1],
                city_b_name=second[1],
                distance_km=parsed.one_way_km,
                distance_sum=parsed.one_way_km,
                observations=1,
                route_geometry=geometry,
                last_match_id=candidate["match_id"],
                last_source_key=candidate["source_key"],
                created_at=now,
                updated_at=now,
            )
        )


async def _mark_source(key: str, state: str, error: Optional[str] = None) -> None:
    values: dict[str, Any] = {
        "status": state,
        "error": (error or "")[:700] or None,
        "updated_at": _now(),
    }
    if state == "done":
        values["processed_at"] = _now()
    await database.execute(
        update(national_distance_sources)
        .where(national_distance_sources.c.source_key == key)
        .values(**values)
    )


async def _process_batch_inner(
    username: str,
    password: str,
    candidates: list[dict[str, str]],
    settings: Settings,
) -> None:
    client = None
    try:
        client = await login_and_client(username, password, settings)
        for candidate in candidates:
            key = candidate["source_key"]
            try:
                row = await database.fetch_one(
                    select(national_distance_sources).where(
                        national_distance_sources.c.source_key == key,
                    )
                )
                await database.execute(
                    update(national_distance_sources)
                    .where(national_distance_sources.c.source_key == key)
                    .values(
                        status="processing",
                        attempts=int(row["attempts"] or 0) + 1 if row else 1,
                        error=None,
                        updated_at=_now(),
                    )
                )
                response = await client.get(
                    candidate["path"],
                    params={
                        "Id": candidate["settlement_id"],
                        "IdZawody": candidate["match_id"],
                    },
                    timeout=25.0,
                )
                if response.status_code != 200:
                    raise ValueError(f"ZPRP zwrócił HTTP {response.status_code}")
                parsed = parse_settlement_pdf(
                    await response.aread(),
                    judge_city_hint=candidate["judge_city"],
                    venue_city_hint=candidate["venue_city"],
                )
                await _store_connection(parsed, candidate)
                await _mark_source(key, "done")
            except Exception as exc:  # jeden wadliwy PDF nie zatrzymuje batcha
                logger.warning("Ryczałt %s nie został przetworzony: %s", key, exc)
                await _mark_source(key, "failed", str(exc))
    except Exception as exc:
        logger.warning("Nie udało się otworzyć sesji ZPRP dla ryczałtów: %s", exc)
        for candidate in candidates:
            await _mark_source(candidate["source_key"], "failed", str(exc))
    finally:
        if client is not None:
            await client.aclose()
        # Poświadczenia nie trafiają do bazy, logów ani plików. Zerujemy też
        # lokalne referencje natychmiast po zakończeniu zadania.
        username = ""
        password = ""


async def _process_batch(
    username: str,
    password: str,
    candidates: list[dict[str, str]],
    settings: Settings,
) -> None:
    # Dwa równoległe konta to rozsądny sufit: kolejne paczki spokojnie czekają
    # w pamięci serwera, zamiast mnożyć sesje ZPRP i geokodowania.
    async with _harvest_slots:
        await _process_batch_inner(username, password, candidates, settings)


async def _remember_full_judge(judge_id: str, links: int) -> None:
    """Wpis „sędzia zbudował tabelę" po pełnym pobraniu. Błąd bazy nie psuje harvestu."""
    key = str(judge_id or "").strip()[:40]
    if not key:
        return
    now = _now()
    statement = pg_insert(national_distance_judges).values(
        judge_id=key,
        first_full_at=now,
        last_full_at=now,
        links=max(0, int(links)),
    )
    try:
        await database.execute(
            statement.on_conflict_do_update(
                index_elements=[national_distance_judges.c.judge_id],
                # `links` to liczba ryczałtów w OSTATNIM pełnym pobraniu.
                set_={"last_full_at": now, "links": max(0, int(links))},
            )
        )
    except Exception as exc:
        logger.warning("Nie udało się zapisać sędziego po pełnym pobraniu: %s", exc)


@router.post(
    "/harvest",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Kolejkuj nowe ryczałty ZPRP bez blokowania synchronizacji meczów",
)
async def harvest_distances(
    body: HarvestRequest,
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    unique: dict[str, dict[str, str]] = {}
    rejected = 0
    for item in body.links[:_MAX_BATCH]:
        try:
            normalized = _validated_candidate(item)
            unique[normalized["source_key"]] = normalized
        except ValueError:
            rejected += 1

    accepted: list[dict[str, str]] = []
    for item in unique.values():
        if await _reserve(item):
            accepted.append(item)

    if accepted or body.full:
        private_key, _ = keys
        try:
            username = decrypt_field(body.username, private_key)
            password = decrypt_field(body.password, private_key)
            judge_id = decrypt_field(body.judge_id, private_key)
        except HTTPException:
            for item in accepted:
                await _mark_source(item["source_key"], "failed", "Błąd deszyfrowania")
            raise
        if body.full:
            await _remember_full_judge(judge_id, len(unique))
        if accepted:
            _spawn(_process_batch(username, password, accepted, settings))
        username = ""
        password = ""

    return {
        "accepted": len(accepted),
        "known": max(0, len(unique) - len(accepted)),
        "rejected": rejected,
        "processing": bool(accepted),
    }


def _city_payload(row: Any) -> dict[str, Any]:
    return {
        "key": row["city_key"],
        "name": row["name"],
        "latitude": row["latitude"],
        "longitude": row["longitude"],
        "observations": int(row["observations"] or 0),
    }


def _connection_payload(
    row: Any, include_route: bool = True, route_mode: str = "full"
) -> dict[str, Any]:
    return {
        "fromKey": row["city_a_key"],
        "toKey": row["city_b_key"],
        "from": row["city_a_name"],
        "to": row["city_b_name"],
        "distanceKm": int(row["distance_km"]),
        "roundTripKm": int(row["distance_km"]) * 2,
        "observations": int(row["observations"] or 0),
        "route": RS.route_for_mode(row["route_geometry"], route_mode) if include_route else None,
        "updatedAt": row["updated_at"].isoformat() if row["updated_at"] else None,
    }


#: Od tylu bajtów przegląd idzie skompresowany (gdy telefon to przyjmuje).
_GZIP_MIN_BYTES = 32 * 1024


def _json_response(request: Request, payload: dict[str, Any]) -> Response:
    """JSON przeglądu, skompresowany gzipem, gdy klient go przyjmuje.

    Serwer nie ma globalnej kompresji, a przegląd to największa odpowiedź
    mapy. Telefon (OkHttp, NSURLSession) i przeglądarka rozpakowują ją same.
    """
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    accepts = "gzip" in (request.headers.get("accept-encoding") or "").lower()
    if accepts and len(body) >= _GZIP_MIN_BYTES:
        return Response(
            content=gzip.compress(body, compresslevel=5),
            media_type="application/json",
            headers={"Content-Encoding": "gzip", "Vary": "Accept-Encoding"},
        )
    return Response(content=body, media_type="application/json")


@router.get("", summary="Mapa i katalog miejscowości z ryczałtów ZPRP")
async def national_distances_overview(
    request: Request,
    limit: int = Query(1000, ge=1, le=3000),
    # `slim` = trasy uproszczone do mapy kraju (aplikacja od 08.10.2026),
    # `none` = bez geometrii, `full` = jak dotąd (starsza aplikacja).
    routes: Optional[str] = Query(None),
):
    mode = RS.route_mode(routes)
    cities = await database.fetch_all(
        select(national_distance_cities).order_by(national_distance_cities.c.name.asc())
    )
    connections = await database.fetch_all(
        select(national_distance_connections)
        .order_by(national_distance_connections.c.updated_at.desc())
        .limit(limit)
    )
    processed = await database.fetch_val(
        select(func.count())
        .select_from(national_distance_sources)
        .where(national_distance_sources.c.status == "done")
    )
    connections_total = await database.fetch_val(
        select(func.count()).select_from(national_distance_connections)
    )
    return _json_response(request, {
        "cities": [_city_payload(row) for row in cities],
        # Przegląd mapy dostaje geometrię, dzięki czemu po wejściu nic już nie
        # dociąga. Przy dużej bazie limit chroni telefon; wyszukiwarka ma osobny
        # endpoint i zawsze znajdzie także starszą relację.
        "connections": [_connection_payload(row, route_mode=mode) for row in connections],
        "routes": mode,
        "stats": {
            "cities": len(cities),
            "connections": int(connections_total or 0),
            "documents": int(processed or 0),
        },
    })


class ProgressRequest(BaseModel):
    match_ids: list[str] = Field(default_factory=list, max_length=3000)
    home: Optional[str] = Field(default=None, max_length=120)
    cities: list[str] = Field(default_factory=list, max_length=1000)


@router.post(
    "/progress",
    summary="Postęp czytania ryczałtów jednego sędziego (overlay budowy tabeli)",
)
async def national_distances_progress(body: ProgressRequest):
    """Ile ryczałtów z podanych meczów serwer już przeczytał i jakie trasy z nich
    wyszły. Telefon pyta co kilka sekund po pełnym pobraniu, żeby kilometry
    dorysowywały się na mapie, gdy tylko powstaną.

    Bez logowania, bo nie zdradza nic ponad to, co i tak pokazuje publiczna mapa:
    stan przetwarzania dokumentu i kilometry między miastami.
    """
    ids = sorted({str(i).strip() for i in body.match_ids if str(i).strip().isdigit()})
    counts = summarize_sources([])
    if ids:
        rows = await database.fetch_all(
            select(
                national_distance_sources.c.status,
                national_distance_sources.c.attempts,
                func.count(),
            )
            .where(national_distance_sources.c.match_id.in_(ids))
            .group_by(
                national_distance_sources.c.status,
                national_distance_sources.c.attempts,
            )
        )
        counts = summarize_sources((row[0], row[1], row[2]) for row in rows)

    connections: list[dict[str, Any]] = []
    home_key = normalize_city_key(body.home or "")
    wanted = {normalize_city_key(c) for c in body.cities}
    wanted.discard("")
    wanted.discard(home_key)
    if home_key and wanted:
        rows = await database.fetch_all(
            select(national_distance_connections).where(
                (
                    (national_distance_connections.c.city_a_key == home_key)
                    & national_distance_connections.c.city_b_key.in_(wanted)
                )
                | (
                    (national_distance_connections.c.city_b_key == home_key)
                    & national_distance_connections.c.city_a_key.in_(wanted)
                )
            )
        )
        connections = routes_from_home(rows, home_key)
    return {"sources": counts, "connections": connections}


class JudgeStatusRequest(BaseModel):
    judge_id: str = Field(min_length=1, max_length=40)
    match_ids: list[str] = Field(default_factory=list, max_length=NL.MAX_STATUS_MATCH_IDS)


@router.post(
    "/judge-status",
    summary="Czy sędzia zbudował już tabelę odległości (pełne pobranie ryczałtów)",
)
async def national_distances_judge_status(body: JudgeStatusRequest):
    """Aplikacja pyta, czy zachęcać sędziego do pełnego pobrania.

    Zbudowana = wpis po pełnym pobraniu (`full: true`). Bez logowania:
    odpowiedź to tylko tak/nie i data.
    """
    judge_id = body.judge_id.strip()
    row = await database.fetch_one(
        select(
            national_distance_judges.c.first_full_at,
            national_distance_judges.c.last_full_at,
        ).where(national_distance_judges.c.judge_id == judge_id)
    )
    judge_row = (
        {"first_full_at": row["first_full_at"], "last_full_at": row["last_full_at"]}
        if row
        else None
    )
    # `match_ids` zostaje w zapytaniu dla zgodności ze starszymi telefonami,
    # ale nie jest już dowodem (patrz NL.judge_status).
    return NL.judge_status(judge_row)


# ---------------------------------------------------------------------------
# Tabela ZPRP do liczenia kilometrów (rozliczenia, prognoza, ręczne mecze)
# ---------------------------------------------------------------------------

_PAIRS_CHECK_EVERY = 60.0
_pairs_cache: dict[str, Any] = {
    "signature": None,
    "checked": 0.0,
    "version": "0-0",
    "rows": [],
    "lookup": {},
}
_pairs_lock = asyncio.Lock()


async def _refresh_pairs(force: bool = False) -> dict[str, Any]:
    """Pamięć tabeli w procesie. Podpis (liczba, max(updated_at)) sprawdzamy
    najwyżej raz na minutę; pełny odczyt tylko wtedy, gdy podpis się zmienił."""
    now = time.monotonic()
    cache = _pairs_cache
    if not force and cache["signature"] is not None and now - cache["checked"] < _PAIRS_CHECK_EVERY:
        return cache
    async with _pairs_lock:
        if not force and cache["signature"] is not None and time.monotonic() - cache["checked"] < _PAIRS_CHECK_EVERY:
            return cache
        head = await database.fetch_one(
            select(
                func.count().label("n"),
                func.max(national_distance_connections.c.updated_at).label("at"),
            ).select_from(national_distance_connections)
        )
        signature = (int(head["n"] or 0), head["at"]) if head else (0, None)
        if signature != cache["signature"]:
            rows = await database.fetch_all(
                select(
                    national_distance_connections.c.city_a_key,
                    national_distance_connections.c.city_b_key,
                    national_distance_connections.c.distance_km,
                    national_distance_connections.c.observations,
                )
            )
            listed = NL.pairs_rows(rows)
            cache["rows"] = listed
            cache["lookup"] = NL.expand_pairs({(a, b): km for a, b, km, _ in listed})
            cache["version"] = NL.pairs_version(*signature)
            cache["signature"] = signature
        cache["checked"] = time.monotonic()
    return cache


async def load_national_pairs() -> dict[tuple[str, str], int]:
    """
    Tabela ZPRP gotowa do `national_lookup_rules.national_km`: klucze ułożone
    rosnąco, uzupełnione o warianty pisowni. Błąd bazy = pusta tabela, a nie
    wywrócone rozliczenie - kilometry pójdą wtedy dalszym źródłem reguły.
    """
    try:
        return (await _refresh_pairs())["lookup"]
    except Exception as exc:
        logger.warning("Tabela odległości ZPRP chwilowo niedostępna: %s", exc)
        return _pairs_cache.get("lookup") or {}


@router.get("/pairs", summary="Cała tabela odległości ZPRP w lekkiej postaci (z ETag)")
async def national_distance_pairs(
    response: Response,
    if_none_match: Optional[str] = Header(None, alias="If-None-Match"),
):
    cache = await _refresh_pairs()
    version = cache["version"]
    headers = {
        "ETag": f'"{version}"',
        "Cache-Control": "public, max-age=600",
    }
    if NL.etag_matches(if_none_match, version):
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)
    for name, value in headers.items():
        response.headers[name] = value
    return {"version": version, "pairs": cache["rows"]}


@router.get("/connection", summary="Odległość pomiędzy dwiema miejscowościami")
async def national_distance_connection(
    from_city: str = Query(..., alias="from", min_length=1, max_length=120),
    to_city: str = Query(..., alias="to", min_length=1, max_length=120),
    route: int = Query(1, ge=0, le=1, description="0 = bez geometrii trasy"),
):
    a = normalize_city_key(from_city)
    b = normalize_city_key(to_city)
    if not a or not b or a == b:
        return {"found": False, "connection": None}
    if a > b:
        a, b = b, a
    row = await database.fetch_one(
        select(national_distance_connections).where(
            national_distance_connections.c.city_a_key == a,
            national_distance_connections.c.city_b_key == b,
        )
    )
    return {
        "found": bool(row),
        "connection": _connection_payload(row, include_route=bool(route)) if row else None,
    }

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
from app import national_place_rules as NP_RULES
from app import national_route_shape as RS
from app.db import (
    database,
    national_distance_cities,
    national_distance_connections,
    national_distance_judges,
    national_distance_sources,
    zprp_public_competitions,
    zprp_public_matches,
)
from app.deps import Settings, get_rsa_keys, get_settings
from app.national_distance_progress import (
    pick_home_node,
    point_of,
    routes_from_home,
    summarize_sources,
)
from app.national_distance_parser import (
    ParsedSettlement,
    hint_columns,
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
    # Wskazówki położenia (od 15.10.2026) - tylko priorytet przy wyborze
    # jednej z kilku miejscowości o tej samej nazwie, nigdy rozstrzygnięcie.
    judge_province: Optional[str] = Field(default=None, max_length=80)
    judge_postal_code: Optional[str] = Field(default=None, max_length=12)
    match_province: Optional[str] = Field(default=None, max_length=120)
    venue_street: Optional[str] = Field(default=None, max_length=160)


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
        judge_province=candidate.judge_province,
        judge_postal_code=candidate.judge_postal_code,
        match_province=candidate.match_province,
        venue_street=candidate.venue_street,
    )


_hint_values = hint_columns


async def _remember_hints(candidates: list[dict[str, str]]) -> None:
    """Znane dokumenty bez wskazówek dostają je z bieżącego wysłania.

    Ryczałty sprzed 15.10.2026 nie mają ani wskazówek, ani szczegółów. Telefon
    wysyła cały sezon przy każdym pobraniu, więc stare dokumenty dostają
    wskazówki po cichu, bez ponownego czytania PDF (rozpoznanie miejscowości
    korzysta z nich przy następnym przebiegu)."""
    with_hints = [c for c in candidates if any(_hint_values(c).values())]
    if not with_hints:
        return
    try:
        rows = await database.fetch_all(
            select(national_distance_sources.c.source_key).where(
                national_distance_sources.c.source_key.in_([c["source_key"] for c in with_hints]),
                national_distance_sources.c.hint_judge_city.is_(None),
                national_distance_sources.c.judge_province.is_(None),
                national_distance_sources.c.match_province.is_(None),
            )
        )
        missing = {r["source_key"] for r in rows}
        for candidate in with_hints:
            if candidate["source_key"] in missing:
                await database.execute(
                    update(national_distance_sources)
                    .where(national_distance_sources.c.source_key == candidate["source_key"])
                    .values(**_hint_values(candidate))
                )
    except Exception as exc:  # wskazówki nigdy nie psują harvestu
        logger.info("Wskazówki znanych ryczałtów nie zostały zapisane: %s", exc)


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
            .values(status="queued", error=None, updated_at=now, **_hint_values(candidate))
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
                **_hint_values(candidate),
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


def _document_hints(candidate: dict[str, str]) -> tuple[frozenset[str], frozenset[str]]:
    """Województwa ze wskazówek: (strona sędziego, strona hali)."""
    judge = NP_RULES.hint_provinces(
        candidate.get("judge_province"), postal=candidate.get("judge_postal_code")
    )
    venue = NP_RULES.hint_provinces(candidate.get("match_province"))
    return judge, venue


async def _public_match_province(match_id: str) -> str:
    """Związek prowadzący rozgrywki z publicznej bazy meczów (gdy telefon
    go nie przysłał). Brak wiersza = pusta wskazówka."""
    try:
        row = await database.fetch_one(
            select(zprp_public_competitions.c.association_name)
            .select_from(
                zprp_public_matches.join(
                    zprp_public_competitions,
                    zprp_public_competitions.c.competition_id == zprp_public_matches.c.competition_id,
                )
            )
            .where(zprp_public_matches.c.match_id == str(match_id))
        )
        return str(row["association_name"] or "") if row else ""
    except Exception:
        return ""


async def _store_connection(
    parsed: ParsedSettlement,
    candidate: dict[str, str],
) -> set[str]:
    """Zapis jednego ryczałtu. Zwraca klucze nazw, których dotknął (do
    późniejszego rozpoznania sieci)."""
    from app import national_places as NP

    judge_name, venue_name = parsed.judge_city, parsed.venue_city
    judge_nk, venue_nk = normalize_city_key(judge_name), normalize_city_key(venue_name)
    if not judge_nk or not venue_nk or judge_nk == venue_nk:
        raise ValueError("Ryczałt nie tworzy połączenia między dwiema miejscowościami")

    judge_hints, venue_hints = _document_hints(candidate)
    if not venue_hints and candidate.get("match_id"):
        venue_hints = NP_RULES.hint_provinces(await _public_match_province(candidate["match_id"]))

    # Węzeł = nazwa + rozpoznane miejsce (15.10.2026). Dawniej klucz był samą
    # nazwą, więc dwie różne Krzywe zlewały się w jedną.
    judge_key, venue_key = await NP.resolve_document(
        judge_name, venue_name, parsed.one_way_km, judge_hints, venue_hints
    )
    if judge_key == venue_key:
        raise ValueError("Ryczałt nie tworzy połączenia między dwiema miejscowościami")
    await NP.bump_observations(judge_key)
    await NP.bump_observations(venue_key)

    first, second = (judge_key, judge_name), (venue_key, venue_name)
    if first[0] > second[0]:
        first, second = second, first
    a_key, b_key = first[0], second[0]
    points = await NP.node_points([a_key, b_key])

    existing = await database.fetch_one(
        select(national_distance_connections).where(
            national_distance_connections.c.city_a_key == a_key,
            national_distance_connections.c.city_b_key == b_key,
        )
    )
    geometry = existing["route_geometry"] if existing else None
    pa, pb = points.get(a_key) or {}, points.get(b_key) or {}
    if not geometry and pa.get("latitude") is not None and pb.get("latitude") is not None:
        geometry = await _route_geometry(
            (float(pa["latitude"]), float(pa["longitude"])),
            (float(pb["latitude"]), float(pb["longitude"])),
        )

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

    # Szczegóły dokumentu - połączenie da się później rozłożyć na dokumenty.
    await database.execute(
        update(national_distance_sources)
        .where(national_distance_sources.c.source_key == candidate["source_key"])
        .values(
            judge_city=judge_name[:120],
            venue_city=venue_name[:120],
            one_way_km=int(parsed.one_way_km),
            judge_node=judge_key,
            venue_node=venue_key,
        )
    )
    return {judge_nk, venue_nk}


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
    touched: set[str] = set()
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
                touched |= await _store_connection(parsed, candidate)
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
    if touched:
        # Nowe trasy = nowy dowód: rozpoznanie (i ewentualne przeniesienie albo
        # rozdzielenie) tylko tych nazw, których paczka dotknęła.
        from app import national_places as NP

        await NP.reresolve(touched)


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
    known = [item for item in unique.values() if item not in accepted]
    if known:
        await _remember_hints(known)

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
    data = dict(row)
    return {
        "key": data["city_key"],
        "name": data["name"],
        "latitude": data["latitude"],
        "longitude": data["longitude"],
        "observations": int(data["observations"] or 0),
        # Od 15.10.2026: węzeł = nazwa + miejsce. Kilka węzłów może mieć tę
        # samą nazwę (`nameKey`), województwo je rozróżnia. `approximate` =
        # położenie niepewne (mapa rysuje pusty pierścień zamiast kropki).
        "nameKey": data.get("name_key") or data["city_key"],
        "province": data.get("province"),
        "provinceLabel": NP_RULES.province_label(data.get("province") or "") or None,
        "approximate": bool(data.get("approximate")),
        "pinned": bool(data.get("pinned")),
    }


def _connection_payload(
    row: Any,
    include_route: bool = True,
    route_mode: str = "full",
    points: Optional[dict[str, dict]] = None,
) -> dict[str, Any]:
    extra: dict[str, Any] = {}
    if points is not None:
        # Wyszukiwarka: położenie obu końców, żeby karta trasy wiedziała,
        # czy któryś jest „przybliżony" (przegląd ma to w `cities`).
        extra = {
            "fromPoint": points.get(row["city_a_key"]),
            "toPoint": points.get(row["city_b_key"]),
        }
    return {
        **extra,
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
    # Wskazówki domu sędziego (15.10.2026): wybór między węzłami o tej samej nazwie.
    home_province: Optional[str] = Field(default=None, max_length=80)
    home_postal_code: Optional[str] = Field(default=None, max_length=12)


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
    home_point: Optional[dict[str, Any]] = None
    home_name = normalize_city_key(body.home or "")
    wanted = {normalize_city_key(c) for c in body.cities}
    wanted.discard("")
    wanted.discard(home_name)
    if home_name and wanted:
        # Nazwy -> węzły (kilka miejscowości może nosić tę samą nazwę).
        T = national_distance_cities
        node_rows = await database.fetch_all(
            select(T).where(
                T.c.name_key.in_([home_name, *wanted]) | T.c.city_key.in_([home_name, *wanted])
            )
        )
        nodes = {r["city_key"]: dict(r) for r in node_rows}
        home_keys = [k for k, r in nodes.items() if (r.get("name_key") or k) == home_name]
        other_keys = [k for k in nodes if k not in home_keys]
        rows = []
        if home_keys and other_keys:
            E = national_distance_connections
            rows = await database.fetch_all(
                select(E).where(
                    (E.c.city_a_key.in_(home_keys) & E.c.city_b_key.in_(other_keys))
                    | (E.c.city_b_key.in_(home_keys) & E.c.city_a_key.in_(other_keys))
                )
            )
        home_key = pick_home_node(
            [nodes[k] for k in home_keys],
            rows,
            NP_RULES.hint_provinces(body.home_province, postal=body.home_postal_code),
        )
        if home_key:
            connections = routes_from_home(
                [r for r in rows if home_key in (r["city_a_key"], r["city_b_key"])],
                home_key,
                points=nodes,
            )
            home_point = point_of(nodes.get(home_key))

    # Węzeł hali per mecz (dokumenty od 15.10.2026 znają swój węzeł) - overlay
    # stawia kropkę tam, dokąd sędzia naprawdę jechał.
    venues: dict[str, Any] = {}
    if ids:
        S = national_distance_sources
        venue_rows = await database.fetch_all(
            select(S.c.match_id, S.c.venue_node)
            .where(S.c.match_id.in_(ids), S.c.venue_node.isnot(None))
        )
        venue_points = await _node_points_by_key({r["venue_node"] for r in venue_rows})
        for r in venue_rows:
            point = venue_points.get(r["venue_node"])
            if point:
                venues[str(r["match_id"])] = point
    return {
        "sources": counts,
        "connections": connections,
        "home": home_point,
        "venues": venues,
    }


async def _node_points_by_key(keys: set[str]) -> dict[str, dict[str, Any]]:
    wanted = sorted(k for k in keys if k)
    if not wanted:
        return {}
    rows = await database.fetch_all(
        select(national_distance_cities).where(national_distance_cities.c.city_key.in_(wanted))
    )
    return {r["city_key"]: point_of(dict(r)) for r in rows}


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
            E = national_distance_connections
            A = national_distance_cities.alias("node_a")
            B = national_distance_cities.alias("node_b")
            rows = await database.fetch_all(
                select(
                    E.c.city_a_key,
                    E.c.city_b_key,
                    E.c.distance_km,
                    E.c.observations,
                    A.c.name_key.label("a_name_key"),
                    B.c.name_key.label("b_name_key"),
                    A.c.province.label("a_province"),
                    B.c.province.label("b_province"),
                )
                .select_from(
                    E.outerjoin(A, A.c.city_key == E.c.city_a_key).outerjoin(
                        B, B.c.city_key == E.c.city_b_key
                    )
                )
            )
            # Wyszukiwanie po NAZWACH: rozliczenia, prognoza i telefon znają
            # tylko napisy. Węzły o tej samej nazwie (15.10.2026) zostają
            # wariantami, które rozstrzyga okręg wołającego.
            listed, variants = NL.name_pairs(rows)
            cache["rows"] = listed
            cache["lookup"] = NL.NationalPairs(
                NL.expand_pairs({(a, b): km for a, b, km, _ in listed}),
                variants=variants,
            )
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
    E = national_distance_connections
    T = national_distance_cities
    # Klucz węzła („krzywa|lubuskie") trafia wprost; goła nazwa - wszystkie
    # węzły tej nazwy, wygrywa najczęściej potwierdzona trasa.
    raw_a, raw_b = from_city.strip(), to_city.strip()
    node_rows = await database.fetch_all(
        select(T).where(
            T.c.city_key.in_([raw_a, raw_b, a, b]) | T.c.name_key.in_([a, b])
        )
    )
    nodes = {r["city_key"]: dict(r) for r in node_rows}

    def keys_for(raw: str, name: str) -> list[str]:
        if raw in nodes:
            return [raw]
        return [k for k, r in nodes.items() if (r.get("name_key") or k) == name] or [name]

    left, right = keys_for(raw_a, a), keys_for(raw_b, b)
    rows = await database.fetch_all(
        select(E).where(
            (E.c.city_a_key.in_(left) & E.c.city_b_key.in_(right))
            | (E.c.city_a_key.in_(right) & E.c.city_b_key.in_(left))
        )
    )
    row = max(rows, key=lambda r: int(r["observations"] or 0)) if rows else None
    points = {k: point_of(v) for k, v in nodes.items()}
    return {
        "found": bool(row),
        "connection": _connection_payload(row, include_route=bool(route), points=points) if row else None,
    }


# ---------------------------------------------------------------------------
# Admin: położenie miejscowości (15.10.2026)
# ---------------------------------------------------------------------------


async def _require_admin(authorization: Optional[str] = Header(None)) -> str:
    """Admin aplikacji z tokenem JWT BAZY (`Authorization: Bearer`).

    Nowe trasy, więc bez okresu przejściowego `app/admin_guard.py`: żadna
    starsza wersja aplikacji ich nie woła."""
    from app.admin_guard import bearer_token, decode_token, read_admin_ids

    payload, reason = decode_token(bearer_token(authorization))
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesja wygasła albo brak logowania. Zaloguj się ponownie i powtórz.",
        )
    judge_id = str(payload.get("judge_id") or "").strip()
    if not judge_id or judge_id not in await read_admin_ids():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Położenie miejscowości zmienia tylko administrator aplikacji.",
        )
    return judge_id


@router.get("/admin/places", summary="Miejscowości do przejrzenia (przybliżone, przeniesione)")
async def admin_places(
    days: int = Query(45, ge=1, le=3650),
    admin: str = Depends(_require_admin),
):
    from app import national_places as NP

    return {"places": await NP.attention_list(days=days)}


class RelocateRequest(BaseModel):
    apply: bool = False


@router.post(
    "/admin/places/relocate",
    summary="Rozpoznanie położenia wszystkich miejscowości (podgląd albo zapis)",
)
async def admin_places_relocate(body: RelocateRequest, admin: str = Depends(_require_admin)):
    """`apply=false` (domyślnie) - tylko podgląd: kto się przesunie, gdzie
    i które nazwy się rozdzielą. `apply=true` - zapis w jednej transakcji
    i przeliczenie geometrii OSRM przeniesionych tras w tle. Kilometry nie
    zmieniają się nigdy (połączenia przechodzą w całości)."""
    from app import national_places as NP

    summary = await NP.relocate(bool(body.apply))
    if body.apply:
        logger.info("[national-places] relocate przez %s: %s przeniesień", admin, len(summary["moved"]))
    return summary


class PinRequest(BaseModel):
    key: str = Field(min_length=1, max_length=200)
    #: Kandydat z listy (gid GeoNames albo „fit:..." / „geo:...") albo własny punkt.
    gid: Optional[str] = Field(default=None, max_length=80)
    latitude: Optional[float] = Field(default=None, ge=48.5, le=55.5)
    longitude: Optional[float] = Field(default=None, ge=13.5, le=24.8)
    province: Optional[str] = Field(default=None, max_length=40)
    unpin: bool = False


@router.post("/admin/places/pin", summary="Przypnij położenie miejscowości (automat go nie ruszy)")
async def admin_places_pin(body: PinRequest, admin: str = Depends(_require_admin)):
    from app import national_places as NP

    if body.unpin:
        await NP.unpin(body.key)
        return {"key": body.key, "pinned": False}
    lat, lon, province = body.latitude, body.longitude, body.province or ""
    if body.gid and (lat is None or lon is None):
        gaz = await NP.gazetteer()
        place = gaz.places.get(body.gid)
        if place is None:
            raise HTTPException(status_code=404, detail="Nie znam tego kandydata - odśwież listę.")
        lat, lon, province = place.lat, place.lon, place.province
    if lat is None or lon is None:
        raise HTTPException(status_code=422, detail="Wybierz kandydata albo podaj punkt na mapie.")
    if not province:
        gaz = await NP.gazetteer()
        near = gaz.nearest(lat, lon, 40)
        province = near.province if near else ""
    try:
        result = await NP.pin(
            body.key, lat=float(lat), lon=float(lon), province=province, gid=body.gid or "", actor=admin
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="Tej miejscowości nie ma już w tabeli - odśwież listę.")
    logger.info("[national-places] %s przypiął %s (%s km)", admin, body.key, result.get("movedKm"))
    return {**result, "pinned": True}

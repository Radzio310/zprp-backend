"""Pod Ręką, runda 3: załączniki, strzelcy, hale, wykres sezonu, .ics, rekordy,
head-to-head, podsumowanie kolejki i profil sędziego.

Prefiks jak reszta publicznego API (`/api/v1/handball`). Logika w
`match_rules.py` (czyste funkcje); tu tylko zapytania i cache. Ciężkie agregaty
(strzelcy krajowi, rekordy, lista hal) mają krótki cache w pamięci.
"""

from __future__ import annotations

from app.zprp_details import details_url

import asyncio
import re
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import and_, func, or_, select

from app.db import (
    database,
    zprp_public_associations,
    zprp_public_competitions,
    zprp_public_match_players,
    zprp_public_matchdays,
    zprp_public_matches,
    zprp_public_players,
    zprp_public_rounds,
    zprp_public_scorers,
    zprp_public_seasons,
    zprp_public_standings,
    zprp_public_teams,
)
from app import time_pl as TP
from app.standings_refresh import apply_provisional
from app.zprp_public import corrections, match_rules as MR, portal_rules as R, referee_stats as RS
from app.zprp_public import referee_placeholder as RP
from app.zprp_public import round_rules as ROUNDS
from app.zprp_public import round_review_rules as RV
from app.zprp_public import proel_card_rules as PR, proel_live_rules as LR
from app.zprp_public.proel_cards import _rows as proel_rows
from app import standings_provisional as SP
from app.zprp_public.api import _dict
from app.zprp_public import geocode
from app.zprp_public.enrich import seasons_info
from app.zprp_public.portal import _cards, _card_cols, _clean_ref_name, _club_lookup, _gazetteer_lookup, _node_index

router = APIRouter(prefix="/api/v1/handball", tags=["handball_round3"])

M = zprp_public_matches
MP = zprp_public_match_players
_CORS = {"Access-Control-Allow-Origin": "*"}

_cache: dict[str, tuple[float, Any]] = {}
_CACHE_MAX = 256


async def _cached(key: str, ttl: float, factory: Callable[[], Awaitable[Any]]) -> Any:
    hit = _cache.get(key)
    now = time.monotonic()
    if hit and now - hit[0] < ttl:
        return hit[1]
    value = await factory()
    if len(_cache) > _CACHE_MAX:
        _cache.clear()
    _cache[key] = (now, value)
    return value


def clear_cache() -> None:
    _cache.clear()
    _attachment_cache.clear()
    _file_cache.clear()


async def _season_or_current(season_id: str = "") -> Optional[str]:
    if season_id.strip():
        return season_id.strip()
    return (await seasons_info())[1]


# ---------------------------------------------------------------------------
# Załączniki meczu + proxy plików
# ---------------------------------------------------------------------------

_DETAILS_URL = "https://rozgrywki.zprp.pl/api/pokaz_mecze_szczegoly.php"
_ATTACH_TTL = 60.0
_FILE_TTL = 3600.0
_FILE_CACHE_BYTES = 60 * 1024 * 1024
_attachment_cache: dict[str, tuple[float, list[dict]]] = {}
_file_cache: dict[str, tuple[float, bytes, str]] = {}
_thumb_cache: dict[str, bytes] = {}


def _proxy_url(file_url: str) -> str:
    return f"/api/v1/handball/attachments/file?u={quote(file_url, safe='')}"


async def _hidden_ids(match_id: str) -> set[str]:
    try:
        from app import zprp_hidden_attachments as ledger

        mid = ledger.normalize_match_id(match_id)
        if mid is None:
            return set()
        return {str(i["attachment_id"]) for i in await ledger.ledger_hidden_for_match(mid)}
    except Exception:  # noqa: BLE001 - brak księgi nie blokuje listy (upstream i tak ukrywa)
        return set()


async def _fetch_attachments(match_id: str) -> list[dict]:
    from app import zprp_hidden_attachments as ledger

    async with httpx.AsyncClient(timeout=15.0, headers={"User-Agent": "BAZA-PodReka/1.0"}) as client:
        resp = await client.get(await details_url(match_id))
    if resp.status_code != 200:
        raise HTTPException(502, "Rozgrywki ZPRP nie odpowiadają")
    match = ledger.match_from_details(resp.json()) or {}
    return MR.attachment_items(ledger.visible_attachments(match), await _hidden_ids(match_id), _proxy_url)


@router.get("/matches/{match_id}/attachments")
async def match_attachments(match_id: str) -> Response:
    if not re.fullmatch(r"[0-9]{1,12}", match_id):
        raise HTTPException(400, "Nieprawidłowy numer meczu")
    hit = _attachment_cache.get(match_id)
    if not hit or time.monotonic() - hit[0] > _ATTACH_TTL:
        try:
            items = await _fetch_attachments(match_id)
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            if hit:
                items = hit[1]
            else:
                raise HTTPException(502, "Nie udało się pobrać załączników") from exc
        if len(_attachment_cache) > 300:
            _attachment_cache.clear()
        _attachment_cache[match_id] = (time.monotonic(), items)
    else:
        items = hit[1]
    import json

    return Response(
        json.dumps(items, ensure_ascii=False), media_type="application/json",
        headers={**_CORS, "Cache-Control": "public, max-age=60"},
    )


def _remember_file(url: str, body: bytes, ctype: str) -> None:
    total = sum(len(v[1]) for v in _file_cache.values()) + len(body)
    while _file_cache and total > _FILE_CACHE_BYTES:
        oldest = min(_file_cache, key=lambda k: _file_cache[k][0])
        total -= len(_file_cache.pop(oldest)[1])
    _file_cache[url] = (time.monotonic(), body, ctype)


@router.get("/attachments/file")
async def attachment_file(u: str = Query(..., max_length=600), download: bool = False, name: str = "", w: int = Query(0, ge=0, le=1600)) -> Response:
    """Proxy plików protokołu (CORS `*`). Tylko https, hosty ZPRP, katalog załączników, limit 15 MB."""
    if not MR.is_allowed_attachment_url(u):
        raise HTTPException(400, "Niedozwolony adres pliku")
    hit = _file_cache.get(u)
    if hit and time.monotonic() - hit[0] < _FILE_TTL:
        body, ctype = hit[1], hit[2]
    else:
        body = b""
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=False, headers={"User-Agent": "BAZA-PodReka/1.0"}) as client:
            try:
                async with client.stream("GET", u) as resp:
                    if resp.status_code == 404:
                        raise HTTPException(404, "Nie znaleziono pliku")
                    if resp.status_code != 200:
                        raise HTTPException(502, "Plik niedostępny")
                    ctype = resp.headers.get("content-type", "application/octet-stream").split(";")[0].strip().lower()
                    declared = int(resp.headers.get("content-length") or 0)
                    if declared > MR.ATTACHMENT_MAX_BYTES:
                        raise HTTPException(413, "Plik jest za duży")
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in resp.aiter_bytes():
                        size += len(chunk)
                        if size > MR.ATTACHMENT_MAX_BYTES:
                            raise HTTPException(413, "Plik jest za duży")
                        chunks.append(chunk)
                    body = b"".join(chunks)
            except httpx.HTTPError as exc:
                raise HTTPException(502, "Plik niedostępny") from exc
        if not (ctype == "application/pdf" or ctype.startswith("image/")):
            ctype = "application/octet-stream"
        _remember_file(u, body, ctype)
    if w and ctype.startswith("image/"):
        key = f"{u}|{w}"
        thumb = _thumb_cache.get(key)
        if thumb is None:
            thumb = await asyncio.to_thread(MR.make_thumbnail, body, w)
            if thumb is not None:
                if len(_thumb_cache) > 400:
                    _thumb_cache.clear()
                _thumb_cache[key] = thumb
        if thumb is not None:
            return Response(thumb, media_type="image/jpeg", headers={**_CORS, "Cache-Control": "public, max-age=604800, immutable", "X-Content-Type-Options": "nosniff"})
    filename = re.sub(r"[^A-Za-z0-9._-]+", "_", name or u.rsplit("/", 1)[-1])[:80] or "zalacznik"
    headers = {
        **_CORS,
        "Cache-Control": "public, max-age=86400",
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": f'{"attachment" if download else "inline"}; filename="{filename}"',
    }
    return Response(body, media_type=ctype, headers=headers)


# ---------------------------------------------------------------------------
# Strzelcy: rozgrywki / okręg / kraj
# ---------------------------------------------------------------------------

_SCORERS_TTL = 420.0


async def _scorer_rows(scope: str, competition_id: str, association_id: str, season_id: Optional[str],
                       category: str, gender: str) -> list[dict]:
    S, C, P, T = zprp_public_scorers, zprp_public_competitions, zprp_public_players, zprp_public_teams
    conditions = []
    if scope == "competition":
        conditions.append(S.c.competition_id == competition_id)
    else:
        if season_id:
            conditions.append(C.c.season_id == season_id)
        if scope == "association":
            conditions.append(C.c.association_id == association_id)
    if category:
        conditions.append(C.c.category == category)
    if gender:
        conditions.append(C.c.gender == gender)
    query = (
        select(
            S.c.player_id, S.c.team_id, S.c.team_name, S.c.goals, S.c.matches, S.c.warnings, S.c.two_minutes,
            S.c.disqualifications, S.c.penalty_attempts, S.c.penalty_goals,
            P.c.first_name, P.c.last_name, P.c.photo_url, C.c.season_id.label("season_id"), T.c.club_id.label("club_id"),
        )
        .select_from(
            S.join(C, C.c.competition_id == S.c.competition_id)
            .join(P, P.c.player_id == S.c.player_id)
            .outerjoin(T, and_(T.c.team_id == S.c.team_id, T.c.season_id == C.c.season_id))
        )
    )
    if conditions:
        query = query.where(and_(*conditions))
    return [_dict(r) for r in await database.fetch_all(query)]


async def _scorer_filters(scope: str, season_id: Optional[str]) -> dict[str, Any]:
    C = zprp_public_competitions
    seasons = await database.fetch_all(
        select(zprp_public_seasons.c.season_id, zprp_public_seasons.c.name, zprp_public_seasons.c.active)
        .order_by(zprp_public_seasons.c.start_year.desc())
    )
    cond = [C.c.season_id == season_id] if season_id else []
    cats = await database.fetch_all(select(C.c.category).where(and_(*cond)).distinct() if cond else select(C.c.category).distinct())
    gens = await database.fetch_all(select(C.c.gender).where(and_(*cond)).distinct() if cond else select(C.c.gender).distinct())
    assocs = await database.fetch_all(
        select(zprp_public_associations.c.association_id, zprp_public_associations.c.name).order_by(zprp_public_associations.c.name)
    )
    return {
        "scopes": ["competition", "association", "country"],
        "sorts": list(MR.SCORER_SORTS),
        "seasons": [_dict(s) for s in seasons],
        "categories": sorted({r["category"] for r in cats if r["category"]}),
        "genders": sorted({r["gender"] for r in gens if r["gender"]}),
        "associations": [_dict(a) for a in assocs],
        "min_matches_avg": MR.MIN_MATCHES_AVG,
        "min_penalties_acc": MR.MIN_PENALTIES_ACC,
    }


@router.get("/scorers")
async def scorers(
    scope: str = Query("country", pattern="^(competition|association|country)$"),
    competition_id: str = "",
    association_id: str = "",
    season_id: str = "",
    category: str = "",
    gender: str = "",
    sort: str = Query("goals", pattern="^(goals|avg|pen_acc|penalties)$"),
    limit: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    if scope == "competition" and not competition_id:
        raise HTTPException(400, "Podaj competition_id")
    if scope == "association" and not association_id:
        raise HTTPException(400, "Podaj association_id")
    season = None if scope == "competition" else await _season_or_current(season_id)

    async def build() -> dict[str, Any]:
        rows = await _scorer_rows(scope, competition_id, association_id, season, category, gender)
        items = MR.aggregate_scorers(rows, sort, limit)
        lookup = await _club_lookup({i.get("club_id") for i in items})
        for item in items:
            item["club_logo_url"] = (lookup.get(item.get("club_id")) or {}).get("logo_url")
        players = [{"player_id": i["player_id"], "first_name": i["name"], "last_name": "", "photo_url": i.get("photo_url")}
                   for i in items]
        await corrections.apply("player", players)
        for item, p in zip(items, players):
            item["name"] = p["first_name"]
            item["photo_url"] = p.get("photo_url") or None
        return {"items": items, "filters": await _scorer_filters(scope, season),
                "applied": {"scope": scope, "season_id": season, "competition_id": competition_id or None,
                            "association_id": association_id or None, "category": category or None,
                            "gender": gender or None, "sort": sort, "limit": limit},
                "total_players": len({r["player_id"] for r in rows})}

    key = f"scorers|{scope}|{competition_id}|{association_id}|{season}|{category}|{gender}|{sort}|{limit}"
    return await _cached(key, _SCORERS_TTL, build)


@router.get("/players/{player_id}/competitions")
async def player_competitions(player_id: str, season_id: str = "") -> dict[str, Any]:
    S, C, T = zprp_public_scorers, zprp_public_competitions, zprp_public_teams
    conditions = [S.c.player_id == player_id]
    if season_id.strip():
        conditions.append(C.c.season_id == season_id.strip())

    async def build() -> dict[str, Any]:
        rows = await database.fetch_all(
            select(
                C.c.competition_id, C.c.name, C.c.season_id, C.c.category, C.c.gender, C.c.association_id,
                C.c.association_name, S.c.team_id, S.c.team_name, S.c.goals, S.c.matches,
                zprp_public_seasons.c.name.label("season_name"), T.c.name.label("tname"),
            )
            .select_from(
                S.join(C, C.c.competition_id == S.c.competition_id)
                .outerjoin(zprp_public_seasons, zprp_public_seasons.c.season_id == C.c.season_id)
                .outerjoin(T, and_(T.c.team_id == S.c.team_id, T.c.season_id == C.c.season_id))
            )
            .where(and_(*conditions))
        )
        items = []
        for r in rows:
            d = _dict(r)
            d["team_name"] = d.get("team_name") or d.pop("tname", None)
            d.pop("tname", None)
            d["goals"] = int(d.get("goals") or 0)
            d["matches"] = int(d.get("matches") or 0)
            items.append(d)
        current = (await seasons_info())[1]
        return {"items": MR.sort_player_competitions(items, current), "count": len(items)}

    return await _cached(f"player-comps|{player_id}|{season_id.strip()}", _SCORERS_TTL, build)


# ---------------------------------------------------------------------------
# Hale
# ---------------------------------------------------------------------------

_VENUES_TTL = 600.0


async def _venue_index() -> dict[str, dict]:
    async def build() -> dict[str, dict]:
        rows = await database.fetch_all(
            select(M.c.venue_name, M.c.venue_city, M.c.venue_street, M.c.venue_number,
                   func.max(M.c.venue_capacity).label("capacity"), func.count().label("n"))
            .where(M.c.venue_name.is_not(None))
            .group_by(M.c.venue_name, M.c.venue_city, M.c.venue_street, M.c.venue_number)
        )
        index: dict[str, dict] = {}
        for r in rows:
            name = (r["venue_name"] or "").strip()
            if not name:
                continue
            key = MR.venue_key(name, r["venue_city"])
            v = index.setdefault(key, {"key": key, "name": name, "city": None, "street": None, "number": None,
                                       "capacity": None, "matches": 0, "_best": -1, "variants": set()})
            v["variants"].add((r["venue_name"], r["venue_city"]))
            v["matches"] += int(r["n"])
            if int(r["n"]) > v["_best"]:
                v.update(_best=int(r["n"]), city=R.display_city(r["venue_city"]) if r["venue_city"] else None,
                         street=r["venue_street"] or None, number=r["venue_number"] or None)
            if r["capacity"]:
                v["capacity"] = max(v["capacity"] or 0, int(r["capacity"]))
        return index

    return await _cached("venue-index", _VENUES_TTL, build)


async def _geocode(city: Optional[str], hint: str = "") -> tuple[Optional[float], Optional[float]]:
    """Współrzędne miasta: tabela odległości -> skorowidz GeoNames -> pamięć geokodera
    (Nominatim, `app/zprp_public/geocode.py`). Nieznane = (None, None), bez zgadywania."""
    if not city:
        return None, None
    place = R.resolve_city(city, await _node_index(), hint)
    if not place:
        place = R.resolve_city(city, await _node_index(), hint, await _gazetteer_lookup(), await geocode.cache_lookup())
    return (place["lat"], place["lon"]) if place else (None, None)


@router.get("/venues")
async def venues(q: str = "", limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)) -> dict[str, Any]:
    index = await _venue_index()
    needle = MR._fold(q)
    items = [
        {k: v for k, v in venue.items() if not k.startswith("_") and k != "variants"}
        for venue in index.values()
        if not needle or needle in MR._fold(f"{venue['name']} {venue['city'] or ''}")
    ]
    items.sort(key=lambda v: (-v["matches"], v["name"]))
    page = items[offset: offset + limit]
    # Punkt MIASTA hali (ta sama funkcja co /venues/{key} i atlasy) - hala bez adresu
    # na mapie stoi w swoim mieście. `lat`/`lon` tylko z adresu hali (geokoder ulic,
    # `coords_precision: "address"`); bez niego puste (punkt miasta to nie hala).
    coords = {city: await _geocode(city) for city in {v["city"] for v in page if v.get("city")}}
    for v in page:
        v["city_lat"], v["city_lon"] = coords.get(v.get("city"), (None, None))
        exact = await geocode.venue_point(v.get("city"), v.get("street"), v.get("number"))
        v["lat"], v["lon"] = (exact["lat"], exact["lon"]) if exact else (None, None)
        v["coords_precision"] = "address" if exact else ("city" if v["city_lat"] is not None else None)
    return {"items": page, "limit": limit, "offset": offset, "count": len(items)}


@router.get("/venues/{key}")
async def venue_details(key: str) -> dict[str, Any]:
    venue = (await _venue_index()).get(key)
    if not venue:
        raise HTTPException(404, "Nie znaleziono hali")
    names = list({n for n, _ in venue["variants"]})
    rows = await database.fetch_all(
        select(*_card_cols(), M.c.spectators, M.c.venue_street).where(M.c.venue_name.in_(names))
    )
    mine = [r for r in rows if MR.venue_key(r["venue_name"], r["venue_city"]) == key]
    cards = await _cards(mine)
    day_start, _ = TP.today_bounds()
    today = [c for c in cards if c.get("scheduled_at") and day_start <= c["scheduled_at"] < day_start + timedelta(days=1)]
    week = [c for c in cards if c.get("scheduled_at") and day_start + timedelta(days=1) <= c["scheduled_at"] < day_start + timedelta(days=8)]
    today.sort(key=lambda c: TP.kickoff_sort_key(c["scheduled_at"]))
    week.sort(key=lambda c: TP.kickoff_sort_key(c["scheduled_at"]))
    attendance = sorted((c for c in cards if c.get("spectators")), key=lambda c: -int(c["spectators"]))[:5]
    home_clubs = Counter(c["home_club_id"] for c in cards if c.get("home_club_id"))
    lookup = await _club_lookup(set(home_clubs))
    clubs = [
        {"club_id": cid, "name": (lookup.get(cid) or {}).get("name"), "logo_url": (lookup.get(cid) or {}).get("logo_url"),
         "matches": n}
        for cid, n in home_clubs.most_common(20)
    ]
    # Adres hali (geokoder ulic), a bez niego punkt miasta - `coords_precision` mówi, który.
    exact = await geocode.venue_point(venue["city"], venue["street"], venue["number"])
    lat, lon = (exact["lat"], exact["lon"]) if exact else await _geocode(venue["city"])
    precision = "address" if exact else ("city" if lat is not None else None)
    return {
        "key": key, "name": venue["name"], "city": venue["city"], "street": venue["street"], "number": venue["number"],
        "lat": lat, "lon": lon, "coords_precision": precision,
        "capacity": venue["capacity"], "matches": venue["matches"],
        "clubs": clubs, "today": today, "week": week,
        "attendance_records": [
            {"match_id": c["match_id"], "spectators": int(c["spectators"]), "scheduled_at": c["scheduled_at"],
             "home_team_name": c["home_team_name"], "away_team_name": c["away_team_name"],
             "score_home": c["score_home"], "score_away": c["score_away"]}
            for c in attendance
        ],
    }


# ---------------------------------------------------------------------------
# Wykres sezonu drużyny + kalendarz .ics
# ---------------------------------------------------------------------------

_TEAM_COLS = (
    "match_id", "competition_id", "competition_name", "matchday_id", "matchday_name", "home_team_id", "away_team_id",
    "home_club_id", "away_club_id", "home_team_name", "away_team_name", "scheduled_at", "score_home", "score_away",
    "winner", "withdrawn", "walkover_team_id", "shootout_home", "shootout_away", "match_code",
)


async def _team_row(team_id: str, season_id: str = "") -> dict:
    T = zprp_public_teams
    query = select(T.c.team_id, T.c.season_id, T.c.club_id, T.c.name, T.c.season_name).where(T.c.team_id == team_id)
    if season_id:
        query = query.where(T.c.season_id == season_id)
    row = await database.fetch_one(query.order_by(T.c.season_id.desc()).limit(1))
    if not row:
        raise HTTPException(404, "Nie znaleziono drużyny")
    return _dict(row)


def _round_from_name(name: Any) -> Optional[int]:
    """„Kolejka 5" -> 5. Mecz bez matchday_id (bywa przy dopisanych meczach) dostawał
    numer porządkowy i dublował kolejkę na osi wykresu."""
    hit = re.search(r"(\d+)", str(name or ""))
    return int(hit.group(1)) if hit else None


@router.get("/teams/{team_id}/season-chart")
async def team_season_chart(team_id: str, season_id: str = "") -> dict[str, Any]:
    team = await _team_row(team_id, season_id)
    mine = await database.fetch_all(
        select(*[M.c[c] for c in _TEAM_COLS])
        .where(and_(or_(M.c.home_team_id == team_id, M.c.away_team_id == team_id), M.c.season_id == team["season_id"],
                    M.c.score_home.is_not(None), M.c.score_away.is_not(None), M.c.scheduled_at.is_not(None)))
        .order_by(M.c.scheduled_at)
    )
    played = [_dict(r) for r in mine]
    if not played:
        return {"team_id": team_id, "season_id": team["season_id"], "competition_id": None, "rounds": [],
                "streaks": MR.streaks([]), "best_match": None, "record": MR.empty_record()}
    competition_id = Counter(m["competition_id"] for m in played).most_common(1)[0][0]
    played = [m for m in played if m["competition_id"] == competition_id]
    comp = [_dict(r) for r in await database.fetch_all(
        select(*[M.c[c] for c in _TEAM_COLS]).where(and_(M.c.competition_id == competition_id, M.c.score_home.is_not(None),
                                                         M.c.score_away.is_not(None), M.c.scheduled_at.is_not(None)))
    )]
    # Rozgrywki bywają podzielone na grupy/tabele pod jednym competition_id. Symulacja
    # po wszystkich meczach mieszała grupy (drużyna „1." na wykresie, a 3. w swojej
    # tabeli). Liczymy wyłącznie mecze drużyn z TEJ SAMEJ tabeli co drużyna.
    S = zprp_public_standings
    mine_st = await database.fetch_one(
        select(S.c.table_id, S.c.group_id, S.c.position, S.c.matches)
        .where(and_(S.c.competition_id == competition_id, S.c.team_id == team_id)).limit(1)
    )
    table_size = None
    if mine_st:
        same = [S.c.competition_id == competition_id]
        for col in ("table_id", "group_id"):
            same.append(S.c[col].is_(None) if mine_st[col] is None else S.c[col] == mine_st[col])
        peers = {r["team_id"] for r in await database.fetch_all(select(S.c.team_id).where(and_(*same)))}
        if team_id in peers:
            comp = [c for c in comp if c["home_team_id"] in peers and c["away_team_id"] in peers]
            played = [m for m in played if m["home_team_id"] in peers and m["away_team_id"] in peers] or played
            table_size = len(peers)
    days = {r["matchday_id"]: _dict(r) for r in await database.fetch_all(
        select(zprp_public_matchdays.c.matchday_id, zprp_public_matchdays.c.number, zprp_public_matchdays.c.sequence)
    )}
    rounds, results, details = [], [], []
    for index, m in enumerate(played, start=1):
        upto = [c for c in comp if c["scheduled_at"] <= m["scheduled_at"] + timedelta(hours=12)]
        table = MR.simulate_table(upto)
        row = next((r for r in table if r["team_id"] == team_id), None)
        result = MR.team_result(m, team_id)
        detail = MR.team_result_detail(m, team_id)
        results.append(result)
        details.append(detail)
        home = m["home_team_id"] == team_id
        day = days.get(m.get("matchday_id")) or {}
        rounds.append({
            "round": day.get("number") or _round_from_name(m.get("matchday_name")) or index,
            "position": row["position"] if row else None,
            "points": row["points"] if row else None, "result": result, "result_detail": detail,
            "decided_by": MR.outcome(m)[1], "match_id": m["match_id"],
            "opponent": m["away_team_name"] if home else m["home_team_name"], "home": home,
            "score": f'{m["score_home"]}:{m["score_away"]}', "scheduled_at": m["scheduled_at"],
        })
    # Ostatni punkt = tabela ZPRP, gdy liczy tyle samo meczów (remisy punktowe ZPRP
    # rozstrzyga też meczami bezpośrednimi - tego symulacja nie odtworzy).
    st_item = dict(mine_st) if mine_st else None
    provisional = False
    if st_item:
        st_item.update(competition_id=competition_id, team_id=team_id)
        # Po wyniku skróconym ostatni punkt to tabela wstępna (do czasu oficjalnej).
        provisional = await apply_provisional([st_item])
    official_position = st_item["position"] if st_item else None
    if rounds and st_item and st_item["position"] is not None and int(st_item["matches"] or 0) == len(rounds):
        rounds[-1]["position"] = st_item["position"]
        rounds[-1]["official"] = not provisional
        if provisional:
            rounds[-1]["provisional"] = True
    best = max(played, key=lambda m: (MR.margin_for(m, team_id) or -999, m["scheduled_at"]))
    best_card = None
    if (MR.margin_for(best, team_id) or 0) > 0:
        best_card = (await _cards([best]))[0]
        best_card["margin"] = MR.margin_for(best, team_id)
    return {"team_id": team_id, "season_id": team["season_id"], "competition_id": competition_id,
            "rounds": rounds, "streaks": MR.streaks([r for r in results if r]), "best_match": best_card,
            "table_size": table_size, "official_position": official_position, "provisional": provisional, "record": MR.tally_results(details)}


@router.get("/teams/{team_id}/calendar.ics")
async def team_calendar(team_id: str, season_id: str = "") -> Response:
    team = await _team_row(team_id, season_id)
    rows = await database.fetch_all(
        select(*[M.c[c] for c in _TEAM_COLS], M.c.venue_name, M.c.venue_city)
        .where(and_(or_(M.c.home_team_id == team_id, M.c.away_team_id == team_id),
                    M.c.season_id == team["season_id"], M.c.scheduled_at.is_not(None)))
        .order_by(M.c.scheduled_at)
    )
    matches = [_dict(r) for r in rows]
    await corrections.apply("match", matches)
    body = MR.build_ics(f'{team["name"]} {team.get("season_name") or ""}'.strip(), matches, team_id)
    return Response(body, media_type="text/calendar; charset=utf-8", headers={
        **_CORS, "Cache-Control": "public, max-age=1800",
        "Content-Disposition": f'inline; filename="team-{re.sub(r"[^0-9A-Za-z]+", "", team_id)}.ics"',
    })


# ---------------------------------------------------------------------------
# Rekordy i ciekawostki
# ---------------------------------------------------------------------------

_RECORDS_TTL = 600.0


def _match_label(m: dict) -> str:
    return f'{m.get("home_team_name") or "?"} {m.get("score_home")}:{m.get("score_away")} {m.get("away_team_name") or "?"}'


@router.get("/records")
async def records(season_id: str = "", scope: str = Query("season", pattern="^(season|all)$")) -> dict[str, Any]:
    season = None if scope == "all" else await _season_or_current(season_id)

    async def build() -> dict[str, Any]:
        cond = [M.c.score_home.is_not(None), M.c.score_away.is_not(None)]
        if season:
            cond.append(M.c.season_id == season)
        rows = [_dict(r) for r in await database.fetch_all(
            select(M.c.match_id, M.c.season_id, M.c.home_team_name, M.c.away_team_name, M.c.home_club_id, M.c.away_club_id,
                   M.c.score_home, M.c.score_away, M.c.spectators, M.c.walkover_team_id, M.c.withdrawn,
                   M.c.shootout_home, M.c.shootout_away, M.c.competition_name, M.c.scheduled_at).where(and_(*cond))
        )]
        regular = [m for m in rows if not m["walkover_team_id"] and not m["withdrawn"]]
        items: list[dict] = []

        def add(kind: str, title: str, value: Any, m: Optional[dict] = None, **extra: Any) -> None:
            items.append({"kind": kind, "title": title, "value": value,
                          "match_id": m["match_id"] if m else None, "player_id": extra.pop("player_id", None),
                          "club_id": extra.pop("club_id", None), "label": _match_label(m) if m else extra.pop("label", None),
                          "season_id": m["season_id"] if m else None, **extra})

        if regular:
            top = max(regular, key=lambda m: m["score_home"] + m["score_away"])
            add("highest_scoring_match", "Najwięcej bramek w meczu", top["score_home"] + top["score_away"], top)
            win = max(regular, key=lambda m: abs(m["score_home"] - m["score_away"]))
            margin = abs(win["score_home"] - win["score_away"])
            if margin:
                home_won = win["score_home"] > win["score_away"]
                add("biggest_win", "Najwyższe zwycięstwo", margin, win, side="home" if home_won else "away",
                    club_id=win["home_club_id"] if home_won else win["away_club_id"])
            hi = max(regular, key=lambda m: max(m["score_home"], m["score_away"]))
            home_hi = hi["score_home"] >= hi["score_away"]
            add("most_goals_by_team", "Najwięcej bramek jednej drużyny", max(hi["score_home"], hi["score_away"]), hi,
                side="home" if home_hi else "away", club_id=hi["home_club_id"] if home_hi else hi["away_club_id"])
        crowd = [m for m in rows if m["spectators"]]
        if crowd:
            m = max(crowd, key=lambda m: m["spectators"])
            add("highest_attendance", "Najwięcej widzów", int(m["spectators"]), m)
        shootouts = [m for m in rows if m["shootout_home"] is not None]
        if shootouts:
            # Rekord zbiorczy (bez jednego meczu): karta bez herbów, a „ostatni” to podpowiedź z linkiem.
            last = max(shootouts, key=lambda m: m["scheduled_at"] or datetime.min)
            add("shootout_matches", "Mecze rozstrzygnięte rzutami karnymi", len(shootouts), latest_match_id=last["match_id"])

        for kind, title, column in (
            ("most_goals_player", "Najwięcej bramek zawodnika w meczu", MP.c.goals),
            ("most_penalty_goals_player", "Najwięcej skutecznych karnych w meczu", MP.c.penalty_goals),
        ):
            pcond = [column > 0, M.c.score_home.is_not(None)]
            if season:
                pcond.append(M.c.season_id == season)
            r = await database.fetch_one(
                select(MP.c.player_id, MP.c.side, column.label("v"), zprp_public_players.c.first_name, zprp_public_players.c.last_name,
                       zprp_public_players.c.photo_url,
                       M.c.match_id, M.c.season_id, M.c.home_team_name, M.c.away_team_name, M.c.home_club_id, M.c.away_club_id,
                       M.c.score_home, M.c.score_away)
                .select_from(MP.join(M, M.c.match_id == MP.c.match_id).join(zprp_public_players, zprp_public_players.c.player_id == MP.c.player_id))
                .where(and_(*pcond)).order_by(column.desc(), M.c.scheduled_at.desc()).limit(1)
            )
            if r:
                d = _dict(r)
                person = {"player_id": d["player_id"], "first_name": d["first_name"], "last_name": d["last_name"],
                          "photo_url": d.get("photo_url")}
                await corrections.apply("player", [person])
                add(kind, title, int(d["v"]), d, player_id=d["player_id"], side=d["side"],
                    club_id=d["home_club_id"] if d["side"] == "home" else d["away_club_id"],
                    player_name=f'{person["first_name"] or ""} {person["last_name"] or ""}'.strip(),
                    player_photo_url=person.get("photo_url") or None)
        # Kary 2 min liczone na DRUŻYNĘ w meczu (u zawodnika limit to 3, rekord bez sensu).
        team_sum = func.sum(MP.c.two_minutes)
        tcond = [M.c.score_home.is_not(None)]
        if season:
            tcond.append(M.c.season_id == season)
        r = await database.fetch_one(
            select(MP.c.side, MP.c.team_id, team_sum.label("v"),
                   M.c.match_id, M.c.season_id, M.c.home_team_name, M.c.away_team_name, M.c.home_club_id, M.c.away_club_id,
                   M.c.score_home, M.c.score_away)
            .select_from(MP.join(M, M.c.match_id == MP.c.match_id))
            .where(and_(*tcond)).group_by(MP.c.side, MP.c.team_id, M.c.match_id, M.c.season_id, M.c.home_team_name, M.c.away_team_name,
                      M.c.home_club_id, M.c.away_club_id, M.c.score_home, M.c.score_away, M.c.scheduled_at)
            .having(team_sum > 0).order_by(team_sum.desc(), M.c.scheduled_at.desc()).limit(1)
        )
        if r:
            d = _dict(r)
            add("most_two_minutes_team_match", "Najwięcej kar 2 min jednej drużyny w meczu", int(d["v"]), d, side=d["side"],
                club_id=d["home_club_id"] if d["side"] == "home" else d["away_club_id"])
        lookup = await _club_lookup({i["club_id"] for i in items})
        for item in items:
            club = lookup.get(item.get("club_id")) or {}
            item["club_name"], item["club_logo_url"] = club.get("name"), club.get("logo_url")
        # Karta meczu-rekordu: herby obu drużyn, wynik, data i rozgrywki z tej samej bazy
        # (jedno zapytanie na wszystkie rekordy, zero zapytań do ZPRP).
        ids = {i.get("match_id") for i in items} | {i.get("latest_match_id") for i in items}
        ids.discard(None)
        cards = {c["match_id"]: c for c in await _cards(
            await database.fetch_all(select(*_card_cols()).where(M.c.match_id.in_(list(ids))))
        )} if ids else {}
        for item in items:
            item["match"] = cards.get(item.get("match_id"))
            if item.get("latest_match_id"):
                item["latest"] = cards.get(item["latest_match_id"])
        return {"items": items, "season_id": season, "scope": scope, "matches_considered": len(rows)}

    return await _cached(f"records|{season}|{scope}", _RECORDS_TTL, build)


# ---------------------------------------------------------------------------
# Head-to-head
# ---------------------------------------------------------------------------


@router.get("/h2h")
async def head_to_head(club_a: str = Query(..., min_length=1), club_b: str = Query(..., min_length=1),
                       limit: int = Query(50, ge=1, le=200),
                       category: Optional[str] = None, gender: Optional[str] = None,
                       team_a: Optional[str] = None, team_b: Optional[str] = None) -> dict[str, Any]:
    """`category`/`gender` (opcjonalne, jak w `zprp_public_competitions`) zawężają bilans
    do jednej kategorii — seniorzy nie mieszają się z juniorami tych samych klubów.
    `team_a`/`team_b` (nazwy drużyn klubów A i B) zawężają do tych dwóch drużyn przez sezony
    (id drużyny zmienia się co sezon); bez nich bilans jest na poziomie klubów."""
    if club_a == club_b:
        raise HTTPException(400, "Wybierz dwa różne kluby")
    conds = [
        or_(and_(M.c.home_club_id == club_a, M.c.away_club_id == club_b),
            and_(M.c.home_club_id == club_b, M.c.away_club_id == club_a)),
        M.c.score_home.is_not(None), M.c.score_away.is_not(None),
    ]
    category = (category or "").strip() or None
    gender = (gender or "").strip() or None
    if category or gender:
        C = zprp_public_competitions
        kind = [c for c in ((C.c.category == category) if category else None,
                            (C.c.gender == gender) if gender else None) if c is not None]
        conds.append(M.c.competition_id.in_(select(C.c.competition_id).where(and_(*kind))))
    rows = await database.fetch_all(select(*_card_cols()).where(and_(*conds)).order_by(M.c.scheduled_at.desc()))
    team_a, team_b = (team_a or "").strip(), (team_b or "").strip()
    if team_a and team_b:
        rows = R.h2h_between([dict(r) for r in rows], {"club_id": club_a, "name": team_a}, {"club_id": club_b, "name": team_b})
    cards = await _cards(rows)
    # `a_wins`/`b_wins` liczą też zwycięstwa po karnych; `draws` = równy wynik bez serii karnych
    # w danych (nierozstrzygnięte w źródle). Bilans w czterech stanach: `a_record`/`b_record`.
    bal = {"a_wins": 0, "b_wins": 0, "draws": 0, "shootouts": 0, "a_goals": 0, "b_goals": 0,
           "a_wins_shootout": 0, "b_wins_shootout": 0}
    best: dict[str, Optional[dict]] = {"a": None, "b": None}
    for c in cards:
        a_home = c["home_club_id"] == club_a
        a_goals, b_goals = (c["score_home"], c["score_away"]) if a_home else (c["score_away"], c["score_home"])
        bal["a_goals"] += a_goals
        bal["b_goals"] += b_goals
        if c.get("decided_by") == "shootout":
            bal["shootouts"] += 1
        side = c.get("winner_side")
        if side is None:
            bal["draws"] += 1
            continue
        a_won = (side == "home") == a_home
        bal["a_wins" if a_won else "b_wins"] += 1
        if c.get("decided_by") == "shootout":
            bal["a_wins_shootout" if a_won else "b_wins_shootout"] += 1
        key = "a" if a_won else "b"
        margin = abs(a_goals - b_goals)
        if c.get("decided_by") != "walkover" and margin and (best[key] is None or margin > best[key]["margin"]):
            best[key] = {**c, "margin": margin}
    a_wk, b_wk = bal["a_wins_shootout"], bal["b_wins_shootout"]
    bal["a_record"] = {"w": bal["a_wins"] - a_wk, "wk": a_wk, "lk": b_wk, "l": bal["b_wins"] - b_wk}
    bal["b_record"] = {"w": bal["b_wins"] - b_wk, "wk": b_wk, "lk": a_wk, "l": bal["a_wins"] - a_wk}
    lookup = await _club_lookup({club_a, club_b})
    return {
        "club_a": {"club_id": club_a, **{k: (lookup.get(club_a) or {}).get(k) for k in ("name", "logo_url", "city")}},
        "club_b": {"club_id": club_b, **{k: (lookup.get(club_b) or {}).get(k) for k in ("name", "logo_url", "city")}},
        "matches": cards[:limit], "total": len(cards), "balance": bal, "biggest_wins": best,
        "category": category, "gender": gender,
        "team_a": team_a or None, "team_b": team_b or None,
    }


# ---------------------------------------------------------------------------
# Podsumowanie kolejki
# ---------------------------------------------------------------------------


@router.get("/competitions/{competition_id}/rounds/{round}/review")
async def round_review(competition_id: str, round: str) -> dict[str, Any]:  # noqa: A002 - nazwa z kontraktu
    """`round` = matchday_id albo numer kolejki (przy kilku rundach: pierwsza po kolei).

    Ruchy w tabeli: miejsce po tej kolejce kontra po poprzedniej, obie tabele z wyników
    (z zapasem ProEla) tą samą regułą (`round_review_rules`). Do tego statystyki kolejki.
    """
    return await _cached(f"round-review:{competition_id}:{round}", 30.0, lambda: _round_review(competition_id, round))


async def _round_review(competition_id: str, round: str) -> dict[str, Any]:  # noqa: A002
    D, RN, ST = zprp_public_matchdays, zprp_public_rounds, zprp_public_standings
    days = [_dict(r) for r in await database.fetch_all(
        select(D.c.matchday_id, D.c.round_id, D.c.number, D.c.sequence, D.c.name, D.c.starts_on, D.c.ends_on,
               RN.c.name.label("round_name"))
        .join(RN, RN.c.round_id == D.c.round_id).where(RN.c.competition_id == competition_id).order_by(D.c.sequence)
    )]
    order = RV.day_order(days)
    by_order = sorted(days, key=lambda d: order[str(d["matchday_id"])])
    target = next((d for d in days if d["matchday_id"] == round), None) or next(
        (d for d in by_order if str(d["number"]) == round), None) or next(
        (d for d in by_order if str(ROUNDS.matchday_number(d["number"], d["name"]) or "") == round), None)
    if not target:
        raise HTTPException(404, "Nie znaleziono kolejki")
    target_id = str(target["matchday_id"])

    # Wszystkie mecze rozgrywek jako karty: ten sam wynik co na ekranie (korekty, zapas z ProEla).
    cards = await _cards(await database.fetch_all(
        select(*_card_cols(), M.c.matchday_id).where(M.c.competition_id == competition_id)))
    cards = RV.assign_days(cards, days)
    current = sorted((c for c in cards if c.get("matchday_id") == target_id),
                     key=lambda c: TP.kickoff_sort_key(c.get("scheduled_at")))
    official = [_dict(r) for r in await database.fetch_all(
        select(ST.c.table_id, ST.c.group_id, ST.c.team_id, ST.c.wins, ST.c.draws, ST.c.points)
        .where(ST.c.competition_id == competition_id))]
    win_pts = SP.win_points(official) if official else 3
    round_teams = {str(c.get(k)) for c in current for k in ("home_team_id", "away_team_id") if c.get(k)}
    group_of = RV.team_groups(official, round_teams)
    teams: dict[str, dict] = {}
    for c in cards:
        for side in ("home", "away"):
            tid = c.get(f"{side}_team_id")
            if tid and tid not in teams:
                teams[tid] = {"team_id": tid, "team_name": c.get(f"{side}_team_name"), "club_id": c.get(f"{side}_club_id")}
    moves = RV.table_moves(cards, order, target_id, win_pts, teams.values(), group_of)
    logos = {c.get(f"{s}_club_id"): c.get(f"{s}_logo_url") for c in cards for s in ("home", "away") if c.get(f"{s}_club_id")}
    for m in moves:
        m["logo_url"] = logos.get(m.get("club_id"))

    players = await _round_players([c for c in current if RV.counts(c)])
    potr = _player_of_round(players)
    season_cards = await _season_two_minutes(competition_id)
    timelines = await _round_timelines([c for c in current if RV.counts(c)])
    stats = RV.round_stats(current, [c for c in cards if RV.counts(c)], players, season_cards, timelines)

    day = ROUNDS.decorate_matchday({k: target[k] for k in ("matchday_id", "number", "name", "round_name", "starts_on", "ends_on")}, current)
    return {"competition_id": competition_id,
            "round": {k: day.get(k) for k in ("matchday_id", "number", "name", "round_name", "label", "date_from", "date_to",
                                               "matches_played", "matches_total")},
            "results": current, "table_moves": moves, "moves_source": "results", "win_points": win_pts,
            "player_of_round": potr, "stats": stats}


async def _round_players(played: list[dict]) -> list[dict]:
    """Zawodnicy z protokołów meczów kolejki (bramki, kary) z nazwą drużyny i herbem."""
    if not played:
        return []
    by_id = {str(c["match_id"]): c for c in played}
    P = zprp_public_players
    rows = [_dict(r) for r in await database.fetch_all(
        select(MP.c.match_id, MP.c.player_id, MP.c.team_id, MP.c.side, MP.c.goals, MP.c.two_minutes,
               MP.c.penalty_goals, MP.c.penalty_attempts, P.c.first_name, P.c.last_name, P.c.photo_url)
        .select_from(MP.join(P, P.c.player_id == MP.c.player_id))
        .where(MP.c.match_id.in_(list(by_id))))]
    out = []
    for r in rows:
        card = by_id.get(str(r["match_id"])) or {}
        side = "home" if r.get("side") == "home" else "away"
        out.append({**r, "name": f'{r.get("first_name") or ""} {r.get("last_name") or ""}'.strip(),
                    "team_id": r.get("team_id") or card.get(f"{side}_team_id"),
                    "team_name": card.get(f"{side}_team_name"), "club_id": card.get(f"{side}_club_id"),
                    "club_logo_url": card.get(f"{side}_logo_url")})
    return out


def _player_of_round(players: list[dict]) -> Optional[dict]:
    """Najwięcej bramek w jednym meczu kolejki (mniej karnych, mniej kar wyżej)."""
    scored = [p for p in players if (p.get("goals") or 0) > 0]
    if not scored:
        return None
    d = min(scored, key=lambda p: (-(p.get("goals") or 0), p.get("penalty_attempts") or 0, p.get("two_minutes") or 0,
                                   str(p.get("player_id"))))
    pens = f'{d.get("penalty_goals") or 0}/{d["penalty_attempts"]}' if d.get("penalty_attempts") else None
    return {"player_id": d["player_id"], "name": d["name"], "team_name": d.get("team_name"), "team": d.get("team_name"),
            "club_id": d.get("club_id"), "club_logo_url": d.get("club_logo_url"), "photo_url": d.get("photo_url"),
            "match_id": d["match_id"], "goals": d["goals"], "penalty_goals": d.get("penalty_goals"), "penalties": pens,
            "rule": "najwięcej bramek w kolejce"}


async def _season_two_minutes(competition_id: str) -> dict:
    """Kary 2 min w meczach rozgrywek z protokołem (średnia sezonu do porównania)."""
    row = await database.fetch_one(
        select(func.count(func.distinct(MP.c.match_id)).label("matches"), func.sum(MP.c.two_minutes).label("two_minutes"))
        .select_from(MP.join(M, M.c.match_id == MP.c.match_id))
        .where(and_(M.c.competition_id == competition_id, M.c.score_home.is_not(None))))
    return _dict(row) if row else {}


async def _round_timelines(played: list[dict]) -> dict[str, dict]:
    """Przebieg meczów kolejki z zakończonych protokołów ProEl. Dodatek: błąd = brak dodatków."""
    if not played:
        return {}
    try:
        rows = await proel_rows([str(c["match_id"]) for c in played],
                                sorted({str(c.get("match_code") or "").strip() for c in played} - {""}))
        out: dict[str, dict] = {}
        for c in played:
            row = PR.pick_row(rows, c)
            if not row or str(row.get("status") or "") not in PR.FINISHED:
                continue
            blob = row.get("blob") or {}
            cfg = blob.get("matchConfig") if isinstance(blob.get("matchConfig"), dict) else {}
            out[str(c["match_id"])] = LR.timeline(blob, LR.host_is_home(cfg, c.get("home_team_name"), c.get("away_team_name")))
        return out
    except Exception:  # noqa: BLE001 - ProEl jest dodatkiem
        return {}


# ---------------------------------------------------------------------------
# Sędzia (tylko dane z API, bez ocen)
# ---------------------------------------------------------------------------


@router.post("/referees/{referee_id}/refresh")
async def referee_refresh(referee_id: str) -> dict[str, Any]:
    """Odświeża z ZPRP najbliższe mecze sędziego (maks. 10; limit 2 min na mecz w refresh_match)."""
    from app.zprp_public.ondemand import refresh_match

    if RP.is_placeholder_id(referee_id):  # brak obsady nie ma czego odświeżać
        return {"checked": 0, "refreshed": 0, "changed": False}
    since = datetime.now(timezone.utc) - timedelta(days=1)
    rows = await database.fetch_all(
        select(M.c.match_id)
        .where(and_(or_(M.c.referee_1_id == referee_id, M.c.referee_2_id == referee_id), M.c.scheduled_at >= since))
        .order_by(M.c.scheduled_at.asc()).limit(10)
    )
    async def run() -> dict[str, Any]:
        results = []
        for r in rows:  # po kolei, żeby nie młotkować ZPRP
            results.append(await refresh_match(r["match_id"]))
        return {"checked": len(results), "refreshed": sum(1 for r in results if r["refreshed"]),
                "changed": any(r["changed"] for r in results)}

    task = asyncio.ensure_future(run())
    try:
        return await asyncio.wait_for(asyncio.shield(task), timeout=6)
    except asyncio.TimeoutError:
        return {"checked": len(rows), "refreshed": 0, "changed": False, "pending": True}  # reszta dobiega w tle


# ---------------------------------------------------------------------------
# Jeden zakres dla całego profilu sędziego (sezon albo `all` = cała kariera):
# nagłówek liczy karierę BEZ limitów, a pasek liczb, mapa z km, kluby,
# rozgrywki, para i lista meczów biorą dokładnie ten sam zakres z serwera.
# ---------------------------------------------------------------------------

_REF_TTL = 120.0


def _ref_cols() -> tuple:
    return (M.c.referee_1_id, M.c.referee_1_name, M.c.referee_2_id, M.c.referee_2_name)


def _who(referee_id: str):
    return or_(M.c.referee_1_id == referee_id, M.c.referee_2_id == referee_id)


def _placeholder_404() -> HTTPException:
    """Numer, którym ZPRP oznacza brak obsady: 404 z kodem, front pokazuje wyjaśnienie, nie liczby."""
    return HTTPException(404, {"detail": RP.ERROR_MESSAGE, "code": RP.ERROR_CODE})


async def _referee_names(referee_id: str) -> Counter:
    """Nazwiska przy tym numerze (oczyszczone, z liczbą meczów) - także znaczniki braku obsady."""
    names: Counter = Counter()
    for idc, nmc in RP.REFEREE_SLOTS:
        for r in await database.fetch_all(
            select(M.c[nmc].label("name"), func.count().label("n")).where(M.c[idc] == referee_id).group_by(M.c[nmc])
        ):
            name = _clean_ref_name(r["name"] or "")
            if name:
                names[name] += int(r["n"])
    return names


async def _referee_scope(referee_id: str, season_id: str = "") -> dict[str, Any]:
    """Kariera (jedno GROUP BY, bez limitu) i rozstrzygnięty zakres. 404, gdy sędzia nie ma meczów;
    404 z kodem REFEREE_PLACEHOLDER, gdy numer to placeholder ZPRP (brak obsady)."""
    if RP.is_placeholder_id(referee_id):
        raise _placeholder_404()
    groups = [_dict(r) for r in await database.fetch_all(
        select(M.c.season_id, M.c.competition_id, func.max(M.c.competition_name).label("competition_name"),
               func.count().label("n"))
        .where(_who(referee_id)).group_by(M.c.season_id, M.c.competition_id)
    )]
    if not groups:
        # Po sprzątaniu stary link do placeholdera nie ma meczów - rejestr mówi, czym był.
        await RP.load_known_ids()
        if RP.is_placeholder_id(referee_id):
            raise _placeholder_404()
        raise HTTPException(404, "Nie znaleziono sędziego")
    # Dane sprzed sprzątania: numer, przy którym stoją głównie znaczniki „--- ---", to brak obsady.
    names = await _referee_names(referee_id)
    real = Counter({n: c for n, c in names.items() if not RP.is_blank_name(n)})
    marked = sum(c for n, c in names.items() if RP.is_placeholder_name(n))
    if marked and marked >= sum(real.values()):
        raise _placeholder_404()
    seasons_map, current = await seasons_info()
    career = RS.career_totals(groups)
    counts = career.pop("by_season")
    order = sorted(counts, key=lambda sid: -((seasons_map.get(sid) or {}).get("start_year") or 0))
    seasons = [{"season_id": sid, "name": (seasons_map.get(sid) or {}).get("name"), "matches": counts[sid],
                "is_current": sid == current} for sid in order]
    return {
        "name": real.most_common(1)[0][0] if real else None,
        "groups": groups, "career": career, "seasons": seasons, "current": current, "seasons_map": seasons_map,
        "default": RS.pick_season("", counts, current, order),
        "wanted": RS.pick_season(season_id, counts, current, order),
    }


def _scope_meta(scope: dict) -> dict[str, Any]:
    wanted = scope["wanted"]
    if wanted == RS.ALL_SEASONS:
        return {"season_id": RS.ALL_SEASONS, "name": None, "is_current": False, "all": True}
    return {"season_id": wanted, "name": (scope["seasons_map"].get(wanted) or {}).get("name"),
            "is_current": wanted == scope["current"], "all": False}


async def _scope_rows(referee_id: str, wanted: str) -> list[dict]:
    cond = _who(referee_id)
    if wanted != RS.ALL_SEASONS:
        cond = and_(cond, M.c.season_id == wanted)
    return [_dict(r) for r in await database.fetch_all(
        select(*_card_cols(), *_ref_cols()).where(cond).order_by(M.c.scheduled_at.desc())
    )]


@router.get("/referees/{referee_id}")
async def referee_profile(referee_id: str, limit: int = Query(1000, ge=0, le=5000)) -> dict[str, Any]:
    """Profil: kariera bez limitów (`career`, `matches_total`, sezony, rozgrywki) i domyślny zakres.
    `matches` zostaje dla starszych klientów (liczyły nagłówek z długości listy, więc domyślnie
    wszystkie); portal bierze listę zakresu z /referees/{id}/matches i podaje `limit=0`."""
    return await _cached(f"refprof:{referee_id}:{limit}", _REF_TTL, lambda: _referee_profile(referee_id, limit))


async def _referee_profile(referee_id: str, limit: int) -> dict[str, Any]:
    from app.zprp_public import portal as P

    scope = await _referee_scope(referee_id)
    comps: dict[str, dict] = {}
    for g in scope["groups"]:
        e = comps.setdefault(g["competition_id"], {"competition_id": g["competition_id"], "name": g["competition_name"],
                                                  "season_id": g["season_id"], "matches": 0})
        e["matches"] += int(g["n"])
    cards: list[dict] = []
    if limit:
        cards = await _cards(await database.fetch_all(
            select(*_card_cols(), *_ref_cols()).where(_who(referee_id)).order_by(M.c.scheduled_at.desc()).limit(limit)
        ))
    career = scope["career"]
    P.note_referee_total(referee_id, career["matches"])  # wyszukiwarka pokaże tę samą liczbę
    return {
        "referee_id": referee_id, "name": scope["name"],
        "matches_total": career["matches"],
        "career": career,
        "current_season_id": scope["current"],
        "default_season_id": scope["default"],
        "seasons": scope["seasons"],
        "matches": cards,
        "matches_truncated": len(cards) < career["matches"],
        "competitions": sorted(comps.values(), key=lambda e: (-e["matches"], e["name"] or "")),
    }


@router.get("/referees/{referee_id}/matches")
async def referee_matches(referee_id: str, season_id: str = "", limit: int = Query(1000, ge=1, le=5000),
                          offset: int = Query(0, ge=0)) -> dict[str, Any]:
    """Wszystkie mecze sędziego w zakresie (sezon albo `all`), najnowsze najpierw."""
    key = f"refmatches:{referee_id}:{season_id.strip()}:{limit}:{offset}"
    return await _cached(key, _REF_TTL, lambda: _referee_matches(referee_id, season_id, limit, offset))


async def _referee_matches(referee_id: str, season_id: str, limit: int, offset: int) -> dict[str, Any]:
    scope = await _referee_scope(referee_id, season_id)
    rows = await _scope_rows(referee_id, scope["wanted"])
    finished = sum(1 for r in rows if r.get("score_home") is not None and r.get("score_away") is not None)
    return {
        "referee_id": referee_id,
        "season": _scope_meta(scope),
        "count": len(rows),
        "finished": finished,
        "not_played": len(rows) - finished,
        "limit": limit, "offset": offset,
        "items": await _cards(rows[offset: offset + limit]),
    }


@router.get("/referees/{referee_id}/stats")
async def referee_stats(referee_id: str, season_id: str = "") -> dict[str, Any]:
    # Krótki cache: Moje pyta o każdego obserwowanego sędziego; zmiana obsady czyści _cache.
    return await _cached(f"refstats:{referee_id}:{season_id.strip()}", _REF_TTL, lambda: _referee_stats(referee_id, season_id))


async def _referee_stats(referee_id: str, season_id: str) -> dict[str, Any]:
    """Zakres sędziego dla „Moje Pod Ręką” i profilu: najbliższy mecz, ostatnie wyniki,
    rozgrywki/kategorie, partner w parze, hale/miasta z przybliżonymi km, średnie
    bramek i kar 2 min, czerwone kartki, kluby. `season_id=all` - cała kariera (km tą samą
    regułą: od najczęstszego miasta). Bez `season_id`: bieżący sezon, a gdy sędzia nie ma
    w nim meczów - ostatni sezon, w którym gwizdał. `career` - kariera bez limitów."""
    scope = await _referee_scope(referee_id, season_id)
    rows = await _scope_rows(referee_id, scope["wanted"])
    ids = [r["match_id"] for r in rows]
    protocol: dict[str, dict] = {}
    if ids:
        sums = await database.fetch_all(
            select(MP.c.match_id, func.sum(MP.c.two_minutes).label("two_minutes"),
                   func.sum(MP.c.disqualifications).label("disqualifications"),
                   func.sum(MP.c.warnings).label("warnings"))
            .where(MP.c.match_id.in_(ids)).group_by(MP.c.match_id)
        )
        protocol = {r["match_id"]: _dict(r) for r in sums}
    kinds: dict[str, tuple[Any, Any]] = {}
    comp_ids = list({r["competition_id"] for r in rows if r.get("competition_id")})
    if comp_ids:
        C = zprp_public_competitions
        kinds = {r["competition_id"]: (r["category"], r["gender"]) for r in await database.fetch_all(
            select(C.c.competition_id, C.c.category, C.c.gender).where(C.c.competition_id.in_(comp_ids)))}

    lookup = await _club_lookup({r.get(k) for r in rows for k in ("home_club_id", "away_club_id")})
    # Mecz bez miasta hali w terminarzu: miasto gospodarza, żeby trafił na mapę i do km.
    geo_rows = [r if (r.get("venue_city") or "").strip()
                else {**r, "venue_city": (lookup.get(r.get("home_club_id")) or {}).get("city")} for r in rows]
    summary = RS.summarize(geo_rows, referee_id, protocol, venue_key=MR.venue_key, display_city=R.display_city,
                           clean_name=_clean_ref_name, kinds=kinds)
    coords = {}
    for c in summary["cities"]:
        coords[c["city"]] = await _geocode(c["city"])
    RS.attach_geo(summary, coords)

    club_counts = summary.pop("club_counts")
    clubs = [{"club_id": cid, "name": (lookup.get(cid) or {}).get("name"), "logo_url": (lookup.get(cid) or {}).get("logo_url"),
              "city": (lookup.get(cid) or {}).get("city"), "matches": n} for cid, n in club_counts]

    cards = await _cards(rows)  # wiersze mają kolumny pary, więc karta niesie obu sędziów
    now = TP.warsaw_now()
    upcoming = sorted((c for c in cards if c["status"] == "scheduled" and c.get("scheduled_at")
                       and TP.is_upcoming_at(c["scheduled_at"], now, R.UPCOMING_GRACE)),
                      key=lambda c: TP.kickoff_sort_key(c["scheduled_at"]))
    recent = [c for c in cards if c["status"] == "finished"][:5]
    names = Counter(n for n in (_clean_ref_name((r["referee_1_name"] if r["referee_1_id"] == referee_id else r["referee_2_name"]) or "")
                                for r in rows) if not RP.is_blank_name(n))
    return {
        "referee_id": referee_id,
        "name": (names.most_common(1)[0][0] if names else None) or scope["name"],
        "season": _scope_meta(scope),
        "scope": "all" if scope["wanted"] == RS.ALL_SEASONS else "season",
        "seasons": scope["seasons"],
        "career": scope["career"],
        "current_season_id": scope["current"],
        "default_season_id": scope["default"],
        "next": upcoming[0] if upcoming else None,
        "upcoming_count": len(upcoming),
        "recent": recent,
        "clubs": clubs,
        **summary,
    }

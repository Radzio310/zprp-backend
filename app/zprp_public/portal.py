"""Rozszerzenia publicznego API pod portal BAZA pod RĘKĄ (tylko dodatki).

Prefiks jak `app.zprp_public.api` (`/api/v1/handball`). Nic z istniejących
odpowiedzi się nie zmienia - to nowe trasy:

* `GET /map`                         miasta klubów ze współrzędnymi,
* `GET /clubs/{id}/overview`         profil klubu,
* `GET /teams/{id}/overview`         profil drużyny,
* `GET /players/{id}/overview`       profil zawodnika (statystyki per sezon),
* `GET /matches/{id}/overview`       ekran meczu,
* `GET /competitions/{id}/schedule`  terminarz wg kolejek,
* `GET /search/global`               szukajka z miastami i meczami,
* `GET /compare`                     metryki do porównywarki (do 4 podmiotów).
"""

from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timedelta
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import and_, func, or_, select

from app.db import (
    database,
    national_distance_cities,
    zprp_public_associations,
    zprp_public_clubs,
    zprp_public_competitions,
    zprp_public_match_players,
    zprp_public_match_staff,
    zprp_public_matchdays,
    zprp_public_matches,
    zprp_public_players,
    zprp_public_rounds,
    zprp_public_scorers,
    zprp_public_seasons,
    zprp_public_standings,
    zprp_public_team_rosters,
    zprp_public_teams,
)
from app.national_distance_parser import normalize_city_key
from app.zprp_public import corrections, portal_rules as R
from app.zprp_public import match_rules as MR
from app.zprp_public.protocol_times import attach_protocol_times
from app.zprp_public.enrich import enrich_matches
from app.zprp_public.ondemand import ensure_details
from app.zprp_public.api import _dict, _public_player, search as base_search
from app.zprp_public.privacy import public_club, public_team

router = APIRouter(prefix="/api/v1/handball", tags=["handball_portal"])

M = zprp_public_matches
MP = zprp_public_match_players

CARD_COLUMNS = (
    "match_id", "season_id", "competition_id", "competition_name", "round_name", "matchday_name",
    "home_team_id", "away_team_id", "home_club_id", "away_club_id", "home_team_name", "away_team_name",
    "scheduled_at", "played_at", "score_home", "score_away", "halftime_home", "halftime_away",
    "winner", "withdrawn", "protocol_approved", "venue_name", "venue_city",
    "match_code", "shootout_home", "shootout_away", "walkover_team_id",
)
PLAYER_STAT_COLUMNS = (
    "goals", "warnings", "two_minutes", "disqualifications", "direct_red_cards",
    "penalty_attempts", "penalty_goals", "shootout_attempts", "shootout_goals",
)


# ---------------------------------------------------------------------------
# Wspólne helpery
# ---------------------------------------------------------------------------


def _card_cols():
    return [M.c[name] for name in CARD_COLUMNS]


def _status(card: dict) -> str:
    """Status meczu wyłącznie z danych źródła. Nigdy „live" z heurystyki czasu."""
    if card.get("withdrawn"):
        return "withdrawn"
    if card.get("score_home") is not None and card.get("score_away") is not None:
        return "finished"
    return "scheduled"


async def _club_lookup(club_ids: set[str]) -> dict[str, dict]:
    ids = [c for c in club_ids if c]
    if not ids:
        return {}
    rows = await database.fetch_all(
        select(
            zprp_public_clubs.c.club_id, zprp_public_clubs.c.name,
            zprp_public_clubs.c.logo_url, zprp_public_clubs.c.city,
        ).where(zprp_public_clubs.c.club_id.in_(ids))
    )
    found = {r["club_id"]: _dict(r) for r in rows}
    await corrections.apply("club", list(found.values()))
    return found


async def _cards(rows: list[Any]) -> list[dict[str, Any]]:
    cards = [_dict(r) for r in rows]
    lookup = await _club_lookup({c.get(k) for c in cards for k in ("home_club_id", "away_club_id")})
    for card in cards:
        card["status"] = _status(card)
        card["home_logo_url"] = (lookup.get(card.get("home_club_id")) or {}).get("logo_url")
        card["away_logo_url"] = (lookup.get(card.get("away_club_id")) or {}).get("logo_url")
    await corrections.apply("match", cards)
    await enrich_matches(cards)
    return cards


async def _resolve_season(season_id: str = "") -> Optional[str]:
    if season_id.strip():
        return season_id.strip()
    row = await database.fetch_one(
        select(zprp_public_seasons.c.season_id)
        .order_by(zprp_public_seasons.c.active.desc(), zprp_public_seasons.c.start_year.desc())
        .limit(1)
    )
    return row["season_id"] if row else None


async def _season_info(season_id: Optional[str]) -> Optional[dict]:
    if not season_id:
        return None
    row = await database.fetch_one(
        select(zprp_public_seasons.c.season_id, zprp_public_seasons.c.name, zprp_public_seasons.c.start_year,
               zprp_public_seasons.c.active).where(zprp_public_seasons.c.season_id == season_id)
    )
    return _dict(row) or None


def _split_upcoming(cards: list[dict], now: datetime, limit: int = 5) -> tuple[list[dict], list[dict]]:
    played = [c for c in cards if c["status"] == "finished"]
    played.sort(key=lambda c: c.get("scheduled_at") or datetime.min, reverse=True)
    upcoming = [c for c in cards if c["status"] == "scheduled" and (c.get("scheduled_at") or now) >= now - timedelta(hours=3)]
    upcoming.sort(key=lambda c: c.get("scheduled_at") or datetime.max)
    return played[:limit], upcoming[:limit]


async def _standing_rows(team_ids: list[str], season_id: Optional[str]) -> list[dict]:
    if not team_ids:
        return []
    query = (
        select(
            zprp_public_standings.c.competition_id, zprp_public_standings.c.table_id,
            zprp_public_standings.c.group_id, zprp_public_standings.c.team_id,
            zprp_public_standings.c.position, zprp_public_standings.c.matches,
            zprp_public_standings.c.wins, zprp_public_standings.c.draws, zprp_public_standings.c.losses,
            zprp_public_standings.c.goals_for, zprp_public_standings.c.goals_against,
            zprp_public_standings.c.points,
            zprp_public_competitions.c.name.label("competition_name"),
            zprp_public_competitions.c.season_id,
            zprp_public_competitions.c.team_count,
        )
        .join(zprp_public_competitions, zprp_public_competitions.c.competition_id == zprp_public_standings.c.competition_id)
        .where(zprp_public_standings.c.team_id.in_(team_ids))
    )
    if season_id:
        query = query.where(zprp_public_competitions.c.season_id == season_id)
    return [_dict(r) for r in await database.fetch_all(query)]


async def _scorers_for_teams(team_ids: list[str], season_id: Optional[str], limit: int = 10) -> list[dict]:
    if not team_ids:
        return []
    query = (
        select(
            zprp_public_players.c.player_id, zprp_public_players.c.first_name, zprp_public_players.c.last_name,
            zprp_public_players.c.birth_year, zprp_public_players.c.photo_url,
            func.sum(zprp_public_scorers.c.goals).label("goals"),
            func.sum(zprp_public_scorers.c.matches).label("matches"),
            func.sum(zprp_public_scorers.c.penalty_goals).label("penalty_goals"),
            func.sum(zprp_public_scorers.c.two_minutes).label("two_minutes"),
        )
        .join(zprp_public_players, zprp_public_players.c.player_id == zprp_public_scorers.c.player_id)
        .join(zprp_public_competitions, zprp_public_competitions.c.competition_id == zprp_public_scorers.c.competition_id)
        .where(zprp_public_scorers.c.team_id.in_(team_ids))
        .group_by(zprp_public_players.c.player_id, zprp_public_players.c.first_name, zprp_public_players.c.last_name,
                  zprp_public_players.c.birth_year, zprp_public_players.c.photo_url)
        .order_by(func.sum(zprp_public_scorers.c.goals).desc())
        .limit(limit)
    )
    if season_id:
        query = query.where(zprp_public_competitions.c.season_id == season_id)
    return [_dict(r) for r in await database.fetch_all(query)]


# ---------------------------------------------------------------------------
# Mapa
# ---------------------------------------------------------------------------

_NODES_TTL = 1800
_MAP_TTL = 300
_nodes_cache: dict[str, Any] = {"at": 0.0, "index": {}}
_map_cache: dict[str, tuple[float, dict]] = {}


async def _node_index() -> dict[str, list[dict]]:
    if time.monotonic() - _nodes_cache["at"] < _NODES_TTL and _nodes_cache["index"]:
        return _nodes_cache["index"]
    rows = await database.fetch_all(
        select(
            national_distance_cities.c.city_key, national_distance_cities.c.name, national_distance_cities.c.name_key,
            national_distance_cities.c.latitude, national_distance_cities.c.longitude,
            national_distance_cities.c.province, national_distance_cities.c.observations,
            national_distance_cities.c.approximate,
        )
    )
    nodes = [
        {
            "key": r["city_key"], "name": r["name"], "name_key": r["name_key"],
            "lat": r["latitude"], "lon": r["longitude"], "province": r["province"] or "",
            "weight": int(r["observations"] or 0), "approximate": bool(r["approximate"]),
        }
        for r in rows
    ]
    index = R.build_index(nodes)
    _nodes_cache.update(at=time.monotonic(), index=index)
    return index


async def _gazetteer_lookup():
    """Skorowidz GeoNames jako rezerwa (ładowany leniwie, poza pętlą zdarzeń)."""
    try:
        from app import national_places

        gaz = await national_places.gazetteer()
    except Exception:  # noqa: BLE001 - brak pliku skorowidza nie wywraca mapy
        return None

    def lookup(key: str) -> list[dict]:
        return [
            {"key": f"gz:{p.gid}", "name": p.name, "lat": p.lat, "lon": p.lon, "province": p.province,
             "weight": p.population, "approximate": False}
            for p in gaz.candidates(key)
        ]

    return lookup


async def build_map(season_id: Optional[str]) -> dict[str, Any]:
    now = datetime.now()
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    index = await _node_index()
    club_rows, assoc_rows, team_rows, today_rows = await asyncio.gather(
        database.fetch_all(
            select(zprp_public_clubs.c.club_id, zprp_public_clubs.c.name, zprp_public_clubs.c.city,
                   zprp_public_clubs.c.logo_url, zprp_public_clubs.c.association_id)
            .where(zprp_public_clubs.c.archived.is_(False))
        ),
        database.fetch_all(select(zprp_public_associations.c.association_id, zprp_public_associations.c.name)),
        database.fetch_all(
            select(zprp_public_teams.c.club_id, func.count().label("n"))
            .where(zprp_public_teams.c.season_id == season_id if season_id else True)
            .group_by(zprp_public_teams.c.club_id)
        ),
        database.fetch_all(
            select(M.c.match_id, M.c.venue_city, M.c.home_club_id)
            .where(and_(M.c.scheduled_at >= day_start, M.c.scheduled_at < day_start + timedelta(days=1)))
        ),
    )
    assoc_province = {r["association_id"]: R.province_hint(r["name"]) for r in assoc_rows}
    teams_by_club = {r["club_id"]: int(r["n"]) for r in team_rows}
    club_by_id = {r["club_id"]: _dict(r) for r in club_rows}

    # (nazwa miasta, województwo-wskazówka) -> rekord miasta
    groups: dict[str, dict] = {}
    unresolved: dict[str, dict] = {}

    def slot(raw: object, hint: str) -> Optional[dict]:
        variants = R.city_variants(raw)
        if not variants:
            return None
        bucket = unresolved.setdefault(variants[0], {"city": R.display_city(raw), "hint": hint, "raw": raw, "clubs": [], "matches": []})
        if hint and not bucket["hint"]:
            bucket["hint"] = hint
        return bucket

    for club in club_rows:
        bucket = slot(club["city"], assoc_province.get(club["association_id"], ""))
        if bucket:
            bucket["clubs"].append(club["club_id"])
    for match in today_rows:
        home = club_by_id.get(match["home_club_id"]) or {}
        raw = match["venue_city"] or home.get("city")
        hint = assoc_province.get(home.get("association_id"), "")
        bucket = slot(raw, hint)
        if bucket:
            bucket["matches"].append(match["match_id"])

    fallback_fn = None
    resolved_map: dict[str, Optional[dict]] = {}
    for vkey, bucket in unresolved.items():
        resolved_map[vkey] = R.resolve_city(bucket["raw"], index, bucket["hint"])
    if any(v is None for v in resolved_map.values()):
        fallback_fn = await _gazetteer_lookup()
        if fallback_fn:
            for vkey, bucket in unresolved.items():
                if resolved_map[vkey] is None:
                    resolved_map[vkey] = R.resolve_city(bucket["raw"], index, bucket["hint"], fallback_fn)

    unmatched = []
    for vkey, bucket in unresolved.items():
        place = resolved_map[vkey]
        if not place:
            unmatched.append({"city": bucket["city"], "clubs": len(bucket["clubs"]), "matches_today": len(bucket["matches"])})
            continue
        gkey = place["key"]
        group = groups.setdefault(gkey, {
            "key": gkey, "city": place["name"] or bucket["city"], "lat": place["lat"], "lon": place["lon"],
            "province": place.get("province") or "", "voivodeship": R.voivodeship(place.get("province") or ""),
            "approximate": bool(place.get("approximate")), "source": place["source"],
            "club_ids": [], "match_ids": [], "aliases": [],
        })
        group["club_ids"] += bucket["clubs"]
        group["match_ids"] += bucket["matches"]
        if bucket["city"] not in group["aliases"]:
            group["aliases"].append(bucket["city"])

    cities = []
    for group in groups.values():
        clubs = [
            {"club_id": cid, "name": club_by_id[cid]["name"], "logo_url": club_by_id[cid]["logo_url"]}
            for cid in group.pop("club_ids")
        ]
        clubs.sort(key=lambda c: c["name"])
        match_ids = group.pop("match_ids")
        cities.append({
            **group,
            "clubs": clubs,
            "clubs_count": len(clubs),
            "teams_count": sum(teams_by_club.get(c["club_id"], 0) for c in clubs),
            "matches_today": len(match_ids),
            "today_match_ids": match_ids[:20],
        })
    cities.sort(key=lambda c: (-c["clubs_count"], c["city"]))
    club_total = len(club_rows)
    matched_clubs = sum(c["clubs_count"] for c in cities)
    return {
        "season_id": season_id,
        "generated_at": now,
        "cities": cities,
        "stats": {
            "cities": len(cities), "clubs": club_total, "clubs_on_map": matched_clubs,
            "matches_today": sum(c["matches_today"] for c in cities),
        },
        "unmatched": {"count": len(unmatched), "clubs": club_total - matched_clubs, "items": unmatched[:100]},
    }


async def _cached_map(season_id: Optional[str]) -> dict[str, Any]:
    key = season_id or ""
    hit = _map_cache.get(key)
    if hit and time.monotonic() - hit[0] < _MAP_TTL:
        return hit[1]
    payload = await build_map(season_id)
    _map_cache[key] = (time.monotonic(), payload)
    return payload


@router.get("/map")
async def handball_map(season_id: str = "") -> dict[str, Any]:
    """Miasta klubów (i meczów dziś) ze współrzędnymi do warstw mapy."""
    return await _cached_map(await _resolve_season(season_id))


# ---------------------------------------------------------------------------
# Klub
# ---------------------------------------------------------------------------


@router.get("/clubs/{club_id}/overview")
async def club_overview(club_id: str, season_id: str = "") -> dict[str, Any]:
    club = await database.fetch_one(select(zprp_public_clubs).where(zprp_public_clubs.c.club_id == club_id))
    if not club:
        raise HTTPException(404, "Nie znaleziono klubu")
    all_teams = await database.fetch_all(
        select(zprp_public_teams).where(zprp_public_teams.c.club_id == club_id)
        .order_by(zprp_public_teams.c.season_name.desc(), zprp_public_teams.c.name)
    )
    seasons = []
    for t in all_teams:
        if t["season_id"] not in {s["season_id"] for s in seasons}:
            seasons.append({"season_id": t["season_id"], "season_name": t["season_name"]})
    chosen = season_id.strip() or (seasons[0]["season_id"] if seasons else await _resolve_season())
    teams = [t for t in all_teams if t["season_id"] == chosen]
    team_ids = [t["team_id"] for t in teams]
    now = datetime.now()

    match_rows, players_count, assoc = await asyncio.gather(
        database.fetch_all(
            select(*_card_cols()).where(and_(
                M.c.season_id == chosen,
                or_(M.c.home_club_id == club_id, M.c.away_club_id == club_id),
            )).order_by(M.c.scheduled_at)
        ),
        database.fetch_val(
            select(func.count(func.distinct(zprp_public_team_rosters.c.player_id))).where(and_(
                zprp_public_team_rosters.c.season_id == chosen,
                zprp_public_team_rosters.c.team_id.in_(team_ids or [""]),
                zprp_public_team_rosters.c.active.is_(True),
            ))
        ),
        database.fetch_val(select(zprp_public_associations.c.name).where(
            zprp_public_associations.c.association_id == club["association_id"])) if club["association_id"] else asyncio.sleep(0),
    )
    cards = await _cards(match_rows)
    recent, upcoming = _split_upcoming(cards, now)
    today = [c for c in cards if c.get("scheduled_at") and c["scheduled_at"].date() == now.date()]
    record = R.team_record(
        cards, lambda side, m: m.get(f"{side}_club_id") == club_id,
    )
    club_out = await corrections.apply_one("club", public_club(club))
    teams_out = [public_team(t) for t in teams]
    await corrections.apply("team", teams_out)
    return {
        "club": club_out,
        "association_name": assoc or None,
        "season": await _season_info(chosen),
        "seasons": seasons,
        "teams": teams_out,
        "teams_count": len(teams),
        "players_count": int(players_count or 0),
        "recent_matches": recent,
        "upcoming_matches": upcoming,
        "today_matches": today,
        "stats": record,
        "standings": await _standing_rows(team_ids, chosen),
        "top_scorers": await _scorers_for_teams(team_ids, chosen, 10),
    }


# ---------------------------------------------------------------------------
# Drużyna
# ---------------------------------------------------------------------------


@router.get("/teams/{team_id}/overview")
async def team_overview(team_id: str, season_id: str = "") -> dict[str, Any]:
    seasons_rows = await database.fetch_all(
        select(zprp_public_teams.c.season_id, zprp_public_teams.c.season_name)
        .where(zprp_public_teams.c.team_id == team_id).order_by(zprp_public_teams.c.season_name.desc())
    )
    if not seasons_rows:
        raise HTTPException(404, "Nie znaleziono drużyny")
    chosen = season_id.strip() or seasons_rows[0]["season_id"]
    team = await database.fetch_one(select(zprp_public_teams).where(and_(
        zprp_public_teams.c.team_id == team_id, zprp_public_teams.c.season_id == chosen)))
    if not team:
        raise HTTPException(404, "Nie znaleziono drużyny w tym sezonie")
    club = await database.fetch_one(select(zprp_public_clubs).where(zprp_public_clubs.c.club_id == team["club_id"])) if team["club_id"] else None
    now = datetime.now()

    roster_rows, stat_rows, match_rows, lineup_matches = await asyncio.gather(
        database.fetch_all(
            select(zprp_public_team_rosters, zprp_public_players)
            .join(zprp_public_players, zprp_public_players.c.player_id == zprp_public_team_rosters.c.player_id)
            .where(and_(zprp_public_team_rosters.c.team_id == team_id, zprp_public_team_rosters.c.season_id == chosen,
                        zprp_public_team_rosters.c.active.is_(True)))
            .order_by(zprp_public_players.c.last_name, zprp_public_players.c.first_name)
        ),
        database.fetch_all(
            select(
                MP.c.player_id, func.count().label("matches"),
                *[func.coalesce(func.sum(MP.c[c]), 0).label(c) for c in PLAYER_STAT_COLUMNS],
            )
            .join(M, M.c.match_id == MP.c.match_id)
            .where(and_(MP.c.team_id == team_id, M.c.season_id == chosen))
            .group_by(MP.c.player_id)
        ),
        database.fetch_all(
            select(*_card_cols()).where(and_(
                M.c.season_id == chosen, or_(M.c.home_team_id == team_id, M.c.away_team_id == team_id)
            )).order_by(M.c.scheduled_at)
        ),
        # Mianownik dyscypliny: mecze, w których drużyna ma skład w źródle.
        database.fetch_val(
            select(func.count(func.distinct(MP.c.match_id)))
            .join(M, M.c.match_id == MP.c.match_id)
            .where(and_(MP.c.team_id == team_id, M.c.season_id == chosen))
        ),
    )
    stats = {r["player_id"]: _dict(r) for r in stat_rows}
    roster = []
    for row in roster_rows:
        data = _dict(row)
        s = stats.get(data["player_id"], {})
        roster.append({
            **_public_player(data),
            "shirt_number": data.get("shirt_number"), "position_id": data.get("position_id"),
            "position": data.get("position"),
            "stats": {"matches": s.get("matches", 0), **{c: int(s.get(c) or 0) for c in PLAYER_STAT_COLUMNS}},
        })
    cards = await _cards(match_rows)
    recent, upcoming = _split_upcoming(cards, now)
    club_out = await corrections.apply_one("club", public_club(club)) if club else None
    await corrections.apply("player", roster)
    return {
        "team": await corrections.apply_one("team", public_team(team)),
        "club": club_out,
        "club_logo_url": club_out["logo_url"] if club_out else None,
        "season": await _season_info(chosen),
        "seasons": [_dict(r) for r in seasons_rows],
        "roster": roster,
        "roster_count": len(roster),
        "matches": cards,
        "recent_matches": recent,
        "upcoming_matches": upcoming,
        "stats": R.team_record(cards, lambda side, m: m.get(f"{side}_team_id") == team_id),
        "standings": await _standing_rows([team_id], chosen),
        "top_scorers": await _scorers_for_teams([team_id], chosen, 10),
        "discipline": _team_discipline(stat_rows, int(lineup_matches or 0)),
    }


def _team_discipline(stat_rows: list[Any], matches: int) -> dict[str, Any]:
    """Kary drużyny w sezonie - po WSZYSTKICH zawodnikach z protokołów, nie tylko
    z aktywnej kadry (kto odszedł w trakcie, też łapał kary). `per_match` = None,
    gdy nie ma ani jednego meczu ze składem."""
    keys = ("two_minutes", "warnings", "disqualifications", "direct_red_cards")
    totals = {k: sum(int(_dict(r).get(k) or 0) for r in stat_rows) for k in keys}
    return {
        "matches": matches, **totals,
        "per_match": {k: round(totals[k] / matches, 2) for k in keys} if matches else None,
    }


# ---------------------------------------------------------------------------
# Zawodnik
# ---------------------------------------------------------------------------


def _player_totals(rows: list[dict]) -> dict[str, Any]:
    total = {c: 0 for c in PLAYER_STAT_COLUMNS}
    best: Optional[dict] = None
    for r in rows:
        for c in PLAYER_STAT_COLUMNS:
            total[c] += int(r.get(c) or 0)
        if best is None or int(r.get("goals") or 0) > best["goals"]:
            best = {"goals": int(r.get("goals") or 0), "match_id": r.get("match_id")}
    matches = len(rows)
    return {
        "matches": matches, **total,
        "goals_per_match": round(total["goals"] / matches, 2) if matches else None,
        "penalty_accuracy": round(total["penalty_goals"] / total["penalty_attempts"], 3) if total["penalty_attempts"] else None,
        "best_match": best if best and best["goals"] > 0 else None,
    }


@router.get("/players/{player_id}/overview")
async def player_overview(player_id: str) -> dict[str, Any]:
    player = await database.fetch_one(select(zprp_public_players).where(zprp_public_players.c.player_id == player_id))
    if not player:
        raise HTTPException(404, "Nie znaleziono zawodnika")
    roster_rows, line_rows = await asyncio.gather(
        database.fetch_all(
            select(
                zprp_public_team_rosters.c.team_id, zprp_public_team_rosters.c.season_id,
                zprp_public_team_rosters.c.shirt_number, zprp_public_team_rosters.c.position,
                zprp_public_teams.c.name.label("team_name"), zprp_public_teams.c.season_name,
                zprp_public_teams.c.category, zprp_public_teams.c.club_id,
                zprp_public_clubs.c.name.label("club_name"), zprp_public_clubs.c.logo_url.label("club_logo_url"),
            )
            .join(zprp_public_teams, and_(zprp_public_teams.c.team_id == zprp_public_team_rosters.c.team_id,
                                          zprp_public_teams.c.season_id == zprp_public_team_rosters.c.season_id))
            .outerjoin(zprp_public_clubs, zprp_public_clubs.c.club_id == zprp_public_teams.c.club_id)
            .where(and_(zprp_public_team_rosters.c.player_id == player_id, zprp_public_team_rosters.c.active.is_(True)))
            .order_by(zprp_public_team_rosters.c.season_id.desc())
        ),
        database.fetch_all(
            select(*_card_cols(), *[MP.c[c] for c in PLAYER_STAT_COLUMNS], MP.c.team_id.label("player_team_id"),
                   MP.c.shirt_number.label("player_shirt_number"))
            .join(M, M.c.match_id == MP.c.match_id)
            .where(MP.c.player_id == player_id).order_by(M.c.scheduled_at.desc())
        ),
    )
    lines = [_dict(r) for r in line_rows]
    by_season: dict[str, list[dict]] = {}
    for line in lines:
        by_season.setdefault(line["season_id"] or "", []).append(line)
    season_names = {r["season_id"]: r["season_name"] for r in roster_rows}
    seasons = [
        {"season_id": sid, "season_name": season_names.get(sid), "team_ids": sorted({l["player_team_id"] for l in rows}),
         **_player_totals(rows)}
        for sid, rows in sorted(by_season.items(), reverse=True)
    ]
    recent_rows = lines[:10]
    recent = await _cards([{k: v for k, v in l.items() if k in CARD_COLUMNS} for l in recent_rows])
    for card, line in zip(recent, recent_rows):
        card["player_line"] = {c: line.get(c) for c in PLAYER_STAT_COLUMNS}
        card["player_team_id"] = line["player_team_id"]
    teams_out = [_dict(r) for r in roster_rows]
    over = await corrections.active_overrides()
    for t in teams_out:
        club_patch = over.get("club", {}).get(str(t.get("club_id")), {})
        team_patch = over.get("team", {}).get(str(t.get("team_id")), {})
        if "name" in club_patch:
            t["club_name"] = club_patch["name"]
        if "logo_url" in club_patch:
            t["club_logo_url"] = club_patch["logo_url"]
        if "name" in team_patch:
            t["team_name"] = team_patch["name"]
    return {
        "player": await corrections.apply_one("player", _public_player(player)),
        "teams": teams_out,
        "totals": _player_totals(lines),
        "seasons": seasons,
        "recent_matches": recent,
    }


# ---------------------------------------------------------------------------
# Mecz
# ---------------------------------------------------------------------------


@router.post("/matches/{match_id}/refresh")
async def match_refresh(match_id: str) -> dict[str, Any]:
    """Odświeża mecz z ZPRP (limit 1 na 2 min na mecz); błąd ZPRP nie psuje odpowiedzi."""
    from app.zprp_public.ondemand import refresh_match

    exists = await database.fetch_one(select(M.c.match_id).where(M.c.match_id == match_id))
    if not exists:
        raise HTTPException(404, "Nie znaleziono meczu")
    return await refresh_match(match_id)


@router.get("/matches/{match_id}/overview")
async def match_overview(match_id: str) -> dict[str, Any]:
    match = await database.fetch_one(select(M).where(M.c.match_id == match_id))
    if not match:
        raise HTTPException(404, "Nie znaleziono meczu")
    details_pending = await ensure_details(match)
    if not details_pending:
        match = await database.fetch_one(select(M).where(M.c.match_id == match_id)) or match
    m = {k: v for k, v in _dict(match).items() if k not in {"source_hash", "source_json"}}
    await corrections.apply_one("match", m)
    await enrich_matches([m])
    clubs = await _club_lookup({m.get("home_club_id"), m.get("away_club_id")})

    def side(prefix: str) -> dict:
        club = clubs.get(m.get(f"{prefix}_club_id")) or {}
        return {
            "team_id": m.get(f"{prefix}_team_id"), "team_name": m.get(f"{prefix}_team_name"),
            "club_id": m.get(f"{prefix}_club_id"), "club_name": club.get("name"),
            "logo_url": club.get("logo_url"), "city": club.get("city"),
            "score": m.get(f"score_{prefix}"), "halftime": m.get(f"halftime_{prefix}"),
            "shootout": m.get(f"shootout_{prefix}"),
        }

    player_rows, staff_rows = await asyncio.gather(
        database.fetch_all(
            select(MP, zprp_public_players).join(zprp_public_players, zprp_public_players.c.player_id == MP.c.player_id)
            .where(MP.c.match_id == match_id).order_by(MP.c.side, MP.c.goals.desc())
        ),
        database.fetch_all(
            select(zprp_public_match_staff.c.team_id, zprp_public_match_staff.c.person_id, zprp_public_match_staff.c.side,
                   zprp_public_match_staff.c.first_name, zprp_public_match_staff.c.last_name,
                   zprp_public_match_staff.c.role, zprp_public_match_staff.c.function,
                   zprp_public_match_staff.c.license, zprp_public_match_staff.c.source_json)
            .where(zprp_public_match_staff.c.match_id == match_id)
        ),
    )
    lineups: dict[str, list[dict]] = {"home": [], "away": []}
    for row in player_rows:
        d = _dict(row)
        lineups.setdefault(d["side"], []).append({
            **_public_player(d),
            **{k: d.get(k) for k in ("team_id", "side", "shirt_number", "position", *PLAYER_STAT_COLUMNS)},
            **MR.penalty_fields(d.get("warnings"), d.get("two_minutes"), d.get("disqualifications"), d.get("direct_red_cards")),
        })
    staff_items = [MR.staff_view(_dict(r)) for r in staff_rows]
    # Zabezpieczenie: stare wiersze mogły powstać ze składami zamienionymi stronami przez źródło.
    sums = {k: sum(int(p.get("goals") or 0) for p in v) for k, v in lineups.items()}
    sc_h, sc_a = m.get("score_home"), m.get("score_away")
    if MR.lineups_swapped(sums["home"], sums["away"], sc_h, sc_a):
        lineups = {"home": lineups["away"], "away": lineups["home"]}
        for key, tid in (("home", m.get("home_team_id")), ("away", m.get("away_team_id"))):
            for p in lineups[key]:
                p["side"] = key
                if tid:
                    p["team_id"] = tid
        for it in staff_items:
            if it.get("side") in ("home", "away"):
                it["side"] = "away" if it["side"] == "home" else "home"
        sums = {"home": sums["away"], "away": sums["home"]}
    # Dotychczasowe spotkania tych drużyn (po klubach - id drużyn zmieniają się z sezonem).
    h2h_rows = []
    if m.get("home_club_id") and m.get("away_club_id"):
        pair = {m["home_club_id"], m["away_club_id"]}
        h2h_cond = [M.c.match_id != match_id, M.c.home_club_id.in_(pair), M.c.away_club_id.in_(pair),
                    M.c.score_home.is_not(None)]
        # Tylko ta sama kategoria i płeć co bieżący mecz (seniorzy nie mieszają się z juniorami).
        C = zprp_public_competitions
        if m.get("competition_category") or m.get("competition_gender"):
            kind = [cond for cond in (
                (C.c.category == m["competition_category"]) if m.get("competition_category") else None,
                (C.c.gender == m["competition_gender"]) if m.get("competition_gender") else None,
            ) if cond is not None]
            h2h_cond.append(M.c.competition_id.in_(select(C.c.competition_id).where(and_(*kind))))
        elif m.get("competition_name"):
            h2h_cond.append(M.c.competition_name == m["competition_name"])
        h2h_rows = await database.fetch_all(
            select(*_card_cols()).where(and_(*h2h_cond)).order_by(M.c.scheduled_at.desc())
        )
        # Tylko te dwie drużyny (nie inne drużyny tych klubów, nie mecz klubu z samym sobą).
        h2h_rows = R.h2h_between(
            [_dict(r) for r in h2h_rows],
            {"club_id": m.get("home_club_id"), "team_id": m.get("home_team_id"), "name": m.get("home_team_name")},
            {"club_id": m.get("away_club_id"), "team_id": m.get("away_team_id"), "name": m.get("away_team_name")},
        )[:5]
    team_ids = [t for t in (m.get("home_team_id"), m.get("away_team_id")) if t]
    standing = [r for r in await _standing_rows(team_ids, m.get("season_id")) if r["competition_id"] == m.get("competition_id")]
    officials = [
        {"role": label, "id": m.get(f"{col}_id"), "name": m.get(f"{col}_name")}
        for col, label in (("referee_1", "Sędzia"), ("referee_2", "Sędzia"), ("delegate_1", "Delegat"),
                           ("delegate_2", "Delegat"), ("secretary", "Sekretarz"), ("timekeeper", "Czas"))
        if m.get(f"{col}_name")
    ]
    status = _status(m)
    m["times_source"] = await attach_protocol_times(m, [p for side_list in lineups.values() for p in side_list], staff_items)
    return {
        "match": m,
        "status": status,
        "home": side("home"),
        "away": side("away"),
        "venue": {k: m.get(f"venue_{k}") for k in ("name", "city", "street", "number", "capacity")},
        "officials": officials,
        "lineups": lineups,
        # False = źródło nie podało bramek zawodników (front pokazuje "brak danych", nie 0).
        "lineups_goals_known": MR.goals_known(sums["home"], sums["away"], sc_h, sc_a),
        "staff": staff_items,
        "head_to_head": await _cards(h2h_rows),
        "standings": standing,
        # Źródło nie udostępnia przebiegu meczu (bramki w czasie) - tylko statystyki zawodników.
        "events": [],
        "events_available": False,
        "details_pending": bool(details_pending),
    }


# ---------------------------------------------------------------------------
# Rozgrywki - terminarz wg kolejek
# ---------------------------------------------------------------------------


@router.get("/competitions/{competition_id}/schedule")
async def competition_schedule(competition_id: str, team_id: str = "") -> dict[str, Any]:
    competition = await database.fetch_one(
        select(zprp_public_competitions.c.competition_id, zprp_public_competitions.c.name,
               zprp_public_competitions.c.season_id, zprp_public_competitions.c.gender,
               zprp_public_competitions.c.category)
        .where(zprp_public_competitions.c.competition_id == competition_id)
    )
    if not competition:
        raise HTTPException(404, "Nie znaleziono rozgrywek")
    conditions = [M.c.competition_id == competition_id]
    if team_id:
        conditions.append(or_(M.c.home_team_id == team_id, M.c.away_team_id == team_id))
    rounds, matchdays, match_rows = await asyncio.gather(
        database.fetch_all(select(zprp_public_rounds.c.round_id, zprp_public_rounds.c.name)
                           .where(zprp_public_rounds.c.competition_id == competition_id)),
        database.fetch_all(
            select(zprp_public_matchdays.c.matchday_id, zprp_public_matchdays.c.round_id, zprp_public_matchdays.c.number,
                   zprp_public_matchdays.c.sequence, zprp_public_matchdays.c.name, zprp_public_matchdays.c.starts_on,
                   zprp_public_matchdays.c.ends_on)
            .join(zprp_public_rounds, zprp_public_rounds.c.round_id == zprp_public_matchdays.c.round_id)
            .where(zprp_public_rounds.c.competition_id == competition_id).order_by(zprp_public_matchdays.c.sequence)
        ),
        database.fetch_all(select(*_card_cols()).where(and_(*conditions)).order_by(M.c.scheduled_at)),
    )
    cards = await _cards(match_rows)
    return await _schedule_payload(competition, rounds, matchdays, cards, team_id)


async def _schedule_payload(competition, rounds, matchdays, cards, team_id) -> dict[str, Any]:
    # `matchday_id` nie jest w kartach (lżejsze), dociągamy mapę jednym zapytaniem.
    ids = [c["match_id"] for c in cards]
    day_of: dict[str, Optional[str]] = {}
    if ids:
        rows = await database.fetch_all(select(M.c.match_id, M.c.matchday_id, M.c.round_id).where(M.c.match_id.in_(ids)))
        day_of = {r["match_id"]: r["matchday_id"] for r in rows}
    days_by_round: dict[str, list[dict]] = {}
    known_days = set()
    for d in matchdays:
        day = {**_dict(d), "matches": []}
        known_days.add(day["matchday_id"])
        days_by_round.setdefault(day["round_id"], []).append(day)
    day_index = {d["matchday_id"]: d for days in days_by_round.values() for d in days}
    unassigned = []
    for card in cards:
        did = day_of.get(card["match_id"])
        if did in day_index:
            day_index[did]["matches"].append(card)
        else:
            unassigned.append(card)
    out_rounds = []
    for r in rounds:
        days = [d for d in days_by_round.get(r["round_id"], []) if d["matches"] or not team_id]
        out_rounds.append({"round_id": r["round_id"], "name": r["name"], "matchdays": days})
    return {"competition": _dict(competition), "rounds": out_rounds, "unassigned": unassigned, "count": len(cards)}


# ---------------------------------------------------------------------------
# Wyszukiwarka globalna
# ---------------------------------------------------------------------------


_REF_INDEX: dict[str, Any] = {"at": 0.0, "rows": []}
_REF_TTL = 600


def invalidate_caches() -> None:
    """Zmiana obsady/wyniku: zapomnij indeks sędziów i gotowe mapy."""
    _REF_INDEX.update(at=0.0, rows=[])
    _map_cache.clear()


def _clean_ref_name(raw: str) -> str:
    """Nazwisko z ZPRP bywa dopełnione spacjami i znacznikiem na końcu ("KOWALCZYK Jan          O").
    Znacznik odcięty tylko, gdy stoi za długim odstępem; reszta spacji zwinięta do jednej."""
    s = re.sub(r"\s{2,}\S\s*$", "", raw or "")
    return re.sub(r"\s+", " ", s).strip()


def _match_referees(rows: list[dict], q: str, limit: int) -> list[dict]:
    """Sędziowie pasujący do frazy: wszystkie słowa frazy w nazwisku, bez wielkości liter i ogonków.
    Najpierw nazwisko zaczynające się od frazy, potem więcej meczów."""
    tokens = [t for t in MR._fold(q).split("-") if t]
    if not tokens:
        return []
    hits = []
    for r in rows:
        folded = MR._fold(r["name"])
        parts = folded.split("-")
        if all(any(p.startswith(t) or t in p for p in parts) for t in tokens):
            starts = folded.startswith(tokens[0]) or any(p.startswith(tokens[0]) for p in parts[:1])
            hits.append((0 if starts else 1, -r["matches"], r))
    hits.sort(key=lambda x: x[:2])
    return [h[2] for h in hits[:limit]]


async def _referee_index() -> list[dict]:
    """Publiczna lista sędziów z meczów: id, nazwa, liczba meczów (tylko dane z API ZPRP)."""
    if _REF_INDEX["rows"] and time.time() - _REF_INDEX["at"] < _REF_TTL:
        return _REF_INDEX["rows"]
    acc: dict[str, dict] = {}
    for idc, nmc in (("referee_1_id", "referee_1_name"), ("referee_2_id", "referee_2_name")):
        rows = await database.fetch_all(
            select(M.c[idc].label("rid"), M.c[nmc].label("rname"), func.count().label("n"))
            .where(and_(M.c[idc].isnot(None), M.c[idc] != "", M.c[nmc].isnot(None), M.c[nmc] != ""))
            .group_by(M.c[idc], M.c[nmc])
        )
        for r in rows:
            name = _clean_ref_name(r["rname"])
            e = acc.setdefault(r["rid"], {"referee_id": r["rid"], "name": name, "matches": 0, "_best": 0})
            e["matches"] += int(r["n"])
            if int(r["n"]) > e["_best"]:
                e["_best"], e["name"] = int(r["n"]), name
    out = [{k: v for k, v in e.items() if k != "_best"} for e in acc.values()]
    _REF_INDEX.update(at=time.time(), rows=out)
    return out


@router.get("/search/global")
async def search_global(q: str = Query(..., min_length=2), limit_per_type: int = Query(8, ge=1, le=25)) -> dict[str, Any]:
    like = f"%{q.strip()}%"
    base, match_rows, map_payload = await asyncio.gather(
        base_search(q=q, limit_per_type=limit_per_type),
        database.fetch_all(
            select(*_card_cols()).where(or_(M.c.home_team_name.ilike(like), M.c.away_team_name.ilike(like)))
            .order_by(M.c.scheduled_at.desc()).limit(limit_per_type)
        ),
        _cached_map(await _resolve_season()),
    )
    try:
        referees = _match_referees(await _referee_index(), q, limit_per_type)
    except Exception:  # sędziowie to dodatek, szukajka działa dalej bez nich
        referees = []
    needle = normalize_city_key(q)
    cities = []
    for c in map_payload["cities"]:
        names = [c["city"], *c.get("aliases", [])]
        hit = any(needle in normalize_city_key(n) for n in names)
        # Pierwsze trafienia: nazwa zaczyna się od frazy.
        if hit:
            starts = any(normalize_city_key(n).startswith(needle) for n in names)
            cities.append((0 if starts else 1, -c["clubs_count"], c))
    cities.sort(key=lambda x: x[:2])
    return {
        **base,
        "cities": [
            {k: c[k] for k in ("key", "city", "lat", "lon", "voivodeship", "clubs_count", "teams_count", "matches_today")}
            for _, _, c in cities[:limit_per_type]
        ],
        "matches": await _cards(match_rows),
        "referees": referees,
    }


# ---------------------------------------------------------------------------
# Porównywarka
# ---------------------------------------------------------------------------

COMPARE_TYPES = {"club", "team", "player"}
RECORD_METRICS = ["played", "wins", "draws", "losses", "goals_for", "goals_against", "goal_difference",
                  "avg_goals_for", "avg_goals_against", "win_rate"]
PLAYER_METRICS = ["matches", "goals", "goals_per_match", "penalty_goals", "penalty_accuracy", "two_minutes",
                  "warnings", "disqualifications"]


@router.get("/compare")
async def compare(
    type: str = Query(..., description="club | team | player"),
    ids: str = Query(..., description="do 4 identyfikatorów po przecinku"),
    season_id: str = "",
) -> dict[str, Any]:
    if type not in COMPARE_TYPES:
        raise HTTPException(400, "type musi być jednym z: club, team, player")
    wanted = list(dict.fromkeys(i.strip() for i in ids.split(",") if i.strip()))
    if not 2 <= len(wanted) <= 4:
        raise HTTPException(400, "Podaj od 2 do 4 identyfikatorów")
    season = await _resolve_season(season_id) if type != "player" or season_id else None
    items: list[dict] = []
    for ident in wanted:
        if type == "club":
            items.append(await _compare_club(ident, season))
        elif type == "team":
            items.append(await _compare_team(ident, season))
        else:
            items.append(await _compare_player(ident, season))
    missing = [w for w, i in zip(wanted, items) if i is None]
    items = [i for i in items if i is not None]
    metrics = RECORD_METRICS + (["teams_count", "players_count"] if type == "club" else
                                ["players_count", "position", "points", "top_scorer_goals"] if type == "team" else [])
    if type == "player":
        metrics = PLAYER_METRICS
    metrics = [m for m in metrics if m != "position"]
    scale = R.normalise_for_radar(items, metrics)
    return {"type": type, "season_id": season, "metrics": metrics, "max": scale["max"], "items": items, "missing": missing}


async def _compare_club(club_id: str, season: Optional[str]) -> Optional[dict]:
    club = await database.fetch_one(select(zprp_public_clubs).where(zprp_public_clubs.c.club_id == club_id))
    if not club:
        return None
    rows = await database.fetch_all(
        select(*_card_cols()).where(and_(M.c.season_id == season, or_(M.c.home_club_id == club_id, M.c.away_club_id == club_id)))
    )
    team_ids = [r["team_id"] for r in await database.fetch_all(
        select(zprp_public_teams.c.team_id).where(and_(zprp_public_teams.c.club_id == club_id, zprp_public_teams.c.season_id == season)))]
    players = await database.fetch_val(
        select(func.count(func.distinct(zprp_public_team_rosters.c.player_id))).where(and_(
            zprp_public_team_rosters.c.season_id == season, zprp_public_team_rosters.c.team_id.in_(team_ids or [""]),
            zprp_public_team_rosters.c.active.is_(True))))
    record = R.team_record([_dict(r) for r in rows], lambda side, m: m.get(f"{side}_club_id") == club_id)
    return {"id": club_id, "name": club["name"], "logo_url": club["logo_url"], "subtitle": club["city"],
            "metrics": {**record, "teams_count": len(team_ids), "players_count": int(players or 0)}}


async def _compare_team(team_id: str, season: Optional[str]) -> Optional[dict]:
    team = await database.fetch_one(select(zprp_public_teams).where(and_(
        zprp_public_teams.c.team_id == team_id, zprp_public_teams.c.season_id == season)))
    if not team:
        return None
    rows = await database.fetch_all(
        select(*_card_cols()).where(and_(M.c.season_id == season, or_(M.c.home_team_id == team_id, M.c.away_team_id == team_id)))
    )
    club = await database.fetch_one(select(zprp_public_clubs.c.logo_url).where(zprp_public_clubs.c.club_id == team["club_id"])) if team["club_id"] else None
    players = await database.fetch_val(
        select(func.count()).select_from(zprp_public_team_rosters).where(and_(
            zprp_public_team_rosters.c.team_id == team_id, zprp_public_team_rosters.c.season_id == season,
            zprp_public_team_rosters.c.active.is_(True))))
    standings = await _standing_rows([team_id], season)
    scorers = await _scorers_for_teams([team_id], season, 1)
    record = R.team_record([_dict(r) for r in rows], lambda side, m: m.get(f"{side}_team_id") == team_id)
    best = min(standings, key=lambda s: s["position"] or 999, default=None)
    return {"id": team_id, "name": team["name"], "logo_url": club["logo_url"] if club else None,
            "subtitle": team["season_name"],
            "position": best["position"] if best else None,
            "metrics": {**record, "players_count": int(players or 0), "points": best["points"] if best else None,
                        "top_scorer_goals": int(scorers[0]["goals"]) if scorers else 0}}


async def _compare_player(player_id: str, season: Optional[str]) -> Optional[dict]:
    player = await database.fetch_one(select(zprp_public_players).where(zprp_public_players.c.player_id == player_id))
    if not player:
        return None
    query = (
        select(MP.c.match_id, *[MP.c[c] for c in PLAYER_STAT_COLUMNS])
        .join(M, M.c.match_id == MP.c.match_id).where(MP.c.player_id == player_id)
    )
    if season:
        query = query.where(M.c.season_id == season)
    rows = [_dict(r) for r in await database.fetch_all(query)]
    return {"id": player_id, "name": f"{player['first_name']} {player['last_name']}", "logo_url": player["photo_url"],
            "subtitle": str(player["birth_year"]) if player["birth_year"] else None,
            "metrics": _player_totals(rows)}

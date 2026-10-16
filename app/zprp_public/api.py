"""Wersjonowane API lokalnej hurtowni rozgrywek piłki ręcznej."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, func, or_, select

from app.admin_guard import admin_write_guard
from app.db import (
    database,
    zprp_public_associations,
    zprp_public_changes,
    zprp_public_club_licenses,
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
    zprp_public_sync_runs,
    zprp_public_team_rosters,
    zprp_public_teams,
)
from app.zprp_public import corrections, match_rules as MR
from app.zprp_public.enrich import enrich_matches
from app.zprp_public.sync import run_sync_job
from app.zprp_public.privacy import public_club, public_team

router = APIRouter(prefix="/api/v1/handball", tags=["handball_public"])
admin_router = APIRouter(
    prefix="/admin/handball-sync",
    tags=["handball_sync"],
    dependencies=[Depends(admin_write_guard)],
)


def _dict(row: Any) -> dict[str, Any]:
    return dict(row) if row else {}


def _public_player(row: Any) -> dict[str, Any]:
    data = _dict(row)
    return {
        "player_id": data.get("player_id"),
        "first_name": data.get("first_name"),
        "last_name": data.get("last_name"),
        "gender": data.get("gender"),
        "birth_year": data.get("birth_year"),
        "photo_url": data.get("photo_url"),
        "updated_at": data.get("updated_at"),
    }


def _page(limit: int, offset: int, rows: list[Any]) -> dict[str, Any]:
    return {"items": [_dict(row) for row in rows], "limit": limit, "offset": offset, "count": len(rows)}


def _public_match(row: Any) -> dict[str, Any]:
    """Wspólny, stabilny kształt meczu bez surowego payloadu źródłowego."""
    data = _dict(row)
    return {key: value for key, value in data.items() if key not in {"source_hash", "source_json"}}


async def _decorate_matches(items: list[dict[str, Any]]) -> None:
    """Dokłada herby/nazwy klubów do kart meczów oraz nakłada korekty meczów."""
    ids = {i for item in items for i in (item.get("home_club_id"), item.get("away_club_id")) if i}
    lookup: dict[str, dict[str, Any]] = {}
    if ids:
        rows = await database.fetch_all(
            select(zprp_public_clubs.c.club_id, zprp_public_clubs.c.name, zprp_public_clubs.c.logo_url)
            .where(zprp_public_clubs.c.club_id.in_(list(ids)))
        )
        lookup = {r["club_id"]: _dict(r) for r in rows}
        await corrections.apply("club", list(lookup.values()))
    for item in items:
        item["home_logo_url"] = (lookup.get(item.get("home_club_id")) or {}).get("logo_url")
        item["away_logo_url"] = (lookup.get(item.get("away_club_id")) or {}).get("logo_url")
    await corrections.apply("match", items)
    await enrich_matches(items)


@router.get("/health")
async def health() -> dict[str, Any]:
    last = await database.fetch_one(
        select(zprp_public_sync_runs.c.status, zprp_public_sync_runs.c.finished_at)
        .order_by(zprp_public_sync_runs.c.started_at.desc())
        .limit(1)
    )
    return {"ok": True, "last_sync": _dict(last) or None}


@router.get("/portal/overview")
async def portal_overview() -> dict[str, Any]:
    """Jedno lekkie zapytanie startowe dla publicznego Centrum dnia.

    Widok jest celowo złożony po stronie serwera: przeglądarka nie wykonuje
    kilkunastu niezależnych zapytań, a baza może zoptymalizować agregaty.
    """
    now = datetime.now()
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    day_end = day_start + timedelta(days=1)

    season = await database.fetch_one(
        select(
            zprp_public_seasons.c.season_id,
            zprp_public_seasons.c.start_year,
            zprp_public_seasons.c.name,
            zprp_public_seasons.c.active,
            zprp_public_seasons.c.competition_count,
            zprp_public_seasons.c.updated_at,
        ).order_by(zprp_public_seasons.c.active.desc(), zprp_public_seasons.c.start_year.desc()).limit(1)
    )
    season_id = season["season_id"] if season else None
    season_filter = zprp_public_matches.c.season_id == season_id if season_id else True

    today, recent, upcoming = await asyncio.gather(
        database.fetch_all(
            select(zprp_public_matches)
            .where(and_(season_filter, zprp_public_matches.c.scheduled_at >= day_start, zprp_public_matches.c.scheduled_at < day_end))
            .order_by(zprp_public_matches.c.scheduled_at.asc())
            .limit(40)
        ),
        database.fetch_all(
            select(zprp_public_matches)
            .where(and_(season_filter, zprp_public_matches.c.scheduled_at < now, zprp_public_matches.c.score_home.is_not(None)))
            .order_by(zprp_public_matches.c.scheduled_at.desc())
            .limit(8)
        ),
        database.fetch_all(
            select(zprp_public_matches)
            .where(and_(season_filter, zprp_public_matches.c.scheduled_at >= now))
            .order_by(zprp_public_matches.c.scheduled_at.asc())
            .limit(8)
        ),
    )

    leader_query = (
        select(
            zprp_public_players.c.player_id,
            zprp_public_players.c.first_name,
            zprp_public_players.c.last_name,
            zprp_public_players.c.birth_year,
            zprp_public_players.c.photo_url,
            func.sum(zprp_public_scorers.c.goals).label("goals"),
            func.sum(zprp_public_scorers.c.matches).label("matches"),
        )
        .join(zprp_public_scorers, zprp_public_scorers.c.player_id == zprp_public_players.c.player_id)
        .join(zprp_public_competitions, zprp_public_competitions.c.competition_id == zprp_public_scorers.c.competition_id)
    )
    if season_id:
        leader_query = leader_query.where(zprp_public_competitions.c.season_id == season_id)
    leaders = await database.fetch_all(
        leader_query.group_by(
            zprp_public_players.c.player_id,
            zprp_public_players.c.first_name,
            zprp_public_players.c.last_name,
            zprp_public_players.c.birth_year,
            zprp_public_players.c.photo_url,
        ).order_by(func.sum(zprp_public_scorers.c.goals).desc()).limit(8)
    )

    counter_tables = (
        zprp_public_competitions,
        zprp_public_clubs,
        zprp_public_teams,
        zprp_public_players,
        zprp_public_matches,
    )
    counter_rows = await asyncio.gather(
        *(database.fetch_val(select(func.count()).select_from(table)) for table in counter_tables)
    )
    last_sync = await database.fetch_one(
        select(zprp_public_sync_runs.c.status, zprp_public_sync_runs.c.finished_at)
        .where(zprp_public_sync_runs.c.status == "success")
        .order_by(zprp_public_sync_runs.c.finished_at.desc())
        .limit(1)
    )
    last_updated = last_sync["finished_at"] if last_sync else None
    freshness = "unknown"
    if last_updated:
        comparable_now = datetime.now(last_updated.tzinfo) if last_updated.tzinfo else now
        freshness = "fresh" if comparable_now - last_updated <= timedelta(minutes=20) else "delayed"

    leader_items = []
    for row in leaders:
        item = _dict(row)
        matches_count = int(item.get("matches") or 0)
        goals_count = int(item.get("goals") or 0)
        item["average"] = round(goals_count / matches_count, 2) if matches_count else 0
        leader_items.append(item)

    today_items, recent_items, upcoming_items = (
        [_public_match(row) for row in rows] for rows in (today, recent, upcoming)
    )
    await _decorate_matches(today_items + recent_items + upcoming_items)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "freshness": {"status": freshness, "updated_at": last_updated},
        "season": _dict(season) or None,
        "counters": dict(zip(("competitions", "clubs", "teams", "players", "matches"), counter_rows)),
        "today": today_items,
        "recent": recent_items,
        "upcoming": upcoming_items,
        "leaders": leader_items,
    }


@router.get("/seasons")
async def list_seasons(include_historical: bool = False) -> dict[str, Any]:
    query = select(
        zprp_public_seasons.c.season_id,
        zprp_public_seasons.c.start_year,
        zprp_public_seasons.c.name,
        zprp_public_seasons.c.active,
        zprp_public_seasons.c.competition_count,
        zprp_public_seasons.c.updated_at,
    ).order_by(zprp_public_seasons.c.start_year.desc())
    if not include_historical:
        newest = select(zprp_public_seasons.c.start_year).order_by(zprp_public_seasons.c.start_year.desc()).limit(1).scalar_subquery()
        query = query.where(zprp_public_seasons.c.start_year >= newest - 1)
    result = await database.fetch_all(query)
    return {"items": [_dict(row) for row in result], "count": len(result)}


@router.get("/associations")
async def list_associations() -> dict[str, Any]:
    result = await database.fetch_all(
        select(
            zprp_public_associations.c.association_id,
            zprp_public_associations.c.name,
            zprp_public_associations.c.code,
            zprp_public_associations.c.full_name,
            zprp_public_associations.c.updated_at,
        ).order_by(zprp_public_associations.c.name)
    )
    return {"items": [_dict(row) for row in result], "count": len(result)}


@router.get("/clubs")
async def list_clubs(
    q: str = "",
    association_id: str = "",
    city: str = "",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    conditions = []
    if q.strip():
        like = f"%{q.strip()}%"
        conditions.append(or_(zprp_public_clubs.c.name.ilike(like), zprp_public_clubs.c.city.ilike(like)))
    if association_id.strip():
        conditions.append(zprp_public_clubs.c.association_id == association_id.strip())
    if city.strip():
        conditions.append(zprp_public_clubs.c.city.ilike(f"%{city.strip()}%"))
    query = select(
        zprp_public_clubs.c.club_id,
        zprp_public_clubs.c.association_id,
        zprp_public_clubs.c.name,
        zprp_public_clubs.c.member,
        zprp_public_clubs.c.city,
        zprp_public_clubs.c.logo_url,
        zprp_public_clubs.c.archived,
        zprp_public_clubs.c.updated_at,
    )
    if conditions:
        query = query.where(and_(*conditions))
    result = await database.fetch_all(query.order_by(zprp_public_clubs.c.name).limit(limit).offset(offset))
    page = _page(limit, offset, result)
    await corrections.apply("club", page["items"])
    return page


@router.get("/club-licenses")
async def list_club_licenses(
    club_id: str = "",
    season_name: str = "",
    gender: str = "",
    status: str = "",
    q: str = "",
    limit: int = Query(100, ge=1, le=300),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """Publiczny katalog licencji bez pól kontaktowych i surowego payloadu."""
    conditions = []
    if club_id.strip():
        conditions.append(zprp_public_club_licenses.c.club_id == club_id.strip())
    if season_name.strip():
        conditions.append(zprp_public_club_licenses.c.season_name == season_name.strip())
    if gender.strip():
        conditions.append(zprp_public_club_licenses.c.gender == gender.strip())
    if status.strip():
        conditions.append(zprp_public_club_licenses.c.status == status.strip())
    if q.strip():
        conditions.append(zprp_public_club_licenses.c.name.ilike(f"%{q.strip()}%"))
    query = (
        select(
            zprp_public_club_licenses.c.id,
            zprp_public_club_licenses.c.club_id,
            zprp_public_clubs.c.name.label("club_name"),
            zprp_public_club_licenses.c.season_name,
            zprp_public_club_licenses.c.name,
            zprp_public_club_licenses.c.status,
            zprp_public_club_licenses.c.gender,
            zprp_public_club_licenses.c.fetched_at,
        )
        .join(zprp_public_clubs, zprp_public_clubs.c.club_id == zprp_public_club_licenses.c.club_id)
    )
    if conditions:
        query = query.where(and_(*conditions))
    rows = await database.fetch_all(
        query.order_by(
            zprp_public_club_licenses.c.season_name.desc(),
            zprp_public_clubs.c.name,
            zprp_public_club_licenses.c.name,
        ).limit(limit).offset(offset)
    )
    return _page(limit, offset, rows)


@router.get("/clubs/{club_id}")
async def club_details(club_id: str) -> dict[str, Any]:
    club = await database.fetch_one(
        select(
            zprp_public_clubs.c.club_id,
            zprp_public_clubs.c.association_id,
            zprp_public_clubs.c.name,
            zprp_public_clubs.c.member,
            zprp_public_clubs.c.city,
            zprp_public_clubs.c.website,
            zprp_public_clubs.c.archived,
            zprp_public_clubs.c.logo_url,
            zprp_public_clubs.c.source_updated_at,
            zprp_public_clubs.c.updated_at,
        ).where(zprp_public_clubs.c.club_id == club_id)
    )
    if not club:
        raise HTTPException(404, "Nie znaleziono klubu")
    teams = await database.fetch_all(
        select(
            zprp_public_teams.c.team_id,
            zprp_public_teams.c.season_id,
            zprp_public_teams.c.season_name,
            zprp_public_teams.c.name,
            zprp_public_teams.c.gender,
            zprp_public_teams.c.category,
        )
        .where(zprp_public_teams.c.club_id == club_id)
        .order_by(zprp_public_teams.c.season_name.desc(), zprp_public_teams.c.name)
    )
    licenses = await database.fetch_all(
        select(
            zprp_public_club_licenses.c.season_name,
            zprp_public_club_licenses.c.name,
            zprp_public_club_licenses.c.status,
            zprp_public_club_licenses.c.gender,
        )
        .where(zprp_public_club_licenses.c.club_id == club_id)
        .order_by(zprp_public_club_licenses.c.season_name.desc(), zprp_public_club_licenses.c.name)
    )
    club_out = await corrections.apply_one("club", public_club(club))
    teams_out = [public_team(row) for row in teams]
    await corrections.apply("team", teams_out)
    return {"club": club_out, "teams": teams_out, "licenses": [_dict(row) for row in licenses]}


@router.get("/teams")
async def list_teams(
    season_id: str = "",
    club_id: str = "",
    gender: str = "",
    category: str = "",
    q: str = "",
    limit: int = Query(100, ge=1, le=300),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """Lista drużyn w bezpiecznym, publicznym kształcie."""
    conditions = []
    if season_id.strip():
        conditions.append(zprp_public_teams.c.season_id == season_id.strip())
    if club_id.strip():
        conditions.append(zprp_public_teams.c.club_id == club_id.strip())
    if gender.strip():
        conditions.append(zprp_public_teams.c.gender == gender.strip())
    if category.strip():
        conditions.append(zprp_public_teams.c.category == category.strip())
    if q.strip():
        conditions.append(zprp_public_teams.c.name.ilike(f"%{q.strip()}%"))
    query = select(
        zprp_public_teams.c.team_id,
        zprp_public_teams.c.season_id,
        zprp_public_teams.c.club_id,
        zprp_public_teams.c.season_name,
        zprp_public_teams.c.name,
        zprp_public_teams.c.gender,
        zprp_public_teams.c.category,
        zprp_public_teams.c.city,
        zprp_public_teams.c.roster_fetched_at,
        zprp_public_teams.c.updated_at,
    )
    if conditions:
        query = query.where(and_(*conditions))
    rows = await database.fetch_all(query.order_by(zprp_public_teams.c.name).limit(limit).offset(offset))
    page = _page(limit, offset, rows)
    await corrections.apply("team", page["items"])
    return page


@router.get("/teams/{team_id}")
async def team_details(team_id: str, season_id: str = Query(...)) -> dict[str, Any]:
    team = await database.fetch_one(
        select(zprp_public_teams).where(
            and_(zprp_public_teams.c.team_id == team_id, zprp_public_teams.c.season_id == season_id)
        )
    )
    if not team:
        raise HTTPException(404, "Nie znaleziono drużyny w tym sezonie")
    roster_rows = await database.fetch_all(
        select(zprp_public_team_rosters, zprp_public_players)
        .join(zprp_public_players, zprp_public_players.c.player_id == zprp_public_team_rosters.c.player_id)
        .where(
            and_(
                zprp_public_team_rosters.c.team_id == team_id,
                zprp_public_team_rosters.c.season_id == season_id,
                zprp_public_team_rosters.c.active.is_(True),
            )
        )
        .order_by(zprp_public_players.c.last_name, zprp_public_players.c.first_name)
    )
    roster = []
    for row in roster_rows:
        data = _dict(row)
        roster.append(
            {
                **_public_player(data),
                "shirt_number": data.get("shirt_number"),
                "position_id": data.get("position_id"),
                "position": data.get("position"),
            }
        )
    await corrections.apply("player", roster)
    return {"team": await corrections.apply_one("team", public_team(team)), "roster": roster, "roster_count": len(roster)}


@router.get("/competitions")
async def list_competitions(
    season_id: str = "",
    association_id: str = "",
    gender: str = "",
    category: str = "",
    q: str = "",
    limit: int = Query(100, ge=1, le=300),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    conditions = []
    for column, value in (
        (zprp_public_competitions.c.season_id, season_id),
        (zprp_public_competitions.c.association_id, association_id),
        (zprp_public_competitions.c.gender, gender),
        (zprp_public_competitions.c.category, category),
    ):
        if value.strip():
            conditions.append(column == value.strip())
    if q.strip():
        like = f"%{q.strip()}%"
        conditions.append(or_(zprp_public_competitions.c.name.ilike(like), zprp_public_competitions.c.code.ilike(like)))
    query = select(
        zprp_public_competitions.c.competition_id,
        zprp_public_competitions.c.season_id,
        zprp_public_competitions.c.association_id,
        zprp_public_competitions.c.association_name,
        zprp_public_competitions.c.name,
        zprp_public_competitions.c.gender,
        zprp_public_competitions.c.category,
        zprp_public_competitions.c.code,
        zprp_public_competitions.c.team_count,
        zprp_public_competitions.c.started,
        zprp_public_competitions.c.has_groups,
        zprp_public_competitions.c.updated_at,
    )
    if conditions:
        query = query.where(and_(*conditions))
    result = await database.fetch_all(query.order_by(zprp_public_competitions.c.name).limit(limit).offset(offset))
    page = _page(limit, offset, result)
    await corrections.apply("competition", page["items"])
    return page


@router.get("/competitions/{competition_id}")
async def competition_details(competition_id: str) -> dict[str, Any]:
    competition = await database.fetch_one(
        select(zprp_public_competitions).where(zprp_public_competitions.c.competition_id == competition_id)
    )
    if not competition:
        raise HTTPException(404, "Nie znaleziono rozgrywek")
    rounds = await database.fetch_all(
        select(zprp_public_rounds.c.round_id, zprp_public_rounds.c.name).where(
            zprp_public_rounds.c.competition_id == competition_id
        )
    )
    round_ids = [row["round_id"] for row in rounds]
    matchdays = []
    if round_ids:
        matchdays = await database.fetch_all(
            select(
                zprp_public_matchdays.c.matchday_id,
                zprp_public_matchdays.c.round_id,
                zprp_public_matchdays.c.number,
                zprp_public_matchdays.c.sequence,
                zprp_public_matchdays.c.name,
                zprp_public_matchdays.c.starts_on,
                zprp_public_matchdays.c.ends_on,
            )
            .where(zprp_public_matchdays.c.round_id.in_(round_ids))
            .order_by(zprp_public_matchdays.c.sequence)
        )
    public_comp = {key: value for key, value in _dict(competition).items() if key not in {"source_hash", "source_json"}}
    await corrections.apply_one("competition", public_comp)
    return {"competition": public_comp, "rounds": [_dict(row) for row in rounds], "matchdays": [_dict(row) for row in matchdays]}


@router.get("/competitions/{competition_id}/standings")
async def competition_standings(competition_id: str, table_id: str = "", group_id: str = "") -> dict[str, Any]:
    conditions = [zprp_public_standings.c.competition_id == competition_id]
    if table_id:
        conditions.append(zprp_public_standings.c.table_id == table_id)
    if group_id:
        conditions.append(zprp_public_standings.c.group_id == group_id)
    result = await database.fetch_all(
        select(
            zprp_public_standings.c.competition_id,
            zprp_public_standings.c.table_id,
            zprp_public_standings.c.group_id,
            zprp_public_standings.c.team_id,
            zprp_public_standings.c.club_id,
            zprp_public_standings.c.position,
            zprp_public_standings.c.team_name,
            zprp_public_standings.c.matches,
            zprp_public_standings.c.wins,
            zprp_public_standings.c.draws,
            zprp_public_standings.c.losses,
            zprp_public_standings.c.goals_for,
            zprp_public_standings.c.goals_against,
            zprp_public_standings.c.goal_difference,
            zprp_public_standings.c.points,
            zprp_public_standings.c.fetched_at,
        )
        .where(and_(*conditions))
        .order_by(zprp_public_standings.c.table_id, zprp_public_standings.c.group_id, zprp_public_standings.c.position)
    )
    return {"items": [_dict(row) for row in result], "count": len(result)}


@router.get("/competitions/{competition_id}/scorers")
async def competition_scorers(competition_id: str, limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    result = await database.fetch_all(
        select(zprp_public_scorers, zprp_public_players)
        .join(zprp_public_players, zprp_public_players.c.player_id == zprp_public_scorers.c.player_id)
        .where(zprp_public_scorers.c.competition_id == competition_id)
        .order_by(zprp_public_scorers.c.goals.desc(), zprp_public_scorers.c.matches.asc())
        .limit(limit)
    )
    items = []
    for row in result:
        data = _dict(row)
        items.append(
            {
                **_public_player(data),
                "team_id": data.get("team_id"),
                "team_name": data.get("team_name"),
                "goals": data.get("goals"),
                "matches": data.get("matches"),
                "average": data.get("average"),
                "warnings": data.get("warnings"),
                "two_minutes": data.get("two_minutes"),
                "disqualifications": data.get("disqualifications"),
                "direct_red_cards": data.get("direct_red_cards"),
                "penalty_attempts": data.get("penalty_attempts"),
                "penalty_goals": data.get("penalty_goals"),
            }
        )
    return {"items": items, "count": len(items)}


@router.get("/matches")
async def list_matches(
    competition_id: str = "",
    team_id: str = "",
    season_id: str = "",
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    limit: int = Query(50, ge=1, le=300),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    date_from, date_to = MR.naive_local(date_from), MR.naive_local(date_to)
    conditions = []
    if competition_id:
        conditions.append(zprp_public_matches.c.competition_id == competition_id)
    if season_id:
        conditions.append(zprp_public_matches.c.season_id == season_id)
    if team_id:
        conditions.append(or_(zprp_public_matches.c.home_team_id == team_id, zprp_public_matches.c.away_team_id == team_id))
    if date_from:
        conditions.append(zprp_public_matches.c.scheduled_at >= date_from)
    if date_to:
        conditions.append(zprp_public_matches.c.scheduled_at <= date_to)
    query = select(zprp_public_matches)
    if conditions:
        query = query.where(and_(*conditions))
    result = await database.fetch_all(query.order_by(zprp_public_matches.c.scheduled_at.desc()).limit(limit).offset(offset))
    items = [_public_match(row) for row in result]
    await _decorate_matches(items)
    return {"items": items, "limit": limit, "offset": offset, "count": len(items)}


@router.get("/matches/{match_id}")
async def match_details(match_id: str) -> dict[str, Any]:
    match = await database.fetch_one(select(zprp_public_matches).where(zprp_public_matches.c.match_id == match_id))
    if not match:
        raise HTTPException(404, "Nie znaleziono meczu")
    player_rows = await database.fetch_all(
        select(zprp_public_match_players, zprp_public_players)
        .join(zprp_public_players, zprp_public_players.c.player_id == zprp_public_match_players.c.player_id)
        .where(zprp_public_match_players.c.match_id == match_id)
        .order_by(zprp_public_match_players.c.side, zprp_public_match_players.c.goals.desc())
    )
    players = []
    for row in player_rows:
        data = _dict(row)
        players.append(
            {
                **_public_player(data),
                **{key: data.get(key) for key in (
                    "team_id", "side", "shirt_number", "position", "goals", "warnings",
                    "two_minutes", "disqualifications", "direct_red_cards", "penalty_attempts",
                    "penalty_goals", "shootout_attempts", "shootout_goals",
                )},
            }
        )
    staff = await database.fetch_all(
        select(
            zprp_public_match_staff.c.team_id,
            zprp_public_match_staff.c.person_id,
            zprp_public_match_staff.c.side,
            zprp_public_match_staff.c.first_name,
            zprp_public_match_staff.c.last_name,
            zprp_public_match_staff.c.role,
            zprp_public_match_staff.c.function,
            zprp_public_match_staff.c.license,
            zprp_public_match_staff.c.source_json,
        ).where(zprp_public_match_staff.c.match_id == match_id)
    )
    public_match = {key: value for key, value in _dict(match).items() if key not in {"source_hash", "source_json"}}
    await _decorate_matches([public_match])
    await corrections.apply("player", players)
    return {"match": public_match, "players": players, "staff": [MR.staff_view(_dict(row)) for row in staff]}


@router.get("/players")
async def list_players(q: str = Query(..., min_length=2), limit: int = Query(30, ge=1, le=100)) -> dict[str, Any]:
    like = f"%{q.strip()}%"
    result = await database.fetch_all(
        select(zprp_public_players)
        .where(or_(zprp_public_players.c.first_name.ilike(like), zprp_public_players.c.last_name.ilike(like)))
        .order_by(zprp_public_players.c.last_name, zprp_public_players.c.first_name)
        .limit(limit)
    )
    items = [_public_player(row) for row in result]
    await corrections.apply("player", items)
    return {"items": items, "count": len(result)}


@router.get("/players/{player_id}")
async def player_details(player_id: str) -> dict[str, Any]:
    player = await database.fetch_one(select(zprp_public_players).where(zprp_public_players.c.player_id == player_id))
    if not player:
        raise HTTPException(404, "Nie znaleziono zawodnika")
    rosters = await database.fetch_all(
        select(
            zprp_public_team_rosters.c.team_id,
            zprp_public_team_rosters.c.season_id,
            zprp_public_team_rosters.c.shirt_number,
            zprp_public_team_rosters.c.position,
            zprp_public_teams.c.name.label("team_name"),
            zprp_public_teams.c.club_id,
        )
        .join(
            zprp_public_teams,
            and_(
                zprp_public_teams.c.team_id == zprp_public_team_rosters.c.team_id,
                zprp_public_teams.c.season_id == zprp_public_team_rosters.c.season_id,
            ),
        )
        .where(and_(zprp_public_team_rosters.c.player_id == player_id, zprp_public_team_rosters.c.active.is_(True)))
        .order_by(zprp_public_team_rosters.c.season_id.desc())
    )
    totals = await database.fetch_one(
        select(
            func.count(zprp_public_match_players.c.match_id).label("matches"),
            func.coalesce(func.sum(zprp_public_match_players.c.goals), 0).label("goals"),
            func.coalesce(func.sum(zprp_public_match_players.c.two_minutes), 0).label("two_minutes"),
            func.coalesce(func.sum(zprp_public_match_players.c.disqualifications), 0).label("disqualifications"),
        ).where(zprp_public_match_players.c.player_id == player_id)
    )
    return {"player": await corrections.apply_one("player", _public_player(player)), "teams": [_dict(row) for row in rosters], "totals": _dict(totals)}


@router.get("/search")
async def search(q: str = Query(..., min_length=2), limit_per_type: int = Query(8, ge=1, le=25)) -> dict[str, Any]:
    like = f"%{q.strip()}%"
    clubs, teams, competitions, players = await asyncio.gather(
        database.fetch_all(select(zprp_public_clubs.c.club_id, zprp_public_clubs.c.name, zprp_public_clubs.c.city, zprp_public_clubs.c.logo_url).where(zprp_public_clubs.c.name.ilike(like)).limit(limit_per_type)),
        database.fetch_all(select(zprp_public_teams.c.team_id, zprp_public_teams.c.season_id, zprp_public_teams.c.name, zprp_public_teams.c.category, zprp_public_teams.c.gender).where(zprp_public_teams.c.name.ilike(like)).limit(limit_per_type)),
        database.fetch_all(select(zprp_public_competitions.c.competition_id, zprp_public_competitions.c.season_id, zprp_public_competitions.c.name, zprp_public_competitions.c.code).where(or_(zprp_public_competitions.c.name.ilike(like), zprp_public_competitions.c.code.ilike(like))).limit(limit_per_type)),
        database.fetch_all(select(zprp_public_players).where(or_(zprp_public_players.c.first_name.ilike(like), zprp_public_players.c.last_name.ilike(like))).limit(limit_per_type)),
    )
    return {
        "clubs": [_dict(row) for row in clubs],
        "teams": [_dict(row) for row in teams],
        "competitions": [_dict(row) for row in competitions],
        "players": [_public_player(row) for row in players],
    }


@router.get("/changes")
async def recent_changes(
    limit: int = Query(50, ge=1, le=200),
    resource_type: str = "",
    since: datetime | None = None,
) -> dict[str, Any]:
    query = select(zprp_public_changes)
    if resource_type:
        query = query.where(zprp_public_changes.c.resource_type == resource_type)
    if since:
        query = query.where(zprp_public_changes.c.changed_at > since)
    result = await database.fetch_all(query.order_by(zprp_public_changes.c.changed_at.desc()).limit(limit))
    return {"items": [_dict(row) for row in result], "count": len(result)}


@router.get("/sync/status")
async def public_sync_status() -> dict[str, Any]:
    result = await database.fetch_all(
        select(
            zprp_public_sync_runs.c.id,
            zprp_public_sync_runs.c.kind,
            zprp_public_sync_runs.c.status,
            zprp_public_sync_runs.c.counters,
            zprp_public_sync_runs.c.started_at,
            zprp_public_sync_runs.c.heartbeat_at,
            zprp_public_sync_runs.c.finished_at,
        )
        .order_by(zprp_public_sync_runs.c.started_at.desc())
        .limit(20)
    )
    return {"items": [_dict(row) for row in result]}


class SyncRequest(BaseModel):
    kind: str
    season_id: str | None = None


@admin_router.post("/run", status_code=202)
async def queue_sync(payload: SyncRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    allowed = {"catalog", "live", "clubs", "details", "historical", "cleanup"}
    if payload.kind not in allowed:
        raise HTTPException(400, f"kind musi należeć do: {', '.join(sorted(allowed))}")
    if payload.kind == "historical" and not payload.season_id:
        raise HTTPException(400, "Synchronizacja historyczna wymaga season_id")
    background_tasks.add_task(run_sync_job, payload.kind, season_id=payload.season_id)
    return {"queued": True, "kind": payload.kind, "season_id": payload.season_id}


@admin_router.get("/runs")
async def admin_sync_runs(limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    result = await database.fetch_all(
        select(zprp_public_sync_runs).order_by(zprp_public_sync_runs.c.started_at.desc()).limit(limit)
    )
    return {"items": [_dict(row) for row in result]}


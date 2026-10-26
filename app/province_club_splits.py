"""
Rozbicie klubu na kilka klubów - baza i trasy /province/clubs/splits.

Reguła siedzi w liściu `province_club_splits_rules`; tutaj czytamy i zapisujemy
nakładkę (grupy, przypisania drużyn, historię) i wystawiamy ją panelowi klubów:
`province_clubs._teams` zamienia klub drużyny na część, więc obciążenia, salda,
wyciągi, faktury i raporty widzą części jako osobne kluby bez dalszych zmian.

⚠ `province_clubs` importuje ten moduł, więc `province_clubs` wolno ruszać
dopiero w środku funkcji. Router trzeba dołączyć PRZED routerem
`/province/clubs` (tam GET `/{club_id}` połknąłby `/splits`).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, delete, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import club_charges as C
from app import district_payer as DP
from app import province_club_splits_rules as SR
from app.db import (
    database,
    province_club_entries,
    province_club_split_log,
    province_club_split_teams,
    province_club_splits,
    province_clubs,
)
from app.province_clubs_scrape import team_key
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import panel_write_gate
from app.province_settlements import require_province
from app.settlement_seasons import season_of

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/province/clubs/splits",
    tags=["province_clubs"],
    dependencies=[Depends(panel_write_gate(PANEL_SETTLEMENTS, "Zapis w panelu klubów"))],
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value or "").strip()


# ---------------------------------------------------------------------------
# Odczyt nakładki
# ---------------------------------------------------------------------------

async def assignment_rows(province: str) -> list[dict]:
    rows = await database.fetch_all(
        select(province_club_split_teams)
        .where(province_club_split_teams.c.province == province)
        .order_by(province_club_split_teams.c.id.asc())
    )
    return [dict(row) for row in rows]


async def group_rows(province: str) -> list[dict]:
    rows = await database.fetch_all(
        select(province_club_splits)
        .where(province_club_splits.c.province == province)
        .order_by(province_club_splits.c.parent_club_id, province_club_splits.c.part_no)
    )
    return [dict(row) for row in rows]


async def overlay(province: str) -> tuple[list[dict], list[dict]]:
    """(przypisania drużyn, grupy) - dwa tanie zapytania; puste, gdy nikt nie rozbijał."""
    groups = await group_rows(province)
    if not groups:
        return [], []
    return await assignment_rows(province), groups


# ---------------------------------------------------------------------------
# Wspólne: kontekst sezonu
# ---------------------------------------------------------------------------

async def _context(key: str, season: str):
    from app.province_clubs import load_clubs

    return await load_clubs(key, season)


def _teams_of(data: dict, club_id: str) -> list[dict]:
    return sorted(
        (t for t in data["teams_meta"].values() if _s(t["club_id"]) == club_id),
        key=lambda t: t["name"],
    )


async def _forbidden_reason(key: str, club_id: str) -> str:
    if DP.is_district_payer(club_id):
        return "Okręg jako płatnik nie jest klubem - nie ma czego rozbijać."
    if SR.is_part_id(club_id):
        return "To już część rozbitego klubu. Rozbić można klub macierzysty; drużynę przenosi się między częściami."
    from app import province_club_budgets as CB
    from app import province_club_budgets_rules as BR

    group = BR.group_of(club_id, await CB.budget_groups(key))
    if group and len(group.get("member_ids") or []) > 1:
        return (
            "Ten klub należy do wspólnego budżetu - najpierw rozłącz budżet, "
            "potem rozbij klub. Wspólny budżet i rozbicie wykluczają się."
        )
    return ""


async def _log(key: str, parent: str, season: str, action: str, detail: dict, who: Optional[str]) -> None:
    await database.execute(
        insert(province_club_split_log).values(
            province=key,
            parent_club_id=parent,
            season=season,
            action=action,
            detail=json.dumps(detail, ensure_ascii=False),
            created_by=_s(who) or None,
            created_at=_now(),
        )
    )


def _fail(exc: ValueError):
    raise HTTPException(400, str(exc))


# ---------------------------------------------------------------------------
# Plan (podgląd i zapis)
# ---------------------------------------------------------------------------

class PartIn(BaseModel):
    name: str = ""
    team_ids: list[str] = []
    expected_in: float = 0.0


class SplitRequest(BaseModel):
    province: str
    season: Optional[str] = None
    club_id: str
    parts: list[PartIn] = []
    #: {id wpisu: numer części (0 = zostaje w macierzystym)}
    entry_moves: dict[str, int] = {}
    updated_by: Optional[str] = None


async def _plan(payload: SplitRequest) -> dict:
    key = require_province(payload.province)
    season = _s(payload.season) or season_of(_now())
    SR.season_start(season)
    club_id = _s(payload.club_id)
    data = await _context(key, season)
    teams = _teams_of(data, club_id)
    reason = await _forbidden_reason(key, club_id)
    if not reason and data.get("splits", {}).get(club_id):
        reason = (
            "Ten klub jest już rozbity w tym sezonie. Przenoś drużyny między częściami "
            "albo użyj „Scal z powrotem”."
        )
    try:
        parts = SR.validate_plan(
            [t["team_id"] for t in teams],
            [p.model_dump() for p in payload.parts],
            forbidden=reason,
        )
        entries = [row for row in data["entries"] if _s(row["club_id"]) == club_id]
        moves = SR.validate_entry_moves(entries, payload.entry_moves, len(parts))
    except ValueError as exc:
        _fail(exc)
    existing = [row["club_id"] for row in await group_rows(key)]
    part_ids = [club_id]
    for _ in parts[1:]:
        part_ids.append(SR.part_club_id(club_id, existing + part_ids))
    per_team = C.team_totals([row for row in data["charges"] if row.club_id == club_id])
    preview = SR.preview_balances(
        parent=club_id,
        part_ids=part_ids,
        names=[p["name"] for p in parts],
        parts=parts,
        team_charged={t: float(v["charged"]) for t, v in per_team.items()},
        team_matches={t: int(v["matches"]) for t, v in per_team.items()},
        entries=entries,
        entry_moves=moves,
    )
    return {
        "key": key,
        "season": season,
        "club_id": club_id,
        "teams": teams,
        "parts": parts,
        "part_ids": part_ids,
        "moves": moves,
        "preview": preview,
        "data": data,
    }


@router.post("/preview", summary="Podgląd rozbicia klubu: salda przed i po")
async def preview_split(payload: SplitRequest):
    plan = await _plan(payload)
    return {
        "season": plan["season"],
        "club_id": plan["club_id"],
        "parts": [
            {**part, "club_id": plan["part_ids"][i]} for i, part in enumerate(plan["parts"])
        ],
        **plan["preview"],
    }


@router.post("", summary="Rozbij klub na kilka klubów")
async def create_split(payload: SplitRequest):
    plan = await _plan(payload)
    key, season, club_id = plan["key"], plan["season"], plan["club_id"]
    parts, part_ids, who = plan["parts"], plan["part_ids"], _s(payload.updated_by) or None
    now = _now()
    parent_settings = plan["data"]["settings"].get(club_id) or {}
    names = {t["team_id"]: t.get("name_key") or team_key(t["name"]) for t in plan["teams"]}
    rows = SR.assignment_rows_for_plan(club_id, season, parts, part_ids, names)

    async with database.transaction():
        for index, part in enumerate(parts):
            values = {
                "province": key,
                "club_id": part_ids[index],
                "parent_club_id": club_id,
                "part_no": index + 1,
                "name": part["name"],
                "expected_in": part["expected_in"],
                "created_by": who,
                "created_at": now,
            }
            await database.execute(
                pg_insert(province_club_splits)
                .values(**values)
                .on_conflict_do_update(
                    index_elements=[province_club_splits.c.province, province_club_splits.c.club_id],
                    set_={k: v for k, v in values.items() if k not in ("province", "club_id", "created_by", "created_at")},
                )
            )
            if index == 0:
                continue
            # Ustawienia nowej części: kopia z macierzystego.
            copy = {
                "province": key,
                "club_id": part_ids[index],
                "display_name": part["name"],
                "settles_via_district": bool(parent_settings.get("settles_via_district", True)),
                "settles_since": parent_settings.get("settles_since"),
                "note": _s(parent_settings.get("note")) or None,
                "updated_by": who,
                "updated_at": now,
            }
            await database.execute(
                pg_insert(province_clubs)
                .values(**copy)
                .on_conflict_do_update(
                    index_elements=[province_clubs.c.province, province_clubs.c.club_id],
                    set_={k: v for k, v in copy.items() if k not in ("province", "club_id")},
                )
            )
        await database.execute(
            delete(province_club_split_teams).where(
                and_(
                    province_club_split_teams.c.province == key,
                    province_club_split_teams.c.parent_club_id == club_id,
                    province_club_split_teams.c.season == season,
                )
            )
        )
        for row in rows:
            await database.execute(
                insert(province_club_split_teams).values(
                    province=key, **row, updated_by=who, updated_at=now
                )
            )
        for entry_id, part in plan["moves"].items():
            await database.execute(
                update(province_club_entries)
                .where(
                    and_(
                        province_club_entries.c.id == entry_id,
                        province_club_entries.c.province == key,
                        province_club_entries.c.club_id == club_id,
                        province_club_entries.c.season == season,
                    )
                )
                .values(club_id=part_ids[part])
            )
        await _log(
            key,
            club_id,
            season,
            "split",
            {
                "parts": [
                    {
                        "club_id": part_ids[i],
                        "name": p["name"],
                        "teams": [t["name"] for t in plan["teams"] if t["team_id"] in p["team_ids"]],
                        "expected_in": p["expected_in"],
                    }
                    for i, p in enumerate(parts)
                ],
                "entries_moved": len(plan["moves"]),
            },
            who,
        )
    return {"success": True, "club_id": club_id, "part_ids": part_ids, "after": plan["preview"]["after"]}


# ---------------------------------------------------------------------------
# Przenoszenie drużyny, scalanie, historia
# ---------------------------------------------------------------------------

class MoveTeamRequest(BaseModel):
    province: str
    season: Optional[str] = None
    team_id: str
    to_club_id: str
    updated_by: Optional[str] = None


@router.post("/move-team", summary="Przenieś drużynę do innej części rozbitego klubu")
async def move_team(payload: MoveTeamRequest):
    key = require_province(payload.province)
    season = _s(payload.season) or season_of(_now())
    SR.season_start(season)
    data = await _context(key, season)
    team = data["teams_meta"].get(_s(payload.team_id))
    if team is None:
        raise HTTPException(404, "Nie ma takiej drużyny w tym sezonie - odśwież panel.")
    from_club = _s(team["club_id"])
    info = (data.get("splits") or {}).get(from_club)
    if info is None:
        raise HTTPException(400, "Ten klub nie jest rozbity w tym sezonie, więc nie ma dokąd przenosić drużyny.")
    parent = info["parent_club_id"]
    counts: dict[str, int] = {}
    for item in data["teams_meta"].values():
        counts[_s(item["club_id"])] = counts.get(_s(item["club_id"]), 0) + 1
    name_key = team.get("name_key") or team_key(team["name"])
    try:
        plan = SR.move_team(
            [],
            parent=parent,
            season=season,
            team_id=team["team_id"],
            name_key=name_key,
            to_club_id=_s(payload.to_club_id),
            group_clubs=[p["club_id"] for p in info["parts"]],
            team_counts=counts,
            from_club_id=from_club,
        )
    except ValueError as exc:
        _fail(exc)
    who = _s(payload.updated_by) or None
    names = {p["club_id"]: p["name"] for p in info["parts"]}
    async with database.transaction():
        gone = plan["delete_same_season"]
        await database.execute(
            delete(province_club_split_teams).where(
                and_(
                    province_club_split_teams.c.province == key,
                    province_club_split_teams.c.parent_club_id == gone["parent_club_id"],
                    province_club_split_teams.c.season == gone["season"],
                    province_club_split_teams.c.team_id == gone["team_id"],
                )
            )
        )
        await database.execute(
            insert(province_club_split_teams).values(
                province=key, **plan["insert"], updated_by=who, updated_at=_now()
            )
        )
        await _log(
            key,
            parent,
            season,
            "move-team",
            {
                "team": team["name"],
                "from": {"club_id": from_club, "name": names.get(from_club, from_club)},
                "to": {"club_id": plan["insert"]["club_id"], "name": names.get(plan["insert"]["club_id"], "")},
            },
            who,
        )
    return {"success": True}


class MergeRequest(BaseModel):
    province: str
    season: Optional[str] = None
    #: Część do scalenia albo klub macierzysty (wtedy wszystkie części).
    club_id: str
    updated_by: Optional[str] = None


@router.post("/merge", summary="Scal rozbity klub z powrotem")
async def merge_split(payload: MergeRequest):
    key = require_province(payload.province)
    season = _s(payload.season) or season_of(_now())
    start = SR.season_start(season)
    club_id = _s(payload.club_id)
    data = await _context(key, season)
    info = (data.get("splits") or {}).get(club_id)
    if info is None:
        raise HTTPException(400, "Ten klub nie jest rozbity w tym sezonie, więc nie ma czego scalać.")
    parent = info["parent_club_id"]
    part_id = None if club_id == parent else club_id
    group_clubs = {p["club_id"] for p in info["parts"]}
    teams = [
        {"team_id": t["team_id"], "name_key": t.get("name_key") or team_key(t["name"]), "club_id": _s(t["club_id"])}
        for t in data["teams_meta"].values()
        if _s(t["club_id"]) in group_clubs
    ]
    rows = await assignment_rows(key)
    plan = SR.merge_back(rows, parent=parent, season=season, part_id=part_id, teams=teams)
    who = _s(payload.updated_by) or None
    moved_entries = 0
    async with database.transaction():
        if plan["delete_ids"]:
            await database.execute(
                delete(province_club_split_teams).where(
                    province_club_split_teams.c.id.in_(plan["delete_ids"])
                )
            )
        for row in plan["insert"]:
            await database.execute(
                insert(province_club_split_teams).values(
                    province=key, **row, updated_by=who, updated_at=_now()
                )
            )
        if plan["entry_clubs"]:
            found = await database.fetch_all(
                select(province_club_entries.c.id, province_club_entries.c.season).where(
                    and_(
                        province_club_entries.c.province == key,
                        province_club_entries.c.club_id.in_(plan["entry_clubs"]),
                    )
                )
            )
            ids = []
            for row in found:
                try:
                    if SR.season_start(row["season"]) >= start:
                        ids.append(int(row["id"]))
                except ValueError:
                    continue
            if ids:
                await database.execute(
                    update(province_club_entries)
                    .where(province_club_entries.c.id.in_(ids))
                    .values(club_id=parent)
                )
                moved_entries = len(ids)
        names = {p["club_id"]: p["name"] for p in info["parts"]}
        await _log(
            key,
            parent,
            season,
            "merge",
            {
                "merged": [{"club_id": c, "name": names.get(c, c)} for c in plan["entry_clubs"]],
                "teams": [t["name"] for t in data["teams_meta"].values() if _s(t["club_id"]) in plan["entry_clubs"]],
                "entries_moved": moved_entries,
            },
            who,
        )
    return {"success": True, "club_id": parent, "entries_moved": moved_entries}


@router.get("/log", summary="Historia zmian rozbicia klubu")
async def split_log(province: str = Query(...), club_id: str = Query(...), limit: int = Query(100, ge=1, le=500)):
    key = require_province(province)
    parent = SR.parent_of_part(club_id)
    rows = await database.fetch_all(
        select(province_club_split_log)
        .where(
            and_(
                province_club_split_log.c.province == key,
                province_club_split_log.c.parent_club_id == parent,
            )
        )
        .order_by(province_club_split_log.c.id.desc())
        .limit(limit)
    )
    out = []
    for row in rows:
        try:
            detail = json.loads(row["detail"] or "{}")
        except (TypeError, ValueError):
            detail = {}
        out.append(
            {
                "id": int(row["id"]),
                "season": row["season"],
                "action": row["action"],
                "detail": detail,
                "created_by": row["created_by"],
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            }
        )
    return {"club_id": parent, "log": out}

"""
Panel klubow - warstwa HTTP.

Saldo klubu liczy sie NA ZYWO: wplaty minus wyplaty minus obciazenia za mecze.
Obciazen nie ksiegujemy na sztywno, wiec poprawiona wstecz stawka albo dopisany
wyjatek od razu poprawiaja saldo - a rachunek klubu i zestawienie sedziow
wychodza z tego samego silnika (`settlement_engine`), wiec nie maja jak sie
rozjechac.

Cala regula „kto placi i ile" siedzi w lisciu `club_charges`; tutaj tylko
czytamy fakty z bazy i skladamy odpowiedz.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import date, datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import and_, delete, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import club_charges as C
from app import settlement_engine as E
from app import settlement_rates as R
from app.db import (
    database,
    province_club_entries,
    province_club_seasons,
    province_club_teams,
    province_clubs,
    province_match_overrides,
    province_matches,
)
from app.province_clubs_excel import build_workbook, parse_workbook
from app.province_clubs_scrape import team_key
from app.province_clubs_sync import RUN_KIND, last_run, refresh_clubs, start_run
from app.province_settlement_sync import module_enabled
from app.province_settlements import (
    _assignments,
    _judge_names,
    _versions,
    require_province,
)
from app.settlement_province import display, spellings
from app.settlement_runs import cooldown_left, run_is_active
from app.settlement_seasons import season_of

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province/clubs", tags=["province_clubs"])

#: Zadania w tle - asyncio trzyma do nich slaba referencje.
_BACKGROUND: set = set()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value or "").strip()


def _state(raw: Any) -> dict:
    """JSONB potrafi wrocic napisem - wtedy trzeba go rozpakowac."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except Exception:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def season_range(season: str) -> tuple[date, date]:
    """Sezon `2026/2027` to 1.09.2026 - 31.08.2027 - jak w statystykach."""
    match = re.match(r"^(\d{4})/(\d{4})$", _s(season))
    if not match:
        raise HTTPException(400, f"Nieznany sezon: {season}")
    start = int(match.group(1))
    return date(start, 9, 1), date(start + 1, 8, 31)


async def _known_seasons(province: str) -> list[str]:
    rows = await database.fetch_all(
        select(province_club_seasons.c.season, province_club_seasons.c.completed_at)
        .where(province_club_seasons.c.province == province)
        .order_by(province_club_seasons.c.season.desc())
    )
    return [_s(row["season"]) for row in rows]


async def _hosts(province: str) -> dict[str, str]:
    """Gospodarz meczu - po NAZWIE, bo mecze nie niosa numeru druzyny."""
    rows = await database.fetch_all(
        select(province_matches.c.match_id, province_matches.c.state_json).where(
            and_(
                province_matches.c.province.in_(spellings(province)),
                province_matches.c.active.is_(True),
            )
        )
    )
    out: dict[str, str] = {}
    for row in rows:
        state = _state(row["state_json"])
        host = _s(state.get("ID_zespoly_gosp_ZespolNazwa"))
        if host:
            out[f"d:{_s(row['match_id'])}"] = host
    return out


async def _teams(province: str, season: str) -> tuple[dict[str, C.TeamRef], dict[str, C.TeamRef], dict[str, dict]]:
    rows = await database.fetch_all(
        select(province_club_teams).where(
            and_(
                province_club_teams.c.province == province,
                province_club_teams.c.season == season,
            )
        )
    )
    by_id: dict[str, C.TeamRef] = {}
    by_key: dict[str, C.TeamRef] = {}
    meta: dict[str, dict] = {}
    for row in rows:
        team_id = _s(row["team_id"])
        ref = C.TeamRef(
            team_id=team_id,
            club_id=_s(row["club_id"]),
            name=_s(row["team_name"]),
            category=_s(row["category"]),
            gender=_s(row["gender"]),
        )
        by_id[team_id] = ref
        key = _s(row["name_key"]) or team_key(ref.name)
        by_key.setdefault(key, ref)
        entry = meta.setdefault(
            team_id,
            {
                "team_id": team_id,
                "name": ref.name,
                "club_id": ref.club_id,
                "category": ref.category,
                "gender": ref.gender,
                "province": _s(row["team_province"]),
                "competitions": [],
            },
        )
        label = _s(row["competition_name"])
        if label and label not in entry["competitions"]:
            entry["competitions"].append(label)
    return by_id, by_key, meta


async def _club_settings(province: str) -> dict[str, dict]:
    rows = await database.fetch_all(
        select(province_clubs).where(province_clubs.c.province == province)
    )
    return {_s(row["club_id"]): dict(row) for row in rows}


async def _overrides(province: str) -> dict[str, C.MatchOverride]:
    rows = await database.fetch_all(
        select(province_match_overrides).where(province_match_overrides.c.province == province)
    )
    return {
        _s(row["match_key"]): C.MatchOverride(
            excluded=bool(row["excluded"]),
            team_id=_s(row["team_id"]),
            team_name=_s(row["team_name"]),
            triple_table=bool(row["triple_table"]),
        )
        for row in rows
    }


async def _entries(province: str, season: str) -> list[dict]:
    rows = await database.fetch_all(
        select(province_club_entries)
        .where(
            and_(
                province_club_entries.c.province == province,
                province_club_entries.c.season == season,
            )
        )
        .order_by(province_club_entries.c.day.desc(), province_club_entries.c.id.desc())
    )
    return [dict(row) for row in rows]


async def load_clubs(province: str, season: str, *, include_future: bool = False) -> dict:
    """Jedno wejscie: druzyny, obciazenia, wplaty - dla listy i dla szczegolu."""
    date_from, date_to = season_range(season)
    central_versions, province_versions = await _versions(province)
    names = await _judge_names(province)
    assignments = await _assignments(province)

    settled = E.settle_judges(
        assignments,
        province=province,
        central_versions=central_versions,
        province_versions=province_versions,
        now=_now(),
        date_from=date_from,
        date_to=date_to,
        include_future=include_future,
        names=names,
    )
    matches = [item for entry in settled for item in entry.matches]

    by_id, by_key, meta = await _teams(province, season)
    settings = await _club_settings(province)
    clubs_setting = {
        club_id: C.ClubSetting(
            settles=bool(row.get("settles_via_district", True)),
            since=row.get("settles_since"),
        )
        for club_id, row in settings.items()
    }

    charges = C.build_charges(
        matches,
        hosts=await _hosts(province),
        teams_by_key=by_key,
        teams_by_id=by_id,
        overrides=await _overrides(province),
        clubs=clubs_setting,
        judge_names=names,
        key_of=team_key,
    )

    return {
        "season": season,
        "teams_by_id": by_id,
        "teams_meta": meta,
        "settings": settings,
        "charges": charges,
        "entries": await _entries(province, season),
    }


def _club_name(settings: dict, meta: dict, club_id: str) -> str:
    row = settings.get(club_id) or {}
    name = _s(row.get("display_name"))
    if name:
        return name
    names = [item["name"] for item in meta.values() if item["club_id"] == club_id]
    return sorted(names, key=lambda value: (len(value), value))[0] if names else club_id


def _entry_json(row: dict) -> dict:
    return {
        "id": row["id"],
        "club_id": _s(row["club_id"]),
        "team_id": _s(row["team_id"]),
        "team_name": _s(row["team_name"]),
        "kind": _s(row["kind"]),
        "amount": float(row["amount"] or 0),
        "description": _s(row["description"]),
        "day": row["day"].isoformat() if row["day"] else None,
        "source": _s(row["source"]),
        "created_by": _s(row["created_by"]),
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
    }


def _charge_json(row: C.ChargeRow, province: str) -> dict:
    # Potrójny ryczałt wolno zaproponować tylko tam, gdzie reguła na to pozwala
    # (stolik OKRĘGOWY, okręg z tą opcją) i gdy przy stoliku stał JEDEN sędzia.
    tables = [share for share in row.referees if share.role.startswith(R.ROLE_TABLE)]
    triple_allowed = len(tables) == 1 and R.triple_table_allowed(row.code, R.ROLE_TABLE, province)
    return {
        "match_key": row.match_key,
        "match_at": row.match_at.isoformat() if row.match_at else None,
        "day": row.day.isoformat() if row.day else None,
        "code": row.code,
        "category": row.category,
        "city": row.city,
        "host_name": row.host_name,
        "team_id": row.team_id,
        "team_name": row.team_name,
        "club_id": row.club_id,
        "gross": row.gross,
        "travel": row.travel,
        "amount": row.amount,
        "status": row.status,
        "moved": row.moved,
        "triple": row.triple,
        "triple_allowed": triple_allowed,
        "referees": [
            {
                "judge_id": share.judge_id,
                "name": share.name,
                "role": share.role + (" x3" if share.triple else ""),
                "gross": share.gross,
                "travel": share.travel,
                "triple": share.triple,
            }
            for share in row.referees
        ],
    }


# ---------------------------------------------------------------------------
# Odczyt
# ---------------------------------------------------------------------------

@router.get("/status", summary="Stan danych klubów w okręgu")
async def status(province: str = Query(...)):
    key = require_province(province)
    run = await last_run(key)
    now = _now()
    seasons = await _known_seasons(key)
    current = season_of(now)

    def iso(value):
        return value.isoformat() if value else None

    return {
        "province": key,
        "display": display(key),
        "current_season": current,
        "seasons": seasons or ([current] if current else []),
        "settlements_enabled": await module_enabled(key, "settlements"),
        "last_run": {
            "id": run.get("id"),
            "kind": run.get("kind"),
            "started_at": iso(run.get("started_at")),
            "finished_at": iso(run.get("finished_at")),
            "running": run_is_active(run.get("started_at"), run.get("finished_at"), now),
            "ok": run.get("ok"),
            "competitions": run.get("judges"),
            "teams": run.get("matches"),
            "seasons": run.get("outside_matches"),
            "error": run.get("error"),
        } if run else None,
    }


@router.get("", summary="Lista klubów z saldami")
async def list_clubs(
    province: str = Query(...),
    season: Optional[str] = Query(None),
    q: Optional[str] = Query(None, description="Szukaj po nazwie klubu albo drużyny"),
    category: Optional[str] = Query(None),
    gender: Optional[str] = Query(None),
    only_debt: bool = Query(False, description="Tylko kluby na minusie"),
    include_future: bool = Query(False),
):
    key = require_province(province)
    if not await module_enabled(key, "settlements"):
        raise HTTPException(403, "Moduł Rozliczeń nie jest włączony w tym okręgu")
    season = _s(season) or season_of(_now())

    data = await load_clubs(key, season, include_future=include_future)
    charges: list[C.ChargeRow] = data["charges"]
    meta: dict[str, dict] = data["teams_meta"]
    settings: dict[str, dict] = data["settings"]

    charged = C.club_totals(charges)
    money: dict[str, dict[str, float]] = {}
    for row in data["entries"]:
        entry = money.setdefault(_s(row["club_id"]), {"in": 0.0, "out": 0.0})
        entry["in" if _s(row["kind"]) == "in" else "out"] += float(row["amount"] or 0)

    club_ids = {item["club_id"] for item in meta.values() if item["club_id"]}
    club_ids |= set(charged.keys()) | set(money.keys()) | set(settings.keys())

    needle = team_key(q) if q else ""
    clubs: list[dict] = []
    for club_id in sorted(club_ids):
        teams = [item for item in meta.values() if item["club_id"] == club_id]
        if category:
            teams = [item for item in teams if item["category"] == category]
        if gender:
            teams = [item for item in teams if item["gender"] == gender]
        if (category or gender) and not teams:
            continue

        name = _club_name(settings, meta, club_id)
        if needle and needle not in team_key(name) and not any(
            needle in team_key(item["name"]) for item in teams
        ):
            continue

        row = settings.get(club_id) or {}
        totals = charged.get(club_id) or {"charged": 0, "matches": 0}
        paid = money.get(club_id) or {"in": 0.0, "out": 0.0}
        balance = C.balance(paid_in=paid["in"], paid_out=paid["out"], charged=totals["charged"])
        if only_debt and balance >= 0:
            continue

        clubs.append(
            {
                "club_id": club_id,
                "name": name,
                "settles_via_district": bool(row.get("settles_via_district", True)),
                "settles_since": row["settles_since"].isoformat() if row.get("settles_since") else None,
                "note": _s(row.get("note")),
                "teams": sorted(teams, key=lambda item: item["name"]),
                "categories": sorted({item["category"] for item in teams if item["category"]}),
                "paid_in": round(paid["in"], 2),
                "paid_out": round(paid["out"], 2),
                "charged": totals["charged"],
                "matches": totals["matches"],
                "balance": balance,
            }
        )

    unassigned = [_charge_json(row, key) for row in charges if row.status == C.UNASSIGNED]
    totals = {
        "clubs": len(clubs),
        "paid_in": round(sum(item["paid_in"] for item in clubs), 2),
        "paid_out": round(sum(item["paid_out"] for item in clubs), 2),
        "charged": sum(item["charged"] for item in clubs),
        "balance": sum(item["balance"] for item in clubs),
        "matches": sum(item["matches"] for item in clubs),
        "unassigned": len(unassigned),
    }

    return {
        "province": key,
        "season": season,
        "seasons": await _known_seasons(key) or [season],
        "clubs": clubs,
        "totals": totals,
        "unassigned": unassigned,
    }


@router.get("/unassigned", summary="Mecze bez rozpoznanej drużyny gospodarza")
async def unassigned(
    province: str = Query(...),
    season: Optional[str] = Query(None),
    include_future: bool = Query(False),
):
    key = require_province(province)
    season = _s(season) or season_of(_now())
    data = await load_clubs(key, season, include_future=include_future)
    rows = [_charge_json(row, key) for row in data["charges"] if row.status == C.UNASSIGNED]
    teams = sorted(data["teams_meta"].values(), key=lambda item: item["name"])
    return {"province": key, "season": season, "matches": rows, "teams": teams}


@router.get("/{club_id}", summary="Klub: mecze, wpłaty i saldo")
async def club_detail(
    club_id: str,
    province: str = Query(...),
    season: Optional[str] = Query(None),
    include_future: bool = Query(False),
):
    key = require_province(province)
    season = _s(season) or season_of(_now())
    data = await load_clubs(key, season, include_future=include_future)

    charges = [row for row in data["charges"] if row.club_id == club_id]
    entries = [row for row in data["entries"] if _s(row["club_id"]) == club_id]
    teams = [item for item in data["teams_meta"].values() if item["club_id"] == club_id]

    paid_in = sum(float(row["amount"] or 0) for row in entries if _s(row["kind"]) == "in")
    paid_out = sum(float(row["amount"] or 0) for row in entries if _s(row["kind"]) == "out")
    charged = sum(row.amount for row in charges if row.status == C.CHARGED)
    per_team = C.team_totals(charges)
    settings = data["settings"].get(club_id) or {}

    return {
        "province": key,
        "season": season,
        "club": {
            "club_id": club_id,
            "name": _club_name(data["settings"], data["teams_meta"], club_id),
            "settles_via_district": bool(settings.get("settles_via_district", True)),
            "settles_since": settings["settles_since"].isoformat() if settings.get("settles_since") else None,
            "note": _s(settings.get("note")),
            "paid_in": round(paid_in, 2),
            "paid_out": round(paid_out, 2),
            "charged": charged,
            "balance": C.balance(paid_in=paid_in, paid_out=paid_out, charged=charged),
            "matches": sum(1 for row in charges if row.status == C.CHARGED),
        },
        "teams": [
            {**item, "charged": (per_team.get(item["team_id"]) or {}).get("charged", 0),
             "matches": (per_team.get(item["team_id"]) or {}).get("matches", 0)}
            for item in sorted(teams, key=lambda item: item["name"])
        ],
        "charges": [_charge_json(row, key) for row in charges],
        "entries": [_entry_json(row) for row in entries],
    }


# ---------------------------------------------------------------------------
# Zapis
# ---------------------------------------------------------------------------

class EntryRequest(BaseModel):
    province: str
    season: Optional[str] = None
    team_id: Optional[str] = None
    team_name: Optional[str] = None
    kind: str = "in"                       # "in" = wpłata, "out" = wypłata
    amount: float = 0.0
    description: Optional[str] = None
    day: Optional[date] = None
    source: str = "manual"
    created_by: Optional[str] = None


class SettingsRequest(BaseModel):
    province: str
    settles_via_district: bool = True
    settles_since: Optional[date] = None
    display_name: Optional[str] = None
    note: Optional[str] = None
    updated_by: Optional[str] = None


class OverrideRequest(BaseModel):
    province: str
    excluded: bool = False
    team_id: Optional[str] = None
    team_name: Optional[str] = None
    triple_table: bool = False
    note: Optional[str] = None
    updated_by: Optional[str] = None


class RefreshRequest(BaseModel):
    province: str
    username: Optional[str] = None
    password: Optional[str] = None
    #: Reczne puszczenie z panelu nadrabia sezony nigdy nie pobrane w calosci.
    full_check: bool = True


@router.post("/{club_id}/entries", summary="Dopisz wpłatę albo wypłatę")
async def add_entry(club_id: str, payload: EntryRequest):
    key = require_province(payload.province)
    kind = "out" if _s(payload.kind).lower().startswith("out") else "in"
    amount = round(abs(float(payload.amount or 0)), 2)
    if amount <= 0:
        raise HTTPException(400, "Kwota musi być większa od zera")

    season = _s(payload.season) or season_of(_now())
    new_id = await database.execute(
        insert(province_club_entries).values(
            province=key,
            club_id=_s(club_id),
            team_id=_s(payload.team_id) or None,
            team_name=_s(payload.team_name) or None,
            season=season,
            kind=kind,
            amount=amount,
            description=_s(payload.description) or None,
            day=payload.day or _now().date(),
            source=_s(payload.source) or "manual",
            created_by=_s(payload.created_by) or None,
            created_at=_now(),
        )
    )
    return {"success": True, "id": int(new_id)}


@router.delete("/entries/{entry_id}", summary="Usuń wpłatę albo wypłatę")
async def remove_entry(entry_id: int, province: str = Query(...)):
    key = require_province(province)
    removed = await database.execute(
        delete(province_club_entries).where(
            and_(
                province_club_entries.c.id == entry_id,
                province_club_entries.c.province == key,
            )
        )
    )
    if not removed:
        raise HTTPException(404, "Nie znaleziono takiego wpisu")
    return {"success": True}


@router.put("/{club_id}/settings", summary="Ustawienia klubu")
async def set_club(club_id: str, payload: SettingsRequest):
    key = require_province(payload.province)
    values = {
        "province": key,
        "club_id": _s(club_id),
        "settles_via_district": bool(payload.settles_via_district),
        "settles_since": payload.settles_since,
        "note": _s(payload.note) or None,
        "updated_by": _s(payload.updated_by) or None,
        "updated_at": _now(),
    }
    if payload.display_name is not None:
        values["display_name"] = _s(payload.display_name) or None

    statement = pg_insert(province_clubs).values(**values)
    await database.execute(
        statement.on_conflict_do_update(
            index_elements=[province_clubs.c.province, province_clubs.c.club_id],
            set_={k: v for k, v in values.items() if k not in ("province", "club_id")},
        )
    )
    return {"success": True}


@router.put("/matches/{match_key}/override", summary="Wyjątek na meczu")
async def set_override(match_key: str, payload: OverrideRequest):
    key = require_province(payload.province)
    values = {
        "province": key,
        "match_key": _s(match_key),
        "excluded": bool(payload.excluded),
        "team_id": _s(payload.team_id) or None,
        "team_name": _s(payload.team_name) or None,
        "triple_table": bool(payload.triple_table),
        "note": _s(payload.note) or None,
        "updated_by": _s(payload.updated_by) or None,
        "updated_at": _now(),
    }
    statement = pg_insert(province_match_overrides).values(**values)
    await database.execute(
        statement.on_conflict_do_update(
            index_elements=[
                province_match_overrides.c.province,
                province_match_overrides.c.match_key,
            ],
            set_={k: v for k, v in values.items() if k not in ("province", "match_key")},
        )
    )
    return {"success": True}


@router.post("/refresh", summary="Pobierz kluby i drużyny z ZPRP (w tle)")
async def refresh(payload: RefreshRequest):
    key = require_province(payload.province)
    if not await module_enabled(key, "settlements"):
        raise HTTPException(403, "Moduł Rozliczeń nie jest włączony w tym okręgu")

    now = _now()
    previous = await last_run(key)
    if previous and run_is_active(previous.get("started_at"), previous.get("finished_at"), now):
        return {"province": key, "started": False, "running": True, "run_id": previous.get("id")}

    with_credentials = bool(payload.username and payload.password)
    if previous and not with_credentials:
        left = cooldown_left(previous.get("finished_at"), previous.get("ok"), now)
        if left is not None:
            minutes = max(1, round(left.total_seconds() / 60))
            return {
                "province": key,
                "started": False,
                "running": False,
                "run_id": previous.get("id"),
                "message": f"Kluby odświeżono przed chwilą - kolejne odświeżenie możliwe za {minutes} min.",
            }

    run_id = await start_run(key, f"{RUN_KIND}-manual")
    task = asyncio.create_task(
        refresh_clubs(
            key,
            username=payload.username,
            password=payload.password,
            kind=f"{RUN_KIND}-manual",
            full_check=bool(payload.full_check),
            run_id=run_id,
        )
    )
    _BACKGROUND.add(task)
    task.add_done_callback(_BACKGROUND.discard)
    return {"province": key, "started": True, "running": True, "run_id": run_id}


# ---------------------------------------------------------------------------
# Excel
# ---------------------------------------------------------------------------

@router.get("/export/xlsx", summary="Szablon wpłat i wypłat")
async def export_xlsx(
    province: str = Query(...),
    season: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    gender: Optional[str] = Query(None),
):
    key = require_province(province)
    season = _s(season) or season_of(_now())
    _, _, meta = await _teams(key, season)
    settings = await _club_settings(key)

    rows = []
    for item in sorted(meta.values(), key=lambda value: (value["category"], value["name"])):
        if category and item["category"] != category:
            continue
        if gender and item["gender"] != gender:
            continue
        rows.append(
            {
                "team_id": item["team_id"],
                "team_name": item["name"],
                "club_name": _club_name(settings, meta, item["club_id"]),
                "category": item["category"],
            }
        )
    if not rows:
        raise HTTPException(404, "Dla tego sezonu i filtrów nie ma żadnych drużyn")

    label = " ".join(x for x in [display(key), season, category or "", gender or ""] if x).strip()
    data = build_workbook(rows, title=f"Wpłaty i wypłaty klubów - {label}")
    name = f"kluby_{key}_{season.replace('/', '_')}{'_' + category if category else ''}.xlsx"
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.post("/import/preview", summary="Podgląd wgranego pliku")
async def import_preview(
    province: str = Query(...),
    season: Optional[str] = Query(None),
    file: UploadFile = File(...),
):
    key = require_province(province)
    season = _s(season) or season_of(_now())
    try:
        parsed = parse_workbook(await file.read())
    except Exception as exc:
        raise HTTPException(400, f"Nie udało się odczytać pliku: {exc}")

    by_id, by_key, meta = await _teams(key, season)
    settings = await _club_settings(key)
    existing = await _entries(key, season)

    def duplicate(club_id: str, team_id: str, kind: str, amount: float, note: str) -> bool:
        for row in existing:
            if (
                _s(row["club_id"]) == club_id
                and _s(row["team_id"]) == team_id
                and _s(row["kind"]) == kind
                and abs(float(row["amount"] or 0) - amount) < 0.005
                and _s(row["description"]) == _s(note)
            ):
                return True
        return False

    items: list[dict] = []
    for row in parsed:
        team = by_id.get(_s(row["team_id"])) or by_key.get(team_key(row["team_name"]))
        club_id = team.club_id if team else ""
        base = {
            "row": row["row"],
            "team_id": team.team_id if team else "",
            "team_name": team.name if team else _s(row["team_name"]),
            "club_id": club_id,
            "club_name": _club_name(settings, meta, club_id) if club_id else _s(row["club_name"]),
            "known": team is not None,
        }
        if row["in_amount"]:
            items.append({
                **base,
                "kind": "in",
                "amount": row["in_amount"],
                "description": row["in_note"],
                "duplicate": duplicate(club_id, base["team_id"], "in", row["in_amount"], row["in_note"]),
            })
        if row["out_amount"]:
            items.append({
                **base,
                "kind": "out",
                "amount": row["out_amount"],
                "description": row["out_note"],
                "duplicate": duplicate(club_id, base["team_id"], "out", row["out_amount"], row["out_note"]),
            })

    return {
        "province": key,
        "season": season,
        "items": items,
        "summary": {
            "rows": len(items),
            "unknown": sum(1 for item in items if not item["known"]),
            "duplicates": sum(1 for item in items if item["duplicate"]),
            "in": round(sum(item["amount"] for item in items if item["kind"] == "in"), 2),
            "out": round(sum(item["amount"] for item in items if item["kind"] == "out"), 2),
        },
    }


class ImportItem(BaseModel):
    club_id: str
    team_id: Optional[str] = None
    team_name: Optional[str] = None
    kind: str = "in"
    amount: float = 0.0
    description: Optional[str] = None


class ImportRequest(BaseModel):
    province: str
    season: Optional[str] = None
    day: Optional[date] = None
    created_by: Optional[str] = None
    items: list[ImportItem] = []


@router.post("/import/commit", summary="Zapisz zaznaczone pozycje z pliku")
async def import_commit(payload: ImportRequest):
    key = require_province(payload.province)
    season = _s(payload.season) or season_of(_now())
    day = payload.day or _now().date()
    saved = 0
    for item in payload.items:
        amount = round(abs(float(item.amount or 0)), 2)
        club_id = _s(item.club_id)
        if amount <= 0 or not club_id:
            continue
        await database.execute(
            insert(province_club_entries).values(
                province=key,
                club_id=club_id,
                team_id=_s(item.team_id) or None,
                team_name=_s(item.team_name) or None,
                season=season,
                kind="out" if _s(item.kind).lower().startswith("out") else "in",
                amount=amount,
                description=_s(item.description) or None,
                day=day,
                source="excel",
                created_by=_s(payload.created_by) or None,
                created_at=_now(),
            )
        )
        saved += 1
    return {"success": True, "saved": saved}

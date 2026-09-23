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
import hashlib
import json
import logging
import re
from datetime import date, datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import and_, delete, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import club_charges as C
from app import province_clubs_bulk as B
from app import province_clubs_scope as S
from app import province_club_budgets as CB
from app import province_club_budgets_rules as BR
from app import settlement_engine as E
from app import settlement_rates as R
from app.db import (
    database,
    province_club_assignment,
    province_club_entries,
    province_competitions,
    province_club_season_closures,
    province_club_seasons,
    province_club_teams,
    province_clubs,
    province_match_overrides,
    province_matches,
    province_settlement_matches,
)
from app.province_clubs_excel import build_club_workbook, parse_workbook
from app.province_clubs_scrape import team_key
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import panel_write_gate
from app.province_clubs_sync import RUN_KIND, last_run, refresh_clubs, start_run
from app.province_settlement_sync import module_enabled
from app.province_settlements import (
    _assignments,
    _judge_names,
    _versions,
    require_province,
)
from app.settlement_province import canonical, display, spellings
from app.settlement_runs import cooldown_left, run_is_active
from app.settlement_seasons import season_of

logger = logging.getLogger(__name__)

# Każdy zapis w panelu klubów (wpłaty, salda, rozliczanie przez okręg, import,
# rozliczenie sezonu) przechodzi przez bramkę konta VIP z uprawnieniem
# „Rozliczenia" - patrz `province_panel_guard`. Odczyty zostają wolne.
router = APIRouter(
    prefix="/province/clubs",
    tags=["province_clubs"],
    dependencies=[Depends(panel_write_gate(PANEL_SETTLEMENTS, "Zapis w panelu klubów"))],
)

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
                "codes": [],
            },
        )
        label = _s(row["competition_name"])
        if label and label not in entry["competitions"]:
            entry["competitions"].append(label)
        code = _s(row["competition_code"])
        if code and code not in entry["codes"]:
            entry["codes"].append(code)
    return by_id, by_key, meta


async def _club_settings(province: str) -> dict[str, dict]:
    rows = await database.fetch_all(
        select(province_clubs).where(province_clubs.c.province == province)
    )
    return {_s(row["club_id"]): dict(row) for row in rows}


async def _table_rules(province: str) -> dict[str, dict]:
    """
    Kto stawia drugiego stolikowego - deklaracje z zakladki Kluby w Obsadzie.

    ⚠ Jedno zrodlo prawdy: to ta sama tabela, ktora czyta Automat
    (`assignment_context._club_rules`). Panel klubow jej nie kopiuje, tylko
    czyta, zeby „kogo wysylamy" i „za kogo klub placi" nie mogly sie rozjechac.
    """
    rows = await database.fetch_all(
        select(province_club_assignment).where(
            province_club_assignment.c.province.in_(spellings(province))
        )
    )
    # Jeden wiersz na klub, najświeższy - patrz `newest_rule_per_club`.
    return {
        club_id: {
            "table_by_club": int(row["table_by_club"] or 0),
            "table_by_club_since": row["table_by_club_since"],
        }
        for club_id, row in B.newest_rule_per_club(rows, canonical(province)).items()
    }


def _table_json(rule: Optional[dict]) -> dict:
    """Deklaracja stolikowego klubu w odpowiedzi - obok platnosci przez okreg."""
    rule = rule or {}
    since = rule.get("table_by_club_since")
    return {
        "table_by_club": int(rule.get("table_by_club", 0) or 0),
        "table_by_club_since": since.isoformat() if since else None,
    }


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
    # Reczne mecze z rachunkiem (np. SPARING) nie maja gospodarza z terminarza
    # - klub wskazano przy dopisaniu. Wylaczamy je z rozpoznawania i skladamy
    # osobno z TYCH SAMYCH przeliczonych obsad (`manual_charge_rules`).
    from app.manual_charge_rules import is_manual_key
    from app.province_manual_charges import manual_charges_for

    manual_matches = [item for item in matches if is_manual_key(item.match_key)]
    matches = [item for item in matches if not is_manual_key(item.match_key)]

    by_id, by_key, meta = await _teams(province, season)
    settings = await _club_settings(province)
    table_rules = await _table_rules(province)
    clubs_setting = {
        club_id: C.ClubSetting(
            settles=bool((settings.get(club_id) or {}).get("settles_via_district", True)),
            since=(settings.get(club_id) or {}).get("settles_since"),
            table_by_club=int((table_rules.get(club_id) or {}).get("table_by_club", 0)),
            table_since=(table_rules.get(club_id) or {}).get("table_by_club_since"),
        )
        # Klub bywa tylko w jednej z tabel: platnosc ustawiona w panelu, a
        # stolik w Obsadzie - albo odwrotnie.
        for club_id in set(settings) | set(table_rules)
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
    if manual_matches:
        charges.extend(await manual_charges_for(province, manual_matches, names))
        charges.sort(key=lambda item: (item.day or date.min, item.match_key))

    return {
        "season": season,
        "teams_by_id": by_id,
        "teams_meta": meta,
        "settings": settings,
        "table_rules": table_rules,
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
    triple_allowed = (
        len(tables) == 1
        and R.triple_table_allowed(row.code, R.ROLE_TABLE, province)
        and row.manual_id is None
    )
    return {
        "match_key": row.match_key,
        # Reczny mecz z karty klubu - plakietka „ręczny", edycja i usuwanie.
        "manual_id": row.manual_id,
        "match_at": row.match_at.isoformat() if row.match_at else None,
        "day": row.day.isoformat() if row.day else None,
        "code": row.code,
        "category": row.category,
        "city": row.city,
        "host_name": row.host_name,
        "guest_name": row.guest_name,
        "teams": row.teams,
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
        # Klub stawia drugiego stolikowego sam; `extra_table` = okreg i tak
        # wystawil dwoch, a drugiego klubowi nie liczymy.
        "own_table": row.own_table,
        "extra_table": row.extra_table,
        "referees": [
            {
                "judge_id": share.judge_id,
                "name": share.name,
                "role": share.role + (" x3" if share.triple else ""),
                "gross": share.gross,
                "travel": share.travel,
                "triple": share.triple,
                "charged": share.charged,
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


async def _season_clubs(key: str, season: str, *, include_future: bool = False) -> dict:
    """
    Kluby sezonu z saldami - bez filtrow listy.

    Kto nalezy do sezonu, rozstrzyga `province_clubs_scope`: klub z meczem albo
    wpisem w tym sezonie i klub z druzyna w zasiegu okregu. Sam wiersz ustawien
    NIE wystarcza - pobieranie zaklada go kazdemu klubowi z kazdego sezonu i stad
    bralo sie „0 druzyn".

    Trzy kubelki pieniedzy: wplaty, wyplaty i rozliczenie sezonu poza systemem
    (`source="season-close"`). To ostatnie nie jest wplata, tylko zapis, ze sezon
    rozliczono poza aplikacja - ale saldo liczy je tak samo.
    """
    data = await load_clubs(key, season, include_future=include_future)
    charges: list[C.ChargeRow] = data["charges"]
    meta: dict[str, dict] = data["teams_meta"]
    settings: dict[str, dict] = data["settings"]

    charged = C.club_totals(charges)
    money: dict[str, dict[str, float]] = {}
    for row in data["entries"]:
        entry = money.setdefault(_s(row["club_id"]), {"in": 0.0, "out": 0.0, "settled": 0.0})
        entry[B.entry_bucket(row["kind"], row.get("source"))] += float(row["amount"] or 0)

    teams_of: dict[str, list[dict]] = {}
    for item in meta.values():
        teams_of.setdefault(item["club_id"], []).append(item)
    club_ids = S.season_club_ids(
        meta.values(),
        [row.club_id for row in charges if row.club_id] + list(money.keys()),
    )

    clubs: dict[str, dict] = {}
    for club_id in sorted(club_ids):
        row = settings.get(club_id) or {}
        totals = charged.get(club_id) or {"charged": 0, "matches": 0}
        paid = money.get(club_id) or {"in": 0.0, "out": 0.0, "settled": 0.0}
        clubs[club_id] = {
            "club_id": club_id,
            "name": _club_name(settings, meta, club_id),
            "settles_via_district": bool(row.get("settles_via_district", True)),
            "settles_since": row["settles_since"].isoformat() if row.get("settles_since") else None,
            **_table_json(data["table_rules"].get(club_id)),
            "note": _s(row.get("note")),
            "teams": sorted(teams_of.get(club_id, []), key=lambda item: item["name"]),
            "paid_in": round(paid["in"], 2),
            "paid_out": round(paid["out"], 2),
            "settled": round(paid["settled"], 2),
            "charged": totals["charged"],
            "matches": totals["matches"],
            "balance": C.balance(
                paid_in=paid["in"] + paid["settled"],
                paid_out=paid["out"],
                charged=totals["charged"],
            ),
        }
    return {"clubs": clubs, "charges": charges}


async def _closure(key: str, season: str, clubs: dict[str, dict]) -> Optional[dict]:
    """Sezon rozliczony poza systemem: kto i kiedy, a kwoty na zywo z wpisow."""
    row = await database.fetch_one(
        select(province_club_season_closures).where(
            and_(
                province_club_season_closures.c.province == key,
                province_club_season_closures.c.season == season,
            )
        )
    )
    if row is None:
        return None
    settled = [club["settled"] for club in clubs.values() if club["settled"] > 0]
    return {
        "closed_at": row["closed_at"].isoformat() if row["closed_at"] else None,
        "closed_by": _s(row["closed_by"]) or None,
        "clubs": len(settled),
        "amount": round(sum(settled), 2),
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

    base = await _season_clubs(key, season, include_future=include_future)
    charges: list[C.ChargeRow] = base["charges"]
    # Wspólny budżet = jeden wiersz (23.09.2026). Salda, sumy sezonu i filtry
    # („Na minusie", „Przez okręg") liczą budżet, nie jego numery osobno.
    budgets = await CB.merged_clubs(key, base["clubs"])

    needle = team_key(q) if q else ""
    clubs: list[dict] = []
    for club in budgets.values():
        teams = club["teams"]
        if category:
            teams = [item for item in teams if item["category"] == category]
        if gender:
            teams = [item for item in teams if item["gender"] == gender]
        if (category or gender) and not teams:
            continue
        if needle and needle not in team_key(club["name"]) and not any(
            needle in team_key(item["name"]) for item in teams
        ) and not any(needle in team_key(member["name"]) for member in club.get("members") or []):
            continue
        if only_debt and club["balance"] >= 0:
            continue
        clubs.append(
            {
                **club,
                "teams": teams,
                "categories": sorted({item["category"] for item in teams if item["category"]}),
            }
        )

    unassigned = [_charge_json(row, key) for row in charges if row.status == C.UNASSIGNED]
    # Mecze bez druzyny zdjete recznie z obciazen. Nie siedza na koncie zadnego
    # klubu, wiec bez tej listy nie daloby sie ich przywrocic.
    dismissed = [
        _charge_json(row, key) for row in charges if row.status == C.EXCLUDED and not row.club_id
    ]
    totals = {
        "clubs": len(clubs),
        "paid_in": round(sum(item["paid_in"] for item in clubs), 2),
        "paid_out": round(sum(item["paid_out"] for item in clubs), 2),
        "settled": round(sum(item["settled"] for item in clubs), 2),
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
        "dismissed": dismissed,
        "closure": await _closure(key, season, budgets),
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


class CreateTeamFromMatchRequest(BaseModel):
    province: str
    season: str
    match_key: str
    club_name: Optional[str] = None
    team_name: Optional[str] = None
    settles_via_district: bool = True
    include_history: bool = True
    created_by: Optional[str] = None


def _manual_id(prefix: str, value: str) -> str:
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:14]
    return f"manual:{prefix}:{digest}"


@router.post("/teams/from-match", summary="Dodaj nierozpoznanego gospodarza do Panelu klubow")
async def create_team_from_match(payload: CreateTeamFromMatchRequest):
    """Tworzy pelnoprawny klub/druzyne i od razu przypisuje wskazany mecz.

    Przy wlaczonej historii ten sam, jednoznaczny gospodarz jest dopisywany do
    sezonow, w ktorych wystepuje w zapisanych obsadach. Nie laczymy podobnych
    nazw automatycznie — to chroni przed sklejeniem dwoch roznych klubow.
    """
    key = require_province(payload.province)
    season = _s(payload.season) or season_of(_now())
    data = await load_clubs(key, season, include_future=True)
    charge = next((row for row in data["charges"] if row.match_key == payload.match_key), None)
    if charge is None:
        raise HTTPException(404, "Nie znaleziono meczu w wybranym sezonie")
    host = _s(payload.team_name) or _s(charge.host_name)
    if not host:
        raise HTTPException(400, "Mecz nie ma rozpoznanej nazwy gospodarza")

    club_name = _s(payload.club_name) or host
    name_key = team_key(host)
    club_id = _manual_id("club", team_key(club_name))
    team_id = _manual_id("team", name_key)

    # Dokladne wystapienia w historii. Tylko identyczny znormalizowany gospodarz;
    # sponsorzy i skroty wymagaja swiadomego przypisania w panelu.
    season_codes = {(season, _s(charge.code), _s(charge.category))}
    if payload.include_history:
        history = await database.fetch_all(
            select(
                province_settlement_matches.c.season,
                province_settlement_matches.c.match_code,
                province_settlement_matches.c.teams,
            ).where(province_settlement_matches.c.province == key)
        )
        for row in history:
            teams = _s(row["teams"])
            host_text = re.split(r"\s+(?:-|–|—|vs\.?|:)\s+", teams, maxsplit=1, flags=re.I)[0]
            if host_text and team_key(host_text) == name_key:
                season_codes.add((_s(row["season"]), _s(row["match_code"]), ""))

    await database.execute(
        pg_insert(province_clubs).values(
            province=key,
            club_id=club_id,
            display_name=club_name,
            settles_via_district=bool(payload.settles_via_district),
            settles_since=None if payload.settles_via_district else date.min,
            note="Klub dodany z nierozpoznanego gospodarza",
            updated_by=payload.created_by,
            updated_at=_now(),
        ).on_conflict_do_update(
            index_elements=[province_clubs.c.province, province_clubs.c.club_id],
            set_={
                "display_name": club_name,
                "settles_via_district": bool(payload.settles_via_district),
                "updated_by": payload.created_by,
                "updated_at": _now(),
            },
        )
    )

    saved_seasons = set()
    for item_season, code, fallback_category in season_codes:
        if not item_season:
            continue
        competition_id = _manual_id("competition", f"{item_season}:{code or fallback_category or 'inne'}")
        await database.execute(
            pg_insert(province_competitions).values(
                province=key, season=item_season, competition_id=competition_id,
                name=code or fallback_category or "Rozgrywki ligowe", code=code,
                category=fallback_category or None, kind="manual", fetched_at=_now(),
            ).on_conflict_do_nothing()
        )
        await database.execute(
            pg_insert(province_club_teams).values(
                province=key, season=item_season, team_id=team_id,
                competition_id=competition_id, team_name=host, name_key=name_key,
                team_province=key, club_id=club_id,
                category=fallback_category or None,
                competition_name=code or fallback_category or "Rozgrywki ligowe",
                competition_code=code or None, fetched_at=_now(),
            ).on_conflict_do_update(
                index_elements=[province_club_teams.c.province, province_club_teams.c.season,
                                province_club_teams.c.team_id, province_club_teams.c.competition_id],
                set_={"team_name": host, "name_key": name_key, "club_id": club_id,
                      "fetched_at": _now()},
            )
        )
        saved_seasons.add(item_season)

    await set_override(
        payload.match_key,
        OverrideRequest(
            province=key, team_id=team_id, team_name=host,
            updated_by=payload.created_by,
        ),
    )
    return {
        "club_id": club_id, "team_id": team_id, "club_name": club_name,
        "team_name": host, "seasons": sorted(saved_seasons, reverse=True),
    }


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

    # Wejście po numerze DOWOLNEGO członka wspólnego budżetu pokazuje cały
    # budżet: mecze, drużyny i wpisy wszystkich numerów, ustawienia z głównego.
    group = BR.group_of(_s(club_id), await CB.budget_groups(key))
    member_ids = list(group["member_ids"]) if group else [_s(club_id)]
    primary = _s(group["primary_club_id"]) if group else _s(club_id)
    members = set(member_ids)

    charges = [row for row in data["charges"] if row.club_id in members]
    entries = [row for row in data["entries"] if _s(row["club_id"]) in members]
    teams = [item for item in data["teams_meta"].values() if item["club_id"] in members]

    buckets = {"in": 0.0, "out": 0.0, "settled": 0.0}
    for row in entries:
        buckets[B.entry_bucket(row["kind"], row.get("source"))] += float(row["amount"] or 0)
    paid_in, paid_out, settled = buckets["in"], buckets["out"], buckets["settled"]
    charged = round(sum(row.amount for row in charges if row.status == C.CHARGED), 2)
    per_team = C.team_totals(charges)
    settings = data["settings"].get(primary) or {}

    def member_name(member_id: str) -> str:
        return _club_name(data["settings"], data["teams_meta"], member_id)

    member_rows = [
        {
            "club_id": member_id,
            "name": member_name(member_id),
            "settles_via_district": bool(
                (data["settings"].get(member_id) or {}).get("settles_via_district", True)
            ),
            "table_by_club": _table_json(data["table_rules"].get(member_id))["table_by_club"],
        }
        for member_id in member_ids
    ]
    multi = len(member_ids) > 1

    return {
        "province": key,
        "season": season,
        "club": {
            "club_id": primary,
            "name": (group or {}).get("name") or member_name(primary),
            "settles_via_district": bool(settings.get("settles_via_district", True)),
            "settles_since": settings["settles_since"].isoformat() if settings.get("settles_since") else None,
            **_table_json(data["table_rules"].get(primary)),
            "note": _s(settings.get("note")),
            "paid_in": round(paid_in, 2),
            "paid_out": round(paid_out, 2),
            "settled": round(settled, 2),
            "charged": charged,
            "balance": C.balance(paid_in=paid_in + settled, paid_out=paid_out, charged=charged),
            "matches": sum(1 for row in charges if row.status == C.CHARGED),
            "budget_id": (group or {}).get("budget_id"),
            "budget_name": (group or {}).get("name"),
            "member_ids": member_ids,
            "members": member_rows,
            "mixed_settings": len({item["settles_via_district"] for item in member_rows}) > 1
            or len({item["table_by_club"] for item in member_rows}) > 1,
        },
        "teams": [
            {**item, "charged": (per_team.get(item["team_id"]) or {}).get("charged", 0),
             "matches": (per_team.get(item["team_id"]) or {}).get("matches", 0),
             **({"club_name": member_name(item["club_id"])} if multi else {})}
            for item in sorted(teams, key=lambda item: item["name"])
        ],
        "charges": [_charge_json(row, key) for row in charges],
        # Przy budżecie z kilkoma numerami wpis mówi, na który numer go zapisano.
        "entries": [
            {**_entry_json(row), **({"club_name": member_name(_s(row["club_id"]))} if multi else {})}
            for row in entries
        ],
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
    where = and_(
        province_club_entries.c.id == entry_id,
        province_club_entries.c.province == key,
    )
    # `databases` na asyncpg oddaje z DELETE None (fetchval bez RETURNING), więc
    # wynik usunięcia nie mówi, czy wpis był - sprawdzamy przed usunięciem.
    if await database.fetch_one(select(province_club_entries.c.id).where(where)) is None:
        raise HTTPException(404, "Nie znaleziono takiego wpisu")
    await database.execute(delete(province_club_entries).where(where))
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


class BulkSettingsRequest(BaseModel):
    province: str
    club_ids: list[str] = []
    settles_via_district: bool = True
    settles_since: Optional[date] = None
    updated_by: Optional[str] = None


class BulkEntryRequest(BaseModel):
    province: str
    season: Optional[str] = None
    club_ids: list[str] = []
    kind: str = "in"                       # "in" = wpłata, "out" = wypłata
    amount: float = 0.0
    description: Optional[str] = None
    day: Optional[date] = None
    created_by: Optional[str] = None


def _bulk_ids(raw: list[str]) -> list[str]:
    try:
        return B.clean_club_ids(raw)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.put("/settings/bulk", summary="Akcja grupowa: rozliczanie przez okręg")
async def set_clubs_bulk(payload: BulkSettingsRequest):
    key = require_province(payload.province)
    club_ids = _bulk_ids(payload.club_ids)
    now = _now()
    settles = bool(payload.settles_via_district)
    since = B.settles_since(settles, payload.settles_since, now.date())

    # Nazwa i notatka klubu zostają - akcja grupowa rusza tylko rozliczanie.
    async with database.transaction():
        for club_id in club_ids:
            values = {
                "province": key,
                "club_id": club_id,
                "settles_via_district": settles,
                "settles_since": since,
                "updated_by": _s(payload.updated_by) or None,
                "updated_at": now,
            }
            statement = pg_insert(province_clubs).values(**values)
            await database.execute(
                statement.on_conflict_do_update(
                    index_elements=[province_clubs.c.province, province_clubs.c.club_id],
                    set_={k: v for k, v in values.items() if k not in ("province", "club_id")},
                )
            )
    return {"success": True, "updated": len(club_ids)}


class FourthBulkRequest(BaseModel):
    province: str
    club_ids: list[str] = []
    #: 1 = drugiego stolikowego klub stawia sam, 0 = obu wysyła okręg.
    table_by_club: int = 0
    table_by_club_since: Optional[date] = None
    updated_by: Optional[str] = None


@router.put("/fourth/bulk", summary="4. sędzia przez okręg - deklaracja stolikowego klubu")
async def set_fourth_bulk(payload: FourthBulkRequest):
    """
    Ta sama deklaracja co w Obsadzie (jedna tabela, jedno źródło prawdy), ale
    pod bramką PANELU KLUBÓW - tak jak „Rozlicza się przez okręg". Konto
    z uprawnieniem do Rozliczeń nie musi mieć uprawnienia do Obsady, żeby
    ustawić to, za kogo klub płaci.
    """
    from app.province_assignment_auto import write_club_rules

    key = require_province(payload.province)
    club_ids = _bulk_ids(payload.club_ids)
    updated = await write_club_rules(
        key,
        club_ids,
        table_by_club=payload.table_by_club,
        table_by_club_since=payload.table_by_club_since,
        updated_by=payload.updated_by,
    )
    return {"success": True, "updated": updated}


@router.post("/entries/bulk", summary="Akcja grupowa: ta sama wpłata albo wypłata dla wielu klubów")
async def add_entries_bulk(payload: BulkEntryRequest):
    key = require_province(payload.province)
    club_ids = _bulk_ids(payload.club_ids)
    amount = round(abs(float(payload.amount or 0)), 2)
    if amount <= 0:
        raise HTTPException(400, "Kwota musi być większa od zera")

    now = _now()
    season = _s(payload.season) or season_of(now)
    rows = [
        {
            "province": key,
            "club_id": club_id,
            "team_id": None,
            "team_name": None,
            "season": season,
            "kind": "out" if _s(payload.kind).lower().startswith("out") else "in",
            "amount": amount,
            "description": _s(payload.description) or None,
            "day": payload.day or now.date(),
            "source": "bulk",
            "created_by": _s(payload.created_by) or None,
            "created_at": now,
        }
        for club_id in club_ids
    ]
    # Wszystko albo nic: połowa klubów z opłatą i połowa bez to gorsze niż błąd.
    async with database.transaction():
        await database.execute_many(insert(province_club_entries), rows)
    return {"success": True, "saved": len(rows)}


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


class SeasonCloseRequest(BaseModel):
    province: str
    season: str
    #: Kluby do rozliczenia; bez listy - kazdy klub na minusie i kazdy z wpisem.
    club_ids: Optional[list[str]] = None
    #: Sam podglad do okna potwierdzenia: co by sie zmienilo, bez zapisu.
    dry_run: bool = False
    closed_by: Optional[str] = None


class SeasonReopenRequest(BaseModel):
    province: str
    season: str


def _closing_filter(key: str, season: str):
    return and_(
        province_club_entries.c.province == key,
        province_club_entries.c.season == season,
        province_club_entries.c.source == B.SEASON_CLOSE_SOURCE,
    )


@router.post("/season/close", summary="Rozlicz sezon - salda klubów do zera wpisem poza systemem")
async def close_season(payload: SeasonCloseRequest):
    """
    Sezon rozliczony poza aplikacja.

    Wstecz nie dopisujemy klubom wplat (decyzja z 11.09.2026), wiec bez tego
    kazdy klub minionego sezonu wisial na minusie. Rozliczenie dopisuje kazdemu
    wskazanemu klubowi JEDEN wpis „Rozliczenie sezonu ... poza systemem" na kwote
    dlugu; ponowne tylko ten wpis poprawia (`province_clubs_bulk.closing_amounts`).
    Mecze i obciazenia zostaja bez zmian. Cofniecie usuwa wpisy i znacznik.
    """
    key = require_province(payload.province)
    season = _s(payload.season)
    _, season_end = season_range(season)
    # Wspólny budżet rozliczamy RAZEM: dług budżetu, jeden wpis na klubie
    # głównym. Osobno numer na minusie dostałby wpis, choć budżet jest na plusie.
    owner = BR.member_map(await CB.budget_groups(key))
    selected = (
        {owner.get(club_id, club_id) for club_id in _bulk_ids(payload.club_ids)}
        if payload.club_ids
        else None
    )

    clubs = await CB.merged_clubs(key, (await _season_clubs(key, season))["clubs"])
    rows = await database.fetch_all(
        select(province_club_entries)
        .where(_closing_filter(key, season))
        .order_by(province_club_entries.c.id.asc())
    )
    existing: dict[str, list[dict]] = {}
    for row in rows:
        row_club = _s(row["club_id"])
        existing.setdefault(owner.get(row_club, row_club), []).append(dict(row))
    before = {
        club_id: round(sum(float(item["amount"] or 0) for item in items), 2)
        for club_id, items in existing.items()
    }
    # Saldo co do grosza - lista pokazuje je zaokraglone do zlotych.
    exact = {
        club_id: round(club["paid_in"] + club["settled"] - club["paid_out"] - club["charged"], 2)
        for club_id, club in clubs.items()
    }
    plan = B.closing_amounts(exact, before, selected)

    changes = sorted(
        (
            {
                "club_id": club_id,
                "name": (clubs.get(club_id) or {}).get("name") or club_id,
                "before": before.get(club_id, 0.0),
                "amount": amount,
                "change": round(amount - before.get(club_id, 0.0), 2),
            }
            for club_id, amount in plan.items()
            if abs(amount - before.get(club_id, 0.0)) >= 0.005 or len(existing.get(club_id, [])) > 1
        ),
        key=lambda item: (-item["change"], item["name"]),
    )
    summary = {
        "clubs": len(changes),
        "amount": round(sum(item["change"] for item in changes), 2),
        "changes": changes,
    }
    if payload.dry_run or not changes:
        return {"success": True, "saved": False, **summary}

    now = _now()
    day = B.closing_day(season_end, now.date())
    note = f"Rozliczenie sezonu {season} poza systemem"
    by = _s(payload.closed_by) or None
    async with database.transaction():
        for club_id, amount in plan.items():
            entries = existing.get(club_id, [])
            # Jeden wpis na klub i sezon: nadmiarowe znikaja, zostaje aktualna kwota.
            for extra in entries[1:]:
                await database.execute(
                    delete(province_club_entries).where(province_club_entries.c.id == extra["id"])
                )
            if amount <= 0:
                if entries:
                    await database.execute(
                        delete(province_club_entries).where(province_club_entries.c.id == entries[0]["id"])
                    )
                continue
            if not entries:
                await database.execute(
                    insert(province_club_entries).values(
                        province=key,
                        club_id=club_id,
                        team_id=None,
                        team_name=None,
                        season=season,
                        kind="in",
                        amount=amount,
                        description=note,
                        day=day,
                        source=B.SEASON_CLOSE_SOURCE,
                        created_by=by,
                        created_at=now,
                    )
                )
            elif abs(float(entries[0]["amount"] or 0) - amount) >= 0.005:
                await database.execute(
                    update(province_club_entries)
                    .where(province_club_entries.c.id == entries[0]["id"])
                    .values(amount=amount, day=day, description=note, created_by=by, created_at=now)
                )

        statement = pg_insert(province_club_season_closures).values(
            province=key, season=season, closed_at=now, closed_by=by
        )
        await database.execute(
            statement.on_conflict_do_update(
                index_elements=[
                    province_club_season_closures.c.province,
                    province_club_season_closures.c.season,
                ],
                set_={"closed_at": now, "closed_by": by},
            )
        )
    return {"success": True, "saved": True, **summary}


@router.post("/season/reopen", summary="Cofnij rozliczenie sezonu")
async def reopen_season(payload: SeasonReopenRequest):
    key = require_province(payload.province)
    season = _s(payload.season)
    season_range(season)
    existing = await database.fetch_all(
        select(province_club_entries.c.amount).where(_closing_filter(key, season))
    )
    async with database.transaction():
        await database.execute(delete(province_club_entries).where(_closing_filter(key, season)))
        await database.execute(
            delete(province_club_season_closures).where(
                and_(
                    province_club_season_closures.c.province == key,
                    province_club_season_closures.c.season == season,
                )
            )
        )
    return {
        "success": True,
        "removed": len(existing),
        "amount": round(sum(float(row["amount"] or 0) for row in existing), 2),
    }


# ---------------------------------------------------------------------------
# Excel
# ---------------------------------------------------------------------------

@router.get("/export/xlsx", summary="Szablon wpłat i wypłat")
async def export_xlsx(
    province: str = Query(...),
    season: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    gender: Optional[str] = Query(None),
    club_ids: Optional[str] = Query(
        None, description="Numery klubów po przecinku - szablon tylko dla zaznaczonych"
    ),
):
    key = require_province(province)
    season = _s(season) or season_of(_now())
    wanted = B.parse_club_filter(club_ids)
    # JEDEN WIERSZ = JEDEN KLUB (23.09.2026) - okręg rozlicza się z klubem,
    # nie z każdą drużyną osobno. Lista klubów i salda z tego samego miejsca co
    # panel, więc kolumny informacyjne zgadzają się z ekranem. Wspólny budżet
    # to jeden wiersz z numerem klubu głównego.
    clubs = await CB.merged_clubs(key, (await _season_clubs(key, season))["clubs"])

    rows = []
    for club in sorted(clubs.values(), key=lambda value: team_key(value["name"])):
        teams = club["teams"]
        if category and not any(team["category"] == category for team in teams):
            continue
        if gender and not any(team["gender"] == gender for team in teams):
            continue
        if wanted is not None and not (set(club.get("member_ids") or [club["club_id"]]) & wanted):
            continue
        # Bez zaznaczenia pomijamy kluby rozliczane poza okręgiem - okręg nie
        # przyjmuje od nich wpłat. Zaznaczony świadomie wchodzi zawsze.
        if wanted is None and not club["settles_via_district"]:
            continue
        categories = sorted({team["category"] for team in teams if team.get("category")})
        count = len(teams)
        word = "drużyna" if count == 1 else ("drużyny" if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14 else "drużyn")
        rows.append(
            {
                "club_id": club["club_id"],
                "club_name": club["name"],
                "teams_label": f"{count} {word}" + (f" · {', '.join(categories)}" if categories else ""),
                "charged": club["charged"],
                "paid_in": round(club["paid_in"] + club["settled"], 2),
                "balance": club["balance"],
            }
        )
    if not rows:
        raise HTTPException(404, "Dla tego sezonu i filtrów nie ma żadnych klubów")

    label = " ".join(x for x in [display(key), season, category or "", gender or ""] if x).strip()
    data = build_club_workbook(rows, title=f"Wpłaty i wypłaty klubów - {label}")
    suffix = ("_" + category if category else "") + ("_zaznaczone" if wanted else "")
    name = f"kluby_{key}_{season.replace('/', '_')}{suffix}.xlsx"
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
    # Szablon klubowy: dopasowanie po numerze klubu, a gdy ktoś go skasował -
    # po nazwie klubu (tej z panelu albo nazwie którejś z jego drużyn).
    # Numer członka wspólnego budżetu trafia do budżetu (klubu głównego).
    clubs = await CB.merged_clubs(key, (await _season_clubs(key, season))["clubs"])
    owner: dict[str, str] = {}
    club_by_key: dict[str, str] = {}
    for club in clubs.values():
        club_by_key.setdefault(team_key(club["name"]), club["club_id"])
        for member in club.get("members") or []:
            owner.setdefault(member["club_id"], club["club_id"])
            club_by_key.setdefault(team_key(member["name"]), club["club_id"])
        for team in club["teams"]:
            club_by_key.setdefault(team_key(team["name"]), club["club_id"])

    def duplicate(club_id: str, team_id: str, kind: str, amount: float, note: str) -> bool:
        for row in existing:
            row_club = _s(row["club_id"])
            if (
                owner.get(row_club, row_club) == club_id
                and _s(row["team_id"]) == team_id
                and _s(row["kind"]) == kind
                and abs(float(row["amount"] or 0) - amount) < 0.005
                and _s(row["description"]) == _s(note)
            ):
                return True
        return False

    items: list[dict] = []
    for row in parsed:
        by_team = bool(_s(row.get("team_id")) or _s(row.get("team_name")))
        if by_team:
            # Stary szablon z wierszem na drużynę - wpłata idzie do jej klubu.
            team = by_id.get(_s(row["team_id"])) or by_key.get(team_key(row["team_name"]))
            club_id = owner.get(team.club_id, team.club_id) if team else ""
            known = team is not None
        else:
            team = None
            wanted_id = _s(row.get("club_id"))
            club_id = owner.get(wanted_id) or club_by_key.get(team_key(row.get("club_name")), "")
            known = bool(club_id)
        base = {
            "row": row["row"],
            "team_id": team.team_id if team else "",
            "team_name": team.name if team else _s(row.get("team_name")),
            "club_id": club_id,
            "club_name": (
                (clubs.get(club_id) or {}).get("name") or _club_name(settings, meta, club_id)
                if club_id
                else _s(row["club_name"])
            ),
            "known": known,
            # Czym był wiersz w pliku - panel mówi „klubu nie ma" albo „drużyny nie ma".
            "by": "team" if by_team else "club",
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

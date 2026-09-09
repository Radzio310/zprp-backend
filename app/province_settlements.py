"""
Rozliczenia i statystyki okregowe - warstwa HTTP.

Caly rachunek robi `settlement_engine`; tutaj tylko czytamy fakty z bazy,
dobieramy tabele stawek i oddajemy wynik. Zaden endpoint nie liczy kwoty na
wlasna reke - inaczej po miesiacu bylyby trzy rachunki zamiast jednego.
"""

from __future__ import annotations

import calendar
import logging
from datetime import date, datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, select

from app import settlement_engine as E
from app import settlement_rates as R
from app.db import (
    central_rates,
    database,
    okreg_rates,
    province_judges,
    province_modules,
    province_settlement_matches,
)
from app.province_settlement_sync import (
    last_run,
    module_enabled,
    refresh_province,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province/settlements", tags=["province_settlements"])

MODULES = ("stats", "settlements")

#: Skroty tablic rejestracyjnych - czesc numeru dokumentu (SL/01/2026/1).
PROVINCE_SHORT: dict[str, str] = {
    "DOLNOSLASKIE": "DS",
    "KUJAWSKOPOMORSKIE": "KP",
    "LUBELSKIE": "LU",
    "LUBUSKIE": "LB",
    "LODZKIE": "LD",
    "MALOPOLSKIE": "MA",
    "MAZOWIECKIE": "MZ",
    "OPOLSKIE": "OP",
    "PODKARPACKIE": "PK",
    "PODLASKIE": "PD",
    "POMORSKIE": "PM",
    "SLASKIE": "SL",
    "SWIETOKRZYSKIE": "SW",
    "WARMINSKOMAZURSKIE": "WM",
    "WIELKOPOLSKIE": "WP",
    "ZACHODNIOPOMORSKIE": "ZP",
}


def province_short(province: str) -> str:
    return PROVINCE_SHORT.get(R.province_key(province), R.province_key(province)[:2] or "XX")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def month_range(year: int, month: int) -> tuple[date, date]:
    if not 1 <= month <= 12:
        raise HTTPException(400, "Miesiąc poza zakresem")
    last = calendar.monthrange(year, month)[1]
    return date(year, month, 1), date(year, month, last)


async def _versions(province: str) -> tuple[list[dict], list[dict]]:
    central_rows = await database.fetch_all(
        select(central_rates).order_by(central_rates.c.id.asc())
    )
    province_rows = await database.fetch_all(
        select(okreg_rates)
        .where(okreg_rates.c.province == province)
        .order_by(okreg_rates.c.id.asc())
    )
    return [dict(r) for r in central_rows], [dict(r) for r in province_rows]


async def _judge_names(province: str) -> dict[str, str]:
    rows = await database.fetch_all(
        select(province_judges.c.judge_id, province_judges.c.full_name)
        .where(province_judges.c.province == province)
    )
    return {str(r["judge_id"]): str(r["full_name"] or "") for r in rows}


async def _assignments(
    province: str,
    *,
    judge_ids: Optional[list[str]] = None,
) -> list[E.Assignment]:
    query = select(province_settlement_matches).where(
        and_(
            province_settlement_matches.c.province == province,
            province_settlement_matches.c.active.is_(True),
        )
    )
    if judge_ids:
        query = query.where(province_settlement_matches.c.judge_id.in_(judge_ids))
    # Zakres tniemy dopiero w silniku: mecz bez daty ma tam wlasna regule i
    # odsianie go tutaj zabraloby ja bezpowrotnie.
    rows = await database.fetch_all(query)

    out: list[E.Assignment] = []
    for row in rows:
        out.append(
            E.Assignment(
                match_key=str(row["match_key"]),
                judge_id=str(row["judge_id"]),
                match_at=row["match_at"],
                match_code=str(row["match_code"] or ""),
                role=str(row["role"] or R.ROLE_FIELD),
                origin=str(row["origin"] or "district"),
                city=str(row["city"] or ""),
                hall=str(row["hall"] or ""),
                home_city=str(row["home_city"] or ""),
                teams=str(row["teams"] or ""),
                round_text=row["round_text"],
                series_text=row["series_text"],
                distance_km=float(row["distance_km"]) if row["distance_km"] is not None else None,
                distance_source=row["distance_source"],
                approved=row["approved"],
            )
        )
    return out


async def load_settlement(
    province: str,
    *,
    year: int,
    month: int,
    include_future: bool = False,
    judge_ids: Optional[list[str]] = None,
) -> dict:
    """Jedno wejscie dla panelu, aplikacji i PDF-ow."""
    province = province.strip().upper()
    date_from, date_to = month_range(year, month)
    central_versions, province_versions = await _versions(province)
    names = await _judge_names(province)
    assignments = await _assignments(province, judge_ids=judge_ids)

    entries = E.settle_judges(
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

    return {
        "province": province,
        "period": {"year": year, "month": month, "from": date_from.isoformat(), "to": date_to.isoformat()},
        "include_future": include_future,
        "entries": entries,
        "totals": E.totals_of(entries),
        "travel": E.travel_rows(entries),
    }


# ---------------------------------------------------------------------------
# Serializacja
# ---------------------------------------------------------------------------

def _match_json(match: E.SettledMatch) -> dict:
    return {
        "match_key": match.match_key,
        "match_at": match.match_at.isoformat() if match.match_at else None,
        "day": match.day.isoformat() if match.day else None,
        "code": match.match_code,
        "category": match.category,
        "level": match.level,
        "role": match.role,
        "origin": match.origin,
        "city": match.city,
        "teams": match.teams,
        "distance_km": match.distance_km,
        "distance_source": match.distance_source,
        "km_rate": match.km_rate,
        "gross": match.gross,
        "travel": match.travel,
        "travel_shared": match.travel_shared,
        "future": match.future,
        "approved": match.approved,
        "stage": match.stage,
        "stage_guessed": match.stage_guessed,
        "status": match.status,
    }


def _entry_json(entry: E.JudgeSettlement, *, with_matches: bool) -> dict:
    payload = {
        "judge_id": entry.judge_id,
        "name": entry.judge_name,
        "matches": entry.match_count,
        "future": entry.future_count,
        "gross": entry.gross,
        "costs": entry.costs,
        "taxable": entry.taxable,
        "tax": entry.tax,
        "net": entry.net,
        "travel": entry.travel,
        "total": entry.total,
        "missing_distance": entry.missing_distance,
        "missing_rate": entry.missing_rate,
        "guessed_stage": entry.guessed_stage,
    }
    if with_matches:
        payload["rows"] = [_match_json(m) for m in entry.matches]
    return payload


def _travel_json(row: E.TravelRow) -> dict:
    return {
        "judge_id": row.judge_id,
        "name": row.judge_name,
        "day": row.day.isoformat() if row.day else None,
        "route": row.route,
        "one_way_km": row.one_way_km,
        "total_km": row.total_km,
        "rate": row.rate,
        "amount": row.amount,
    }


# ---------------------------------------------------------------------------
# Moduly (panel admina)
# ---------------------------------------------------------------------------

class ModuleToggleRequest(BaseModel):
    enabled: bool


@router.get("/modules", summary="Które okręgi mają włączone Statystyki i Rozliczenia")
async def list_modules():
    rows = await database.fetch_all(select(province_modules))
    out: dict[str, dict[str, bool]] = {}
    for row in rows:
        out.setdefault(str(row["province"]), {})[str(row["module"])] = bool(row["enabled"])
    return {"modules": MODULES, "provinces": out}


@router.put("/modules/{province}/{module}", summary="Włącz lub wyłącz moduł w okręgu")
async def set_module(province: str, module: str, payload: ModuleToggleRequest):
    if module not in MODULES:
        raise HTTPException(400, f"Nieznany moduł: {module}")
    key = province.strip().upper()
    if not key:
        raise HTTPException(400, "Brak województwa")

    from sqlalchemy.dialects.postgresql import insert as pg_insert

    statement = pg_insert(province_modules).values(
        province=key, module=module, enabled=payload.enabled
    )
    await database.execute(
        statement.on_conflict_do_update(
            index_elements=[province_modules.c.province, province_modules.c.module],
            set_={"enabled": payload.enabled},
        )
    )
    return {"province": key, "module": module, "enabled": payload.enabled}


# ---------------------------------------------------------------------------
# Odczyt
# ---------------------------------------------------------------------------

@router.get("/status", summary="Kiedy dane okręgu schodziły ostatni raz")
async def status(province: str = Query(...)):
    key = province.strip().upper()
    run = await last_run(key)
    return {
        "province": key,
        "stats_enabled": await module_enabled(key, "stats"),
        "settlements_enabled": await module_enabled(key, "settlements"),
        "last_run": {
            "kind": run.get("kind") if run else None,
            "started_at": run["started_at"].isoformat() if run and run.get("started_at") else None,
            "finished_at": run["finished_at"].isoformat() if run and run.get("finished_at") else None,
            "ok": run.get("ok") if run else None,
            "judges": run.get("judges") if run else None,
            "matches": run.get("matches") if run else None,
            "outside_matches": run.get("outside_matches") if run else None,
            "error": run.get("error") if run else None,
        } if run else None,
    }


@router.get("/summary", summary="Rozliczenie okręgu za miesiąc")
async def summary(
    province: str = Query(...),
    year: int = Query(...),
    month: int = Query(...),
    include_future: bool = Query(False),
):
    key = province.strip().upper()
    if not await module_enabled(key, "settlements"):
        raise HTTPException(403, "Moduł Rozliczeń nie jest włączony w tym okręgu")

    data = await load_settlement(key, year=year, month=month, include_future=include_future)
    return {
        "province": data["province"],
        "period": data["period"],
        "include_future": include_future,
        "totals": data["totals"],
        "entries": [_entry_json(e, with_matches=False) for e in data["entries"]],
        "document_number_hint": await next_document_number(key, year, month, "zestawienie", peek=True),
    }


@router.get("/judge/{judge_id}", summary="Rozliczenie jednego sędziego, z meczami")
async def judge_detail(
    judge_id: str,
    province: str = Query(...),
    year: int = Query(...),
    month: int = Query(...),
    include_future: bool = Query(False),
):
    key = province.strip().upper()
    data = await load_settlement(
        key, year=year, month=month, include_future=include_future, judge_ids=[judge_id]
    )
    entry = next((e for e in data["entries"] if e.judge_id == judge_id), None)
    if entry is None:
        names = await _judge_names(key)
        entry = E.JudgeSettlement(judge_id=judge_id, judge_name=names.get(judge_id, ""))
    return {
        "province": key,
        "period": data["period"],
        "include_future": include_future,
        "entry": _entry_json(entry, with_matches=True),
        "travel": [_travel_json(r) for r in E.travel_rows([entry])],
    }


@router.get("/travel", summary="Lista kosztów przejazdów za miesiąc")
async def travel(
    province: str = Query(...),
    year: int = Query(...),
    month: int = Query(...),
    include_future: bool = Query(False),
    judge_ids: Optional[str] = Query(None, description="Numery sędziów po przecinku"),
):
    key = province.strip().upper()
    ids = [x.strip() for x in (judge_ids or "").split(",") if x.strip()] or None
    data = await load_settlement(
        key, year=year, month=month, include_future=include_future, judge_ids=ids
    )
    rows = [_travel_json(r) for r in data["travel"]]
    return {
        "province": key,
        "period": data["period"],
        "rows": rows,
        "total": sum(r["amount"] for r in rows),
        "total_km": sum(r["total_km"] for r in rows),
    }


@router.get("/me", summary="Moje rozliczenie - dla aplikacji sędziego")
async def mine(
    province: str = Query(...),
    judge_id: str = Query(...),
    year: int = Query(...),
    month: int = Query(...),
    include_future: bool = Query(False),
):
    key = province.strip().upper()
    if not await module_enabled(key, "settlements"):
        raise HTTPException(403, "Moduł Rozliczeń nie jest włączony w tym okręgu")
    return await judge_detail(
        judge_id, province=key, year=year, month=month, include_future=include_future
    )


# ---------------------------------------------------------------------------
# Odswiezanie
# ---------------------------------------------------------------------------

class RefreshRequest(BaseModel):
    province: str
    username: Optional[str] = None
    password: Optional[str] = None
    with_outside: bool = True


@router.post("/refresh", summary="Wymuś odświeżenie danych okręgu")
async def refresh(payload: RefreshRequest):
    key = payload.province.strip().upper()
    if not (await module_enabled(key, "stats") or await module_enabled(key, "settlements")):
        raise HTTPException(403, "Żaden moduł okręgowy nie jest włączony")
    result = await refresh_province(
        key,
        username=payload.username,
        password=payload.password,
        kind="manual",
        with_outside=payload.with_outside,
    )
    if not result.get("ok"):
        raise HTTPException(502, result.get("error") or "Odświeżanie nie powiodło się")
    return result


# ---------------------------------------------------------------------------
# Numeracja dokumentow
# ---------------------------------------------------------------------------

async def next_document_number(
    province: str, year: int, month: int, kind: str, *, peek: bool = False
) -> str:
    """
    Kolejny numer w okregu, miesiacu i rodzaju dokumentu: `SL/01/2026/1`.

    `peek` podaje numer, ktory PADNIE - nie rezerwuje go. Rezerwacja nastepuje
    dopiero przy zapisie dokumentu, bo numer bez wydruku to dziura w ksiazce.
    """
    from app.db import province_settlement_documents

    row = await database.fetch_one(
        select(province_settlement_documents.c.seq)
        .where(
            and_(
                province_settlement_documents.c.province == province,
                province_settlement_documents.c.kind == kind,
                province_settlement_documents.c.period_year == year,
                province_settlement_documents.c.period_month == month,
            )
        )
        .order_by(province_settlement_documents.c.seq.desc())
        .limit(1)
    )
    seq = int(row["seq"]) + 1 if row else 1
    return f"{province_short(province)}/{month:02d}/{year}/{seq}"


# ---------------------------------------------------------------------------
# Statystyki sedziego (BEZ pieniedzy)
# ---------------------------------------------------------------------------
#
# Osobny router, bo to osobny modul i osobne uprawnienie. Kwot tu NIE MA i nie
# wolno ich tu dolozyc - sedzia oglada swoje obciazenie, nie swoj rachunek.

stats_router = APIRouter(prefix="/province/stats", tags=["province_stats"])


def _season_of(day: Optional[date]) -> str:
    if not day:
        return ""
    year = day.year if day.month >= 9 else day.year - 1
    return f"{year}/{year + 1}"


@stats_router.get("/me", summary="Moje statystyki - dla aplikacji sędziego")
async def my_stats(
    province: str = Query(...),
    judge_id: str = Query(...),
    season: Optional[str] = Query(None, description="np. 2026/2027; brak = wszystko"),
):
    key = province.strip().upper()
    if not await module_enabled(key, "stats"):
        raise HTTPException(403, "Moduł Statystyk nie jest włączony w tym okręgu")

    rows = await database.fetch_all(
        select(province_settlement_matches).where(
            and_(
                province_settlement_matches.c.province == key,
                province_settlement_matches.c.judge_id == judge_id,
                province_settlement_matches.c.active.is_(True),
            )
        )
    )

    now = _now()
    matches: list[dict] = []
    for row in rows:
        when = row["match_at"]
        day = when.date() if when else None
        season_label = _season_of(day)
        if season and season_label != season:
            continue
        code = str(row["match_code"] or "")
        matches.append({
            "match_key": str(row["match_key"]),
            "match_at": when.isoformat() if when else None,
            "day": day.isoformat() if day else None,
            "season": season_label,
            "code": code,
            "category": R.category_label(code),
            "level": R.match_level(code),
            "role": str(row["role"] or ""),
            "origin": str(row["origin"] or ""),
            "city": str(row["city"] or ""),
            "hall": str(row["hall"] or ""),
            "teams": str(row["teams"] or ""),
            "distance_km": float(row["distance_km"]) if row["distance_km"] is not None else None,
            "future": bool(when and when > now),
        })

    matches.sort(key=lambda m: m["match_at"] or "", reverse=True)

    seasons = sorted({m["season"] for m in matches if m["season"]}, reverse=True)
    played = [m for m in matches if not m["future"]]

    def tally(field: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for item in played:
            value = str(item.get(field) or "").strip()
            if value:
                out[value] = out.get(value, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))

    by_month: dict[str, int] = {}
    for item in played:
        if item["day"]:
            by_month[item["day"][:7]] = by_month.get(item["day"][:7], 0) + 1

    distances = [m["distance_km"] for m in played if m["distance_km"] is not None]

    return {
        "province": key,
        "judge_id": judge_id,
        "season": season,
        "seasons": seasons,
        "totals": {
            "matches": len(played),
            "future": sum(1 for m in matches if m["future"]),
            "district": sum(1 for m in played if m["origin"] == "district"),
            "outside": sum(1 for m in played if m["origin"] == "outside"),
            "km": round(sum(distances) * R.ROUND_TRIP, 1),
            "cities": len({m["city"] for m in played if m["city"]}),
            "halls": len({m["hall"] for m in played if m["hall"]}),
            "longest_km": max(distances) if distances else 0,
        },
        "by_category": tally("category"),
        "by_role": tally("role"),
        "by_level": tally("level"),
        "by_city": tally("city"),
        "by_month": dict(sorted(by_month.items())),
        "matches": matches,
    }

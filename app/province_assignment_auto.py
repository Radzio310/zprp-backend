"""
Modul obsadowego: zakladka Sedziowie i automat obsady.

Osobny prefiks (`/province/assignment`, w liczbie pojedynczej), bo lista meczow
(`/province/assignments`) ma trase `/{match_id}` - kazda nowa sciezka wpadalaby
tam jako numer meczu.

Co tu jest:
  - KATALOG SEDZIOW okregu z tym, czego ZPRP nie wie: odznaki, uprawnienia,
    miasto, krotkie statystyki, mikro-podglad niedyspozycji i ustawienia
    automatu (wymaga doswiadczonego partnera, preferowane dni, pary, przerwy,
    pary „nigdy razem"),
  - AUTOMAT: jeden przebieg to propozycje do PUSTYCH gniazd plus raport.
    Przebieg zapisujemy w `province_assignment_runs`, zeby dalo sie do niego
    wrocic, pobrac PDF i zobaczyc, co wlasciwie wtedy zaproponowal.

Automat NICZEGO nie zapisuje w ZPRP. Propozycje ida do panelu, czlowiek
decyduje, a zapis idzie ta sama jedyna droga, co dotad
(`/zprp/obsada/save` -> `apply_referee_assignment`).
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, delete, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import assignment_rules as A
from app import settlement_origin as SO
from app import settlement_rates as R
from app.assignment_auto import build_plan
from app.assignment_context import (
    build_context,
    distance_pairs,
    load_busy,
    load_roster,
    manual_match_ids,
    need_from_state,
)
from app.assignment_distances import fill_missing, load_book
from app.assignment_grades import backfill_grades
from app.assignment_people import fold
from app.assignment_report import build_report, plan_rows
from app.db import (
    badges as badges_table,
    database,
    province_assignment_runs,
    province_judge_blocks,
    province_judge_pairs,
    province_judge_pauses,
    province_judge_settings,
    province_match_manual,
    province_matches,
)
from app.match_market_rules import is_managed_by_province, state_dict
from app.province_assignments import _managed_prefixes, own_prefixes_of
from app.province_settlements import require_province
from app.settlement_province import display, spellings
from app.settlement_seasons import season_of

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province/assignment", tags=["province_assignments"])

#: Ile dni pokazuje mikro-podglad niedyspozycji przy sedzim.
PREVIEW_DAYS = 14
#: Ile dni do przodu liczy sie jako „nadchodzace" w krotkich statystykach.
UPCOMING_DAYS = 30
#: Zapora na jeden przebieg automatu - wiecej meczow naraz nikt i tak nie przejrzy.
MAX_MATCHES = 400

DAY_NAMES = ("poniedziałek", "wtorek", "środa", "czwartek", "piątek", "sobota", "niedziela")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value or "").strip()


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if value else None


def _day_start(day: date) -> datetime:
    return datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)


# ───────────────────────────── katalog sędziów ─────────────────────────────


async def _season_window() -> tuple[date, date]:
    """Sezon liczony tak samo, jak wszędzie indziej: od 1 września."""
    today = _now().date()
    start_year = today.year if today.month >= 9 else today.year - 1
    return date(start_year, 9, 1), today + timedelta(days=120)



async def _badge_look() -> dict[str, dict]:
    """
    Odznaki okregu razem z kolorem i ikona - tak, jak widzi je reszta panelu.

    Kolor i ikona siedza w `meta_json` definicji odznaki, a przy sedzim leza
    same NAZWY. Bez tej mapy zakladka Sedziowie rysowalaby szare pigulki,
    podczas gdy wszedzie indziej te same odznaki maja swoje barwy - a odznaka
    rozpoznawana po kolorze przestaje wtedy dzialac.

    ⚠ Klucz to nazwa bez ogonkow i wielkosci liter: „Mlodzi" i „Młodzi" to
    jedna odznaka.
    """
    out: dict[str, dict] = {}
    try:
        rows = await database.fetch_all(select(badges_table))
    except Exception:
        logger.exception("obsada: nie udało się pobrać definicji odznak")
        return out
    for row in rows:
        name = _s(row["name"])
        if not name:
            continue
        meta = state_dict(row["meta_json"])
        out[fold(name)] = {
            "name": name,
            "color": _s(meta.get("color")) or "",
            "icon": _s(meta.get("icon")) or "",
            "description": _s(meta.get("description")),
        }
    return out


@router.get("/judges", summary="Sędziowie okręgu z parametrami automatu")
async def judges(
    province: str = Query(...),
    q: Optional[str] = Query(None, description="Nazwisko albo miasto"),
):
    """
    Wszystko, co obsadowy chce zobaczyć przy nazwisku - w jednym pobraniu.

    Statystyki liczymy z migawki terminarza, a nie z rejestru obsad: rejestr zna
    tylko sędziów, których śledzi monitor, a terminarz zna wszystkich.
    """
    key = require_province(province)
    # Uprawnienia zbieraja sie przy okazji otwierania meczow, wiec przy pierwszym
    # wejsciu na te zakladke tabela bywa pusta i przy nazwiskach nie byloby liter.
    # Raz, kontem monitora - patrz `backfill_grades`.
    await backfill_grades(key)
    roster = await load_roster(key)
    look = await _badge_look()
    season_from, season_to = await _season_window()
    busy, _load = await load_busy(key, roster, date_from=season_from, date_to=season_to)

    today = _now().date()
    horizon = today + timedelta(days=UPCOMING_DAYS)
    preview_days = [today + timedelta(days=offset) for offset in range(PREVIEW_DAYS)]

    rows: list[dict] = []
    for judge_id, judge in roster.judges.items():
        entries = busy.get(judge_id, [])
        played = [item for item in entries if item.moment and item.moment.date() < today]
        upcoming = [
            item for item in entries if item.moment and today <= item.moment.date() <= horizon
        ]
        settings = roster.settings.get(judge_id, {})
        partner_id = roster.pairs.get(judge_id, "")
        partner = roster.judges.get(partner_id)
        rows.append(
            {
                "judge_id": judge_id,
                "name": judge.name,
                "city": judge.city,
                "badges": sorted(judge.badges),
                "letters": sorted(judge.letters),
                "league": judge.league,
                "central": judge.central,
                "young": judge.young,
                "table_specialist": judge.table_specialist,
                "delegate": judge.delegate,
                "needs_experienced": judge.needs_experienced,
                "preferred_days": sorted(judge.preferred_days),
                "note": _s(settings.get("note")),
                "partner": {"judge_id": partner_id, "name": partner.name if partner else ""}
                if partner_id
                else None,
                "blocked": sorted(
                    {
                        other
                        for one, other in roster.blocks
                        if one == judge_id and other in roster.judges
                    }
                ),
                "pauses": [
                    {"from": start.isoformat(), "to": end.isoformat()}
                    for start, end in sorted(roster.pauses.get(judge_id, []))
                ],
                "stats": {
                    "season": len(entries),
                    "played": len(played),
                    "upcoming": len(upcoming),
                    "next": min(
                        (item.moment.isoformat() for item in upcoming if item.moment),
                        default=None,
                    ),
                },
                # Mikro-podglad: ile minut dnia jest zajete. 1440 to caly dzien.
                "preview": [
                    {"day": day.isoformat(), "minutes": roster.busy_minutes(judge_id, day)}
                    for day in preview_days
                ],
            }
        )

    if q and q.strip():
        needle = fold(q)
        rows = [
            row
            for row in rows
            if needle in fold(row["name"]) or needle in fold(row["city"])
        ]

    rows.sort(key=lambda row: fold(row["name"]))
    return {
        "province": key,
        "display": display(key),
        "season": season_of(_now()),
        "judges": rows,
        "days": list(DAY_NAMES),
        # Kolor i ikona odznaki - raz na odpowiedź, nie przy każdym sędzim.
        "badge_look": look,
        "totals": {
            "judges": len(rows),
            "league": sum(1 for row in rows if row["league"]),
            "central": sum(1 for row in rows if row["central"]),
            "young": sum(1 for row in rows if row["young"]),
            "table": sum(1 for row in rows if row["table_specialist"]),
            "with_settings": sum(
                1 for row in rows if row["needs_experienced"] or row["preferred_days"]
            ),
        },
    }


class JudgeSettingsRequest(BaseModel):
    province: str
    full_name: Optional[str] = None
    needs_experienced: Optional[bool] = None
    preferred_days: Optional[list[int]] = None
    note: Optional[str] = None
    updated_by: Optional[str] = None


@router.put("/judges/{judge_id}", summary="Parametry sędziego dla automatu")
async def save_judge_settings(judge_id: str, payload: JudgeSettingsRequest):
    key = require_province(payload.province)
    days = sorted({int(day) for day in (payload.preferred_days or []) if 0 <= int(day) <= 6})
    values = {
        "province": key,
        "judge_id": _s(judge_id),
        "full_name": _s(payload.full_name) or None,
        "needs_experienced": bool(payload.needs_experienced),
        "preferred_days": days,
        "note": _s(payload.note) or None,
        "updated_by": _s(payload.updated_by) or None,
        "updated_at": _now(),
    }
    await database.execute(
        pg_insert(province_judge_settings)
        .values(**values)
        .on_conflict_do_update(
            index_elements=[
                province_judge_settings.c.province,
                province_judge_settings.c.judge_id,
            ],
            set_={column: values[column] for column in values if column not in ("province", "judge_id")},
        )
    )
    return {"success": True, "judge_id": _s(judge_id), "preferred_days": days}


class BlockRequest(BaseModel):
    province: str
    other_judge_id: str
    reason: Optional[str] = None
    created_by: Optional[str] = None


@router.post("/judges/{judge_id}/blocks", summary="Para, której nie stawiamy razem")
async def add_block(judge_id: str, payload: BlockRequest):
    key = require_province(payload.province)
    other = _s(payload.other_judge_id)
    if not other or other == _s(judge_id):
        raise HTTPException(400, "Wskaż drugiego sędziego")
    existing = await database.fetch_one(
        select(province_judge_blocks.c.id).where(
            and_(
                province_judge_blocks.c.province == key,
                province_judge_blocks.c.judge_id == _s(judge_id),
                province_judge_blocks.c.other_judge_id == other,
            )
        )
    )
    if existing is not None:
        return {"success": True, "id": int(existing["id"]), "already": True}
    new_id = await database.fetch_val(
        insert(province_judge_blocks)
        .values(
            province=key,
            judge_id=_s(judge_id),
            other_judge_id=other,
            reason=_s(payload.reason) or None,
            created_by=_s(payload.created_by) or None,
        )
        .returning(province_judge_blocks.c.id)
    )
    return {"success": True, "id": new_id}


@router.delete("/blocks/{block_id}", summary="Zdejmij wykluczenie pary")
async def drop_block(block_id: int, province: str = Query(...)):
    key = require_province(province)
    await database.execute(
        delete(province_judge_blocks).where(
            and_(
                province_judge_blocks.c.province == key,
                province_judge_blocks.c.id == int(block_id),
            )
        )
    )
    return {"success": True}


class PauseRequest(BaseModel):
    province: str
    date_from: date
    date_to: date
    reason: Optional[str] = None
    created_by: Optional[str] = None


@router.post("/judges/{judge_id}/pauses", summary="Przerwa sędziego")
async def add_pause(judge_id: str, payload: PauseRequest):
    key = require_province(payload.province)
    if payload.date_to < payload.date_from:
        raise HTTPException(400, "Koniec przerwy nie może być przed jej początkiem")
    new_id = await database.fetch_val(
        insert(province_judge_pauses)
        .values(
            province=key,
            judge_id=_s(judge_id),
            date_from=payload.date_from,
            date_to=payload.date_to,
            reason=_s(payload.reason) or None,
            created_by=_s(payload.created_by) or None,
        )
        .returning(province_judge_pauses.c.id)
    )
    await _prune_pauses(key)
    return {"success": True, "id": new_id}


@router.delete("/pauses/{pause_id}", summary="Zdejmij przerwę")
async def drop_pause(pause_id: int, province: str = Query(...)):
    key = require_province(province)
    await database.execute(
        delete(province_judge_pauses).where(
            and_(
                province_judge_pauses.c.province == key,
                province_judge_pauses.c.id == int(pause_id),
            )
        )
    )
    return {"success": True}


async def _prune_pauses(province: str) -> int:
    """
    Przerwy, ktore skonczyly sie ponad tydzien temu, znikaja.

    Decyzja uzytkownika: „zakres wiecej niz tydzien wstecz znika, bo po co nam".
    Sprzatamy przy okazji dopisywania - lista przerw nie zdazy urosnac.
    """
    cutoff = _now().date() - timedelta(days=7)
    return await database.execute(
        delete(province_judge_pauses).where(
            and_(
                province_judge_pauses.c.province == province,
                province_judge_pauses.c.date_to < cutoff,
            )
        )
    )


class PairRequest(BaseModel):
    province: str
    partner_id: str
    created_by: Optional[str] = None


@router.post("/judges/{judge_id}/pairs", summary="Para sędziowska okręgu")
async def set_pair(judge_id: str, payload: PairRequest):
    """
    Wlasna para okregu - rownorzedna z para z listy ZPRP.

    Para jest obustronna, wiec stara para OBU osob ustepuje miejsca nowej.
    Inaczej zostalby w bazie trojkat, w ktorym kazdy ma inne zdanie o tym,
    z kim sedziuje.
    """
    key = require_province(payload.province)
    partner = _s(payload.partner_id)
    if not partner or partner == _s(judge_id):
        raise HTTPException(400, "Wskaż drugiego sędziego")
    await database.execute(
        delete(province_judge_pairs).where(
            and_(
                province_judge_pairs.c.province == key,
                province_judge_pairs.c.source == "own",
                province_judge_pairs.c.judge_id.in_([_s(judge_id), partner]),
            )
        )
    )
    for one, other in ((_s(judge_id), partner), (partner, _s(judge_id))):
        await database.execute(
            insert(province_judge_pairs).values(
                province=key,
                judge_id=one,
                partner_id=other,
                source="own",
                created_by=_s(payload.created_by) or None,
            )
        )
    return {"success": True}


@router.delete("/judges/{judge_id}/pairs", summary="Rozwiąż parę")
async def drop_pair(judge_id: str, province: str = Query(...)):
    key = require_province(province)
    rows = await database.fetch_all(
        select(province_judge_pairs.c.partner_id).where(
            and_(
                province_judge_pairs.c.province == key,
                province_judge_pairs.c.source == "own",
                province_judge_pairs.c.judge_id == _s(judge_id),
            )
        )
    )
    partners = [_s(row["partner_id"]) for row in rows]
    await database.execute(
        delete(province_judge_pairs).where(
            and_(
                province_judge_pairs.c.province == key,
                province_judge_pairs.c.source == "own",
                province_judge_pairs.c.judge_id.in_([_s(judge_id), *partners] or [_s(judge_id)]),
            )
        )
    )
    return {"success": True}


class ManualRequest(BaseModel):
    province: str
    match_id: str
    manual: bool = True
    created_by: Optional[str] = None


@router.post("/manual", summary="Mecz układany ręcznie - automat go nie rusza")
async def set_manual(payload: ManualRequest):
    key = require_province(payload.province)
    if payload.manual:
        await database.execute(
            pg_insert(province_match_manual)
            .values(
                province=key,
                match_id=_s(payload.match_id),
                created_by=_s(payload.created_by) or None,
            )
            .on_conflict_do_nothing(
                index_elements=[
                    province_match_manual.c.province,
                    province_match_manual.c.match_id,
                ]
            )
        )
    else:
        await database.execute(
            delete(province_match_manual).where(
                and_(
                    province_match_manual.c.province == key,
                    province_match_manual.c.match_id == _s(payload.match_id),
                )
            )
        )
    return {"success": True, "manual": bool(payload.manual)}


# ───────────────────────────────── automat ─────────────────────────────────


class AutoRequest(BaseModel):
    province: str
    date_from: Optional[date] = None
    date_to: Optional[date] = None
    #: Puste = wszystkie rozgrywki obsadzane przez okręg.
    competition: Optional[str] = None
    #: Puste = wszystkie mecze z zakresu.
    match_ids: list[str] = []
    #: Puste = wszystkie puste gniazda; inaczej np. ["sekretarz", "czas"].
    slots: Optional[list[str]] = None
    #: Puste = cała lista okręgu.
    judge_ids: list[str] = []
    rounds: int = 2
    #: Dopytać Google o brakujące pary miast (tabela odległości ma pierwszeństwo).
    use_google: bool = True
    created_by: Optional[str] = None


async def _needs_for(payload: AutoRequest, key: str, roster) -> tuple[list, dict]:
    """Mecze z zakresu przełożone na „czego brakuje", plus co odpadło i czemu."""
    managed = await _managed_prefixes(key)
    own = await own_prefixes_of(key)
    manual = await manual_match_ids(key)
    wanted_ids = {_s(item) for item in payload.match_ids if _s(item)}

    start = payload.date_from or _now().date()
    end = payload.date_to or (start + timedelta(days=30))
    rows = await database.fetch_all(
        select(province_matches).where(
            and_(
                province_matches.c.province.in_(spellings(key)),
                province_matches.c.active.is_(True),
                province_matches.c.match_at >= _day_start(start),
                province_matches.c.match_at < _day_start(end + timedelta(days=1)),
            )
        )
    )

    skipped = {"manual": 0, "outside": 0, "complete": 0, "no_hall": 0}
    needs = []
    for row in rows:
        state = state_dict(row["state_json"])
        code = _s(state.get("RozgrywkiCode") or row["match_code"])
        match_id = _s(row["match_id"])
        if not code or R.is_test_competition(code):
            continue
        if not is_managed_by_province(code, managed) or SO.is_other_district(code, own):
            skipped["outside"] += 1
            continue
        if wanted_ids and match_id not in wanted_ids:
            continue
        if payload.competition and A.competition_key(code).upper() != payload.competition.strip().upper():
            continue
        if match_id in manual:
            skipped["manual"] += 1
            continue
        need = need_from_state(match_id, state, code, row["match_at"], roster, slots=payload.slots)
        if not need.field_needed and not need.table_needed:
            skipped["complete"] += 1
            continue
        if not need.host_city:
            # Bez miasta hali nie policzymy ani kilometrow, ani dojazdu. Mecz
            # zostaje na liscie obsadowego, ale automat go nie tyka - zgadywanie
            # trasy bylo by gorsze niz uczciwe „uzupelnij hale".
            skipped["no_hall"] += 1
            continue
        needs.append(need)

    needs.sort(key=lambda item: (item.day or date.max, item.moment or datetime.max, item.code))
    return needs[:MAX_MATCHES], skipped


@router.post("", summary="Automat obsady - propozycje do pustych gniazd")
async def run_auto(payload: AutoRequest):
    key = require_province(payload.province)
    start = payload.date_from or _now().date()
    end = payload.date_to or (start + timedelta(days=30))
    if end < start:
        raise HTTPException(400, "Koniec zakresu nie może być przed jego początkiem")

    # RAZ na okreg: uprawnienia do szczebli. Zbieraja sie przy okazji otwierania
    # meczow, wiec tuz po wdrozeniu tabela jest pusta - a bez liter automat nie
    # odrozni stolika ligowego od okregowego. Kolejne przebiegi mijaja to bez
    # kosztu, bo slad siedzi w `app_migrations`.
    grades = await backfill_grades(key)

    roster = await load_roster(key)
    if not roster.judges:
        raise HTTPException(400, "Okręg nie ma jeszcze listy sędziów")

    needs, skipped = await _needs_for(payload, key, roster)
    book = await load_book(key)
    distances = {"asked": 0, "saved": 0, "missing": 0}
    if needs and payload.use_google:
        distances = await fill_missing(book, distance_pairs(needs, roster))

    busy, load = await load_busy(key, roster, date_from=start, date_to=end)
    ctx = build_context(
        roster,
        book,
        busy=busy,
        load=load,
        only_judges=payload.judge_ids or None,
    )
    plan = build_plan(needs, ctx, rounds=max(1, min(3, int(payload.rounds or 2))))

    window = {"from": start.isoformat(), "to": end.isoformat()}
    report = build_report(
        plan, needs, judges=roster.judges, window=window, load_before=load
    )
    report["skipped"] = skipped
    report["distances"] = {**book.stats, **distances}
    report["grades"] = {
        "known": sum(1 for judge in roster.judges.values() if judge.letters),
        "total": len(roster.judges),
        **({"backfill": grades} if grades.get("ran") else {}),
    }

    rows = plan_rows(plan, needs)
    run_id = await database.fetch_val(
        insert(province_assignment_runs)
        .values(
            province=key,
            created_by=_s(payload.created_by) or None,
            date_from=start,
            date_to=end,
            params_json=payload.model_dump(mode="json"),
            plan_json=rows,
            report_json=report,
        )
        .returning(province_assignment_runs.c.id)
    )

    return {
        "success": True,
        "run_id": run_id,
        "province": key,
        "window": window,
        "plan": rows,
        "gaps": report["gaps_detail"],
        "report": report,
    }


@router.get("/runs", summary="Przebiegi automatu")
async def list_runs(province: str = Query(...), limit: int = Query(20, ge=1, le=100)):
    key = require_province(province)
    rows = await database.fetch_all(
        select(province_assignment_runs)
        .where(province_assignment_runs.c.province == key)
        .order_by(province_assignment_runs.c.id.desc())
        .limit(limit)
    )
    return {
        "province": key,
        "runs": [
            {
                "id": int(row["id"]),
                "created_at": _iso(row["created_at"]),
                "created_by": _s(row["created_by"]),
                "from": _iso(row["date_from"]),
                "to": _iso(row["date_to"]),
                "applied_at": _iso(row["applied_at"]),
                "applied_count": row["applied_count"],
                "totals": {
                    "filled": (state_dict(row["report_json"]) or {}).get("filled", 0),
                    "gaps": (state_dict(row["report_json"]) or {}).get("gaps", 0),
                    "matches": (state_dict(row["report_json"]) or {}).get("matches", 0),
                },
            }
            for row in rows
        ],
    }


async def _run_row(province: str, run_id: int):
    row = await database.fetch_one(
        select(province_assignment_runs).where(
            and_(
                province_assignment_runs.c.province == province,
                province_assignment_runs.c.id == int(run_id),
            )
        )
    )
    if row is None:
        raise HTTPException(404, "Nie znam takiego przebiegu automatu")
    return row


@router.get("/runs/{run_id}", summary="Jeden przebieg automatu")
async def run_detail(run_id: int, province: str = Query(...)):
    key = require_province(province)
    row = await _run_row(key, run_id)
    report = state_dict(row["report_json"]) or {}
    return {
        "id": int(row["id"]),
        "province": key,
        "created_at": _iso(row["created_at"]),
        "created_by": _s(row["created_by"]),
        "window": {"from": _iso(row["date_from"]), "to": _iso(row["date_to"])},
        "params": state_dict(row["params_json"]) or {},
        "plan": _plan_list(row["plan_json"]),
        "report": report,
        "gaps": report.get("gaps_detail") or [],
        "applied_at": _iso(row["applied_at"]),
        "applied_count": row["applied_count"],
    }


def _plan_list(value: Any) -> list:
    """⚠ Kolumna JSON bywa napisem - ta sama pułapka, co przy stanie meczu."""
    parsed = state_dict(value)
    if isinstance(parsed, list):
        return parsed
    if isinstance(value, list):
        return value
    import json

    if isinstance(value, str) and value.strip():
        try:
            loaded = json.loads(value)
            return loaded if isinstance(loaded, list) else []
        except ValueError:
            return []
    return []


class AppliedRequest(BaseModel):
    province: str
    count: int = 0


@router.post("/runs/{run_id}/applied", summary="Ślad publikacji przebiegu")
async def mark_applied(run_id: int, payload: AppliedRequest):
    """Ile propozycji z tego przebiegu faktycznie poszło do ZPRP."""
    key = require_province(payload.province)
    await _run_row(key, run_id)
    await database.execute(
        update(province_assignment_runs)
        .where(
            and_(
                province_assignment_runs.c.province == key,
                province_assignment_runs.c.id == int(run_id),
            )
        )
        .values(applied_at=_now(), applied_count=max(0, int(payload.count or 0)))
    )
    return {"success": True}


# ─────────────────────────────────── PDF ───────────────────────────────────


@router.post("/runs/{run_id}/pdf", summary="PDF: raport z przebiegu automatu")
async def run_pdf(run_id: int, province: str = Query(...)):
    """Ten sam papier firmowy, co zestawienia i przejazdy - jeden wygląd okręgu."""
    key = require_province(province)
    row = await _run_row(key, run_id)
    report = state_dict(row["report_json"]) or {}
    plan = _plan_list(row["plan_json"])

    # Import lokalny: PDF-y ciągną WeasyPrint i Pillow, a katalog sędziów nie ma
    # powodu budzić ich przy starcie aplikacji.
    from app.province_settlement_pdf import _org, _province_logo_b64, _render, _to_pdf

    org = _org(key)
    window_from = row["date_from"]
    window_to = row["date_to"]
    html = _render(
        "okreg_obsada_raport.html",
        {
            "logo": _province_logo_b64(key),
            "org_name": org["name"],
            "org_address": org["address"],
            "period_label": (
                f"{window_from.strftime('%d.%m.%Y')} - {window_to.strftime('%d.%m.%Y')}"
                if window_from and window_to
                else ""
            ),
            "generated_at": (row["created_at"] or _now()).strftime("%d.%m.%Y %H:%M"),
            "report": report,
            "plan": plan,
            "judges": report.get("judges") or [],
            "gaps": report.get("gaps_detail") or [],
            "competitions": report.get("competitions") or [],
            "travel": report.get("travel") or {},
            "balance": report.get("balance") or {},
            "run_id": int(row["id"]),
        },
    )
    result = _to_pdf(html, "obsada", f"obsada_{key.lower()}_{row['id']}.pdf")
    # `_to_pdf` zostawia plik w katalogu rozliczeń - ścieżka pobrania jest tam,
    # bo to ta sama, jednorazowa furtka na token.
    return {"success": True, **result}

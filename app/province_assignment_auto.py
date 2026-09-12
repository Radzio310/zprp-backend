"""
Moduł obsadowego: zakładka Sędziowie i automat obsady.

Osobny prefiks (`/province/assignment`, w liczbie pojedynczej), bo lista meczów
(`/province/assignments`) ma trasę `/{match_id}` - każda nowa ścieżka wpadałaby
tam jako numer meczu.

Co tu jest:
  - KATALOG SĘDZIÓW okręgu z tym, czego ZPRP nie wie: odznaki, uprawnienia,
    miasto, krótkie statystyki, mikro-podgląd niedyspozycji i ustawienia
    automatu (wymaga doświadczonego partnera, preferowane dni, pary, przerwy,
    pary „nigdy razem"),
  - AUTOMAT: jeden przebieg to propozycje do PUSTYCH gniazd plus raport.
    Przebieg zapisujemy w `province_assignment_runs`, żeby dało się do niego
    wrócić, pobrać PDF i zobaczyć, co właściwie wtedy zaproponował.

Automat NICZEGO nie zapisuje w ZPRP. Propozycje idą do panelu, człowiek
decyduje, a zapis idzie ta sama jedyna droga, co dotąd
(`/zprp/obsada/save` -> `apply_referee_assignment`).
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, delete, insert, or_, select, update
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
from app.assignment_report import build_report, plan_rows, slot_label
from app.db import (
    badges as badges_table,
    database,
    province_assignment_changes,
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

#: Ile dni pokazuje mikro-podgląd niedyspozycji przy sędzim.
PREVIEW_DAYS = 14
#: Ile dni do przodu liczy się jako „nadchodzące" w krótkich statystykach.
UPCOMING_DAYS = 30
#: Zapora na jeden przebieg automatu - więcej meczów naraz nikt i tak nie przejrzy.
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


def _window(start: date, end: date, undated: bool):
    """
    Warunek na termin meczu, z opcjonalnym miejscem dla meczów BEZ TERMINU.

    Mecz bez daty nie ma jak wpaść w zakres dat, a przeoczyć go najłatwiej -
    więc lista obsadowego pokazuje go zawsze. Automat to co innego: bez godziny
    nie sprawdzi niedyspozycji ani kolizji, więc bierze go dopiero na wyraźne
    życzenie (patrz `AutoRequest.include_undated`).
    """
    dated = and_(
        province_matches.c.match_at >= _day_start(start),
        province_matches.c.match_at < _day_start(end + timedelta(days=1)),
    )
    return or_(dated, province_matches.c.match_at.is_(None)) if undated else dated


# ───────────────────────────── katalog sędziów ─────────────────────────────


async def _season_window() -> tuple[date, date]:
    """Sezon liczony tak samo, jak wszędzie indziej: od 1 września."""
    today = _now().date()
    start_year = today.year if today.month >= 9 else today.year - 1
    return date(start_year, 9, 1), today + timedelta(days=120)



async def _badge_look() -> dict[str, dict]:
    """
    Odznaki okręgu razem z kolorem i ikona - tak, jak widzi je reszta panelu.

    Kolor i ikona siedzą w `meta_json` definicji odznaki, a przy sędzim leżą
    same NAZWY. Bez tej mapy zakładka Sędziowie rysowałaby szare pigułki,
    podczas gdy wszędzie indziej te same odznaki mają swoje barwy - a odznaka
    rozpoznawana po kolorze przestaje wtedy działać.

    ⚠ Klucz to nazwa bez ogonków i wielkości liter: „Młodzi" i „Młodzi" to
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
    # Uprawnienia zbierają się przy okazji otwierania meczów, więc przy pierwszym
    # wejściu na te zakładkę tabela bywa pusta i przy nazwiskach nie byłoby liter.
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
                # Mikro-podgląd: ile minut dnia jest zajęte. 1440 to cały dzień.
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
    Przerwy, które skończyły się ponad tydzień temu, znikają.

    Decyzja użytkownika: „zakres więcej niż tydzień wstecz znika, bo po co nam".
    Sprzątamy przy okazji dopisywania - lista przerw nie zdąży urosnąć.
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
    Własna para okręgu - równorzędna z para z listy ZPRP.

    Para jest obustronna, więc stara para OBU osób ustępuje miejsca nowej.
    Inaczej zostałby w bazie trójkąt, w którym każdy ma inne zdanie o tym,
    z kim sędziuje.
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
    #: Także mecze BEZ TERMINU. Domyślnie ich nie ruszamy - bez godziny nie da
    #: się sprawdzić ani niedyspozycji, ani kolizji z innym meczem tego dnia,
    #: więc automat stawia tam ludzi „w ciemno". Do próbnego przebiegu bywa
    #: jednak przydatne: widać, kto w ogóle wchodzi w rachubę.
    include_undated: bool = False
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
                _window(start, end, payload.include_undated),
            )
        )
    )

    skipped = {
        "manual": 0,
        "outside": 0,
        "complete": 0,
        "no_hall": 0,
        "undated": 0,
        # Mecze, których nie będzie: pauza drużyny albo wolny los.
        "bye": 0,
    }
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
        if A.is_bye(state):
            # Wiersz terminarza z pauzującą drużyną wygląda jak mecz, ale nikt
            # na niego nie pojedzie.
            skipped["bye"] += 1
            continue
        need = need_from_state(match_id, state, code, row["match_at"], roster, slots=payload.slots)
        if not need.field_needed and not need.table_needed:
            skipped["complete"] += 1
            continue
        if need.day is None and not payload.include_undated:
            skipped["undated"] += 1
            continue
        if not need.host_city:
            # Bez miasta hali nie policzymy ani kilometrów, ani dojazdu. Mecz
            # zostaje na liście obsadowego, ale automat go nie tyka - zgadywanie
            # trasy było by gorsze niż uczciwe „uzupełnij hale".
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

    # RAZ na okręg: uprawnienia do szczebli. Zbierają się przy okazji otwierania
    # meczów, więc tuż po wdrożeniu tabela jest pusta - a bez liter automat nie
    # odróżni stolika ligowego od okręgowego. Kolejne przebiegi mijają to bez
    # kosztu, bo ślad siedzi w `app_migrations`.
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
    changes = await database.fetch_all(
        select(province_assignment_changes)
        .where(
            and_(
                province_assignment_changes.c.province == key,
                province_assignment_changes.c.run_id == int(run_id),
            )
        )
        .order_by(province_assignment_changes.c.id)
    )
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
        # Co ten przebieg FAKTYCZNIE zmienił w bazie związku - z osobą, która
        # stała w gnieździe przedtem. To z tego żyje cofanie.
        "changes": [
            {
                "id": int(item["id"]),
                "match_id": _s(item["match_id"]),
                "code": _s(item["match_code"]),
                "slot": _s(item["slot"]),
                "slot_label": slot_label(item["slot"]),
                "judge_id": _s(item["judge_id"]),
                "judge_name": _s(item["judge_name"]),
                "before_id": _s(item["before_id"]),
                "before_name": _s(item["before_name"]),
                "at": _iso(item["created_at"]),
                "undone_at": _iso(item["undone_at"]),
                "undo_note": _s(item["undo_note"]),
            }
            for item in changes
        ],
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


# ──────────────────────── cofanie i optymalizacja ────────────────────────



def _still_ours(state: dict, slot: str, judge_id: str) -> bool:
    """
    Czy w tym gnieździe nadal stoi ten, kogo wpisał automat.

    Jeżeli nie - ktoś poprawił obsadę ręcznie i to gniazdo przestaje nas
    obchodzić: ani go nie cofamy, ani nie proponujemy tam nikogo innego.
    """
    person = A.slot_person(state, slot) or {}
    return _s(person.get("number")) == _s(judge_id)


@router.get("/runs/{run_id}/undo", summary="Plan cofnięcia przebiegu")
async def run_undo_plan(run_id: int, province: str = Query(...)):
    """
    Co trzeba wysłać do ZPRP, żeby cofnąć ten przebieg.

    Sam PLAN - niczego nie zapisuje. Gniazda, w których od przebiegu ktoś
    stanął ręcznie, wracają w `kept` i zostają nietknięte: automat nie kasuje
    cudzej poprawki tylko dlatego, że sam coś tam wcześniej wpisał.
    """
    key = require_province(province)
    await _run_row(key, run_id)
    from app.assignment_undo import undo_plan

    return await undo_plan(key, int(run_id))


class UndoneRequest(BaseModel):
    province: str
    change_ids: list[int] = []
    note: Optional[str] = None


@router.post("/runs/{run_id}/undone", summary="Ślad cofnięcia")
async def run_mark_undone(run_id: int, payload: UndoneRequest):
    """Które zmiany faktycznie udało się cofnąć. Wiersze zostają w historii."""
    key = require_province(payload.province)
    await _run_row(key, run_id)
    from app.assignment_undo import mark_undone

    count = await mark_undone(key, payload.change_ids, payload.note or "")
    return {"success": True, "undone": count}


class OptimizeRequest(BaseModel):
    province: str
    #: Pominąć gniazda, których ktoś tknął ręcznie po przebiegu.
    keep_manual: bool = True
    use_google: bool = True


@router.post("/runs/{run_id}/optimize", summary="Czy dziś da się ułożyć lepiej")
async def run_optimize(run_id: int, payload: OptimizeRequest):
    """
    Liczy obsadę tych samych meczów JESZCZE RAZ, na dzisiejszych danych.

    Od tamtego przebiegu mogło się zmienić wszystko, co automat bierze pod
    uwagę: doszły niedyspozycje i przerwy, uzupełniły się odległości, ktoś
    dołożył obsady ręcznie. Porównujemy więc obecny układ z nowym i mówimy,
    czy warto cokolwiek ruszać - remis nie jest powodem do przestawiania ludzi.

    Niczego nie zapisuje. Zmiany wykonuje panel, po zatwierdzeniu.
    """
    key = require_province(payload.province)
    row = await _run_row(key, run_id)

    changes = await database.fetch_all(
        select(province_assignment_changes).where(
            and_(
                province_assignment_changes.c.province == key,
                province_assignment_changes.c.run_id == int(run_id),
                province_assignment_changes.c.undone_at.is_(None),
            )
        )
    )
    if not changes:
        return {
            "run_id": int(run_id),
            "comparison": None,
            "reason": "ten przebieg nie zapisał jeszcze żadnej obsady",
        }

    match_ids = sorted({_s(item["match_id"]) for item in changes})
    touched = {(_s(item["match_id"]), _s(item["slot"])) for item in changes}

    roster = await load_roster(key)
    if not roster.judges:
        raise HTTPException(400, "Okręg nie ma jeszcze listy sędziów")

    rows = await database.fetch_all(
        select(province_matches).where(
            and_(
                province_matches.c.province.in_(spellings(key)),
                province_matches.c.match_id.in_(match_ids),
            )
        )
    )

    # Obecny układ TYCH gniazd - punkt odniesienia dla porównania.
    book = await load_book(key)
    before: list[dict] = []
    needs = []
    states: dict[str, dict] = {}
    for row_match in rows:
        state = state_dict(row_match["state_json"])
        match_id = _s(row_match["match_id"])
        code = _s(state.get("RozgrywkiCode") or row_match["match_code"])
        states[match_id] = state
        wanted = [slot for (mid, slot) in touched if mid == match_id]
        for slot in wanted:
            person = A.slot_person(state, slot) or {}
            judge_id = _s(person.get("number"))
            judge = roster.judges.get(judge_id)
            city = roster.city_of(judge_id, None) if judge else ""
            before.append(
                {
                    "match_id": match_id,
                    "slot": slot,
                    "code": code,
                    "judge_id": judge_id,
                    "name": _s(person.get("name")),
                    "km": book.km(city, _s(state.get("Hala_miasto"))) if judge else None,
                }
            )
        # Do ponownego ułożenia zwalniamy WYŁĄCZNIE gniazda z tego przebiegu -
        # reszta obsady meczu zostaje i liczy się przy regułach par.
        need = need_from_state(match_id, state, code, row_match["match_at"], roster, slots=wanted)
        if payload.keep_manual:
            # Gniazdo, w którym od przebiegu ktoś stanął ręcznie, nie jest już
            # nasze - zostawiamy je w spokoju.
            ours = {
                _s(item["slot"])
                for item in changes
                if _s(item["match_id"]) == match_id
                and _still_ours(state, _s(item["slot"]), _s(item["judge_id"]))
            }
            need.field_needed = [slot for slot in need.field_needed if slot in ours]
            need.table_needed = [slot for slot in need.table_needed if slot in ours]
        if need.field_needed or need.table_needed:
            needs.append(need)

    if not needs:
        return {
            "run_id": int(run_id),
            "comparison": None,
            "reason": "wszystkie gniazda z tego przebiegu zmienił już człowiek",
        }

    if payload.use_google:
        await fill_missing(book, distance_pairs(needs, roster))

    start = row["date_from"] or _now().date()
    end = row["date_to"] or (start + timedelta(days=30))
    busy, load = await load_busy(key, roster, date_from=start, date_to=end)
    ctx = build_context(roster, book, busy=busy, load=load)
    plan = build_plan(needs, ctx, rounds=2)

    after = [
        {
            "match_id": item.match_id,
            "slot": item.slot,
            "code": item.code,
            "judge_id": item.judge_id,
            "name": item.judge_name,
            "km": item.km,
            "reasons": item.reasons,
        }
        for item in plan.proposals
    ]

    from app.assignment_undo import compare

    comparison = compare(before, after)
    for move in comparison["moves"]:
        move["slot_label"] = slot_label(move.get("slot"))
    return {
        "run_id": int(run_id),
        "comparison": comparison,
        "gaps": [
            {
                "match_id": item.match_id,
                "code": item.code,
                "slot": item.slot,
                "slot_label": slot_label(item.slot),
                "reason": item.reason,
            }
            for item in plan.gaps
        ],
        "distances": book.stats,
    }


# ─────────────────────────── kluby w obsadzie ───────────────────────────


@router.get("/clubs", summary="Kluby okręgu i ich ustawienia obsadowe")
async def clubs(province: str = Query(...), q: Optional[str] = Query(None)):
    """
    Kluby z tego samego źródła, co panel klubów - ale z innymi ustawieniami.

    Tam rozmowa jest o pieniądzach, tutaj o tym, kogo klub stawia przy stoliku,
    gdy gra u siebie. Liczba drużyn i mecze u siebie są po to, żeby obsadowy
    wiedział, ile ta decyzja waży: klub z dwiema drużynami to co innego niż
    klub z dwunastoma.
    """
    from app.db import province_club_assignment, province_club_teams
    from app.province_clubs_scrape import team_key

    key = require_province(province)
    season = season_of(_now())

    teams = await database.fetch_all(
        select(
            province_club_teams.c.club_id,
            province_club_teams.c.team_name,
            province_club_teams.c.name_key,
            province_club_teams.c.category,
        ).where(
            and_(
                province_club_teams.c.province.in_(spellings(key)),
                province_club_teams.c.season == season,
            )
        )
    )
    rules = {
        _s(row["club_id"]): row
        for row in await database.fetch_all(
            select(province_club_assignment).where(
                province_club_assignment.c.province.in_(spellings(key))
            )
        )
    }

    # Ile meczów U SIEBIE ma każda drużyna w tym sezonie - stąd waga ustawienia.
    hosted: dict[str, int] = {}
    for row in await database.fetch_all(
        select(province_matches.c.state_json).where(
            and_(
                province_matches.c.province.in_(spellings(key)),
                province_matches.c.active.is_(True),
            )
        )
    ):
        host = _s(state_dict(row["state_json"]).get("ID_zespoly_gosp_ZespolNazwa"))
        if host:
            hosted[team_key(host)] = hosted.get(team_key(host), 0) + 1

    grouped: dict[str, dict] = {}
    for row in teams:
        club_id = _s(row["club_id"])
        if not club_id:
            continue
        name = _s(row["team_name"])
        entry = grouped.setdefault(
            club_id,
            {
                "club_id": club_id,
                "name": name,
                "teams": [],
                "matches_at_home": 0,
                "table_by_club": 0,
                "avoid_local": False,
                "note": "",
            },
        )
        entry["teams"].append({"name": name, "category": _s(row["category"])})
        entry["matches_at_home"] += hosted.get(_s(row["name_key"]) or team_key(name), 0)
        # Nazwa klubu: najkrótsza z nazw drużyn czyta się najbliżej nazwy klubu
        # („SPR Sośnica Gliwice" zamiast „SPR Sośnica Gliwice Młodziczki II").
        if name and len(name) < len(entry["name"]):
            entry["name"] = name

    for club_id, entry in grouped.items():
        rule = rules.get(club_id)
        if rule is None:
            continue
        entry["table_by_club"] = int(rule["table_by_club"] or 0)
        entry["avoid_local"] = bool(rule["avoid_local"])
        entry["note"] = _s(rule["note"])

    rows = sorted(grouped.values(), key=lambda item: fold(item["name"]))
    if q and q.strip():
        needle = fold(q)
        rows = [
            row
            for row in rows
            if needle in fold(row["name"])
            or any(needle in fold(team["name"]) for team in row["teams"])
        ]

    return {
        "province": key,
        "display": display(key),
        "season": season,
        "clubs": rows,
        "totals": {
            "clubs": len(rows),
            "with_own_table": sum(1 for row in rows if row["table_by_club"]),
            "avoid_local": sum(1 for row in rows if row["avoid_local"]),
        },
    }


class ClubRuleRequest(BaseModel):
    province: str
    #: Czy klub stawia JEDNEGO stolikowego z własnych ludzi (0 albo 1).
    #: Okręg daje zawsze co najmniej jednego, więc więcej niż jeden nie ma sensu.
    table_by_club: int = 0
    avoid_local: bool = False
    note: Optional[str] = None
    updated_by: Optional[str] = None


@router.put("/clubs/{club_id}", summary="Ustawienia obsadowe klubu")
async def save_club_rule(club_id: str, payload: ClubRuleRequest):
    from app.db import province_club_assignment

    key = require_province(payload.province)
    values = {
        "province": key,
        "club_id": _s(club_id),
        # ⚠ Najwyżej JEDEN od klubu: okręg nigdy nie zostawia stolika całkiem
        # klubowi - albo daje jednego, albo obu.
        "table_by_club": max(0, min(1, int(payload.table_by_club or 0))),
        "avoid_local": bool(payload.avoid_local),
        "note": _s(payload.note) or None,
        "updated_by": _s(payload.updated_by) or None,
        "updated_at": _now(),
    }
    await database.execute(
        pg_insert(province_club_assignment)
        .values(**values)
        .on_conflict_do_update(
            index_elements=[
                province_club_assignment.c.province,
                province_club_assignment.c.club_id,
            ],
            set_={
                column: values[column]
                for column in values
                if column not in ("province", "club_id")
            },
        )
    )
    return {"success": True, "club_id": _s(club_id), "table_by_club": values["table_by_club"]}


class ClubBulkRequest(BaseModel):
    province: str
    club_ids: list[str] = []
    #: Które ustawienie zmieniamy. Pominięte zostaje takie, jakie było -
    #: akcja grupowa nie ma prawa skasować niczego przy okazji.
    table_by_club: Optional[int] = None
    avoid_local: Optional[bool] = None
    updated_by: Optional[str] = None


@router.put("/clubs/bulk", summary="Akcja grupowa: to samo ustawienie dla wielu klubów")
async def save_clubs_bulk(payload: ClubBulkRequest):
    """
    Ta sama deklaracja dla zaznaczonych klubów.

    Zmieniamy WYŁĄCZNIE pola podane w żądaniu. Notatka i to drugie ustawienie
    zostają nietknięte - inaczej zaznaczenie dwudziestu klubów po to, żeby
    zapisać jedną rzecz, po cichu kasowałoby resztę.

    Numery klubów przechodzą przez tę samą bramkę, co akcje grupowe w panelu
    klubów (`clean_club_ids`): bez pustych, bez powtórzeń i z limitem.
    """
    from app.db import province_club_assignment
    from app.province_clubs_bulk import clean_club_ids

    key = require_province(payload.province)
    try:
        club_ids = clean_club_ids(payload.club_ids)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if payload.table_by_club is None and payload.avoid_local is None:
        raise HTTPException(400, "Nie wskazano, co zmienić")

    now = _now()
    patch: dict[str, Any] = {"updated_by": _s(payload.updated_by) or None, "updated_at": now}
    if payload.table_by_club is not None:
        # ⚠ Najwyżej jeden od klubu - okręg zawsze daje co najmniej jednego.
        patch["table_by_club"] = max(0, min(1, int(payload.table_by_club)))
    if payload.avoid_local is not None:
        patch["avoid_local"] = bool(payload.avoid_local)

    async with database.transaction():
        for club_id in club_ids:
            values = {"province": key, "club_id": club_id, **patch}
            await database.execute(
                pg_insert(province_club_assignment)
                .values(**values)
                .on_conflict_do_update(
                    index_elements=[
                        province_club_assignment.c.province,
                        province_club_assignment.c.club_id,
                    ],
                    # Do istniejącego wiersza wchodzi SAM `patch` - pola spoza
                    # niego zostają takie, jakie były.
                    set_=patch,
                )
            )
    return {"success": True, "updated": len(club_ids)}

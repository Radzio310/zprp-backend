"""
Obsada 2.0 (24.09.2026) - pary mentorskie, wspólny szkic kolejki, propozycja
Automatu dla jednego meczu, historia zapisów do ZPRP i gotowy stan panelu.

Ten sam prefiks i ta sama bramka zapisu, co reszta Obsady
(`/province/assignment`, `panel_write_gate(PANEL_ASSIGNMENTS)`): odczyty są
wolne, każdy zapis sprawdza konto VIP z uprawnieniem „Obsada".

Trasy:
  - `GET/PUT /mentor-pairs`   para mentorska przypisana PARZE sędziowskiej,
  - `GET/PUT /draft`          kolejka zmian wspólna dla wszystkich obsadowych
                              okręgu, z numerem wersji (`DRAFT_STALE`),
  - `POST /suggest`           „Obsadź automatycznie" jeden mecz - te same
                              reguły co Automat, bez zapisu i bez przebiegu,
  - `GET /zprp-history`       dziennik zapisów do ZPRP w partiach,
  - `GET /bootstrap`          cały sezon naraz z pamięci serwera (ETag, 304).

Reguły siedzą w liściach (`assignment_board_rules`, `assignment_board_cache`,
`assignment_auto`); tutaj baza i HTTP.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import and_, delete, func, insert, select, update

from app import assignment_board_cache as C
from app import assignment_board_rules as B
from app import assignment_rules as A
from app.assignment_auto import BusyMatch, build_plan
from app.assignment_people import pair_key
from app.db import (
    database,
    province_assignment_board_drafts,
    province_matches,
    province_mentor_pairs,
    province_zprp_write_journal,
)
from app.match_market_rules import state_dict
from app.province_panel_access import PANEL_ASSIGNMENTS
from app.province_panel_guard import panel_write_gate
from app.province_settlements import require_province
from app.settlement_province import spellings

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/province/assignment",
    tags=["province_assignments"],
    dependencies=[Depends(panel_write_gate(PANEL_ASSIGNMENTS, "Zapis w Obsadzie"))],
)

#: Ile sekund żyje „świat" propozycji jednego meczu (sędziowie, kalendarze,
#: odległości) - licznik wersji unieważnia go wcześniej przy każdym zapisie.
WORLD_TTL = 300
#: Okno równego podziału przy propozycji dla jednego meczu: tyle dni w każdą stronę.
SUGGEST_WINDOW_DAYS = 14
#: Budżet pytań do Google o brakujące odległości przy jednej propozycji.
SUGGEST_GOOGLE_BUDGET = 40
SUGGEST_GOOGLE_SECONDS = 3.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if value else None


def _stamp(value: Any) -> datetime:
    floor = datetime.min.replace(tzinfo=timezone.utc)
    if value is None:
        return floor
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


# ───────────────────────────── pary mentorskie ─────────────────────────────


async def _mentor_rows(key: str) -> dict[str, Any]:
    """
    Jeden wpis na parę sędziowską spod WSZYSTKICH pisowni okręgu.

    Wygrywa najświeższy `updated_at`, przy remisie wiersz pod kluczem
    kanonicznym - ta sama zasada, co `newest_rule_per_club`.
    """
    rows = await database.fetch_all(
        select(province_mentor_pairs).where(
            province_mentor_pairs.c.province.in_(spellings(key) or [key])
        )
    )
    out: dict[str, Any] = {}
    for row in rows:
        pair = _s(row["pair_key"])
        if not pair:
            continue
        rank = (_stamp(row["updated_at"]), _s(row["province"]) == key)
        best = out.get(pair)
        if best is None or rank > (_stamp(best["updated_at"]), _s(best["province"]) == key):
            out[pair] = row
    return out


async def mentor_pairs_payload(key: str) -> list[dict]:
    items = []
    for pair, row in sorted((await _mentor_rows(key)).items()):
        mentors = [_s(item) for item in B.load_list(row["mentor_ids"]) if _s(item)]
        if not mentors:
            continue
        items.append(
            {
                "pair_ids": [_s(row["judge_a"]), _s(row["judge_b"])],
                "mentor_ids": mentors,
                "updated_by": _s(row["updated_by"]) or None,
                "updated_at": _iso(row["updated_at"]),
            }
        )
    return items


@router.get("/mentor-pairs", summary="Pary mentorskie przypisane parom sędziowskim")
async def get_mentor_pairs(province: str = Query(...)):
    key = require_province(province)
    return {"items": await mentor_pairs_payload(key)}


class MentorPairRequest(BaseModel):
    province: str
    pair_ids: list[str] = []
    mentor_ids: list[str] = []
    updated_by: Optional[str] = None


@router.put("/mentor-pairs", summary="Przypisz albo zdejmij parę mentorską")
async def put_mentor_pair(payload: MentorPairRequest):
    """
    Para sędziowska ma najwyżej JEDNĄ parę mentorską - zapis ją nadpisuje,
    a puste `mentor_ids` ją zdejmuje. Klucz pary to posortowane numery.
    """
    key = require_province(payload.province)
    try:
        pair_ids = B.clean_pair_ids(payload.pair_ids)
        mentor_ids = B.clean_mentor_ids(payload.mentor_ids, pair_ids)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    pair = pair_key(*pair_ids)
    names = spellings(key) or [key]
    async with database.transaction():
        await database.execute(
            delete(province_mentor_pairs).where(
                and_(
                    province_mentor_pairs.c.province.in_(names),
                    province_mentor_pairs.c.pair_key == pair,
                )
            )
        )
        if mentor_ids:
            await database.execute(
                insert(province_mentor_pairs).values(
                    province=key,
                    pair_key=pair,
                    judge_a=pair_ids[0],
                    judge_b=pair_ids[1],
                    mentor_ids=B.dump(mentor_ids),
                    updated_by=_s(payload.updated_by) or None,
                    updated_at=_now(),
                )
            )
    C.bump(key)
    return {"success": True}


# ─────────────────────────────── szkic kolejki ───────────────────────────────


async def _draft_row(key: str):
    """Szkic okręgu - wiersz pod kluczem kanonicznym, a bez niego najnowszy."""
    rows = await database.fetch_all(
        select(province_assignment_board_drafts).where(
            province_assignment_board_drafts.c.province.in_(spellings(key) or [key])
        )
    )
    if not rows:
        return None
    return max(
        rows,
        key=lambda row: (_s(row["province"]) == key, int(row["rev"] or 0), _stamp(row["updated_at"])),
    )


def _draft_payload(row: Any) -> dict:
    if row is None:
        return {"rev": 0, "changes": [], "updated_by": None, "updated_at": None}
    return {
        "rev": int(row["rev"] or 0),
        "changes": B.load_list(row["changes"]),
        "updated_by": _s(row["updated_by"]) or None,
        "updated_at": _iso(row["updated_at"]),
    }


async def draft_payload(key: str) -> dict:
    return _draft_payload(await _draft_row(key))


@router.get("/draft", summary="Wspólny szkic kolejki zmian")
async def get_draft(province: str = Query(...)):
    key = require_province(province)
    return await draft_payload(key)


class DraftRequest(BaseModel):
    province: str
    base_rev: int = 0
    changes: list[Any] = []
    updated_by: Optional[str] = None


def _stale(row: Any) -> HTTPException:
    current = _draft_payload(row)
    return HTTPException(
        409,
        detail={
            "code": "DRAFT_STALE",
            "rev": current["rev"],
            "changes": current["changes"],
            "updated_by": current["updated_by"],
            "updated_at": current["updated_at"],
            "message": (
                "Kolejkę zmienił w międzyczasie ktoś inny - pobierz ją jeszcze raz "
                "i nanieś swoje zmiany na świeżą wersję."
            ),
        },
    )


@router.put("/draft", summary="Zapisz szkic kolejki (z numerem wersji)")
async def put_draft(payload: DraftRequest):
    """
    Zapis na wersji `base_rev`. Gdy ktoś zapisał w międzyczasie, odpowiedź to
    409 `DRAFT_STALE` z aktualną wersją i zmianami - nic nie ginie po cichu.

    Porównanie i podbicie wersji idą jednym `UPDATE … WHERE rev = base_rev`,
    więc dwa równoczesne zapisy na tej samej wersji nie przejdą oba.
    """
    key = require_province(payload.province)
    try:
        changes = B.clean_draft_changes(payload.changes)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    row = await _draft_row(key)
    current_rev = int(row["rev"] or 0) if row is not None else 0
    if B.draft_conflict(payload.base_rev, current_rev):
        raise _stale(row)

    body = B.dump(changes)
    who = _s(payload.updated_by) or None
    now = _now()
    new_rev: Optional[int]
    async with database.transaction():
        if row is not None and _s(row["province"]) == key:
            new_rev = await database.fetch_val(
                update(province_assignment_board_drafts)
                .where(
                    and_(
                        province_assignment_board_drafts.c.province == key,
                        province_assignment_board_drafts.c.rev == current_rev,
                    )
                )
                .values(rev=current_rev + 1, changes=body, updated_by=who, updated_at=now)
                .returning(province_assignment_board_drafts.c.rev)
            )
        else:
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            new_rev = await database.fetch_val(
                pg_insert(province_assignment_board_drafts)
                .values(province=key, rev=current_rev + 1, changes=body, updated_by=who, updated_at=now)
                .on_conflict_do_nothing(index_elements=[province_assignment_board_drafts.c.province])
                .returning(province_assignment_board_drafts.c.rev)
            )
            others = [name for name in (spellings(key) or []) if name != key]
            if new_rev is not None and others:
                # Szkic spod innej pisowni okręgu przeszedł pod klucz kanoniczny.
                await database.execute(
                    delete(province_assignment_board_drafts).where(
                        province_assignment_board_drafts.c.province.in_(others)
                    )
                )
    if new_rev is None:
        # Ktoś wszedł między odczyt a zapis.
        raise _stale(await _draft_row(key))
    return {"rev": int(new_rev)}


# ─────────────────────── propozycja dla jednego meczu ───────────────────────


class PendingChange(BaseModel):
    match_id: str
    slot: str
    judge_id: Optional[str] = ""


class SuggestRequest(BaseModel):
    province: str
    match_id: str
    slots: Optional[list[str]] = None
    pending: list[PendingChange] = []
    exclude_judge_ids: list[str] = []


async def _world(key: str):
    """Sędziowie, kalendarze, odległości i liczniki sezonu - z pamięci, gdy świeże."""
    hit = C.get(key, None, "world", ttl=WORLD_TTL)
    if hit is not None:
        return hit[2]
    from app.assignment_context import load_roster
    from app.assignment_distances import load_book
    from app.province_assignment_auto import season_field_counts

    built = C.version(key)
    roster = await load_roster(key)
    book = await load_book(key)
    season_field = await season_field_counts(key)
    world = (roster, book, season_field)
    C.put(key, None, "world", world, built_version=built)
    return world


def _apply_pending(state: dict, items: list[PendingChange], roster: Any) -> dict:
    """Stan meczu z naniesioną kolejką: gniazdo z sędzią albo puste („" = zdjęty)."""
    out = dict(state)
    for item in items:
        slot = B.normalize_slot(item.slot)
        if not slot:
            continue
        judge_id = _s(item.judge_id)
        judge = roster.judges.get(judge_id) if judge_id else None
        out[f"NrSedzia_{slot}"] = judge_id
        out[f"NrSedzia_{slot}_nazwisko"] = (judge.name if judge else "") if judge_id else ""
    return out


@router.post("/suggest", summary="Obsadź automatycznie jeden mecz - bez zapisu")
async def suggest(payload: SuggestRequest):
    """
    Propozycja Automatu dla JEDNEGO meczu: te same twarde reguły (aktywni,
    niedyspozycje, przerwy, kolizje dnia, pary wykluczone, młodzi, wymagania
    stolika) i te same punkty (kilometry, miejscowi, pary i pary mentorskie,
    równy podział). Zmiany z kolejki (`pending`) liczą się jak już zapisane -
    zajmują gniazda i ludzi. Niczego nie zapisuje i nie zakłada przebiegu.
    """
    from app.assignment_context import build_context, inactive_judges, load_busy, need_from_state
    from app.offtime_rules import match_moment

    key = require_province(payload.province)
    match_id = _s(payload.match_id)
    row = await database.fetch_one(
        select(province_matches).where(
            and_(
                province_matches.c.province.in_(spellings(key) or [key]),
                province_matches.c.match_id == match_id,
            )
        )
    )
    if row is None:
        raise HTTPException(404, "Nie znamy takiego meczu w terminarzu okręgu")

    roster, book, season_field = await _world(key)
    if not roster.judges:
        raise HTTPException(400, "Okręg nie ma jeszcze listy sędziów")

    state = state_dict(row["state_json"]) or {}
    code = _s(state.get("RozgrywkiCode") or row["match_code"])
    wanted_slots = (
        [slot for slot in (B.normalize_slot(item) for item in payload.slots) if slot]
        if payload.slots
        else None
    )

    def refuse_all(reason: str) -> dict:
        needs = A.club_crew_needs(code)
        slots = wanted_slots or [
            *A.FIELD_SLOTS[: needs["field"]],
            *A.TABLE_SLOTS[: needs["table"]],
        ]
        return {
            "match_id": match_id,
            "picks": [],
            "skipped": [{"slot": slot, "reason": reason} for slot in slots],
        }

    if A.is_bye(state):
        return refuse_all("pauza drużyny - tego meczu nie będzie")

    own = [item for item in payload.pending if _s(item.match_id) == match_id]
    patched = _apply_pending(state, own, roster)
    need = need_from_state(match_id, patched, code, row["match_at"], roster, slots=wanted_slots)
    if not need.field_needed and not need.table_needed:
        return {"match_id": match_id, "picks": [], "skipped": []}
    if not need.host_city:
        # Ta sama zasada, co w Automacie: bez miasta hali nie ma kilometrów
        # ani dojazdu - zgadywanie byłoby gorsze niż „uzupełnij halę".
        return {
            "match_id": match_id,
            "picks": [],
            "skipped": [
                {"slot": slot, "reason": "mecz bez hali - najpierw uzupełnij halę"}
                for slot in [*need.field_needed, *need.table_needed]
            ],
        }

    # Równy podział i kolizje: mecze sędziów w oknie wokół tego meczu.
    moment = match_moment(row["match_at"]) if row["match_at"] else None
    center = moment.date() if moment else _now().date()
    busy, load = await load_busy(
        key,
        roster,
        date_from=center - timedelta(days=SUGGEST_WINDOW_DAYS),
        date_to=center + timedelta(days=SUGGEST_WINDOW_DAYS),
    )
    busy = {judge_id: list(items) for judge_id, items in busy.items()}

    # Kolejka na INNYCH meczach: kto wchodzi, zajmuje termin; kto schodzi, zwalnia.
    others = [item for item in payload.pending if _s(item.match_id) and _s(item.match_id) != match_id]
    if others:
        other_rows = await database.fetch_all(
            select(
                province_matches.c.match_id,
                province_matches.c.match_at,
                province_matches.c.state_json,
            ).where(
                and_(
                    province_matches.c.province.in_(spellings(key) or [key]),
                    province_matches.c.match_id.in_(sorted({_s(item.match_id) for item in others})),
                )
            )
        )
        by_id = {_s(item["match_id"]): item for item in other_rows}
        for item in others:
            other = by_id.get(_s(item.match_id))
            slot = B.normalize_slot(item.slot)
            if other is None or not slot:
                continue
            other_state = state_dict(other["state_json"]) or {}
            before = _s((A.slot_person(other_state, slot) or {}).get("number"))
            if before:
                kept = [entry for entry in busy.get(before, []) if entry.match_id != _s(item.match_id)]
                if len(kept) != len(busy.get(before, [])):
                    busy[before] = kept
                    load[before] = max(0, int(load.get(before, 0)) - 1)
            judge_id = _s(item.judge_id)
            if judge_id:
                entries = busy.setdefault(judge_id, [])
                if not any(entry.match_id == _s(item.match_id) for entry in entries):
                    entries.append(
                        BusyMatch(
                            moment=match_moment(other["match_at"]) if other["match_at"] else None,
                            city=_s(other_state.get("Hala_miasto")),
                            match_id=_s(item.match_id),
                        )
                    )
                    load[judge_id] = int(load.get(judge_id, 0)) + 1

    # Brakujące odległości do tej hali - na krótkiej smyczy, bo panel czeka.
    try:
        from app.assignment_context import distance_pairs
        from app.assignment_distances import fill_missing

        await asyncio.wait_for(
            fill_missing(book, distance_pairs([need], roster), budget=SUGGEST_GOOGLE_BUDGET),
            timeout=SUGGEST_GOOGLE_SECONDS,
        )
    except Exception:  # noqa: BLE001 - brak odległości to kara punktowa, nie błąd
        logger.info("suggest %s/%s: odległości bez dopytania Google", key, match_id)

    inactive = inactive_judges(key, moment or _now(), roster)
    excluded = {_s(item) for item in payload.exclude_judge_ids if _s(item)}
    ctx = build_context(
        roster,
        book,
        busy=busy,
        load=load,
        inactive=set(inactive) | excluded,
        season_field=season_field,
    )
    plan = build_plan([need], ctx)

    return {
        "match_id": match_id,
        "picks": [
            {
                "slot": item.slot,
                "judge_id": item.judge_id,
                "name": item.judge_name,
                "reason": ", ".join(item.reasons),
                "km": item.km,
            }
            for item in plan.proposals
        ],
        "skipped": [{"slot": item.slot, "reason": item.reason} for item in plan.gaps],
    }


# ──────────────────────────── dziennik zapisów ZPRP ────────────────────────────


def _cursor(before: Optional[str]) -> tuple[Optional[int], Optional[datetime]]:
    """`before` to numer wpisu (z `next_before`) albo chwila partii (ISO)."""
    text = _s(before)
    if not text:
        return None, None
    if text.isdigit():
        return int(text), None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, "Parametr before to numer wpisu albo data ISO")
    return None, _stamp(moment)


@router.get("/zprp-history", summary="Dziennik zapisów do ZPRP w partiach")
async def zprp_history(
    province: str = Query(...),
    limit: int = Query(30, ge=1, le=200),
    before: Optional[str] = Query(None, description="next_before z poprzedniej strony albo data ISO"),
):
    key = require_province(province)
    table = province_zprp_write_journal
    names = spellings(key) or [key]
    before_id, before_at = _cursor(before)

    newest = func.max(table.c.id).label("newest")
    newest_at = func.max(table.c.created_at).label("newest_at")
    query = select(table.c.batch_id, newest, newest_at).where(table.c.province.in_(names)).group_by(
        table.c.batch_id
    )
    if before_id is not None:
        query = query.having(func.max(table.c.id) < before_id)
    if before_at is not None:
        query = query.having(func.max(table.c.created_at) < before_at)
    heads = await database.fetch_all(query.order_by(newest.desc()).limit(limit))
    if not heads:
        return {"batches": [], "next_before": None}

    batch_ids = [_s(item["batch_id"]) for item in heads]
    rows = await database.fetch_all(
        select(table)
        .where(and_(table.c.province.in_(names), table.c.batch_id.in_(batch_ids)))
        .order_by(table.c.id.desc())
    )
    order = {batch_id: index for index, batch_id in enumerate(batch_ids)}
    rows = sorted(rows, key=lambda row: (order.get(_s(row["batch_id"]), 0), -int(row["id"])))
    batches = B.group_batches(
        {
            "batch_id": _s(row["batch_id"]),
            "actor": _s(row["actor"]),
            "at": _iso(row["created_at"]),
            "item": {
                "id": int(row["id"]),
                "match_id": _s(row["match_id"]),
                "match_label": _s(row["match_label"]) or _s(row["match_code"]),
                "kind": _s(row["kind"]),
                "slot": _s(row["slot"]) or None,
                "before_id": _s(row["before_id"]) or None,
                "before_name": _s(row["before_name"]) or None,
                "after_id": _s(row["after_id"]) or None,
                "after_name": _s(row["after_name"]) or None,
                "hall_before": _s(row["hall_before"]) or None,
                "hall_after": _s(row["hall_after"]) or None,
                "reverted_of": row["reverted_of"],
                "run_id": row["run_id"],
            },
        }
        for row in rows
    )
    next_before = str(min(int(item["newest"]) for item in heads)) if len(heads) >= limit else None
    return {"batches": batches, "next_before": next_before}


# ─────────────────────────────── gotowy stan ───────────────────────────────


async def _build_bootstrap(key: str, season: int) -> dict:
    from app.province_assignment_auto import clubs as clubs_route
    from app.province_assignment_auto import judges as judges_route
    from app.province_assignments import match_list_payload

    listing = await match_list_payload(
        key,
        season=season,
        include_past=True,
        when="all",
        include_league=True,
        show_unknown=True,
        limit=None,
    )
    matches = listing.pop("matches", [])
    judges_payload = await judges_route(province=key, q=None)
    clubs_payload = await clubs_route(province=key, q=None)
    return {
        "matches": matches,
        # Reszta odpowiedzi listy (sezony, liczniki, rozgrywki) - bez meczów.
        "meta": listing,
        "judges": judges_payload,
        "clubs": clubs_payload,
        "mentor_pairs": await mentor_pairs_payload(key),
    }


def etag_matches(header: Optional[str], tag: str) -> bool:
    """`If-None-Match` może nieść kilka znaczników, także słabych (W/)."""
    if not header:
        return False
    wanted = tag.removeprefix("W/")
    return any(
        part.strip() == "*" or part.strip().removeprefix("W/") == wanted
        for part in header.split(",")
    )


def accepts_gzip(header: Optional[str]) -> bool:
    return "gzip" in (header or "").lower()


def _json_default(value: Any) -> Any:
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        return iso()
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    return str(value)


@router.get("/bootstrap", summary="Cały sezon Obsady naraz - z pamięci serwera")
async def bootstrap(
    request: Request,
    province: str = Query(...),
    season: Optional[int] = Query(None, description="Rok początku sezonu; domyślnie bieżący"),
):
    """
    Mecze całego sezonu (jak `/province/assignments`, bez limitu i z II ligą),
    sędziowie, kluby, pary mentorskie i szkic kolejki - jednym pobraniem.

    Serwer trzyma gotowy stan w pamięci i przebudowuje go po każdym zapisie
    (licznik wersji w `assignment_board_cache`) albo po `TTL`. Szkic kolejki
    jest zawsze świeży. `If-None-Match` ze zgodnym ETagiem -> 304.
    """
    from app import assignment_scope as S
    from app.zprp_seasons import season_catalog

    key = require_province(province)
    chosen = int(season) if season else S.current_start(await season_catalog(), _now().date())

    hit = C.get(key, chosen, "bootstrap")
    if hit is None:
        built = C.version(key)
        hit = C.put(key, chosen, "bootstrap", await _build_bootstrap(key, chosen), built_version=built)
    built_version, built_at, state = hit

    draft = await draft_payload(key)
    tag = C.etag(built_version, built_at, draft["rev"])
    headers = {"ETag": tag, "Cache-Control": "private, no-cache", "Vary": "Accept-Encoding"}
    if etag_matches(request.headers.get("if-none-match"), tag):
        return Response(status_code=304, headers=headers)

    body = json.dumps(
        {"etag": tag, "season": chosen, **state, "draft": draft},
        ensure_ascii=False,
        separators=(",", ":"),
        default=_json_default,
    ).encode("utf-8")
    if len(body) > 2048 and accepts_gzip(request.headers.get("accept-encoding")):
        return Response(
            content=gzip.compress(body, 5),
            media_type="application/json",
            headers={**headers, "Content-Encoding": "gzip"},
        )
    return Response(content=body, media_type="application/json", headers=headers)

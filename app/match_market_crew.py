# app/match_market_crew.py
#
# Oferty OBSADOWEGO na giełdzie meczów (25.10.2026).
#
# Obsadowy wystawia mecz z wybranymi gniazdami (domyślnie wolne gniazda, które
# okręg obsadza), sędziowie zgłaszają się na rolę (stolik / boisko), obsadowy
# przydziela. Przydział to wpis do WSPÓLNEGO szkicu kolejki Obsady
# (`province_assignment_board_drafts`, source="market") - dokładnie jak ręczny
# wpis w panelu. Do ZPRP nic stąd nie jedzie: robi to istniejący „Zapisz".
#
# Reguły siedzą w liściu `match_market_crew_rules`; tu baza, HTTP i push.
# Kontrakt: docs/gielda-oferty-obsadowego-api.md.

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, func, insert, select, update

from app import assignment_board_rules as B
from app import assignment_rules as A
from app import match_market_crew_rules as R
from app.db import (
    database,
    match_market_crew_claims as claims_t,
    match_market_crew_offers as offers_t,
    province_judges,
    province_matches,
)
from app.match_market import (
    Actor,
    _config,
    _market_province,
    _match_view,
    _require_approver,
    _require_enabled,
    _spawn_background,
    market_actor,
)
from app.match_market_access import may_approve
from app.match_market_rules import slots_held_by, state_dict
from app.settlement_province import spellings

logger = logging.getLogger("app.match_market_crew")

router = APIRouter(prefix="/match-market/crew-offers", tags=["Giełda: oferty obsadowego"])

#: Ile dni wstecz widzi lista zamkniętych ofert.
HISTORY_DAYS = 30
DRAFT_RETRIES = 4


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _row(row: Any) -> Dict[str, Any]:
    return dict(row._mapping) if hasattr(row, "_mapping") else dict(row or {})


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else None


def _utc(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _jl(value: Any, default: Any) -> Any:
    if isinstance(value, (list, dict)):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return json.loads(value)
        except ValueError:
            return default
    return default


# ───────────────────────────── odczyt oferty ─────────────────────────────


def _offer_dict(row: Any) -> Dict[str, Any]:
    data = _row(row)
    data["slots"] = R.normalize_slots(_jl(data.get("slots"), []))
    data["badge_filter"] = R.parse_filter(
        {"mode": data.get("badge_mode"), "badges": _jl(data.get("badges"), [])}
        if _s(data.get("badge_mode")) not in ("", "none")
        else None
    )
    data["match_snapshot"] = state_dict(data.get("match_snapshot"))
    return data


async def _load_offer(offer_id: int) -> Dict[str, Any]:
    row = await database.fetch_one(select(offers_t).where(offers_t.c.id == offer_id))
    if row is None:
        raise HTTPException(404, "Nie ma takiej oferty. Mogła zostać usunięta.")
    return _offer_dict(row)


async def _claims_of(offer_id: int) -> List[Dict[str, Any]]:
    rows = await database.fetch_all(
        select(claims_t).where(claims_t.c.offer_id == offer_id).order_by(claims_t.c.created_at, claims_t.c.id)
    )
    return [_row(r) for r in rows]


def _active(claims: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [c for c in claims if _s(c.get("status")) in R.ACTIVE_CLAIMS]


def _assigned(claims: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {_s(c["slot"]): c for c in claims if _s(c.get("status")) == R.ASSIGNED and _s(c.get("slot"))}


async def _judge_cards(ids: List[str]) -> Dict[str, Dict[str, Any]]:
    ids = sorted({_s(i) for i in ids if _s(i)})
    if not ids:
        return {}
    rows = await database.fetch_all(
        select(
            province_judges.c.judge_id,
            province_judges.c.full_name,
            province_judges.c.photo_url,
            province_judges.c.badges,
            province_judges.c.province,
        ).where(province_judges.c.judge_id.in_(ids))
    )
    return {_s(_row(r)["judge_id"]): _row(r) for r in rows}


def _person(judge_id: str, cards: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    card = cards.get(_s(judge_id)) or {}
    return {
        "id": _s(judge_id),
        "name": _s(card.get("full_name")),
        "photoUrl": _s(card.get("photo_url")) or None,
    }


async def _sweep(province: str) -> None:
    """Leniwe wygaszanie: po terminie bez zgłoszeń albo po rozpoczęciu meczu."""
    now = _now()
    rows = await database.fetch_all(
        select(offers_t).where(and_(offers_t.c.province == province, offers_t.c.status == R.OPEN))
    )
    for raw in rows:
        offer = _row(raw)
        deadline, match_at = _utc(offer.get("deadline_at")), _utc(offer.get("match_at"))
        if (deadline is None or now < deadline) and (match_at is None or now < match_at):
            continue
        count = await database.fetch_val(
            select(func.count())
            .select_from(claims_t)
            .where(and_(claims_t.c.offer_id == offer["id"], claims_t.c.status.in_(list(R.ACTIVE_CLAIMS))))
        )
        if R.effective_status(R.OPEN, deadline, match_at, int(count or 0), now) == R.EXPIRED:
            await database.execute(
                update(offers_t)
                .where(and_(offers_t.c.id == offer["id"], offers_t.c.status == R.OPEN))
                .values(status=R.EXPIRED, closed_reason="expired", closed_at=now)
            )


# ───────────────────────────── kontekst meczu ─────────────────────────────


async def _match_context(key: str, match_id: str) -> Dict[str, Any]:
    from app.assignment_access_data import own_teams, resolve_access
    from app.assignment_context import _club_rules
    from app.province_assignments import _host_table_by_club, _managed_prefixes, own_prefixes_of

    row = await database.fetch_one(
        select(province_matches).where(
            and_(
                province_matches.c.province.in_(spellings(key) or [key]),
                province_matches.c.match_id == _s(match_id),
                province_matches.c.active.is_(True),
            )
        )
    )
    if row is None:
        raise HTTPException(404, "Nie ma takiego meczu w terminarzu okręgu.")
    state = state_dict(row["state_json"])
    code = _s(state.get("RozgrywkiCode") or row["match_code"])
    access = resolve_access(
        state, code, await own_teams(key), season=_s(row["season"]),
        managed=await _managed_prefixes(key), own=await own_prefixes_of(key), province=key,
    )
    clubs = await _club_rules(key)
    tbc = _host_table_by_club({**state, "assignment_access": access}, clubs, row["match_at"])
    needs = A.club_crew_needs(code, tbc)
    return {"row": row, "state": state, "code": code, "access": access, "needs": needs, "crew": A.crew(state)}


# ───────────────────────────── wspólny szkic Obsady ─────────────────────────────


async def _draft_edit(key: str, edit, who: str) -> None:
    """Zmiana szkicu kolejki na wersji, którą widzieliśmy; przy cudzym zapisie ponawia."""
    from app.province_assignment_board import DraftRequest, _draft_row, put_draft

    last: Optional[HTTPException] = None
    for _ in range(DRAFT_RETRIES):
        row = await _draft_row(key)
        rev = int(row["rev"] or 0) if row is not None else 0
        changes = B.load_list(row["changes"]) if row is not None else []
        new = edit(list(changes))
        if new is None:
            return
        try:
            await put_draft(DraftRequest(province=key, base_rev=rev, changes=new, updated_by=who))
            return
        except HTTPException as exc:
            if exc.status_code != 409:
                raise
            last = exc
    raise HTTPException(
        409,
        "Kolejkę Obsady zmieniają teraz inne osoby i nie udało się dopisać przydziału. Spróbuj jeszcze raz za chwilę.",
    ) from last


def _market_change_id(claim_id: Any) -> str:
    return f"market-{claim_id}"


# ───────────────────────────── push ─────────────────────────────


def _push_data(offer: Dict[str, Any]) -> Dict[str, str]:
    oid = _s(offer.get("id"))
    return {
        "kind": "match_market_crew",
        "crewOfferId": oid,
        "province": _s(offer.get("province")),
        "matchId": _s(offer.get("match_id")),
        "matchNumber": _s(offer.get("match_code")),
        "notificationThread": f"match-market-crew-{oid}",
    }


async def _push(judge_ids: List[str], text: tuple, offer: Dict[str, Any], *, broadcast: bool = False) -> None:
    targets = sorted({_s(j) for j in judge_ids if _s(j)})
    if not targets:
        return
    try:
        from app.push.push import send_push_to_judges_report

        await send_push_to_judges_report(
            targets, text[0], text[1], _push_data(offer), app_variant="baza", market_broadcast=broadcast
        )
    except Exception:  # noqa: BLE001 - powiadomienie nie wywraca operacji
        logger.warning("giełda obsadowego: powiadomienie nieudane", exc_info=True)


async def _eligible_recipients(offer: Dict[str, Any]) -> List[str]:
    """Wszyscy uprawnieni sędziowie okręgu: filtr odznak + rola pasująca do slotów."""
    from app.province_assignment_board import _world

    key = offer["province"]
    roles = R.roles_of(offer["slots"])
    rows = await database.fetch_all(
        select(province_judges.c.judge_id, province_judges.c.full_name, province_judges.c.badges).where(
            province_judges.c.province.in_(spellings(key) or [key])
        )
    )
    try:
        roster = (await _world(key)).roster
    except Exception:  # noqa: BLE001
        roster = None
    out: List[str] = []
    for raw in rows:
        card = _row(raw)
        jid = _s(card["judge_id"])
        if not jid or jid == _s(offer.get("created_by")):
            continue
        if not R.passes_filter(card.get("badges"), offer["badge_filter"]):
            continue
        if slots_held_by(offer["match_snapshot"], jid, card.get("full_name")):
            continue
        if _my_roles(roster, jid, roles):
            out.append(jid)
    return out


def _my_roles(roster: Any, judge_id: str, offer_roles: List[str]) -> List[str]:
    """Role z oferty, na które sędzia może stanąć (reguły ról obsady)."""
    judge = getattr(roster, "judges", {}).get(judge_id) if roster is not None else None
    if judge is None:
        return list(offer_roles)
    from app.assignment_people import role_refusal

    return [role for role in offer_roles if role_refusal(judge, role) is None]


async def _announce_new(offer_id: int) -> None:
    offer = await _load_offer(offer_id)
    await _push(await _eligible_recipients(offer), R.text_new_offer(offer, offer["slots"]), offer, broadcast=True)


# ───────────────────────────── widoki ─────────────────────────────


def _slot_views(offer: Dict[str, Any], claims: List[Dict[str, Any]], cards: Dict[str, Dict[str, Any]]) -> list:
    held = _assigned(claims)
    out = []
    for slot in offer["slots"]:
        claim = held.get(slot)
        out.append(
            {
                "slot": slot,
                "label": R.SLOT_LABELS[slot],
                "role": R.role_of_slot(slot),
                "assignedTo": _person(claim["judge_id"], cards) if claim else None,
                "claimId": claim["id"] if claim else None,
            }
        )
    return out


def _offer_view(
    offer: Dict[str, Any],
    claims: List[Dict[str, Any]],
    cards: Dict[str, Dict[str, Any]],
    *,
    viewer_id: str,
    can_manage: bool,
    my_roles: List[str],
    now: datetime,
) -> Dict[str, Any]:
    roles = R.roles_of(offer["slots"])
    status = R.effective_status(
        offer["status"], offer.get("deadline_at"), offer.get("match_at"), len(_active(claims)), now
    )
    accepting = R.accepting_claims(status, offer.get("deadline_at"), now)
    mine = next((c for c in claims if _s(c["judge_id"]) == viewer_id and _s(c["status"]) != R.CLAIM_WITHDRAWN), None)
    pk = R.packages(claims)
    my_claim = None
    if mine:
        my_claim = {
            "id": mine["id"],
            "role": mine["role"],
            "partner": _person(mine["partner_id"], cards) if _s(mine.get("partner_id")) else None,
            "packageComplete": any(viewer_id in p["judge_ids"] for p in pk),
            "status": mine["status"],
            "slot": mine.get("slot"),
            "note": mine.get("note"),
        }
    creator = _person(offer["created_by"], cards)
    return {
        "id": offer["id"],
        "type": "crew",
        "isNew": status == R.OPEN and accepting,
        "highlight": "new_match" if status == R.OPEN and accepting else None,
        "province": offer["province"],
        "matchId": offer["match_id"],
        "matchCode": offer.get("match_code"),
        "match": _match_view(offer["match_snapshot"], offer.get("match_at")),
        "slots": _slot_views(offer, claims, cards),
        "roles": roles,
        "needsRoleChoice": len(roles) == 2,
        "comment": offer.get("comment") or "",
        "badgeFilter": offer["badge_filter"],
        "deadlineAt": _iso(offer.get("deadline_at")),
        "acceptingClaims": accepting,
        "status": status,
        "closedReason": offer.get("closed_reason") if status != R.OPEN else None,
        "createdBy": creator,
        "createdAt": _iso(offer.get("created_at")),
        "claimCount": len(_active(claims)),
        "myRoles": my_roles,
        "myClaim": my_claim,
        "canManage": can_manage,
    }


async def _viewer(actor: Actor, province: str):
    cfg = await _config(province)
    allowed = cfg["approver_badges"]
    can_manage = may_approve(
        is_admin=actor.is_admin, province=province, judge_province=actor.province,
        badges_raw=actor.badges, allowed_badges=allowed,
    )
    return cfg, can_manage


async def _roster_for(key: str):
    try:
        from app.province_assignment_board import _world

        return (await _world(key)).roster
    except Exception:  # noqa: BLE001
        logger.warning("giełda obsadowego: brak listy sędziów obsady", exc_info=True)
        return None


def _visibility_refusal(actor: Actor, offer: Dict[str, Any], can_manage: bool, my_roles: List[str]) -> Optional[str]:
    if can_manage:
        return None
    if actor.province != offer["province"]:
        return "Ta oferta jest z innego okręgu."
    if not R.passes_filter(actor.badges, offer["badge_filter"]):
        return "Ta oferta jest ograniczona odznakami i nie jest skierowana do Ciebie. " + R.filter_sentence(offer["badge_filter"])
    if not my_roles:
        return "Ta oferta szuka ról, na które reguły obsady Ci nie pozwalają (np. delegat nie staje na boisku)."
    return None


# ───────────────────────────── podpowiedź ─────────────────────────────


@router.get("/suggest", summary="Domyślne gniazda do wystawienia - wolne, które obsadza okręg")
async def suggest(
    matchId: str = Query(...),
    province: Optional[str] = Query(None),
    actor: Actor = Depends(market_actor),
) -> Dict[str, Any]:
    key = _market_province(actor, province)
    await _require_enabled(key)
    await _require_approver(actor, key)
    ctx = await _match_context(key, matchId)
    access = ctx["access"]
    editable = [s for s in access["editable_slots"] if s in R.CREW_SLOTS]
    result = R.suggest_slots(ctx["crew"], editable, ctx["needs"])
    now = _now()
    match_at = _utc(ctx["row"]["match_at"])
    problem = None
    if not access["manual"]:
        problem = "Okręg nie obsadza tego meczu, więc nie da się go wystawić."
    elif match_at is not None and match_at <= now:
        problem = "Ten mecz już się rozpoczął."
    elif not result["slots"]:
        problem = "Okręg nie ma w tym meczu wolnych gniazd do wystawienia."
    existing = await database.fetch_val(
        select(offers_t.c.id).where(
            and_(offers_t.c.province == key, offers_t.c.match_id == _s(matchId), offers_t.c.status == R.OPEN)
        )
    )
    if existing and not problem:
        problem = f"Ten mecz ma już otwartą ofertę (nr {existing})."
    default_deadline = R.default_deadline(match_at)
    if default_deadline is not None and default_deadline <= now:
        default_deadline = None
    return {
        "matchId": _s(matchId),
        "match": _match_view(ctx["state"], match_at),
        "slots": result["slots"],
        "skipped": result["skipped"],
        "editableSlots": editable,
        "needs": ctx["needs"],
        "roles": R.roles_of(result["slots"]),
        "defaultDeadlineAt": _iso(default_deadline),
        "matchAt": _iso(match_at),
        "canCreate": problem is None,
        "problem": problem,
        "existingOfferId": existing,
    }


# ───────────────────────────── wystawienie ─────────────────────────────


class CreateRequest(BaseModel):
    matchId: str
    province: Optional[str] = None
    slots: Optional[List[str]] = None
    comment: Optional[str] = None
    badgeFilter: Optional[Dict[str, Any]] = None
    deadlineAt: Optional[str] = None


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not _s(value):
        return None
    try:
        return _utc(datetime.fromisoformat(_s(value).replace("Z", "+00:00")))
    except ValueError:
        raise HTTPException(422, "Termin zgłoszeń ma mieć format ISO, np. 2026-11-06T18:00:00+01:00.")


@router.post("", status_code=201, summary="Wystaw mecz jako ofertę obsadowego")
async def create_offer(body: CreateRequest, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    key = _market_province(actor, body.province)
    await _require_enabled(key)
    await _require_approver(actor, key)
    ctx = await _match_context(key, body.matchId)
    if not ctx["access"]["manual"]:
        raise HTTPException(403, "Okręg nie obsadza tego meczu (obsadę ustala inny organizator), więc nie można go wystawić.")
    editable = [s for s in ctx["access"]["editable_slots"] if s in R.CREW_SLOTS]
    slots = R.normalize_slots(body.slots) if body.slots is not None else R.suggest_slots(ctx["crew"], editable, ctx["needs"])["slots"]
    refusal = R.slots_refusal(slots, ctx["crew"], editable)
    if refusal:
        raise HTTPException(422, refusal)
    try:
        flt = R.parse_filter(body.badgeFilter)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    match_at = _utc(ctx["row"]["match_at"])
    now = _now()
    deadline = _parse_dt(body.deadlineAt) or R.default_deadline(match_at)
    # Mecz za mniej niż 24 h: domyślny termin byłby w przeszłości - wtedy bez terminu
    # nie zgadujemy, tylko prosimy o jawny.
    refusal = R.deadline_refusal(deadline, match_at, now)
    if refusal:
        raise HTTPException(422, refusal)
    existing = await database.fetch_val(
        select(offers_t.c.id).where(
            and_(offers_t.c.province == key, offers_t.c.match_id == _s(body.matchId), offers_t.c.status == R.OPEN)
        )
    )
    if existing:
        raise HTTPException(409, f"Ten mecz ma już otwartą ofertę obsadowego (nr {existing}). Wycofaj ją albo dokończ.")
    offer_id = await database.fetch_val(
        insert(offers_t).returning(offers_t.c.id).values(
            province=key,
            match_id=_s(body.matchId),
            match_code=ctx["code"],
            slots=json.dumps(slots),
            comment=_s(body.comment) or None,
            badge_mode=flt["mode"],
            badges=json.dumps(flt["badges"], ensure_ascii=False),
            deadline_at=deadline,
            match_at=match_at,
            match_snapshot=json.dumps(ctx["state"], ensure_ascii=False, default=str),
            status=R.OPEN,
            created_by=actor.judge_id,
        )
    )
    _spawn_background(f"crew-offer-push-{offer_id}", _announce_new(int(offer_id)))
    return await _detail(int(offer_id), actor)


# ───────────────────────────── lista i szczegół ─────────────────────────────


@router.get("", summary="Oferty obsadowego widoczne dla mnie")
async def list_offers(
    scope: str = Query("open", description="open | all (all: także zamknięte z ostatnich 30 dni)"),
    province: Optional[str] = Query(None),
    actor: Actor = Depends(market_actor),
) -> Dict[str, Any]:
    key = _market_province(actor, province)
    await _require_enabled(key)
    await _sweep(key)
    cfg, can_manage = await _viewer(actor, key)
    query = select(offers_t).where(offers_t.c.province == key)
    if scope != "all":
        query = query.where(offers_t.c.status == R.OPEN)
    else:
        query = query.where(
            (offers_t.c.status == R.OPEN) | (offers_t.c.created_at >= _now() - timedelta(days=HISTORY_DAYS))
        )
    rows = await database.fetch_all(query.order_by(offers_t.c.match_at, offers_t.c.id))
    offers = [_offer_dict(r) for r in rows]
    roster = await _roster_for(key)
    all_claims: Dict[int, List[Dict[str, Any]]] = {o["id"]: [] for o in offers}
    if offers:
        for raw in await database.fetch_all(select(claims_t).where(claims_t.c.offer_id.in_(list(all_claims)))):
            all_claims[raw["offer_id"]].append(_row(raw))
    cards = await _judge_cards(
        [o["created_by"] for o in offers]
        + [c["judge_id"] for cl in all_claims.values() for c in cl]
        + [c.get("partner_id") for cl in all_claims.values() for c in cl]
    )
    now = _now()
    out = []
    for offer in offers:
        claims = all_claims[offer["id"]]
        my_roles = _my_roles(roster, actor.judge_id, R.roles_of(offer["slots"]))
        has_claim = any(_s(c["judge_id"]) == actor.judge_id and _s(c["status"]) != R.CLAIM_WITHDRAWN for c in claims)
        if not can_manage and not has_claim:
            if _visibility_refusal(actor, offer, False, my_roles):
                continue
            if scope != "all" and not R.accepting_claims(offer["status"], offer.get("deadline_at"), now):
                continue
        out.append(_offer_view(offer, claims, cards, viewer_id=actor.judge_id, can_manage=can_manage, my_roles=my_roles, now=now))
    return {"offers": out, "canManage": can_manage}


async def _detail(offer_id: int, actor: Actor) -> Dict[str, Any]:
    offer = await _load_offer(offer_id)
    key = offer["province"]
    await _sweep(key)
    offer = await _load_offer(offer_id)
    _, can_manage = await _viewer(actor, key)
    claims = await _claims_of(offer_id)
    roster = await _roster_for(key)
    my_roles = _my_roles(roster, actor.judge_id, R.roles_of(offer["slots"]))
    has_claim = any(_s(c["judge_id"]) == actor.judge_id and _s(c["status"]) != R.CLAIM_WITHDRAWN for c in claims)
    if not has_claim:
        reason = _visibility_refusal(actor, offer, can_manage, my_roles)
        if reason:
            raise HTTPException(403, reason)
    cards = await _judge_cards([offer["created_by"]] + [c["judge_id"] for c in claims] + [c.get("partner_id") for c in claims])
    view = _offer_view(offer, claims, cards, viewer_id=actor.judge_id, can_manage=can_manage, my_roles=my_roles, now=_now())
    if can_manage:
        view["claims"] = await _claims_view(offer, claims, cards)
    return view


@router.get("/{offer_id}", summary="Oferta w całości (dla obsadowego także lista zgłoszeń wg roli)")
async def get_offer(offer_id: int, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    return await _detail(offer_id, actor)


# ───────────────────────────── lista zgłoszeń z liczbami ─────────────────────────────


async def _claims_view(offer: Dict[str, Any], claims: List[Dict[str, Any]], cards: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Zgłoszenia pogrupowane wg roli: km (ze źródłem), mecze, odstępy, kolizje."""
    live = [c for c in claims if _s(c["status"]) != R.CLAIM_WITHDRAWN]
    metrics = await _metrics(offer, live)
    pk = R.packages(live)
    in_pack = {j: p for p in pk for j in p["judge_ids"]}
    by_role: Dict[str, list] = {R.ROLE_TABLE: [], R.ROLE_FIELD: []}
    for claim in live:
        jid = _s(claim["judge_id"])
        m = metrics.get(jid, {})
        partner_id = _s(claim.get("partner_id"))
        by_role.setdefault(claim["role"], []).append(
            {
                "claimId": claim["id"],
                "judge": {**_person(jid, cards), "city": m.get("city", "")},
                "role": claim["role"],
                "status": claim["status"],
                "slot": claim.get("slot"),
                "note": claim.get("note"),
                "createdAt": _iso(claim.get("created_at")),
                "partner": (
                    {**_person(partner_id, cards), "confirmed": jid in in_pack}
                    if partner_id else None
                ),
                "km": m.get("km"),
                "season": m.get("season"),
                "weekMatches": m.get("week_matches"),
                "nearest": m.get("nearest"),
                "gap": m.get("gap"),
                "collisions": m.get("collisions", []),
                "unavailable": m.get("unavailable"),
            }
        )
    return {
        "table": by_role[R.ROLE_TABLE],
        "field": by_role[R.ROLE_FIELD],
        "packages": [
            {
                "judges": [_person(j, cards) for j in p["judge_ids"]],
                "claimIds": p["claim_ids"],
            }
            for p in pk
        ],
    }


async def _metrics(offer: Dict[str, Any], claims: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Liczby przy zgłoszeniach. Brak danych = null, nigdy zmyślone zero."""
    if not claims:
        return {}
    from app import offtime_rules as O
    from app.assignment_context import load_busy
    from app.assignment_distances import fill_missing
    from app.district_alert_rules import offtime_text
    from app.national_distances import load_national_pairs
    from app.national_lookup_rules import national_km
    from app.province_assignment_board import _world
    from app.settlement_distances import DistanceIndex, normalize_city, pick_distance_table
    from app.db import okreg_distances

    key = offer["province"]
    state = offer["match_snapshot"]
    moment = O.match_moment(offer.get("match_at")) if offer.get("match_at") else None
    day = moment.date() if moment else None
    city = _s(state.get("Hala_miasto"))
    world = await _world(key)
    roster, book = world.roster, world.book

    row = await database.fetch_one(
        select(okreg_distances.c.content).where(okreg_distances.c.province.in_(spellings(key) or [key]))
    )
    content = _jl(row["content"], None) if row else None
    index = DistanceIndex(pick_distance_table(content, day))
    national = await load_national_pairs()

    def same_city(a: Any, b: Any) -> bool:
        left, right = normalize_city(a), normalize_city(b)
        return bool(left[0]) and (left[0] == right[0] or left[1] == right[1])

    def chain(origin: Any, dest: Any) -> Dict[str, Any]:
        return R.km_chain(
            origin, dest,
            district=index.lookup,
            national=lambda a, b: national_km(national, a, b, key),
            remembered=lambda a, b: book._cache.get(book.key(a, b)) if book.key(a, b) else None,
            same_city=same_city,
        )

    origins = {j: roster.city_of(j, day) for j in {_s(c["judge_id"]) for c in claims}}
    missing = [(o, city) for o in origins.values() if o and city and chain(o, city)["source"] == "unknown"]
    if missing:
        try:
            import asyncio

            await asyncio.wait_for(fill_missing(book, missing, budget=20), timeout=3.0)
        except Exception:  # noqa: BLE001 - brak km to unknown, nie błąd
            logger.info("giełda obsadowego: kilometry bez dopytania Google")

    busy: Dict[str, list] = {}
    if day is not None:
        start, end = R.week_bounds(day)
        try:
            busy, _ = await load_busy(key, roster, date_from=start - timedelta(days=1), date_to=end + timedelta(days=1))
        except Exception:  # noqa: BLE001
            logger.warning("giełda obsadowego: mecze sędziów niedostępne", exc_info=True)
    season, _months = world.counts()
    here = {
        "match_id": offer["match_id"], "moment": moment, "code": offer.get("match_code") or "",
        "hall": _s(state.get("Hala_nazwa")), "venue": _s(state.get("ID_hala")), "city": city,
    }
    out: Dict[str, Dict[str, Any]] = {}
    for claim in claims:
        jid = _s(claim["judge_id"])
        origin = origins.get(jid, "")
        entries = [
            {"match_id": b.match_id, "moment": b.moment, "code": b.code, "hall": b.hall, "venue": b.venue, "city": b.city}
            for b in busy.get(jid, [])
        ]
        view = R.judge_load_view(entries, here, lambda a, b: chain(a, b)["km"], world.collision)
        counts = season.get(jid) or {}
        field_n, table_n = int(counts.get("field", 0)), int(counts.get("table", 0))
        off = O.blocking_offtime(roster.offtimes.get(jid, ()), moment) if moment else None
        km = chain(origin, city)
        out[jid] = {
            "city": origin,
            "km": {**km, "from": origin, "to": city},
            "season": {"field": field_n, "table": table_n, "total": field_n + table_n},
            "week_matches": view["week_matches"],
            "nearest": view["nearest"],
            "gap": view["gap"],
            "collisions": view["collisions"],
            "unavailable": offtime_text(off) if off is not None else None,
        }
    return out


# ───────────────────────────── zgłoszenia ─────────────────────────────


class ClaimRequest(BaseModel):
    role: Optional[str] = None
    partnerId: Optional[str] = None
    note: Optional[str] = None


@router.post("/{offer_id}/claims", status_code=201, summary="Zgłoś się na ofertę obsadowego")
async def create_claim(offer_id: int, body: ClaimRequest, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    offer = await _load_offer(offer_id)
    key = offer["province"]
    if not actor.known or actor.province != key:
        raise HTTPException(403, "Ta oferta jest z innego okręgu niż Twój.")
    await _require_enabled(key)
    await _sweep(key)
    offer = await _load_offer(offer_id)
    roles = R.roles_of(offer["slots"])
    role, refusal = R.resolve_role(roles, body.role)
    if refusal:
        raise HTTPException(422, refusal)
    roster = await _roster_for(key)
    my_roles = _my_roles(roster, actor.judge_id, roles)
    blocked = None if role in my_roles else "Reguły obsady nie pozwalają Ci stanąć w tej roli (np. delegat nie staje na boisku, a „tylko stolik” nie idzie na boisko)."
    refusal = R.claim_refusal(
        status=offer["status"], deadline=offer.get("deadline_at"), match_at=offer.get("match_at"), now=_now(),
        flt=offer["badge_filter"], badges_raw=actor.badges,
        holds_slot_in_match=bool(slots_held_by(offer["match_snapshot"], actor.judge_id, actor.full_name)),
        role_blocked=blocked,
    )
    if refusal:
        raise HTTPException(403, refusal)

    partner_id = _s(body.partnerId)
    if partner_id:
        cards = await _judge_cards([partner_id])
        card = cards.get(partner_id)
        in_province = bool(card) and card.get("province") in (spellings(key) or [key])
        p_refusal = R.partner_refusal(
            role=role, partner_id=partner_id, self_id=actor.judge_id,
            offer_field_slots=sum(1 for s in offer["slots"] if s in R.FIELD_SLOTS),
            partner_known=in_province,
            partner_passes=R.passes_filter((card or {}).get("badges"), offer["badge_filter"]) if card else False,
            partner_role_blocked=None if R.ROLE_FIELD in _my_roles(roster, partner_id, [R.ROLE_FIELD]) else "reguły obsady",
        )
        if p_refusal:
            raise HTTPException(422, p_refusal)

    existing = await database.fetch_one(
        select(claims_t).where(and_(claims_t.c.offer_id == offer_id, claims_t.c.judge_id == actor.judge_id))
    )
    values = dict(role=role, partner_id=partner_id or None, note=_s(body.note) or None, status=R.PENDING, slot=None)
    if existing is not None:
        if _s(existing["status"]) in R.ACTIVE_CLAIMS:
            raise HTTPException(409, "Już zgłosiłeś się na ten mecz. Możesz zgłoszenie wycofać i złożyć nowe.")
        await database.execute(update(claims_t).where(claims_t.c.id == existing["id"]).values(**values))
        claim_id = existing["id"]
    else:
        try:
            claim_id = await database.fetch_val(
                insert(claims_t).returning(claims_t.c.id).values(offer_id=offer_id, judge_id=actor.judge_id, **values)
            )
        except Exception as exc:  # noqa: BLE001 - wyścig na unikalnym kluczu
            raise HTTPException(409, "Już zgłosiłeś się na ten mecz.") from exc
    result = await _detail(offer_id, actor)
    result["claimId"] = claim_id
    return result


@router.delete("/{offer_id}/claims/me", summary="Wycofaj swoje zgłoszenie")
async def withdraw_claim(offer_id: int, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    await _load_offer(offer_id)
    claim = await database.fetch_one(
        select(claims_t).where(and_(claims_t.c.offer_id == offer_id, claims_t.c.judge_id == actor.judge_id))
    )
    if claim is None or _s(claim["status"]) == R.CLAIM_WITHDRAWN:
        raise HTTPException(404, "Nie masz zgłoszenia na tę ofertę.")
    if _s(claim["status"]) == R.ASSIGNED:
        raise HTTPException(
            409, "Obsadowy już Cię przydzielił do tego meczu. Skontaktuj się z nim, żeby zdjął Cię z obsady."
        )
    await database.execute(update(claims_t).where(claims_t.c.id == claim["id"]).values(status=R.CLAIM_WITHDRAWN, slot=None))
    return await _detail(offer_id, actor)


# ───────────────────────────── przydział ─────────────────────────────


class AssignRequest(BaseModel):
    claimId: int
    slot: Optional[str] = None
    withPartner: bool = False


async def _assign_one(offer: Dict[str, Any], claim: Dict[str, Any], slot: str, actor: Actor, state: Dict[str, Any]) -> None:
    if A.slot_person(state, B.normalize_slot(slot)):
        raise HTTPException(
            409,
            f"Gniazdo „{R.SLOT_LABELS[slot]}” jest już obsadzone w terminarzu. Odśwież Obsadę i zdejmij sędziego, jeśli to pomyłka.",
        )
    cards = await _judge_cards([claim["judge_id"]])
    name = _s((cards.get(_s(claim["judge_id"])) or {}).get("full_name"))
    cid = _market_change_id(claim["id"])

    def edit(changes: list) -> Optional[list]:
        for item in changes:
            if (
                isinstance(item, dict) and _s(item.get("match_id")) == offer["match_id"]
                and B.normalize_slot(item.get("slot")) == slot and _s(item.get("kind")) == "slot"
                and _s(item.get("id")) != cid
            ):
                raise HTTPException(
                    409,
                    f"W kolejce Obsady czeka już zmiana na gnieździe „{R.SLOT_LABELS[slot]}” tego meczu. Zapisz ją albo usuń z kolejki.",
                )
        changes = [c for c in changes if not (isinstance(c, dict) and _s(c.get("id")) == cid)]
        changes.append(
            {
                "id": cid, "match_id": offer["match_id"], "kind": "slot", "slot": slot,
                "judge_id": _s(claim["judge_id"]), "name": name, "before_id": "", "before_name": "",
                "source": "market", "offer_id": offer["id"], "author": actor.full_name or actor.judge_id,
                "at": _now().isoformat(),
                "match_label": B.match_label(state, offer.get("match_code") or ""),
            }
        )
        return changes

    await _draft_edit(offer["province"], edit, actor.full_name or actor.judge_id)
    await database.execute(update(claims_t).where(claims_t.c.id == claim["id"]).values(status=R.ASSIGNED, slot=slot))


@router.post("/{offer_id}/assign", summary="Przydziel zgłoszonego do gniazda (wpis do kolejki Obsady)")
async def assign(offer_id: int, body: AssignRequest, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    offer = await _load_offer(offer_id)
    key = offer["province"]
    await _require_approver(actor, key)
    if _s(offer["status"]) != R.OPEN:
        raise HTTPException(409, "Ta oferta jest już zamknięta, więc nie da się w niej nikogo przydzielić.")
    claims = await _claims_of(offer_id)
    claim = next((c for c in claims if c["id"] == body.claimId), None)
    if claim is None or _s(claim["status"]) != R.PENDING:
        raise HTTPException(409, "To zgłoszenie nie czeka już na decyzję (wycofane albo przydzielone).")
    held = _assigned(claims)
    slot, refusal = R.pick_slot(offer["slots"], held, claim["role"], body.slot)
    if refusal:
        raise HTTPException(409, refusal)
    ctx = await _match_context(key, offer["match_id"])
    state = ctx["state"]
    plan = [(claim, slot)]
    if body.withPartner:
        pair = next(
            (p for p in R.packages(claims) if _s(claim["judge_id"]) in p["judge_ids"]), None
        )
        if pair is None:
            raise HTTPException(409, "To zgłoszenie nie ma potwierdzonej pary (oboje muszą wskazać siebie nawzajem).")
        other = next(c for c in claims if c["id"] in pair["claim_ids"] and c["id"] != claim["id"])
        if _s(other["status"]) != R.PENDING:
            raise HTTPException(409, "Partner z pary nie czeka już na decyzję.")
        slot2, refusal = R.pick_slot(offer["slots"], {**held, slot: claim}, R.ROLE_FIELD)
        if refusal:
            raise HTTPException(409, "Dla partnera nie ma wolnego gniazda boiskowego. " + refusal)
        plan.append((other, slot2))
    for item, target in plan:
        await _assign_one(offer, item, target, actor, state)
        await _push([item["judge_id"]], R.text_assigned(offer, target), offer)
    await _maybe_fill(offer, actor)
    return await _detail(offer_id, actor)


async def _maybe_fill(offer: Dict[str, Any], actor: Actor) -> None:
    claims = await _claims_of(offer["id"])
    if not R.offer_filled(offer["slots"], _assigned(claims)):
        return
    now = _now()
    await database.execute(
        update(offers_t).where(offers_t.c.id == offer["id"]).values(status=R.FILLED, closed_reason="filled", closed_at=now)
    )
    losers = [c for c in claims if _s(c["status"]) == R.PENDING]
    for c in losers:
        await database.execute(update(claims_t).where(claims_t.c.id == c["id"]).values(status=R.DECLINED))
    await _push([c["judge_id"] for c in losers], R.text_filled(offer), offer)


@router.post("/{offer_id}/claims/{claim_id}/unassign", summary="Cofnij przydział")
async def unassign(offer_id: int, claim_id: int, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    offer = await _load_offer(offer_id)
    key = offer["province"]
    await _require_approver(actor, key)
    claims = await _claims_of(offer_id)
    claim = next((c for c in claims if c["id"] == claim_id), None)
    if claim is None or _s(claim["status"]) != R.ASSIGNED:
        raise HTTPException(409, "To zgłoszenie nie jest przydzielone, więc nie ma czego cofać.")
    if _s(offer["status"]) not in (R.OPEN, R.FILLED):
        raise HTTPException(409, "Oferta jest zamknięta (wygasła albo wycofana). Przydział zdejmij bezpośrednio w Obsadzie.")
    cid = _market_change_id(claim_id)
    slot = _s(claim["slot"])
    state = (await _match_context(key, offer["match_id"]))["state"]
    in_state = A.slot_person(state, B.normalize_slot(slot))
    present = {"v": False}

    def edit(changes: list) -> Optional[list]:
        kept = [c for c in changes if not (isinstance(c, dict) and _s(c.get("id")) == cid)]
        present["v"] = len(kept) != len(changes)
        if present["v"]:
            return kept
        # Wpis już poszedł do ZPRP - dopisujemy zdjęcie z gniazda do kolejki.
        if in_state:
            kept.append(
                {
                    "id": f"{cid}-undo-{int(_now().timestamp())}", "match_id": offer["match_id"], "kind": "slot",
                    "slot": slot, "judge_id": "", "name": "", "before_id": _s(in_state.get("number")),
                    "before_name": _s(in_state.get("name")), "source": "market", "offer_id": offer["id"],
                    "author": actor.full_name or actor.judge_id, "at": _now().isoformat(),
                    "match_label": B.match_label(state, offer.get("match_code") or ""),
                }
            )
            return kept
        return None

    await _draft_edit(key, edit, actor.full_name or actor.judge_id)
    await database.execute(update(claims_t).where(claims_t.c.id == claim_id).values(status=R.PENDING, slot=None))
    if _s(offer["status"]) == R.FILLED:
        match_at = _utc(offer.get("match_at"))
        if match_at is None or match_at > _now():
            await database.execute(
                update(offers_t).where(offers_t.c.id == offer_id).values(status=R.OPEN, closed_reason=None, closed_at=None)
            )
            await database.execute(
                update(claims_t).where(and_(claims_t.c.offer_id == offer_id, claims_t.c.status == R.DECLINED)).values(status=R.PENDING)
            )
    await _push([claim["judge_id"]], R.text_unassigned(offer), offer)
    result = await _detail(offer_id, actor)
    result["unassign"] = {
        "removedFromQueue": present["v"],
        "queuedRemovalFromCrew": (not present["v"]) and bool(in_state),
        "note": (
            "Wpis zniknął z kolejki Obsady." if present["v"]
            else "Wpis był już zapisany w ZPRP - zdjęcie z gniazda czeka w kolejce Obsady na „Zapisz”."
            if in_state else "W terminarzu nie było już tego sędziego."
        ),
    }
    return result


# ───────────────────────────── wycofanie oferty ─────────────────────────────


@router.delete("/{offer_id}", summary="Wycofaj ofertę (obsadowy)")
async def withdraw_offer(offer_id: int, actor: Actor = Depends(market_actor)) -> Dict[str, Any]:
    offer = await _load_offer(offer_id)
    await _require_approver(actor, offer["province"])
    if _s(offer["status"]) not in (R.OPEN, R.FILLED):
        raise HTTPException(409, "Ta oferta jest już zamknięta.")
    claims = await _claims_of(offer_id)
    await database.execute(
        update(offers_t).where(offers_t.c.id == offer_id).values(status=R.WITHDRAWN, closed_reason="withdrawn", closed_at=_now())
    )
    pending = [c["judge_id"] for c in claims if _s(c["status"]) == R.PENDING]
    await _push(pending, R.text_withdrawn(offer), offer)
    return await _detail(offer_id, actor)

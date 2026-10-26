# app/match_market_crew_suggest.py
#
# Sugestie przy braku chętnych (25.10.2026, noc): gdy na wolne gniazdo oferty
# obsadowego nikt się nie zgłosił, a inne gniazdo tej samej roli jest obsadzone,
# podpowiadamy stałego partnera obsadzonego i osoby z jego pary mentorskiej.
# Reguły w liściu `match_market_crew_suggest_rules`; tu baza i HTTP.
# Kontrakt: docs/gielda-oferty-obsadowego-api.md (sekcja 8).

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import insert, select, update

from app import assignment_board_rules as B
from app import assignment_rules as A
from app import match_market_crew as M
from app import match_market_crew_rules as R
from app import match_market_crew_suggest_rules as S
from app.db import (
    database,
    match_market_crew_claims as claims_t,
    match_market_crew_invites as invites_t,
    mentoring_assignments,
    mentoring_pairs,
)
from app.match_market import Actor
from app.match_market_rules import slots_held_by
from app.settlement_province import spellings

logger = logging.getLogger("app.match_market_crew")

router = APIRouter(
    prefix="/match-market/crew-offers", tags=["Giełda: oferty obsadowego"], route_class=M._ExplainedErrors
)

_s = M._s


async def _facts_for(key: str) -> list:
    """Mecze z archiwum obsad (wszystkie sezony); pusto, gdy archiwum jeszcze nie ma."""
    from app.assignment_insights import load_facts

    for name in [key] + [n for n in (spellings(key) or []) if n != key]:
        try:
            _, facts = await load_facts(name)
        except Exception:  # noqa: BLE001
            logger.warning("sugestie giełdy: brak archiwum obsad dla %s", name, exc_info=True)
            continue
        if facts:
            return facts
    return []


async def _mentoring() -> Tuple[list, list]:
    pairs = await database.fetch_all(select(mentoring_pairs).where(mentoring_pairs.c.ended_at.is_(None)))
    mentors = await database.fetch_all(select(mentoring_assignments).where(mentoring_assignments.c.ended_at.is_(None)))
    return [M._row(p) for p in pairs], [M._row(m) for m in mentors]


async def _state_of(offer: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return (await M._match_context(offer["province"], offer["match_id"]))["state"]
    except HTTPException:
        return offer.get("match_snapshot") or {}


def _anchors(claims: List[Dict[str, Any]], state: Dict[str, Any], role: str) -> List[str]:
    """Obsadzeni w tej roli: przydzieleni z oferty i ci, którzy już stoją w terminarzu."""
    out: List[str] = []
    for claim in claims:
        if _s(claim["status"]) == R.ASSIGNED and R.role_of_slot(claim.get("slot")) == role:
            out.append(_s(claim["judge_id"]))
    slots = R.FIELD_SLOTS if role == R.ROLE_FIELD else R.TABLE_SLOTS
    for slot in slots:
        person = A.slot_person(state, B.normalize_slot(slot))
        number = _s(person.get("number")) if person else ""
        if number:
            out.append(number)
    return list(dict.fromkeys(i for i in out if i))


async def _check_candidate(
    offer: Dict[str, Any], claims: List[Dict[str, Any]], judge_id: str, role: str
) -> Tuple[Dict[str, Any], Optional[str]]:
    """Karta sędziego i powód odmowy (zdanie po polsku) albo None."""
    key = offer["province"]
    cards = await M._judge_cards([judge_id])
    card = cards.get(judge_id) or {}
    in_province = bool(card) and card.get("province") in (spellings(key) or [key])
    roster = await M._roster_for(key)
    refusal = S.refusal_for_candidate(
        in_province=in_province,
        passes_filter=R.passes_filter(card.get("badges"), offer["badge_filter"]) if card else False,
        holds_slot=bool(slots_held_by(offer["match_snapshot"], judge_id, card.get("full_name"))),
        role_ok=role in M._my_roles(roster, judge_id, [role]),
        already_claimed=any(_s(c["judge_id"]) == judge_id and _s(c["status"]) in R.ACTIVE_CLAIMS for c in claims),
    )
    return card, refusal


async def _invites_of(offer_id: int) -> Dict[str, Dict[str, Any]]:
    rows = await database.fetch_all(select(invites_t).where(invites_t.c.offer_id == offer_id))
    return {_s(M._row(r)["judge_id"]): M._row(r) for r in rows}


def _invite_view(row: Dict[str, Any]) -> Dict[str, Any]:
    return {"judgeId": _s(row["judge_id"]), "role": row["role"], "invitedAt": M._iso(row.get("created_at"))}


@router.get("/{offer_id}/suggestions", summary="Sugestie przy braku chętnych (stały partner, para mentorska)")
async def suggestions(
    offer_id: int,
    actor: Actor = Depends(M.manager_actor),
    fast: int = Query(0, description="1 = bez dopytywania Google (metricsPending mówi, czy pobrać drugi raz)"),
) -> Dict[str, Any]:
    quick = bool(fast)
    offer = await M._load_offer(offer_id)
    key = offer["province"]
    await M._require_manager(actor, key)
    base: Dict[str, Any] = {
        "offerId": offer_id, "slots": [], "inviteLimit": S.INVITE_LIMIT, "invitesUsed": 0, "reason": None,
    }
    if _s(offer["status"]) != R.OPEN:
        return {**base, "reason": "Oferta jest zamknięta - sugestie dotyczą tylko otwartych."}
    claims = await M._claims_of(offer_id)
    invites = await _invites_of(offer_id)
    base["invitesUsed"] = len(invites)
    held = M._assigned(claims)
    state = await _state_of(offer)

    wanted: List[Tuple[str, str, List[str]]] = []  # (slot, role, obsadzeni w tej roli)
    for slot in offer["slots"]:
        role = R.role_of_slot(slot)
        if slot in held:
            continue
        if any(_s(c["status"]) == R.PENDING and _s(c["role"]) == role for c in claims):
            continue
        anchors = _anchors(claims, state, role)
        if anchors:
            wanted.append((slot, role, anchors))
    if not wanted:
        return {
            **base,
            "reason": "Brak sugestii: gniazda są obsadzone, mają zgłoszonych albo nie ma jeszcze nikogo w tej roli, od kogo można zacząć.",
        }

    facts = await _facts_for(key)
    mentor_pairs, mentor_rows = await _mentoring()
    roster = await M._roster_for(key)
    per_slot: Dict[str, Dict[str, Any]] = {}
    ids_all: List[str] = []
    for slot, role, anchors in wanted:
        partners = S.together(facts, anchors, role)
        links = S.mentor_links(mentor_pairs, mentor_rows, anchors)
        ids = list(dict.fromkeys(list(partners) + list(links)))
        per_slot[slot] = {"role": role, "anchors": anchors, "partners": partners, "links": links, "ids": ids}
        ids_all += ids + anchors
    cards = await M._judge_cards(ids_all)

    def eligible(jid: str, info: Dict[str, Any]) -> bool:
        card = cards.get(jid)
        if not card or card.get("province") not in (spellings(key) or [key]):
            return False
        if any(_s(c["judge_id"]) == jid and _s(c["status"]) in R.ACTIVE_CLAIMS for c in claims):
            return False
        if jid in info["anchors"] or slots_held_by(offer["match_snapshot"], jid, card.get("full_name")):
            return False
        if not R.passes_filter(card.get("badges"), offer["badge_filter"]):
            return False
        return info["role"] in M._my_roles(roster, jid, [info["role"]])

    shortlist: Dict[str, List[str]] = {}
    for slot, info in per_slot.items():
        ok = [j for j in info["ids"] if eligible(j, info)]
        ok.sort(key=lambda j: (-(info["partners"].get(j) or {}).get("matches", 0), 0 if j in info["links"] else 1))
        shortlist[slot] = ok[: S.PER_SLOT * 2]
    chosen = list(dict.fromkeys(j for ids in shortlist.values() for j in ids))
    metrics: Dict[str, Dict[str, Any]] = {}
    if chosen:
        try:
            metrics = await M._metrics(offer, [{"judge_id": j} for j in chosen], ask_google=not quick)
        except Exception:  # noqa: BLE001 - bez liczb nadal pokazujemy, kogo podpowiadamy
            logger.warning("sugestie giełdy: liczby sędziów niedostępne", exc_info=True)

    out_slots = []
    for slot, role, anchors in wanted:
        info = per_slot[slot]
        items = []
        for jid in shortlist[slot]:
            m = metrics.get(jid, {})
            reasons = []
            partner = info["partners"].get(jid)
            if partner:
                with_ = M._person(partner["with"][0], cards)
                reasons.append(
                    {
                        "kind": "partner",
                        "matches": partner["matches"],
                        "lastSeason": partner["last_season"],
                        "with": with_,
                        "text": f"Stali razem z {with_['name'] or 'przydzielonym'} "
                        f"{partner['matches']} razy ({'boisko' if role == R.ROLE_FIELD else 'stolik'})",
                    }
                )
            for link in info["links"].get(jid, []):
                who = M._person(link["anchor"], cards)
                label = S.RELATION_LABELS[link["relation"]]
                reasons.append(
                    {
                        "kind": "mentor",
                        "relation": link["relation"],
                        "relationLabel": label,
                        "with": who,
                        "text": f"{label.capitalize()} (para mentorska): {who['name'] or link['anchor']}",
                    }
                )
            invite_row = invites.get(jid)
            items.append(
                {
                    "judge": {**M._person(jid, cards), "city": m.get("city", "")},
                    "reasons": reasons,
                    "availability": S.availability(m.get("unavailable"), m.get("collisions", [])),
                    "km": m.get("km"),
                    "season": m.get("season"),
                    "weekMatches": m.get("week_matches"),
                    "nearest": m.get("nearest"),
                    "gap": m.get("gap"),
                    "collisions": m.get("collisions", []),
                    "unavailable": m.get("unavailable"),
                    "invited": _invite_view(invite_row) if invite_row else None,
                }
            )
        out_slots.append(
            {
                "slot": slot,
                "label": R.SLOT_LABELS[slot],
                "role": role,
                "anchors": [M._person(a, cards) for a in anchors],
                "suggestions": S.rank(items)[: S.PER_SLOT],
            }
        )
    if not any(s["suggestions"] for s in out_slots):
        base["reason"] = "Nikt z kręgu przydzielonych (stali partnerzy, pary mentorskie) nie spełnia warunków tej oferty."
    return {**base, "slots": out_slots, "metricsPending": R.crew_metrics_pending(quick, metrics)}


class InviteRequest(BaseModel):
    judgeId: str
    role: Optional[str] = None


@router.post("/{offer_id}/invite", status_code=201, summary="Zaproś sugerowanego sędziego (osobisty push)")
async def invite(offer_id: int, body: InviteRequest, actor: Actor = Depends(M.manager_actor)) -> Dict[str, Any]:
    offer = await M._load_offer(offer_id)
    key = offer["province"]
    await M._require_manager(actor, key)
    await M._sweep(key)
    offer = await M._load_offer(offer_id)
    if not R.accepting_claims(offer["status"], offer.get("deadline_at"), M._now()):
        raise HTTPException(
            409,
            "Oferta nie przyjmuje już zgłoszeń (termin minął albo jest zamknięta), więc zaproszony nie mógłby się zgłosić. Użyj „Przydziel”.",
        )
    roles = R.roles_of(offer["slots"])
    role, refusal = R.resolve_role(roles, body.role)
    if refusal:
        raise HTTPException(422, refusal)
    claims = await M._claims_of(offer_id)
    held = M._assigned(claims)
    if not [s for s in offer["slots"] if R.role_of_slot(s) == role and s not in held]:
        raise HTTPException(409, f"Wszystkie gniazda roli „{R.ROLE_LABELS[role]}” są już przydzielone.")
    judge_id = _s(body.judgeId)
    _, refusal = await _check_candidate(offer, claims, judge_id, role)
    if refusal:
        raise HTTPException(422, refusal)
    existing = await _invites_of(offer_id)
    if judge_id in existing:
        raise HTTPException(409, "Ten sędzia już dostał zaproszenie na tę ofertę. Poczekaj na odpowiedź albo użyj „Przydziel”.")
    if len(existing) >= S.INVITE_LIMIT:
        raise HTTPException(
            409, f"Limit zaproszeń do jednej oferty to {S.INVITE_LIMIT}. Przydziel kogoś z już zaproszonych albo ze zgłoszonych."
        )
    try:
        await database.execute(
            insert(invites_t).values(
                offer_id=offer_id, judge_id=judge_id, role=role, invited_by=actor.full_name or actor.judge_id
            )
        )
    except Exception as exc:  # noqa: BLE001 - wyścig na unikalnym kluczu
        raise HTTPException(409, "Ten sędzia już dostał zaproszenie na tę ofertę.") from exc
    await M._push([judge_id], S.text_invite(offer, role), offer, extra={"invite": "1", "inviteRole": role})
    used = len(existing) + 1
    return {
        "ok": True,
        "invite": {"judgeId": judge_id, "role": role, "invitedAt": M._now().isoformat()},
        "invitesUsed": used,
        "invitesLeft": max(0, S.INVITE_LIMIT - used),
    }


async def claim_for_suggestion(
    offer: Dict[str, Any], claims: List[Dict[str, Any]], judge_id: str, role: str
) -> Tuple[Dict[str, Any], bool]:
    """Zgłoszenie „w imieniu" sugerowanego (source=suggested). Zwraca (zgłoszenie, utworzone_teraz)."""
    _, refusal = await _check_candidate(offer, claims, judge_id, role)
    if refusal:
        raise HTTPException(422, refusal)
    existing = next((c for c in claims if _s(c["judge_id"]) == judge_id), None)
    values = dict(role=role, partner_id=None, note=None, status=R.PENDING, slot=None, source="suggested")
    if existing is not None:
        await database.execute(update(claims_t).where(claims_t.c.id == existing["id"]).values(**values))
    else:
        await database.execute(insert(claims_t).values(offer_id=offer["id"], judge_id=judge_id, **values))
    fresh = next(c for c in await M._claims_of(offer["id"]) if _s(c["judge_id"]) == judge_id)
    return fresh, True


async def discard_suggested_claim(claim_id: int) -> None:
    await database.execute(update(claims_t).where(claims_t.c.id == claim_id).values(status=R.CLAIM_WITHDRAWN, slot=None))

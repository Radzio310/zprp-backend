"""Tryb prezentacji - udawane odpowiedzi i nakładka na odczyty.

Symulator dostaje kontekst żądania (`Ctx`) i oddaje `Result` w kształcie, jakiego
oczekuje klient - kształty wzięte z handlerów (`return` / modele pydantic), żeby
ekran pokazał „zapisane". Żaden symulator NIE woła ZPRP, nie wysyła pushy i nie
pisze do tabel innych niż `presentation_*`. Odczyty (np. wiersz meczu, lista
sędziów, widok wydarzenia przez wewnętrzne zapytanie GET) są dozwolone.

Nakładka (`MERGES`) dokleja udawane zmiany do prawdziwych odpowiedzi GET - tylko
dla kont objętych trybem. Funkcja nakładki jest wołana dwa razy: `data=None`
przed wywołaniem aplikacji (może oddać `Result` i zastąpić odpowiedź, np. dla
udawanej oferty) i z prawdziwym JSON-em po nim.

Szczegóły i tabela tras: `docs/presentation-mode.md`.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from app import presentation_state as PS

log = logging.getLogger("presentation")

LIVE = ("approval_pending", "open", "applying")
ZPRP_SLOTS = ("sedzia1", "sedzia2", "delegat", "delegat2", "sekretarz", "czas")
SLOT_TO_SELECT = {
    "sedzia1": "NrSedzia_pierwszy",
    "sedzia2": "NrSedzia_drugi",
    "delegat": "NrSedzia_delegat",
    "delegat2": "NrSedzia_delegat2",
    "sekretarz": "NrSedzia_sekretarz",
    "czas": "NrSedzia_czas",
}
DT_FIELDS = ("deadline_at", "created_at", "match_at", "decided_at", "applied_at", "updated_at", "closed_at")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _dt(value: Any) -> Optional[datetime]:
    return PS._utc(value)


def _jsonable(row: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(json.dumps(row, default=lambda v: v.isoformat() if isinstance(v, datetime) else str(v)))


def _runtime(row: Dict[str, Any]) -> Dict[str, Any]:
    """Wiersz z nakładki (daty jako napisy) -> taki, jaki daje baza (datetime)."""
    out = dict(row)
    for key in DT_FIELDS:
        if key in out:
            out[key] = _dt(out[key])
    return out


@dataclass
class Result:
    status: int
    body: Any
    summary: str = ""
    extra: Any = None


@dataclass
class Ctx:
    app: Any
    scope: Dict[str, Any]
    method: str
    path: str
    params: Dict[str, str]
    query: Dict[str, str]
    headers: Dict[str, str]
    raw: Optional[bytes]
    body: Any
    jwt: Optional[Dict[str, Any]]
    account: str
    state: Any
    cache: Dict[str, Any] = field(default_factory=dict)

    @property
    def judge_id(self) -> str:
        jid = _s((self.jwt or {}).get("judge_id"))
        if jid:
            return jid
        if self.account.startswith("judge:"):
            return self.account[6:]
        return ""

    @property
    def login(self) -> str:
        return _s((self.jwt or {}).get("sub")) or (self.account[6:] if self.account.startswith("login:") else "")

    def b(self, key: str, default: Any = None) -> Any:
        return self.body.get(key, default) if isinstance(self.body, dict) else default

    def pid(self, name: str = "id") -> int:
        return int(self.params.get(name) or 0)

    async def sub(self, method: str, path: str, query: Optional[Dict[str, Any]] = None, body: Any = None):
        """Wewnętrzne zapytanie do aplikacji z tym samym tokenem (odczyty)."""
        from app.presentation_middleware import body_receiver, call_capture, subrequest_scope

        raw = b"" if body is None else json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
        scope = subrequest_scope(self.scope, method, path, query, "application/json" if body is not None else None)
        return await call_capture(self.app, scope, body_receiver(raw))


def strip_conditional(scope: Dict[str, Any]) -> Dict[str, Any]:
    inner = dict(scope)
    inner["headers"] = [(k, v) for k, v in scope.get("headers") or [] if k.lower() != b"if-none-match"]
    return inner


def _canonical(province: Any) -> str:
    try:
        from app.settlement_province import canonical

        return canonical(province) or _s(province)
    except Exception:  # noqa: BLE001
        return _s(province).upper()


# ───────────────────────────── proste odpowiedzi ─────────────────────────────


def _echo(ctx: Ctx) -> Dict[str, Any]:
    if not isinstance(ctx.body, dict):
        return {}
    return {k: v for k, v in PS.sanitize(ctx.body).items() if v != "***" and k not in ("success", "ok")}


async def ok_success(ctx: Ctx, route) -> Result:
    return Result(route.status, {"success": True, "ok": True}, route.label)


async def ok_true(ctx: Ctx, route) -> Result:
    return Result(route.status, {"ok": True}, route.label)


async def ok_success_echo(ctx: Ctx, route) -> Result:
    return Result(route.status, {**_echo(ctx), "success": True, "ok": True}, route.label)


async def ok_created_id(ctx: Ctx, route) -> Result:
    return Result(route.status, {"id": await PS.next_synthetic_id(), "success": True, "ok": True}, route.label)


async def no_content(ctx: Ctx, route) -> Result:
    return Result(204, None, route.label)


async def pdf_as_draft(ctx: Ctx, route) -> Result:
    """Oficjalny wydruk zajmuje numer w rejestrze - w trybie idzie jako szkic."""
    body = dict(ctx.body) if isinstance(ctx.body, dict) else {}
    body["official"] = False
    got = await ctx.sub("POST", ctx.path, ctx.query, body)
    return Result(got.status, got.json(), "Wydruk jako szkic (bez numeru w rejestrze)")


# ───────────────────────────── giełda: kto pyta ─────────────────────────────


async def market_viewer(ctx: Ctx) -> Dict[str, Any]:
    """Pytający na giełdzie: numer, okręg, nazwisko, czy rozstrzyga. Bez sieci."""
    if "viewer" in ctx.cache:
        return ctx.cache["viewer"]
    out = {"judge_id": ctx.judge_id, "province": "", "full_name": "", "photo_url": "", "approver": False,
           "is_admin": False, "cfg": None}
    try:
        from app import match_market as M
        from app.match_market_access import may_approve

        actor = await M.market_actor(ctx.jwt or {"judge_id": ctx.judge_id})
        cfg = await M._config(actor.province) if actor.province else None
        out.update(
            judge_id=actor.judge_id,
            province=actor.province,
            full_name=actor.full_name,
            photo_url=actor.photo_url,
            is_admin=actor.is_admin,
            cfg=cfg,
            approver=may_approve(
                is_admin=actor.is_admin,
                province=actor.province,
                judge_province=actor.province,
                badges_raw=actor.badges,
                allowed_badges=(cfg or {}).get("approver_badges") or ["Obsadowy"],
            ),
        )
    except Exception:  # noqa: BLE001
        log.info("tryb prezentacji: widz giełdy bez pełnych danych", exc_info=True)
    ctx.cache["viewer"] = out
    return out


async def judge_cards(ids: List[str]) -> Dict[str, Dict[str, Any]]:
    clean = sorted({_s(i) for i in ids if _s(i)})
    if not clean:
        return {}
    try:
        from app import match_market as M

        return await M._judges_by_id(clean)
    except Exception:  # noqa: BLE001
        return {}


def person(judge_id: Any, card: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    data = card or {}
    return {"judgeId": _s(judge_id), "fullName": _s(data.get("full_name")), "photoUrl": _s(data.get("photo_url"))}


async def _province_match(province: str, match_id: str) -> Dict[str, Any]:
    try:
        from sqlalchemy import and_, select

        from app.db import database, province_matches
        from app.settlement_province import spellings

        row = await database.fetch_one(
            select(province_matches).where(
                and_(
                    province_matches.c.province.in_(spellings(province) or [province]),
                    province_matches.c.match_id == _s(match_id),
                )
            )
        )
        if row is None:
            return {}
        data = dict(row._mapping) if hasattr(row, "_mapping") else dict(row)
        from app.match_market_rules import state_dict

        data["state_json"] = state_dict(data.get("state_json"))
        return data
    except Exception:  # noqa: BLE001
        log.info("tryb prezentacji: wiersz meczu niedostępny", exc_info=True)
        return {}


def _slot_label(slot: str) -> str:
    try:
        from app.match_market_rules import slot_label

        return slot_label(slot)
    except Exception:  # noqa: BLE001
        return slot


# ───────────────────────────── giełda: nakładka ─────────────────────────────


async def market_offer(offer_id: Any) -> Optional[Tuple[int, Dict[str, Any]]]:
    return await PS.overlay_get("market_offer", offer_id)


async def market_patch(offer_id: Any) -> Tuple[Optional[int], Dict[str, Any]]:
    found = await PS.overlay_get("market_patch", offer_id)
    if found:
        return found[0], found[1]
    return None, {"offer": {}, "claims_add": [], "claims_patch": {}}


async def _save_patch(offer_id: Any, row_id: Optional[int], data: Dict[str, Any], kind: str = "market_patch") -> None:
    if row_id is None:
        await PS.overlay_add(kind, offer_id, data)
    else:
        await PS.overlay_put(row_id, data)


async def offer_payload(row: Dict[str, Any], claims: List[Dict[str, Any]], viewer: Dict[str, Any], *, detail: bool) -> Dict[str, Any]:
    """Widok udawanej oferty - przez `_offer_payload` giełdy, gdy się da."""
    rt = _runtime(row)
    claims_rt = [_runtime(c) for c in claims]
    vid = viewer.get("judge_id") or ""
    cards = await judge_cards([rt.get("from_judge_id"), rt.get("decided_by")] + [c.get("judge_id") for c in claims_rt])
    approver = bool(viewer.get("approver"))
    try:
        from app import match_market as M

        payload = await M._offer_payload(rt, cards, claims_rt, viewer_id=vid, hide_names=False)
    except Exception:  # noqa: BLE001 - zapasowy kształt z tymi samymi polami
        payload = _fallback_offer_payload(rt, claims_rt, cards, vid)
    status = _s(rt.get("status"))
    payload["canApprove"] = approver and status == "open"
    if detail:
        mine = _s(rt.get("from_judge_id")) == vid
        payload["canApproveLate"] = approver and status == "approval_pending"
        payload["claims"] = (
            [
                {
                    "id": c["id"],
                    "status": _s(c.get("status")),
                    "note": _s(c.get("note")) or None,
                    "createdAt": PS._iso(c.get("created_at")),
                    "person": person(c.get("judge_id"), cards.get(_s(c.get("judge_id")))),
                    "conflicts": [],
                }
                for c in claims_rt
            ]
            if (approver or mine)
            else []
        )
        payload["metricsPending"] = False
        payload["myConflicts"] = []
        payload["slotHolder"] = _slot_holder(rt)
        payload["matchNow"] = None
    return payload


def _slot_holder(row: Dict[str, Any]) -> str:
    try:
        from app.match_market_rules import slot_holder_name, state_dict

        return slot_holder_name(state_dict(row.get("match_snapshot")), row.get("slot"))
    except Exception:  # noqa: BLE001
        return ""


def _fallback_offer_payload(row, claims, cards, vid) -> Dict[str, Any]:
    pending = [c for c in claims if _s(c.get("status")) == "pending"]
    state = row.get("match_snapshot") or {}
    chosen = next((c for c in claims if _s(c.get("status")) == "chosen"), None)
    mine = next((c for c in claims if _s(c.get("judge_id")) == vid), None)
    return {
        "id": row["id"],
        "province": _s(row.get("province")),
        "matchId": _s(row.get("match_id")),
        "slot": _s(row.get("slot")),
        "slotLabel": _slot_label(_s(row.get("slot"))),
        "status": _s(row.get("status")),
        "reason": _s(row.get("reason")) or None,
        "deadlineAt": PS._iso(row.get("deadline_at")),
        "createdAt": PS._iso(row.get("created_at")),
        "decidedAt": PS._iso(row.get("decided_at")),
        "appliedAt": PS._iso(row.get("applied_at")),
        "error": None,
        "match": {
            "matchCode": _s(state.get("RozgrywkiCode")),
            "hostTeam": _s(state.get("ID_zespoly_gosp_ZespolNazwa")),
            "guestTeam": _s(state.get("ID_zespoly_gosc_ZespolNazwa")),
            "matchAt": PS._iso(row.get("match_at")),
            "hall": " ".join(p for p in (_s(state.get("Hala_nazwa")), _s(state.get("Hala_miasto"))) if p),
        },
        "from": person(row.get("from_judge_id"), cards.get(_s(row.get("from_judge_id")))),
        "isMine": _s(row.get("from_judge_id")) == vid,
        "myCrewLabel": "",
        "claimCount": len(pending),
        "namesHidden": False,
        "nearestKm": None,
        "myKm": None,
        "claimers": [person(c.get("judge_id"), cards.get(_s(c.get("judge_id")))) for c in claims if _s(c.get("status")) in ("pending", "chosen")],
        "takerName": _s((cards.get(_s((chosen or {}).get("judge_id"))) or {}).get("full_name")) or None,
        "taker": person(chosen.get("judge_id"), cards.get(_s(chosen.get("judge_id")))) if chosen else None,
        "decidedBy": None,
        "myClaim": {"id": mine["id"], "status": _s(mine.get("status")), "note": _s(mine.get("note")) or None} if mine else None,
        "claims": [],
    }


def _apply_patch(payload: Dict[str, Any], patch: Dict[str, Any], vid: str, cards: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Prawdziwa oferta + udawane decyzje i zgłoszenia."""
    offer_p = patch.get("offer") or {}
    if offer_p.get("status"):
        payload["status"] = offer_p["status"]
        payload["canApprove"] = False if offer_p["status"] != "open" else payload.get("canApprove")
        if "canApproveLate" in payload and offer_p["status"] != "approval_pending":
            payload["canApproveLate"] = False
    for key in ("decided_at", "applied_at"):
        if offer_p.get(key):
            payload["decidedAt" if key == "decided_at" else "appliedAt"] = offer_p[key]
    claims_patch = {str(k): v for k, v in (patch.get("claims_patch") or {}).items()}
    for item in payload.get("claims") or []:
        p = claims_patch.get(str(item.get("id")))
        if p and p.get("status"):
            item["status"] = p["status"]
    my = payload.get("myClaim")
    if isinstance(my, dict) and claims_patch.get(str(my.get("id")), {}).get("status"):
        my["status"] = claims_patch[str(my.get("id"))]["status"]
        if my["status"] == "withdrawn":
            payload["claimCount"] = max(0, int(payload.get("claimCount") or 0) - 1)
            payload["claimers"] = [c for c in payload.get("claimers") or [] if _s(c.get("judgeId")) != vid]
    for claim in patch.get("claims_add") or []:
        jid = _s(claim.get("judge_id"))
        status = _s(claim.get("status"))
        who = person(jid, cards.get(jid) or claim.get("card"))
        if jid == vid:
            payload["myClaim"] = {"id": claim["id"], "status": status, "note": _s(claim.get("note")) or None}
        if status == "pending":
            payload["claimCount"] = int(payload.get("claimCount") or 0) + 1
            if not payload.get("namesHidden"):
                payload.setdefault("claimers", []).append(who)
        if isinstance(payload.get("claims"), list) and (payload.get("claims") or payload.get("isMine") or "canApproveLate" in payload):
            payload["claims"].append(
                {"id": claim["id"], "status": status, "note": _s(claim.get("note")) or None,
                 "createdAt": claim.get("created_at"), "person": who, "conflicts": []}
            )
    chosen = _s(offer_p.get("chosen_judge_id"))
    if chosen:
        taker = person(chosen, cards.get(chosen) or offer_p.get("chosen_card"))
        payload["taker"] = taker
        payload["takerName"] = taker["fullName"] or None
    return payload


def _scope_wants(scope: str, row: Dict[str, Any], claims: List[Dict[str, Any]], viewer: Dict[str, Any]) -> bool:
    vid = viewer.get("judge_id") or ""
    status = _s(row.get("status"))
    mine = _s(row.get("from_judge_id")) == vid
    claimed = any(_s(c.get("judge_id")) == vid for c in claims)
    claimed_pending = any(_s(c.get("judge_id")) == vid and _s(c.get("status")) == "pending" for c in claims)
    if scope == "mine":
        return (mine or claimed_pending) and status in LIVE
    if scope == "history":
        return (mine or claimed) and status not in LIVE
    if mine:
        return False
    return status == "open" or (status == "approval_pending" and viewer.get("approver"))


async def merge_market_list(ctx: Ctx, data: Any) -> Any:
    if data is None:
        return None
    viewer = await market_viewer(ctx)
    vid = viewer.get("judge_id") or ""
    scope = ctx.query.get("scope") or "market"
    patches = {key: d for key, d in await _patches("market_patch")}
    synthetic = await PS.overlay_list("market_offer")
    cards = await judge_cards(
        [c.get("judge_id") for p in patches.values() for c in p.get("claims_add") or []]
        + [p.get("offer", {}).get("chosen_judge_id") for p in patches.values()]
    )
    offers = []
    for item in data.get("offers") or []:
        patch = patches.get(str(item.get("id")))
        if patch:
            item = _apply_patch(item, patch, vid, cards)
            live = _s(item.get("status")) in LIVE
            if (scope == "history") == live:
                continue
            if scope == "market" and _s(item.get("status")) not in ("open", "approval_pending"):
                continue
        offers.append(item)
    extra = []
    for _row_id, d in synthetic:
        row, claims = d.get("row") or {}, d.get("claims") or []
        if row and _scope_wants(scope, row, claims, viewer):
            extra.append(await offer_payload(row, claims, viewer, detail=False))
    data["offers"] = extra + offers
    return data


async def _patches(kind: str) -> List[Tuple[str, Dict[str, Any]]]:
    db = PS._db()
    t = db.presentation_overlay
    rows = await db.database.fetch_all(t.select().where(t.c.kind == kind).order_by(t.c.id))
    return [(_s(r["key"]), PS._loads(r["data_json"], {}) or {}) for r in rows]


async def merge_market_detail(ctx: Ctx, data: Any) -> Any:
    offer_id = ctx.pid()
    if data is None:
        if not PS.is_synthetic(offer_id):
            return None
        found = await market_offer(offer_id)
        if not found:
            return Result(404, {"error": "Nie ma takiej oferty.", "detail": "Nie ma takiej oferty."})
        viewer = await market_viewer(ctx)
        return Result(200, await offer_payload(found[1]["row"], found[1].get("claims") or [], viewer, detail=True))
    _rid, patch = await market_patch(offer_id)
    if _rid is None:
        return data
    viewer = await market_viewer(ctx)
    cards = await judge_cards([c.get("judge_id") for c in patch.get("claims_add") or []])
    return _apply_patch(data, patch, viewer.get("judge_id") or "", cards)


async def merge_my_matches(ctx: Ctx, data: Any) -> Any:
    if data is None:
        return None
    viewer = await market_viewer(ctx)
    vid = viewer.get("judge_id") or ""
    taken: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for _rid, d in await PS.overlay_list("market_offer"):
        row = d.get("row") or {}
        if _s(row.get("from_judge_id")) == vid and _s(row.get("status")) in LIVE:
            taken[(_s(row.get("match_id")), _s(row.get("slot")))] = {"id": row["id"], "status": row["status"]}
    gone = {key for key, d in await _patches("market_patch") if _s((d.get("offer") or {}).get("status")) not in ("", *LIVE)}
    for match in data.get("matches") or []:
        slots = match.get("slots") or []
        for slot in slots:
            hit = taken.get((_s(match.get("matchId")), _s(slot.get("slot"))))
            if hit:
                slot["offerId"], slot["offerStatus"] = hit["id"], hit["status"]
            elif _s(slot.get("offerId")) in gone:
                slot["offerId"], slot["offerStatus"] = None, None
        if slots and all(s.get("offerId") for s in slots) and any(
            taken.get((_s(match.get("matchId")), _s(s.get("slot")))) for s in slots
        ):
            match["canOffer"] = False
            match["canRequestApproval"] = False
            match["blockedReason"] = (
                "Twoje gniazdo w tym meczu już wisi na giełdzie."
                if len(slots) == 1
                else "Wszystkie Twoje gniazda w tym meczu już wiszą na giełdzie."
            )
    return data


# ───────────────────────────── giełda: zapisy ─────────────────────────────


async def market_create_offer(ctx: Ctx, route) -> Result:
    viewer = await market_viewer(ctx)
    match_id, slot = _s(ctx.b("match_id")), _s(ctx.b("slot"))
    province = viewer.get("province") or _canonical(ctx.b("province"))
    for _rid, d in await PS.overlay_list("market_offer"):
        row = d.get("row") or {}
        if _s(row.get("match_id")) == match_id and _s(row.get("slot")) == slot and _s(row.get("status")) in LIVE:
            return Result(409, {"error": "To gniazdo już wisi na giełdzie.", "detail": "To gniazdo już wisi na giełdzie."})
    match = await _province_match(province, match_id)
    match_at = _dt(match.get("match_at"))
    cfg = viewer.get("cfg") or {}
    hours = int(cfg.get("offer_deadline_hours") or 48)
    now = _now()
    try:
        from app.match_market_rules import can_offer, deadline_for

        ordinary = can_offer(match_at, now, hours)
        deadline = deadline_for(match_at, hours)
    except Exception:  # noqa: BLE001
        ordinary = match_at is None or match_at - now > timedelta(hours=hours)
        deadline = match_at - timedelta(hours=hours) if match_at else None
    status = "open" if ordinary else "approval_pending"
    offer_id = await PS.next_synthetic_id()
    row = {
        "id": offer_id,
        "province": province,
        "match_id": match_id,
        "match_code": _s(match.get("match_code")),
        "slot": slot,
        "from_judge_id": viewer.get("judge_id") or ctx.judge_id,
        "reason": _s(ctx.b("reason")) or None,
        "status": status,
        "deadline_at": match_at if status == "approval_pending" else deadline,
        "match_at": match_at,
        "match_snapshot": match.get("state_json") or {},
        "created_at": now,
        "updated_at": now,
        "decided_by": None,
    }
    await PS.overlay_add("market_offer", offer_id, {"row": _jsonable(row), "claims": [], "account": ctx.account})
    return Result(201, {"id": offer_id, "status": status}, f"Wystawienie meczu {match_id} ({_slot_label(slot)}) na giełdę")


async def _offer_transition(ctx: Ctx, status: str, *, claims_to: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> None:
    offer_id = ctx.pid()
    now_iso = _now().isoformat()
    found = await market_offer(offer_id) if PS.is_synthetic(offer_id) else None
    if found:
        rid, d = found
        d["row"]["status"] = status
        d["row"]["updated_at"] = now_iso
        d["row"].update(extra or {})
        if claims_to:
            for c in d.get("claims") or []:
                if c.get("status") == "pending":
                    c["status"] = claims_to
        await PS.overlay_put(rid, d)
        return
    rid, patch = await market_patch(offer_id)
    patch.setdefault("offer", {})["status"] = status
    patch["offer"].update(extra or {})
    await _save_patch(offer_id, rid, patch)


async def market_withdraw_offer(ctx: Ctx, route) -> Result:
    await _offer_transition(ctx, "cancelled", claims_to="declined")
    return Result(200, {"id": ctx.pid(), "status": "cancelled"}, f"Wycofanie oferty {ctx.pid()}")


async def market_listing_approve(ctx: Ctx, route) -> Result:
    await _offer_transition(ctx, "open")
    return Result(200, {"id": ctx.pid(), "status": "open"}, f"Zgoda na pilne wystawienie {ctx.pid()}")


async def market_listing_reject(ctx: Ctx, route) -> Result:
    reason = _s(ctx.b("reason")) or None
    await _offer_transition(ctx, "approval_rejected", extra={"error": reason})
    return Result(200, {"id": ctx.pid(), "status": "approval_rejected", "reason": reason}, f"Odmowa pilnego wystawienia {ctx.pid()}")


async def market_reject(ctx: Ctx, route) -> Result:
    await _offer_transition(ctx, "rejected", claims_to="declined", extra={"decided_by": ctx.judge_id, "decided_at": _now().isoformat()})
    return Result(200, {"id": ctx.pid(), "status": "rejected"}, f"Odrzucenie wymiany {ctx.pid()}")


async def market_admin_withdraw(ctx: Ctx, route) -> Result:
    reason = _s(ctx.b("reason"))
    await _offer_transition(ctx, "cancelled", claims_to="declined")
    return Result(200, {"id": ctx.pid(), "status": "cancelled", "reason": reason}, f"Zdjęcie oferty {ctx.pid()} przez admina")


async def market_create_claim(ctx: Ctx, route) -> Result:
    offer_id = ctx.pid()
    viewer = await market_viewer(ctx)
    claim_id = await PS.next_synthetic_id()
    claim = {
        "id": claim_id,
        "offer_id": offer_id,
        "judge_id": viewer.get("judge_id") or ctx.judge_id,
        "status": "pending",
        "note": _s(ctx.b("note")) or None,
        "created_at": _now().isoformat(),
        "card": {"full_name": viewer.get("full_name"), "photo_url": viewer.get("photo_url")},
    }
    found = await market_offer(offer_id) if PS.is_synthetic(offer_id) else None
    if found:
        rid, d = found
        d.setdefault("claims", []).append(claim)
        await PS.overlay_put(rid, d)
    else:
        rid, patch = await market_patch(offer_id)
        patch.setdefault("claims_add", []).append(claim)
        await _save_patch(offer_id, rid, patch)
    return Result(201, {"id": claim_id, "status": "pending", "conflicts": []}, f"Zgłoszenie na ofertę {offer_id}")


async def _real_claim_id(offer_id: int, judge_id: str) -> Optional[int]:
    try:
        from sqlalchemy import and_, select

        from app.db import database, match_market_claims as T

        return await database.fetch_val(
            select(T.c.id).where(and_(T.c.offer_id == offer_id, T.c.judge_id == judge_id, T.c.status == "pending"))
        )
    except Exception:  # noqa: BLE001
        return None


async def market_withdraw_claim(ctx: Ctx, route) -> Result:
    offer_id = ctx.pid()
    vid = ctx.judge_id
    found = await market_offer(offer_id) if PS.is_synthetic(offer_id) else None
    if found:
        rid, d = found
        claim = next((c for c in d.get("claims") or [] if _s(c.get("judge_id")) == vid and c.get("status") == "pending"), None)
        if claim:
            claim["status"] = "withdrawn"
            await PS.overlay_put(rid, d)
        return Result(200, {"id": (claim or {}).get("id"), "status": "withdrawn"}, f"Wycofanie zgłoszenia z oferty {offer_id}")
    rid, patch = await market_patch(offer_id)
    claim = next((c for c in patch.get("claims_add") or [] if _s(c.get("judge_id")) == vid and c.get("status") == "pending"), None)
    if claim:
        claim["status"] = "withdrawn"
        cid = claim["id"]
    else:
        cid = await _real_claim_id(offer_id, vid)
        if cid is not None:
            patch.setdefault("claims_patch", {})[str(cid)] = {"status": "withdrawn"}
    await _save_patch(offer_id, rid, patch)
    return Result(200, {"id": cid, "status": "withdrawn"}, f"Wycofanie zgłoszenia z oferty {offer_id}")


async def _real_offer_and_claim(offer_id: int, claim_id: int) -> Tuple[str, str]:
    try:
        from sqlalchemy import select

        from app.db import database, match_market_claims as C, match_market_offers as O

        giver = await database.fetch_val(select(O.c.from_judge_id).where(O.c.id == offer_id))
        taker = await database.fetch_val(select(C.c.judge_id).where(C.c.id == claim_id))
        return _s(giver), _s(taker)
    except Exception:  # noqa: BLE001
        return "", ""


async def market_approve(ctx: Ctx, route) -> Result:
    """Zatwierdzenie wymiany BEZ zapisu w ZPRP (apply_referee_assignment nie rusza)."""
    offer_id, claim_id = ctx.pid(), int(ctx.b("claim_id") or 0)
    now_iso = _now().isoformat()
    found = await market_offer(offer_id) if PS.is_synthetic(offer_id) else None
    if found:
        rid, d = found
        giver = _s(d["row"].get("from_judge_id"))
        taker = ""
        for c in d.get("claims") or []:
            if int(c.get("id") or 0) == claim_id:
                c["status"] = "chosen"
                taker = _s(c.get("judge_id"))
            elif c.get("status") == "pending":
                c["status"] = "declined"
        d["row"].update(status="done", decided_by=ctx.judge_id, decided_at=now_iso, applied_at=now_iso, updated_at=now_iso)
        await PS.overlay_put(rid, d)
    else:
        rid, patch = await market_patch(offer_id)
        added = next((c for c in patch.get("claims_add") or [] if int(c.get("id") or 0) == claim_id), None)
        giver, taker = await _real_offer_and_claim(offer_id, claim_id)
        if added:
            added["status"] = "chosen"
            taker = _s(added.get("judge_id"))
        else:
            patch.setdefault("claims_patch", {})[str(claim_id)] = {"status": "chosen"}
        patch.setdefault("offer", {}).update(
            status="done", decided_by=ctx.judge_id, decided_at=now_iso, applied_at=now_iso, chosen_judge_id=taker
        )
        await _save_patch(offer_id, rid, patch)
    cards = await judge_cards([giver, taker])
    return Result(
        200,
        {"id": offer_id, "status": "done", "applied": True, "from": person(giver, cards.get(giver)), "to": person(taker, cards.get(taker))},
        f"Zatwierdzenie wymiany w ofercie {offer_id} (bez zapisu w ZPRP)",
    )


async def market_admin_prefs(ctx: Ctx, route) -> Result:
    data = {k: bool(ctx.b(k, True)) for k in ("new_offers", "claims", "decisions")}
    return Result(200, {"newOffers": data["new_offers"], "claims": data["claims"], "decisions": data["decisions"]}, route.label)


async def market_notification_test(ctx: Ctx, route) -> Result:
    preview = ctx.path.rsplit("/send", 1)[0] + "/preview"
    got = await ctx.sub("POST", preview, ctx.query, ctx.body if isinstance(ctx.body, dict) else {})
    data = got.json()
    if got.status == 200 and isinstance(data, dict):
        data["sent"] = True
        data["reports"] = []
    return Result(got.status, data, "Test powiadomienia giełdy (bez wysyłki)")


async def market_admin_province(ctx: Ctx, route) -> Result:
    key = _canonical(ctx.params.get("province"))
    out: Dict[str, Any] = {"province": key}
    try:
        from app import match_market as M

        cfg = await M._config(key)
        out.update(
            marketEnabled=cfg["market_enabled"], deadlineHours=cfg["offer_deadline_hours"],
            assignAccountMode=cfg["assign_account_mode"], approverBadges=cfg["approver_badges"],
            notifyAdmins=cfg["notify_admins"], hideClaimers=cfg["hide_claimers"],
            foreignMatchesEnabled=cfg["foreign_matches_enabled"],
            secondLeagueFieldEnabled=cfg["second_league_field_enabled"],
            managedPrefixes=cfg["managed_prefixes"], managedPrefixesCustom=cfg["managed_prefixes_custom"],
        )
    except Exception:  # noqa: BLE001
        pass
    names = {
        "market_enabled": "marketEnabled", "offer_deadline_hours": "deadlineHours",
        "assign_account_mode": "assignAccountMode", "approver_badges": "approverBadges",
        "notify_admins": "notifyAdmins", "hide_claimers": "hideClaimers",
        "foreign_matches_enabled": "foreignMatchesEnabled", "second_league_field_enabled": "secondLeagueFieldEnabled",
        "managed_prefixes": "managedPrefixes",
    }
    for src, dst in names.items():
        if ctx.b(src) is not None:
            out[dst] = ctx.b(src)
    return Result(200, out, f"Ustawienia giełdy {key}")


# ───────────────────────────── giełda obsadowego ─────────────────────────────


async def crew_actor(ctx: Ctx):
    from app import match_market as M
    from app import match_market_crew as C

    if "crew_actor" in ctx.cache:
        return ctx.cache["crew_actor"]
    payload = ctx.jwt or {"judge_id": ctx.judge_id, "sub": ctx.login}
    actor = await M.market_actor(payload) if _s(payload.get("judge_id")) else C.PanelActor(payload)
    ctx.cache["crew_actor"] = actor
    return actor


def _crew_runtime(offer: Dict[str, Any]) -> Dict[str, Any]:
    out = _runtime(offer)
    from app.match_market_rules import state_dict

    out["match_snapshot"] = state_dict(out.get("match_snapshot"))
    out["slots"] = list(out.get("slots") or [])
    return out


async def crew_view(ctx: Ctx, offer: Dict[str, Any], claims: List[Dict[str, Any]], *, detail: bool) -> Dict[str, Any]:
    from app import match_market_crew as C

    rt = _crew_runtime(offer)
    claims_rt = [_runtime(c) for c in claims]
    actor = await crew_actor(ctx)
    key = rt["province"]
    try:
        cfg, can_manage = await C._viewer(actor, key)
    except Exception:  # noqa: BLE001 - panel bez uprawnienia: widok jak dla zarządzającego (konto prezentacji)
        cfg, can_manage = {"hide_claimers": False}, True
    roster = await C._roster_for(key)
    my_roles = C._my_roles(roster, actor.judge_id, C.R.roles_of(rt["slots"]))
    cards = await C._judge_cards([rt.get("created_by")] + [c.get("judge_id") for c in claims_rt] + [c.get("partner_id") for c in claims_rt])
    view = C._offer_view(
        rt, claims_rt, cards, viewer_id=actor.judge_id, can_manage=can_manage, my_roles=my_roles, now=_now(),
        hide_names=bool(cfg.get("hide_claimers")) and not can_manage,
    )
    if detail and can_manage:
        try:
            claims_view = await C._claims_view(rt, claims_rt, cards, quick=True)
        except Exception:  # noqa: BLE001
            claims_view = {"table": [], "field": [], "packages": []}
        view["metricsPending"] = bool(claims_view.pop("_pending", False))
        view["claims"] = claims_view
    return view


async def _crew_real(offer_id: int) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    from app import match_market_crew as C

    offer = await C._load_offer(offer_id)
    claims = await C._claims_of(offer_id)
    return offer, claims


async def crew_load(offer_id: int) -> Optional[Dict[str, Any]]:
    """Oferta obsadowego z nakładką: {offer, claims, rid, kind} albo None (brak)."""
    if PS.is_synthetic(offer_id):
        found = await PS.overlay_get("crew_offer", offer_id)
        if not found:
            return None
        return {"rid": found[0], "kind": "crew_offer", "data": found[1], "offer": found[1]["offer"], "claims": found[1].get("claims") or []}
    offer, claims = await _crew_real(offer_id)
    found = await PS.overlay_get("crew_patch", offer_id)
    patch = found[1] if found else {"offer": {}, "claims_add": [], "claims_patch": {}}
    offer = {**_jsonable(offer), **(patch.get("offer") or {})}
    merged = []
    for c in claims:
        c = _jsonable(c)
        c.update((patch.get("claims_patch") or {}).get(str(c.get("id")), {}))
        merged.append(c)
    merged += list(patch.get("claims_add") or [])
    return {"rid": found[0] if found else None, "kind": "crew_patch", "data": patch, "offer": offer, "claims": merged, "real_claims": {str(c["id"]) for c in claims}}


async def crew_store(offer_id: int, loaded: Dict[str, Any]) -> None:
    if loaded["kind"] == "crew_offer":
        data = loaded["data"]
        data["offer"] = _jsonable(loaded["offer"])
        data["claims"] = [_jsonable(c) for c in loaded["claims"]]
        await PS.overlay_put(loaded["rid"], data)
        return
    patch = loaded["data"]
    real = loaded.get("real_claims") or set()
    patch["offer"] = {k: v for k, v in _jsonable(loaded["offer"]).items() if k in ("status", "closed_reason", "closed_at")}
    patch["claims_patch"] = {
        str(c["id"]): {k: c.get(k) for k in ("status", "slot")} for c in loaded["claims"] if str(c.get("id")) in real
    }
    patch["claims_add"] = [_jsonable(c) for c in loaded["claims"] if str(c.get("id")) not in real]
    await _save_patch(offer_id, loaded["rid"], patch, kind="crew_patch")


async def merge_crew_list(ctx: Ctx, data: Any) -> Any:
    if data is None:
        return None
    patches = {key for key, _d in await _patches("crew_patch")}
    offers = []
    for item in data.get("offers") or []:
        if str(item.get("id")) in patches:
            loaded = await crew_load(int(item["id"]))
            if loaded:
                item = await crew_view(ctx, loaded["offer"], loaded["claims"], detail=False)
        offers.append(item)
    actor = await crew_actor(ctx)
    key = _canonical(ctx.query.get("province")) if ctx.query.get("province") else _s(getattr(actor, "province", ""))
    show_all = ctx.query.get("scope") == "all"
    extra = []
    for _rid, d in await PS.overlay_list("crew_offer"):
        offer = d.get("offer") or {}
        if key and _canonical(offer.get("province")) != _canonical(key):
            continue
        if not show_all and _s(offer.get("status")) != "open":
            continue
        extra.append(await crew_view(ctx, offer, d.get("claims") or [], detail=False))
    data["offers"] = extra + offers
    return data


async def merge_crew_detail(ctx: Ctx, data: Any) -> Any:
    offer_id = ctx.pid()
    if data is None:
        if PS.is_synthetic(offer_id):
            loaded = await crew_load(offer_id)
            if not loaded:
                return Result(404, {"error": "Nie ma takiej oferty. Mogła zostać usunięta."})
            return Result(200, await crew_view(ctx, loaded["offer"], loaded["claims"], detail=True))
        return None
    if await PS.overlay_get("crew_patch", offer_id) is None:
        return data
    loaded = await crew_load(offer_id)
    return await crew_view(ctx, loaded["offer"], loaded["claims"], detail=True) if loaded else data


async def crew_create(ctx: Ctx, route) -> Result:
    from app import match_market_crew as C

    actor = await crew_actor(ctx)
    try:
        key = C._key(actor, ctx.b("province"))
    except Exception:  # noqa: BLE001
        key = _canonical(ctx.b("province"))
    match_id = _s(ctx.b("matchId"))
    mctx = await C._match_context(key, match_id)
    editable = [s for s in mctx["access"]["editable_slots"] if s in C.R.CREW_SLOTS]
    slots = (
        C.R.normalize_slots(ctx.b("slots"))
        if ctx.b("slots") is not None
        else C.R.suggest_slots(mctx["crew"], editable, mctx["needs"])["slots"]
    )
    try:
        flt = C.R.parse_filter(ctx.b("badgeFilter"))
    except ValueError:
        flt = C.R.parse_filter(None)
    match_at = C._utc(mctx["row"]["match_at"])
    deadline = C._parse_dt(ctx.b("deadlineAt")) or C.R.default_deadline(match_at)
    offer_id = await PS.next_synthetic_id()
    offer = await _crew_offer_row(offer_id, key, match_id, mctx["code"], slots, flt, deadline, match_at, mctx["state"], actor.judge_id, _s(ctx.b("comment")))
    await PS.overlay_add("crew_offer", offer_id, {"offer": offer, "claims": [], "account": ctx.account})
    return Result(201, await crew_view(ctx, offer, [], detail=True), f"Oferta obsadowego na mecz {match_id}")


async def _crew_offer_row(offer_id, key, match_id, code, slots, flt, deadline, match_at, state, created_by, comment) -> Dict[str, Any]:
    return _jsonable(
        {
            "id": offer_id, "province": key, "match_id": _s(match_id), "match_code": code, "slots": list(slots),
            "comment": comment or None, "badge_filter": flt, "deadline_at": deadline, "match_at": match_at,
            "match_snapshot": state, "status": "open", "created_by": created_by, "created_at": _now(),
            "closed_reason": None, "closed_at": None,
        }
    )


async def crew_claim(ctx: Ctx, route) -> Result:
    offer_id = ctx.pid()
    loaded = await crew_load(offer_id)
    if not loaded:
        return Result(404, {"error": "Nie ma takiej oferty. Mogła zostać usunięta."})
    actor = await crew_actor(ctx)
    from app import match_market_crew_rules as R

    roles = R.roles_of(loaded["offer"].get("slots") or [])
    role = _s(ctx.b("role")) or (roles[0] if len(roles) == 1 else R.ROLE_FIELD)
    claim_id = await PS.next_synthetic_id()
    loaded["claims"] = [c for c in loaded["claims"] if not (_s(c.get("judge_id")) == actor.judge_id and str(c.get("id")) not in (loaded.get("real_claims") or set()))]
    loaded["claims"].append(
        {"id": claim_id, "offer_id": offer_id, "judge_id": actor.judge_id, "role": role,
         "partner_id": _s(ctx.b("partnerId")) or None, "note": _s(ctx.b("note")) or None,
         "status": R.PENDING, "slot": None, "source": None, "created_at": _now().isoformat()}
    )
    await crew_store(offer_id, loaded)
    view = await crew_view(ctx, loaded["offer"], loaded["claims"], detail=True)
    view["claimId"] = claim_id
    return Result(201, view, f"Zgłoszenie na ofertę obsadowego {offer_id}")


async def crew_withdraw_claim(ctx: Ctx, route) -> Result:
    offer_id = ctx.pid()
    loaded = await crew_load(offer_id)
    if not loaded:
        return Result(404, {"error": "Nie ma takiej oferty. Mogła zostać usunięta."})
    actor = await crew_actor(ctx)
    for c in loaded["claims"]:
        if _s(c.get("judge_id")) == actor.judge_id and _s(c.get("status")) != "withdrawn":
            c["status"], c["slot"] = "withdrawn", None
    await crew_store(offer_id, loaded)
    return Result(200, await crew_view(ctx, loaded["offer"], loaded["claims"], detail=True), f"Wycofanie zgłoszenia z oferty {offer_id}")


async def crew_assign(ctx: Ctx, route) -> Result:
    from app import match_market_crew_rules as R

    offer_id = ctx.pid()
    loaded = await crew_load(offer_id)
    if not loaded:
        return Result(404, {"error": "Nie ma takiej oferty. Mogła zostać usunięta."})
    offer = loaded["offer"]
    claim = None
    if ctx.b("claimId") is not None:
        claim = next((c for c in loaded["claims"] if int(c.get("id") or 0) == int(ctx.b("claimId"))), None)
    if claim is None and _s(ctx.b("judgeId")):
        claim = {"id": await PS.next_synthetic_id(), "offer_id": offer_id, "judge_id": _s(ctx.b("judgeId")),
                 "role": _s(ctx.b("role")) or R.ROLE_FIELD, "partner_id": None, "note": None, "status": R.PENDING,
                 "slot": None, "source": "suggested", "created_at": _now().isoformat()}
        loaded["claims"].append(claim)
    if claim is None:
        return Result(404, {"error": "Nie ma takiego zgłoszenia."})
    held = {_s(c.get("slot")) for c in loaded["claims"] if _s(c.get("status")) == R.ASSIGNED and c.get("slot")}
    role_slots = R.FIELD_SLOTS if _s(claim.get("role")) == R.ROLE_FIELD else R.TABLE_SLOTS
    slot = _s(ctx.b("slot")) or next((s for s in offer.get("slots") or [] if s in role_slots and s not in held), "")
    if not slot:
        slot = next((s for s in offer.get("slots") or [] if s not in held), "")
    claim["status"], claim["slot"] = R.ASSIGNED, slot or None
    held.add(slot)
    if all(s in held for s in offer.get("slots") or []):
        offer["status"], offer["closed_reason"] = R.FILLED, "filled"
    await crew_store(offer_id, loaded)
    await _draft_add_market_change(ctx, offer, claim, slot)
    return Result(200, await crew_view(ctx, offer, loaded["claims"], detail=True), f"Przydział z giełdy: oferta {offer_id}, gniazdo {slot}")


async def crew_unassign(ctx: Ctx, route) -> Result:
    from app import match_market_crew_rules as R

    offer_id, claim_id = ctx.pid(), ctx.pid("cid")
    loaded = await crew_load(offer_id)
    if not loaded:
        return Result(404, {"error": "Nie ma takiej oferty. Mogła zostać usunięta."})
    claim = next((c for c in loaded["claims"] if int(c.get("id") or 0) == claim_id), None)
    if claim:
        suggested = _s(claim.get("source")) == "suggested"
        claim["status"], claim["slot"] = (R.CLAIM_WITHDRAWN if suggested else R.PENDING), None
    if _s(loaded["offer"].get("status")) == R.FILLED:
        loaded["offer"]["status"], loaded["offer"]["closed_reason"] = R.OPEN, None
    await crew_store(offer_id, loaded)
    removed = await _draft_remove_market_change(ctx, loaded["offer"], claim_id)
    view = await crew_view(ctx, loaded["offer"], loaded["claims"], detail=True)
    view["unassign"] = {
        "removedFromQueue": removed,
        "queuedRemovalFromCrew": False,
        "note": "Wpis zniknął z kolejki Obsady." if removed else "W terminarzu nie było już tego sędziego.",
        "suggestedClaimRemoved": bool(claim and _s(claim.get("source")) == "suggested"),
    }
    return Result(200, view, f"Cofnięcie przydziału w ofercie {offer_id}")


async def crew_withdraw(ctx: Ctx, route) -> Result:
    from app import match_market_crew_rules as R

    offer_id = ctx.pid()
    loaded = await crew_load(offer_id)
    if not loaded:
        return Result(404, {"error": "Nie ma takiej oferty. Mogła zostać usunięta."})
    loaded["offer"].update(status=R.WITHDRAWN, closed_reason="withdrawn", closed_at=_now().isoformat())
    await crew_store(offer_id, loaded)
    return Result(200, await crew_view(ctx, loaded["offer"], loaded["claims"], detail=True), f"Wycofanie oferty obsadowego {offer_id}")


async def crew_invite(ctx: Ctx, route) -> Result:
    limit = 3
    try:
        from app import match_market_crew_suggest_rules as S  # type: ignore

        limit = int(getattr(S, "INVITE_LIMIT", limit))
    except Exception:  # noqa: BLE001
        pass
    return Result(
        201,
        {"ok": True, "invite": {"judgeId": _s(ctx.b("judgeId")), "role": ctx.b("role"), "invitedAt": _now().isoformat()},
         "invitesUsed": 1, "invitesLeft": max(0, limit - 1)},
        f"Zaproszenie sędziego {_s(ctx.b('judgeId'))} (bez pusha)",
    )


# ───────────────────────────── szkic kolejki Obsady ─────────────────────────────


async def _real_draft(key: str) -> Dict[str, Any]:
    try:
        from app.province_assignment_board import draft_payload

        return await draft_payload(key)
    except Exception:  # noqa: BLE001
        return {"rev": 0, "changes": [], "updated_by": None, "updated_at": None}


async def draft_current(key: str) -> Tuple[Optional[int], Dict[str, Any]]:
    found = await PS.overlay_get("draft", key)
    if found:
        return found[0], found[1]
    return None, await _real_draft(key)


async def _draft_save(key: str, rid: Optional[int], draft: Dict[str, Any]) -> None:
    if rid is None:
        await PS.overlay_add("draft", key, draft)
    else:
        await PS.overlay_put(rid, draft)


async def obsada_draft(ctx: Ctx, route) -> Result:
    key = _canonical(ctx.b("province"))
    rid, current = await draft_current(key)
    changes = ctx.b("changes") or []
    try:
        from app import assignment_board_rules as B

        changes = B.clean_draft_changes(changes)
    except ValueError as exc:
        return Result(400, {"error": str(exc), "detail": str(exc)})
    except Exception:  # noqa: BLE001
        pass
    rev = max(int(ctx.b("base_rev") or 0), int(current.get("rev") or 0)) + 1
    draft = {"rev": rev, "changes": changes, "updated_by": _s(ctx.b("updated_by")) or None, "updated_at": _now().isoformat()}
    await _draft_save(key, rid, draft)
    return Result(200, {"rev": rev}, f"Szkic kolejki Obsady ({len(changes)} zmian)")


async def _draft_add_market_change(ctx: Ctx, offer: Dict[str, Any], claim: Dict[str, Any], slot: str) -> None:
    key = _canonical(offer.get("province"))
    rid, draft = await draft_current(key)
    cards = await judge_cards([claim.get("judge_id")])
    cid = f"market-{claim['id']}"
    changes = [c for c in draft.get("changes") or [] if not (isinstance(c, dict) and _s(c.get("id")) == cid)]
    label = ""
    try:
        from app import assignment_board_rules as B

        label = B.match_label(offer.get("match_snapshot") or {}, offer.get("match_code") or "")
    except Exception:  # noqa: BLE001
        pass
    changes.append(
        {"id": cid, "match_id": _s(offer.get("match_id")), "kind": "slot", "slot": slot,
         "judge_id": _s(claim.get("judge_id")), "name": _s((cards.get(_s(claim.get("judge_id"))) or {}).get("full_name")),
         "before_id": "", "before_name": "", "source": "market", "offer_id": offer.get("id"),
         "author": ctx.login or ctx.judge_id, "at": _now().isoformat(), "match_label": label}
    )
    await _draft_save(key, rid, {**draft, "rev": int(draft.get("rev") or 0) + 1, "changes": changes, "updated_at": _now().isoformat()})


async def _draft_remove_market_change(ctx: Ctx, offer: Dict[str, Any], claim_id: int) -> bool:
    key = _canonical(offer.get("province"))
    rid, draft = await draft_current(key)
    cid = f"market-{claim_id}"
    changes = draft.get("changes") or []
    kept = [c for c in changes if not (isinstance(c, dict) and _s(c.get("id")) == cid)]
    if len(kept) == len(changes):
        return False
    await _draft_save(key, rid, {**draft, "rev": int(draft.get("rev") or 0) + 1, "changes": kept, "updated_at": _now().isoformat()})
    return True


async def merge_draft(ctx: Ctx, data: Any) -> Any:
    found = await PS.overlay_get("draft", _canonical(ctx.query.get("province")))
    if data is None:
        return Result(200, found[1]) if found else None
    return data


async def merge_bootstrap(ctx: Ctx, data: Any) -> Any:
    if data is None:
        return None
    found = await PS.overlay_get("draft", _canonical(ctx.query.get("province")))
    if found:
        data["draft"] = found[1]
    return data


merge_bootstrap.strip_etag = True  # type: ignore[attr-defined]


# ───────────────────────────── obsada: zapisy do ZPRP ─────────────────────────────


def _fetched_at() -> str:
    return _now().isoformat()


async def obsada_save(ctx: Ctx, route) -> Result:
    """Zapis obsady: odpowiedź `apply_referee_assignment` z gniazdami „po zapisie"."""
    expect = ctx.b("expect") or {}
    try:
        from app.assignment_board_rules import normalize_slot
    except Exception:  # noqa: BLE001
        normalize_slot = lambda value: value  # noqa: E731
    if isinstance(expect, dict):
        # Obsada 2.0 przysyła `expect` w nazwach gniazd tablicy (pierwszy, drugi...).
        expect = {**{normalize_slot(k): v for k, v in expect.items()}, **expect}
    before = {}
    verified = {}
    sent = []
    for label in ZPRP_SLOTS:
        select_name = SLOT_TO_SELECT[label]
        seen_name = _s(expect.get(label) or expect.get(normalize_slot(label))) if isinstance(expect, dict) else ""
        before[label] = {"value": None, "name": seen_name}
        value = ctx.b(select_name)
        if value is not None:
            sent.append(label)
            verified[label] = {"value": _s(value), "name": _s(ctx.b(f"{select_name}_name")) if _s(value) else ""}
        else:
            verified[label] = {"value": None, "name": seen_name}
    result: Dict[str, Any] = {
        "success": True,
        "code": None,
        "fetched_at": _fetched_at(),
        "before_slots": before,
        "verified_slots": verified,
        "error": None,
    }
    if ctx.b("province"):
        result["journal"] = None
        result["announced"] = {"changed": bool(sent), "events": 0}
    names = ", ".join(f"{label}: {verified[label]['name'] or '-'}" for label in sent)
    return Result(200, result, f"Obsada meczu {_s(ctx.b('IdZawody'))} ({names or 'bez zmian'}) - bez ZPRP")


async def obsada_save_hall(ctx: Ctx, route) -> Result:
    hall = ctx.b("hall") or {}
    result = {
        "success": True,
        "fetched_at": _fetched_at(),
        "select_name_used": "IdHala",
        "selected_id": _s(ctx.b("hall_id")),
        "hall_name": _s(hall.get("name")) if isinstance(hall, dict) else "",
        "error": None,
    }
    if ctx.b("province"):
        result["journal"] = None
        result["announced"] = {"changed": True, "events": 0}
    return Result(200, result, f"Hala meczu {_s(ctx.b('IdZawody'))} - bez ZPRP")


async def obsada_save_date(ctx: Ctx, route) -> Result:
    wanted = _s(ctx.b("date_value"))
    try:
        from app.zprp.assignments import _normalise_match_date

        wanted = _normalise_match_date(wanted) or wanted
    except Exception:  # noqa: BLE001
        pass
    result = {"success": True, "fetched_at": _fetched_at(), "date_value": wanted, "error": None}
    if ctx.b("province"):
        result["journal"] = None
        result["announced"] = {"changed": True, "events": 0}
    return Result(200, result, f"Termin meczu {_s(ctx.b('IdZawody'))}: {wanted} - bez ZPRP")


async def obsada_table_save(ctx: Ctx, route) -> Result:
    body = {"ok": True, "name": _s(ctx.b("name")), "role": _s(ctx.b("role")), "fetched_at": _fetched_at()}
    return Result(200, body, f"Stolikowy {body['role']}: {body['name']} - bez ZPRP")


async def obsada_table_clear(ctx: Ctx, route) -> Result:
    return Result(200, {"ok": True, "role": _s(ctx.b("role")), "fetched_at": _fetched_at()}, "Usunięcie stolikowego - bez ZPRP")


async def obsada_judge_settings(ctx: Ctx, route) -> Result:
    days = sorted({int(d) for d in (ctx.b("preferred_days") or []) if str(d).lstrip("-").isdigit() and 0 <= int(d) <= 6})
    role = _s(ctx.b("assign_role")).lower()
    return Result(
        200,
        {"success": True, "judge_id": _s(ctx.params.get("judge_id")), "preferred_days": days, "assign_role": role if role in ("both", "table", "field") else ""},
        f"Parametry sędziego {_s(ctx.params.get('judge_id'))}",
    )


async def obsada_me_availability(ctx: Ctx, route) -> Result:
    got = await ctx.sub("GET", "/province/me/availability", {"province": ctx.b("province") or ""})
    view = got.json() if got.status == 200 and isinstance(got.json(), dict) else {"preferred_days": [], "assign_role": "both", "note": "", "home_city": None}
    if ctx.b("preferred_days") is not None:
        view["preferred_days"] = sorted({int(d) for d in ctx.b("preferred_days") if str(d).isdigit() and 0 <= int(d) <= 6})
    if _s(ctx.b("assign_role")).lower() in ("both", "field", "table"):
        view["assign_role"] = _s(ctx.b("assign_role")).lower()
    if ctx.b("note") is not None:
        view["note"] = _s(ctx.b("note"))
    return Result(200, view, "Moja dyspozycyjność")


async def obsada_runs_undone(ctx: Ctx, route) -> Result:
    return Result(200, {"success": True, "undone": len(ctx.b("change_ids") or [])}, route.label)


async def obsada_auto_dry_run(ctx: Ctx, route) -> Result:
    """Automat liczy naprawdę (odczyty), ale przebieg NIE trafia do historii."""
    token = PS.DRY_RUN.set(True)
    try:
        got = await ctx.sub("POST", ctx.path, ctx.query, ctx.body if isinstance(ctx.body, dict) else {})
    finally:
        PS.DRY_RUN.reset(token)
    data = got.json()
    if got.status == 200 and isinstance(data, dict) and data.get("run_id") is None:
        data["run_id"] = await PS.next_synthetic_id()
    return Result(got.status, data, "Automat (propozycje bez zapisu przebiegu)")


# ───────────────────────────── niedyspozycje ─────────────────────────────


async def offtime_zprp_create(ctx: Ctx, route) -> Result:
    await PS.overlay_add("offtime", ctx.account, {"op": "create", "from": ctx.b("DataOd"), "to": ctx.b("DataDo"), "info": ctx.b("Info")})
    return Result(200, {"success": True, "mailAlert": None}, f"Niedyspozycja {ctx.b('DataOd')} - {ctx.b('DataDo')} (bez ZPRP)")


async def offtime_zprp_update(ctx: Ctx, route) -> Result:
    await PS.overlay_add("offtime", ctx.account, {"op": "update", "id": ctx.b("IdOffT"), "from": ctx.b("DataOd"), "to": ctx.b("DataDo"), "info": ctx.b("Info")})
    return Result(200, {"success": True, "mailAlert": None}, f"Zmiana niedyspozycji {ctx.b('IdOffT')} (bez ZPRP)")


async def offtime_zprp_delete(ctx: Ctx, route) -> Result:
    await PS.overlay_add("offtime", ctx.account, {"op": "delete", "id": ctx.b("IdOffT")})
    return Result(200, {"success": True}, f"Usunięcie niedyspozycji {ctx.b('IdOffT')} (bez ZPRP)")


async def offtime_silesia_set(ctx: Ctx, route) -> Result:
    return Result(200, {"success": True}, f"Niedyspozycje okręgu sędziego {_s(ctx.b('judge_id'))}")


def _assigned_item(ctx: Ctx, item_id: str, judge_id: str) -> Dict[str, Any]:
    now = _now().isoformat()
    body = _echo(ctx)
    body.pop("judge_ids", None)
    return {"id": item_id, "province": _s(ctx.b("province")), "judge_id": judge_id, **body,
            "created_by": ctx.judge_id or ctx.login, "created_at": now, "updated_at": now}


async def offtime_assigned_create(ctx: Ctx, route) -> Result:
    targets = [_s(j) for j in (ctx.b("judge_ids") or []) if _s(j)]
    items = []
    for jid in targets:
        item = _assigned_item(ctx, f"presentation-{await PS.next_synthetic_id()}", jid)
        try:
            from app.offtime_assignments import build_item

            item = build_item(_assigned_row(ctx, item))
        except Exception:  # noqa: BLE001
            pass
        items.append(item)
    return Result(200, {"items": items}, f"Niedyspozycja wpisana {len(items)} sędziom")


def _assigned_row(ctx: Ctx, item: Dict[str, Any]) -> Dict[str, Any]:
    from app.offtime_assignments_rules import normalize_fields

    return {"id": item["id"], "province": item["province"], "judge_id": item["judge_id"], **normalize_fields(ctx.body),
            "created_by": item["created_by"], "created_by_name": ctx.login or ctx.judge_id, "created_by_role": "admin",
            "created_at": _now(), "updated_at": _now()}


async def offtime_assigned_update(ctx: Ctx, route) -> Result:
    return Result(200, {"item": _assigned_item(ctx, _s(ctx.params.get("item")), _s(ctx.b("judge_id")))}, route.label)


async def partner_offtime_upsert(ctx: Ctx, route) -> Result:
    body = {
        "judge_id": _s(ctx.b("judge_id")) or _s(ctx.params.get("judge_id")),
        "full_name": _s(ctx.b("full_name")),
        "partner_id": ctx.b("partner_id"),
        "data_json": ctx.b("data_json"),
        "updated_at": _now().isoformat(),
    }
    return Result(route.status, body, route.label)


# ───────────────────────────── ogłoszenia ─────────────────────────────


def _ann_decrypt(value: Any) -> str:
    from app.presentation_middleware import decrypt_candidates

    found = decrypt_candidates(value)
    return found[-1] if found else _s(value)


async def _ann_list(ctx: Ctx, province: Optional[str]) -> List[Dict[str, Any]]:
    got = await ctx.sub("GET", "/silesia/announcements/", {"province": province} if province else None)
    data = got.json() if got.status == 200 else None
    return list((data or {}).get("announcements") or [])


async def _ann_find(ctx: Ctx, ann_id: int) -> Optional[Dict[str, Any]]:
    if PS.is_synthetic(ann_id):
        found = await PS.overlay_get("announcement", ann_id)
        return dict(found[1]) if found else None
    item = next((a for a in await _ann_list(ctx, None) if int(a.get("id") or 0) == ann_id), None)
    if item is None:
        return None
    patch = await PS.overlay_get("announcement_patch", ann_id)
    return {**item, **(patch[1] if patch else {})}


async def _ann_store(ann_id: int, item: Dict[str, Any]) -> None:
    kind = "announcement" if PS.is_synthetic(ann_id) else "announcement_patch"
    await PS.overlay_upsert(kind, ann_id, item)


def _ann_clean(item: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in item.items() if v is not None and k != "deleted"}


async def ann_create(ctx: Ctx, route) -> Result:
    ann_id = await PS.next_synthetic_id()
    item = {
        "id": ann_id,
        "title": _ann_decrypt(ctx.b("title")),
        "content": _s(ctx.b("content")),
        "link": ctx.b("link") or None,
        "image_url": None,
        "thumb_url": None,
        "priority": int(ctx.b("priority") or 0),
        "updated_at": _now().isoformat(),
        "judge_name": _ann_decrypt(ctx.b("full_name")) or None,
        "province": _s(ctx.b("province")),
        "likes": [],
        "comments": [],
    }
    await PS.overlay_add("announcement", ann_id, item)
    return Result(201, _ann_clean(item), f"Ogłoszenie „{item['title']}” (bez pusha)")


async def ann_update(ctx: Ctx, route) -> Result:
    ann_id = ctx.pid()
    item = await _ann_find(ctx, ann_id)
    if item is None:
        return Result(404, {"error": "Ogłoszenie nie istnieje"})
    if ctx.b("title"):
        item["title"] = _ann_decrypt(ctx.b("title"))
    for key in ("content", "link", "province"):
        if ctx.b(key) is not None:
            item[key] = ctx.b(key)
    if ctx.b("priority") is not None:
        item["priority"] = int(ctx.b("priority") or 0)
    item["updated_at"] = _now().isoformat()
    await _ann_store(ann_id, item)
    return Result(200, _ann_clean(item), f"Zmiana ogłoszenia {ann_id}")


async def ann_reaction(ctx: Ctx, route) -> Result:
    ann_id = ctx.pid()
    item = await _ann_find(ctx, ann_id)
    if item is None:
        return Result(404, {"error": "Ogłoszenie nie istnieje"})
    jid, reaction = _s(ctx.b("judge_id")), ctx.b("reaction")
    likes = [dict(x) for x in item.get("likes") or []]
    idx = next((i for i, x in enumerate(likes) if _s(x.get("judge_id")) == jid), None)
    if idx is None:
        likes.append({"judge_id": jid, "full_name": ctx.b("full_name"), "reaction": reaction, "created_at": _now().isoformat()})
    elif likes[idx].get("reaction") == reaction:
        likes.pop(idx)
    else:
        likes[idx]["reaction"] = reaction
    item["likes"] = likes
    await _ann_store(ann_id, item)
    return Result(200, _ann_clean(item), f"Reakcja na ogłoszenie {ann_id}")


async def ann_comment(ctx: Ctx, route) -> Result:
    import uuid

    ann_id = ctx.pid()
    item = await _ann_find(ctx, ann_id)
    if item is None:
        return Result(404, {"error": "Ogłoszenie nie istnieje"})
    comments = list(item.get("comments") or [])
    comments.append({"id": str(uuid.uuid4()), "judge_id": _s(ctx.b("judge_id")), "full_name": ctx.b("full_name"),
                     "text": _s(ctx.b("text")), "created_at": _now().isoformat(), "is_pinned": False})
    item["comments"] = comments
    await _ann_store(ann_id, item)
    return Result(200, _ann_clean(item), f"Komentarz pod ogłoszeniem {ann_id}")


async def ann_comment_edit(ctx: Ctx, route) -> Result:
    ann_id = ctx.pid()
    item = await _ann_find(ctx, ann_id)
    if item is None:
        return Result(404, {"error": "Ogłoszenie nie istnieje"})
    comments = [dict(c) for c in item.get("comments") or []]
    target = _s(ctx.b("comment_id"))
    if ctx.path.endswith("comment_delete"):
        comments = [c for c in comments if _s(c.get("id")) != target]
    else:
        for c in comments:
            if _s(c.get("id")) == target:
                c["is_pinned"] = bool(ctx.b("pin"))
    item["comments"] = comments
    await _ann_store(ann_id, item)
    return Result(200, _ann_clean(item), route.label)


async def ann_delete(ctx: Ctx, route) -> Result:
    ann_id = ctx.pid()
    if PS.is_synthetic(ann_id):
        found = await PS.overlay_get("announcement", ann_id)
        if found:
            await PS.overlay_put(found[0], {**found[1], "deleted": True})
    else:
        await PS.overlay_upsert("announcement_patch", ann_id, {"deleted": True})
    return Result(204, None, f"Usunięcie ogłoszenia {ann_id}")


async def merge_announcements(ctx: Ctx, data: Any) -> Any:
    if data is None:
        return None
    province = ctx.query.get("province")
    patches = {key: d for key, d in await _patches("announcement_patch")}
    items = []
    for item in data.get("announcements") or []:
        patch = patches.get(str(item.get("id")))
        if patch:
            if patch.get("deleted"):
                continue
            item = _ann_clean({**item, **patch})
        items.append(item)
    for _rid, item in await PS.overlay_list("announcement"):
        if item.get("deleted") or (province and _s(item.get("province")) != province):
            continue
        items.append(_ann_clean(item))
    items.sort(key=lambda a: int(a.get("priority") or 0))
    data["announcements"] = items
    return data


# ───────────────────────────── wydarzenia ─────────────────────────────


async def event_create(ctx: Ctx, route) -> Result:
    event_id = await PS.next_synthetic_id()
    return Result(200, {"ids": [event_id], "series_id": None, "invited": 0, "reused": False}, f"Wydarzenie „{_s(ctx.b('name'))}” (bez pushy)")


async def event_patch(ctx: Ctx, route) -> Result:
    return Result(200, {"updated": 1}, f"Zmiana wydarzenia {ctx.pid()}")


async def event_trash(ctx: Ctx, route) -> Result:
    return Result(200, {"ids": [ctx.pid()]}, f"Wydarzenie {ctx.pid()} do kosza")


async def event_restore(ctx: Ctx, route) -> Result:
    ids = ctx.b("ids") or ([ctx.b("id")] if ctx.b("id") else [])
    return Result(200, {"restored": len(ids)}, route.label)


def _apply_rsvp(view: Dict[str, Any], rsvp: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not rsvp or not isinstance(view, dict):
        return view
    me = view.setdefault("me", {})
    old = me.get("response")
    new = rsvp.get("status")
    me["response"], me["reason"] = new, rsvp.get("reason")
    counts = view.get("counts") or {}
    if counts and old != new:
        for status, key in (("yes", "yes"), ("no", "no")):
            if old == status:
                counts[key] = max(0, int(counts.get(key) or 0) - 1)
            if new == status:
                counts[key] = int(counts.get(key) or 0) + 1
        counts["pending"] = max(0, int(counts.get("invited") or 0) - int(counts.get("yes") or 0) - int(counts.get("no") or 0))
    return view


async def _event_item(ctx: Ctx, event_id: int) -> Tuple[int, Any]:
    got = await ctx.sub("GET", f"/province-events/item/{event_id}")
    return got.status, got.json()


async def event_rsvp(ctx: Ctx, route) -> Result:
    event_id = ctx.pid()
    rsvp = {"status": _s(ctx.b("status")), "reason": ctx.b("reason")}
    await PS.overlay_upsert("event_rsvp", f"{ctx.account}:{event_id}", rsvp)
    status, view = await _event_item(ctx, event_id)
    return Result(status, _apply_rsvp(view, rsvp) if status == 200 else view, f"Odpowiedź „{rsvp['status']}” na wydarzenie {event_id}")


async def event_attendance(ctx: Ctx, route) -> Result:
    status, view = await _event_item(ctx, ctx.pid())
    return Result(status, view, f"Obecność na wydarzeniu {ctx.pid()}")


async def event_checkin_open(ctx: Ctx, route) -> Result:
    got = await ctx.sub("GET", f"/province-events/{ctx.pid()}/checkin")
    return Result(got.status, got.json(), f"Kod obecności wydarzenia {ctx.pid()}")


async def event_checkin(ctx: Ctx, route) -> Result:
    return Result(200, {"already": False, "event": None}, "Potwierdzenie obecności kodem")


async def event_legacy_item(ctx: Ctx, route) -> Result:
    got = await ctx.sub("GET", f"/province-events/{ctx.pid()}", ctx.query)
    return Result(got.status, got.json(), route.label)


async def merge_event_item(ctx: Ctx, data: Any) -> Any:
    if data is None:
        return None
    found = await PS.overlay_get("event_rsvp", f"{ctx.account}:{ctx.pid()}")
    return _apply_rsvp(data, found[1]) if found else data


async def merge_event_feed(ctx: Ctx, data: Any) -> Any:
    if data is None:
        return None
    rsvps = {key: d for key, d in await _patches("event_rsvp") if key.startswith(ctx.account + ":")}
    for event in data.get("events") or []:
        hit = rsvps.get(f"{ctx.account}:{event.get('id')}")
        if hit:
            _apply_rsvp(event, hit)
    return data


SIMS: Dict[str, Callable[..., Awaitable[Result]]] = {
    name: fn
    for name, fn in dict(globals()).items()
    if callable(fn)
    and getattr(fn, "__module__", "") == __name__
    and name.split("_")[0] in ("ok", "no", "pdf", "market", "crew", "obsada", "offtime", "partner", "ann", "event")
    and name not in ("market_viewer", "market_offer", "market_patch")
}
MERGES: Dict[str, Callable[..., Awaitable[Any]]] = {
    name: fn for name, fn in dict(globals()).items() if name.startswith("merge_") and callable(fn)
}

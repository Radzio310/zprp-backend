"""Tryb prezentacji - trasy /presentation/* (tylko administrator aplikacji).

Kontrakt: `kontrakt_ustawienia.md` (22.11.2026), opis: `docs/presentation-mode.md`.
Stan, dziennik i nakładka: `app/presentation_state.py`; udawane odpowiedzi:
`app/presentation_sim.py`; przechwytywanie żądań: `app/presentation_middleware.py`.
"""

from __future__ import annotations

import logging
import os
import random
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app import presentation_state as PS
from app.access_control import require_app_admin

log = logging.getLogger("presentation")

router = APIRouter(prefix="/presentation", tags=["Tryb prezentacji"])

STARTED_AT = datetime.now(timezone.utc)
_STARTED_MONO = time.monotonic()


def _s(value: Any) -> str:
    return "" if value is None else str(value).strip()


async def state_view(state: Optional[PS.State] = None) -> Dict[str, Any]:
    state = state or await PS.current(force=True)
    active = state.active()
    minutes_left = None
    if active and state.expires_at is not None:
        minutes_left = max(0, int((state.expires_at - datetime.now(timezone.utc)).total_seconds() // 60))
    return {
        "enabled": active,
        "expires_at": PS._iso(state.expires_at) if active else None,
        "minutes_left": minutes_left,
        "accounts": state.accounts,
        "areas": [a for a in PS.AREAS if a in state.areas],
        "area_labels": dict(PS.AREA_LABELS),
        "ops_count": await PS.ops_count(),
        "enabled_by": state.enabled_by,
        "updated_at": PS._iso(state.updated_at),
    }


class StateRequest(BaseModel):
    enabled: bool
    accounts: Optional[List[Dict[str, Any]]] = None
    areas: Optional[List[str]] = None
    minutes: Optional[int] = None


@router.get("/state", summary="Stan trybu prezentacji")
async def get_state(_admin: dict = Depends(require_app_admin)) -> Dict[str, Any]:
    return await state_view()


@router.put("/state", summary="Włącz / wyłącz tryb prezentacji (administrator aplikacji)")
async def put_state(req: StateRequest, admin: dict = Depends(require_app_admin)) -> Dict[str, Any]:
    current = await PS.current(force=True)
    accounts = PS.clean_accounts(req.accounts) if req.accounts is not None else list(current.accounts)
    judge_id = _s(admin.get("judge_id"))
    if req.enabled and judge_id and not any(a["kind"] == "judge" and a["value"] == judge_id for a in accounts):
        # Konto admina, który włącza, zawsze w trybie - inaczej sam nagrałby prawdziwe zmiany.
        accounts.append({"kind": "judge", "value": judge_id, "label": _s(admin.get("full_name")) or f"Sędzia {judge_id}"})
    if req.areas is not None and PS.unknown_areas(req.areas):
        raise HTTPException(
            400,
            f"Nieznane obszary: {', '.join(PS.unknown_areas(req.areas))}. Dostępne: {', '.join(PS.AREAS)}.",
        )
    areas = PS.clean_areas(req.areas) if req.areas is not None else [a for a in PS.AREAS if a in current.areas]
    minutes: Optional[int] = PS.clamp_minutes(req.minutes) if req.minutes is not None else None
    if req.enabled and minutes is None and not current.active():
        minutes = PS.DEFAULT_MINUTES
    state = await PS.save_state(
        enabled=req.enabled,
        accounts=accounts,
        areas=areas,
        minutes=minutes,
        enabled_by=_s(admin.get("sub")) or judge_id,
    )
    if req.enabled and PS.learn(admin.get("sub"), judge_id, schedule=False):
        await PS.persist_learned()
    log.info("tryb prezentacji: %s przez %s", "WŁĄCZONY" if req.enabled else "wyłączony", admin.get("sub"))
    return await state_view(state)


@router.get("/ops", summary="Dziennik udawanych operacji")
async def get_ops(limit: int = Query(100, ge=1, le=500), _admin: dict = Depends(require_app_admin)) -> Dict[str, Any]:
    return {"items": await PS.list_ops(limit)}


@router.delete("/ops", summary="Wyczyść dziennik i nakładkę trybu prezentacji")
async def delete_ops(_admin: dict = Depends(require_app_admin)) -> Dict[str, Any]:
    return {"cleared": await PS.clear_ops()}


SCENES = ("market_offer_with_claims", "market_giveaway_ready", "young_rating_ready")


class SceneRequest(BaseModel):
    scene: str
    province: Optional[str] = None
    match_id: Optional[str] = None
    #: Sędzia trybu, dla którego scena (giełda: oddający, oceny: oceniający).
    #: Domyślnie pierwsze konto „judge" w stanie trybu.
    judge_id: Optional[str] = None


@router.post("/scene", summary="Przygotuj scenę demo w nakładce")
async def post_scene(req: SceneRequest, admin: dict = Depends(require_app_admin)) -> Dict[str, Any]:
    state = await PS.current(force=True)
    if not state.active():
        raise HTTPException(409, "Najpierw włącz tryb prezentacji - scena istnieje tylko w nakładce.")
    if req.scene not in SCENES:
        raise HTTPException(400, f"Nieznana scena. Dostępne: {', '.join(SCENES)}.")
    if req.scene == "market_offer_with_claims":
        if not _s(req.province):
            raise HTTPException(400, "Podaj okręg (province).")
        created = await build_market_scene(_s(req.province), req.match_id, admin)
    elif req.scene == "market_giveaway_ready":
        created = await build_giveaway_scene(req.province, req.match_id, scene_judge(state, req.judge_id), admin, state)
    else:
        created = await build_young_rating_scene(req.province, req.match_id, scene_judge(state, req.judge_id), admin)
    return {"ok": True, "created": created}


def scene_judge(state: PS.State, judge_id: Optional[str]) -> str:
    """Sędzia sceny: podany (musi być kontem trybu) albo pierwsze konto „judge"."""
    wanted = _s(judge_id)
    judges = [a["value"] for a in state.accounts if a.get("kind") == "judge"]
    if wanted:
        if wanted not in judges:
            raise HTTPException(
                400, f"Sędzia {wanted} nie jest kontem trybu prezentacji - dopisz go w PUT /presentation/state."
            )
        return wanted
    if not judges:
        raise HTTPException(400, "W trybie prezentacji nie ma konta sędziego - podaj judge_id albo dopisz konto.")
    return judges[0]


def _account_key(admin: Dict[str, Any]) -> str:
    return f"judge:{admin.get('judge_id')}" if admin.get("judge_id") else f"login:{admin.get('sub')}"


async def _upcoming_matches(key: str, limit: int = 25) -> List[Dict[str, Any]]:
    from sqlalchemy import and_, select

    from app.db import database, province_matches
    from app.settlement_province import spellings

    rows = await database.fetch_all(
        select(province_matches.c.match_id, province_matches.c.match_at)
        .where(
            and_(
                province_matches.c.province.in_(spellings(key) or [key]),
                province_matches.c.active.is_(True),
                province_matches.c.match_at > datetime.now(timezone.utc),
            )
        )
        .order_by(province_matches.c.match_at.asc())
        .limit(limit)
    )
    return [dict(r._mapping) if hasattr(r, "_mapping") else dict(r) for r in rows]


async def scene_claimers(key: str, exclude: List[str], count: int = 2) -> List[Dict[str, Any]]:
    """Prawdziwi sędziowie okręgu - aktywni, ze zdjęciem najpierw, nigdy pytający."""
    from sqlalchemy import select

    from app.db import database, province_judges
    from app.settlement_province import spellings

    rows = await database.fetch_all(
        select(province_judges.c.judge_id, province_judges.c.full_name, province_judges.c.photo_url).where(
            province_judges.c.province.in_(spellings(key) or [key])
        )
    )
    inactive: set = set()
    try:
        from app.db import province_judge_inactive

        inactive = {
            _s(r["judge_id"])
            for r in await database.fetch_all(
                select(province_judge_inactive.c.judge_id).where(province_judge_inactive.c.province_key == key)
            )
        }
    except Exception:  # noqa: BLE001
        inactive = set()
    skip = {_s(x) for x in exclude if _s(x)}
    people = [
        {"judge_id": _s(r["judge_id"]), "name": _s(r["full_name"]), "photo_url": _s(r["photo_url"]) or None}
        for r in rows
        if _s(r["judge_id"]) and _s(r["judge_id"]) not in skip and _s(r["judge_id"]) not in inactive
    ]
    with_photo = [p for p in people if p["photo_url"]]
    pool = with_photo if len(with_photo) >= count else people
    return random.sample(pool, min(count, len(pool)))


async def build_market_scene(province: str, match_id: Optional[str], admin: Dict[str, Any]) -> Dict[str, Any]:
    """Oferta obsadowego na prawdziwym, nadchodzącym meczu + 2 zgłoszenia (tylko nakładka)."""
    from app import match_market_crew as C
    from app import presentation_sim as sim

    key = sim._canonical(province)
    candidates = [{"match_id": match_id}] if match_id else await _upcoming_matches(key)
    chosen = None
    for cand in candidates:
        try:
            mctx = await C._match_context(key, _s(cand["match_id"]))
        except HTTPException:
            continue
        editable = [s for s in mctx["access"]["editable_slots"] if s in C.R.CREW_SLOTS]
        slots = C.R.suggest_slots(mctx["crew"], editable, mctx["needs"])["slots"] or editable[:2]
        if slots or match_id:
            chosen = (cand["match_id"], mctx, slots or ["sekretarz"])
            break
    if chosen is None:
        raise HTTPException(404, "Nie znalazłem nadchodzącego meczu okręgu z wolnym gniazdem do sceny.")
    mid, mctx, slots = chosen
    author = _s(admin.get("judge_id")) or f"vip:{_s(admin.get('sub'))}"
    match_at = C._utc(mctx["row"]["match_at"])
    offer_id = await PS.next_synthetic_id()
    offer = await sim._crew_offer_row(
        offer_id, key, mid, mctx["code"], slots, C.R.parse_filter(None), C.R.default_deadline(match_at),
        match_at, mctx["state"], author, "",
    )
    roles = C.R.roles_of(slots)
    claims = []
    people = await scene_claimers(key, [admin.get("judge_id")])
    for index, who in enumerate(people):
        claims.append(
            {
                "id": await PS.next_synthetic_id(),
                "offer_id": offer_id,
                "judge_id": who["judge_id"],
                "role": roles[index % len(roles)] if roles else C.R.ROLE_TABLE,
                "partner_id": None,
                "note": None,
                "status": C.R.PENDING,
                "slot": None,
                "source": None,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
    await PS.overlay_add("crew_offer", offer_id, {"offer": offer, "claims": claims, "account": "scene"})
    await PS.record_op(
        account=_account_key(admin),
        area="market",
        method="POST",
        path="/presentation/scene",
        summary=f"Scena: oferta obsadowego na mecz {mid} z {len(claims)} zgłoszeniami",
    )
    return {
        "crew_offer_id": offer_id,
        "match_id": mid,
        "province": key,
        "slots": slots,
        "claims": [{"judge_id": p["judge_id"], "name": p["name"]} for p in people],
    }


# ───────────────────────────── scena: oddanie meczu na giełdzie ─────────────────────────────


async def judge_row(judge_id: str) -> Dict[str, Any]:
    """Sędzia z listy okręgu (numer, nazwisko, okręg, zdjęcie, odznaki) albo {}."""
    from sqlalchemy import select

    from app.db import database, province_judges

    row = await database.fetch_one(select(province_judges).where(province_judges.c.judge_id == _s(judge_id)))
    return (dict(row._mapping) if hasattr(row, "_mapping") else dict(row)) if row else {}


async def province_rows(key: str, *, upcoming: bool, days: int, limit: int = 600) -> List[Dict[str, Any]]:
    """Mecze okręgu z migawki: nadchodzące (rosnąco) albo rozegrane w ostatnich `days` dniach (malejąco)."""
    from datetime import timedelta

    from sqlalchemy import and_, select

    from app.db import database, province_matches
    from app.match_market_rules import state_dict
    from app.settlement_province import spellings

    now = datetime.now(timezone.utc)
    t = province_matches
    when = (
        and_(t.c.match_at > now, t.c.match_at <= now + timedelta(days=days))
        if upcoming
        else and_(t.c.match_at < now, t.c.match_at >= now - timedelta(days=days))
    )
    rows = await database.fetch_all(
        select(t)
        .where(and_(t.c.province.in_(spellings(key) or [key]), t.c.active.is_(True), when))
        .order_by(t.c.match_at.asc() if upcoming else t.c.match_at.desc())
        .limit(limit)
    )
    out = []
    for r in rows:
        data = dict(r._mapping) if hasattr(r, "_mapping") else dict(r)
        data["state_json"] = state_dict(data.get("state_json"))
        out.append(data)
    return out


async def market_hours(key: str) -> int:
    try:
        from app import match_market as M

        return int((await M._config(key)).get("offer_deadline_hours") or 48)
    except Exception:  # noqa: BLE001
        return 48


async def approver_of(judge_id: str) -> bool:
    """Czy ten sędzia rozstrzyga wymiany w swoim okręgu (odznaka okręgu albo admin)."""
    try:
        from app import match_market as M
        from app.match_market_access import may_approve

        actor = await M.market_actor({"judge_id": judge_id})
        cfg = await M._config(actor.province) if actor.province else {}
        return bool(may_approve(
            is_admin=actor.is_admin, province=actor.province, judge_province=actor.province,
            badges_raw=actor.badges, allowed_badges=(cfg or {}).get("approver_badges") or ["Obsadowy"],
        ))
    except Exception:  # noqa: BLE001
        return False


async def build_giveaway_scene(
    province: Optional[str], match_id: Optional[str], judge_id: str, admin: Dict[str, Any], state: PS.State
) -> Dict[str, Any]:
    """Oddanie meczu przez sędziego trybu: jego oferta (nakładka) + JEDNO zgłoszenie.

    Mecz jest prawdziwy: najbliższy w okręgu, w którym sędzia stoi w gnieździe
    giełdy (po nakładce obsady). Zatwierdzenie (`/match-market/offers/{id}/approve`)
    przestawia nakładkę obsady: oddający wychodzi, biorący wchodzi - i zapisuje
    w dzienniku „wymiana w ZPRP (udawana)".
    """
    from app import presentation_lineup as L
    from app import presentation_sim as sim
    from app.match_market_rules import can_offer, slot_label, slots_held_by

    who = await judge_row(judge_id)
    key = sim._canonical(province or who.get("province"))
    if not key:
        raise HTTPException(400, f"Sędziego {judge_id} nie ma na liście okręgu - podaj province.")
    name = _s(who.get("full_name"))
    lineups = await L.load()
    rows = await province_rows(key, upcoming=True, days=60)
    if match_id:
        rows = [r for r in rows if _s(r.get("match_id")) == _s(match_id)]
    busy = {
        (_s((d.get("row") or {}).get("match_id")), _s((d.get("row") or {}).get("slot")))
        for _rid, d in await PS.overlay_list("market_offer")
        if _s((d.get("row") or {}).get("status")) in sim.LIVE
    }
    hours = await market_hours(key)
    now = datetime.now(timezone.utc)
    picked = None
    for row in rows:
        mid = _s(row.get("match_id"))
        st = row.get("state_json") or {}
        if mid in lineups:
            st = L.patch_state(st, lineups[mid]["slots"])
        held = [slot for slot in slots_held_by(st, judge_id, name) if (mid, slot) not in busy]
        if not held:
            continue
        offerable = bool(can_offer(PS._utc(row.get("match_at")), now, hours))
        if picked is None or (offerable and not picked[3]):
            picked = (row, st, held, offerable)
        if offerable:
            break
    if picked is None:
        where = f"mecz {match_id}" if match_id else "nadchodzącego meczu (60 dni)"
        raise HTTPException(
            404,
            f"Sędzia {judge_id}{' (' + name + ')' if name else ''} nie stoi w gnieździe giełdy w żadnym {where} "
            f"okręgu {key} - nie ma czego oddać. Przypisz go najpierw (udawany zapis obsady) albo wybierz innego sędziego.",
        )
    row, st, held, offerable = picked
    mid, slot = _s(row["match_id"]), held[0]
    match_at = PS._utc(row.get("match_at"))
    crew_ids = [_s(st.get(f"NrSedzia_{s}")) for s in L.SLOTS]
    people = await scene_claimers(key, [judge_id, admin.get("judge_id"), *crew_ids], count=1)
    if not people:
        raise HTTPException(404, f"Nie znalazłem w okręgu {key} innego aktywnego sędziego do zgłoszenia.")
    taker = people[0]
    offer_id = await PS.next_synthetic_id()
    created = now.isoformat()
    try:
        from app.match_market_rules import deadline_for

        deadline = deadline_for(match_at, hours)
    except Exception:  # noqa: BLE001
        deadline = None
    status = "open" if offerable else "approval_pending"
    offer_row = sim._jsonable({
        "id": offer_id, "province": key, "match_id": mid, "match_code": _s(row.get("match_code")),
        "slot": slot, "from_judge_id": judge_id, "reason": None, "status": status,
        "deadline_at": match_at if status == "approval_pending" else deadline, "match_at": match_at,
        "match_snapshot": st, "created_at": created, "updated_at": created, "decided_by": None,
    })
    claim = {
        "id": await PS.next_synthetic_id(), "offer_id": offer_id, "judge_id": taker["judge_id"], "status": "pending",
        "note": None, "created_at": created, "card": {"full_name": taker["name"], "photo_url": taker.get("photo_url")},
    }
    await PS.overlay_add("market_offer", offer_id, {"row": offer_row, "claims": [claim], "account": "scene"})
    approvers = [judge_id] if await approver_of(judge_id) else []
    await PS.record_op(
        account=_account_key(admin), area="market", method="POST", path="/presentation/scene",
        summary=f"Scena: {judge_id} oddaje mecz {mid} ({slot_label(slot)}), zgłasza się {taker['judge_id']}",
    )
    return {
        "offer_id": offer_id,
        "claim_id": claim["id"],
        "status": status,
        "match_id": mid,
        "match_at": PS._iso(match_at),
        "province": key,
        "slot": slot,
        "slot_label": slot_label(slot),
        "giver": {"judge_id": judge_id, "name": name},
        "taker": {"judge_id": taker["judge_id"], "name": taker["name"]},
        "approve": {
            "path": f"/match-market/offers/{offer_id}/approve",
            "body": {"claim_id": claim["id"]},
            "judge_can_approve": bool(approvers),
            "hint": (
                "Sędzia sceny rozstrzyga sam: Giełda > Moje > oferta > Rozstrzygnij."
                if approvers
                else "Sędzia sceny NIE ma prawa rozstrzygać (brak odznaki obsadowego okręgu i nie jest adminem) - "
                "zatwierdź z konta sędziego-obsadowego objętego trybem (panel okręgu nie zatwierdza giełdy sędziów)."
            ),
        },
        "late": status == "approval_pending",
    }


# ───────────────────────────── scena: ocena młodego sędziego ─────────────────────────────


async def young_referees_of(key: str) -> List[Dict[str, Any]]:
    from sqlalchemy import select

    from app.db import database, young_referees
    from app.settlement_province import spellings

    names = {n.upper() for n in (spellings(key) or [key])} | {key.upper()}
    rows = await database.fetch_all(select(young_referees).where(young_referees.c.is_active.is_(True)))
    out = []
    for r in rows:
        data = dict(r._mapping) if hasattr(r, "_mapping") else dict(r)
        if _s(data.get("province")).upper() in names:
            out.append(data)
    return out


async def build_young_rating_scene(
    province: Optional[str], match_id: Optional[str], judge_id: str, admin: Dict[str, Any]
) -> Dict[str, Any]:
    """Rozegrany niedawno mecz okręgu z młodym sędzią na boisku, który sędzia trybu może ocenić.

    Prawo do oceny (jak `young_referees._ensure_rater_is_not_young`): oceniający nie
    jest aktywnym młodym sędzią. Aplikacja pokazuje mecze z pliku meczów telefonu,
    więc najpierw szukamy meczu, w którego obsadzie stoi sam sędzia trybu.
    """
    from app import presentation_lineup as L
    from app import presentation_sim as sim
    from app.match_market_rules import names_match

    who = await judge_row(judge_id)
    key = sim._canonical(province or who.get("province"))
    if not key:
        raise HTTPException(400, f"Sędziego {judge_id} nie ma na liście okręgu - podaj province.")
    name = _s(who.get("full_name"))
    youngs = await young_referees_of(key)
    self_young = [y for y in youngs if _s(y.get("base_judge_id")) == judge_id or (name and names_match(y.get("full_name"), name))]
    if self_young:
        raise HTTPException(
            409,
            f"Sędzia {judge_id} ({name or 'bez nazwiska'}) jest na liście młodych sędziów okręgu "
            f"(id {self_young[0].get('id')}) - młody sędzia nie wystawia ocen. Brakuje: konta oceniającego "
            "spoza listy młodych (mentor, obserwator, delegat) albo zdjęcia go z listy w panelu.",
        )
    if not youngs:
        raise HTTPException(404, f"Okręg {key} nie ma aktywnych młodych sędziów (lista „Młodzi sędziowie” jest pusta).")
    rows = await province_rows(key, upcoming=False, days=45)
    if match_id:
        rows = [r for r in rows if _s(r.get("match_id")) == _s(match_id)]
    best = None
    for row in rows:
        st = row.get("state_json") or {}
        for slot in ("pierwszy", "drugi"):
            number, person_name = _s(st.get(f"NrSedzia_{slot}")), _s(st.get(f"NrSedzia_{slot}_nazwisko"))
            young = next(
                (y for y in youngs
                 if (number and _s(y.get("base_judge_id")) == number) or (person_name and names_match(y.get("full_name"), person_name))),
                None,
            )
            if young is None:
                continue
            mine = bool(L.judge_slots(st, judge_id, name))
            if best is None or (mine and not best[3]):
                best = (row, st, young, mine, slot)
            break
        if best is not None and best[3]:
            break
    if best is None:
        raise HTTPException(
            404,
            f"Nie znalazłem rozegranego w ostatnich 45 dniach meczu okręgu {key} z młodym sędzią na boisku"
            + (f" (mecz {match_id})" if match_id else "") + ".",
        )
    row, st, young, mine, slot = best
    missing = [] if mine else [
        f"Sędziego {judge_id} nie ma w obsadzie tego meczu - aplikacja pokazuje do oceny mecze z jego listy meczów "
        "w telefonie. Wybierz match_id, w którym sędziował, albo pokaż ocenę z konta, które w nim było."
    ]
    await PS.record_op(
        account=_account_key(admin), area="ratings", method="POST", path="/presentation/scene",
        summary=f"Scena: ocena młodego {young.get('full_name')} w meczu {row.get('match_id')}",
    )
    return {
        "match_id": _s(row.get("match_id")),
        "match_code": _s(st.get("RozgrywkiCode") or row.get("match_code")),
        "match_at": PS._iso(row.get("match_at")),
        "host": _s(st.get("ID_zespoly_gosp_ZespolNazwa")),
        "guest": _s(st.get("ID_zespoly_gosc_ZespolNazwa")),
        "province": key,
        "young_referee": {"id": young.get("id"), "name": _s(young.get("full_name")), "slot": slot},
        "rater": {"judge_id": judge_id, "name": name, "in_crew": mine, "may_rate": True},
        "missing": missing,
        "save": {"path": "/young_referees/ratings", "mentor_name": name, "young_referee_id": young.get("id")},
    }


@router.get("/judges", summary="Sędziowie okręgu do wyboru kont trybu i podglądu")
async def get_judges(
    province: str = Query(...), q: str = Query(""), _admin: dict = Depends(require_app_admin)
) -> Dict[str, Any]:
    from sqlalchemy import select

    from app.assignment_people import fold
    from app.db import database, province_judges
    from app.settlement_province import canonical, spellings

    key = canonical(province) or province
    rows = await database.fetch_all(
        select(province_judges.c.judge_id, province_judges.c.full_name, province_judges.c.photo_url).where(
            province_judges.c.province.in_(spellings(key) or [key])
        )
    )
    needle = fold(q) if q else ""
    items = [
        {"judge_id": _s(r["judge_id"]), "name": _s(r["full_name"]) or _s(r["judge_id"]), "photo_url": _s(r["photo_url"]) or None}
        for r in rows
        if _s(r["judge_id"]) and (not needle or needle in fold(r["full_name"]) or needle in _s(r["judge_id"]))
    ]
    items.sort(key=lambda i: fold(i["name"]))
    return {"items": items[:60]}


async def _max_stamp(query) -> Optional[str]:
    from app.db import database

    try:
        return PS._iso(await database.fetch_val(query))
    except Exception:  # noqa: BLE001 - brak tabeli / kolumny = nie wiemy
        return None


@router.get("/diagnostics", summary="Stan serwera, bazy i synchronizacji (administrator)")
async def get_diagnostics(province: str = Query(""), _admin: dict = Depends(require_app_admin)) -> Dict[str, Any]:
    from datetime import timedelta

    from sqlalchemy import and_, func, select, text

    from app import db as D
    from app.settlement_province import canonical, spellings

    key = canonical(province) or province
    names = spellings(key) or ([key] if key else [])

    started = time.monotonic()
    db_ok = True
    try:
        await D.database.fetch_val(text("SELECT 1"))
    except Exception:  # noqa: BLE001
        db_ok = False
    latency = round((time.monotonic() - started) * 1000, 1)

    def where_prov(table):
        return table.c.province.in_(names) if names else True

    schedule = await _max_stamp(
        select(func.max(D.province_match_sync_runs.c.finished_at)).where(where_prov(D.province_match_sync_runs))
    )
    judges = await _max_stamp(select(func.max(D.province_judges.c.updated_at)).where(where_prov(D.province_judges)))
    offtimes = await _max_stamp(
        select(func.max(D.province_offtime_sync_runs.c.finished_at)).where(where_prov(D.province_offtime_sync_runs))
    )
    errors_24h = None
    try:
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        errors_24h = int(
            await D.database.fetch_val(
                select(func.count()).select_from(D.client_error_reports).where(D.client_error_reports.c.last_at >= since)
            )
            or 0
        )
    except Exception:  # noqa: BLE001
        errors_24h = None
    push_count = None
    try:
        query = select(func.count()).select_from(D.push_tokens)
        if names:
            query = query.where(and_(D.push_tokens.c.province.in_(names + [key])))
        push_count = int(await D.database.fetch_val(query) or 0)
    except Exception:  # noqa: BLE001
        push_count = None
    state = await PS.current()
    return {
        "server": {
            "version": _s(os.getenv("RAILWAY_GIT_COMMIT_SHA"))[:7] or _s(os.getenv("APP_VERSION")) or "dev",
            "started_at": STARTED_AT.isoformat(),
            "uptime_s": int(time.monotonic() - _STARTED_MONO),
        },
        "db": {"ok": db_ok, "latency_ms": latency if db_ok else None},
        "zprp": {"last_sync": {"schedule": schedule, "judges": judges, "offtimes": offtimes}},
        "errors_24h": errors_24h,
        "push_tokens": push_count,
        "presentation": {"enabled": state.active(), "ops_count": await PS.ops_count()},
    }

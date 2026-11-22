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


class SceneRequest(BaseModel):
    scene: str
    province: str
    match_id: Optional[str] = None


@router.post("/scene", summary="Przygotuj scenę demo w nakładce")
async def post_scene(req: SceneRequest, admin: dict = Depends(require_app_admin)) -> Dict[str, Any]:
    state = await PS.current(force=True)
    if not state.active():
        raise HTTPException(409, "Najpierw włącz tryb prezentacji - scena istnieje tylko w nakładce.")
    if req.scene != "market_offer_with_claims":
        raise HTTPException(400, "Nieznana scena. Dostępna: market_offer_with_claims.")
    created = await build_market_scene(req.province, req.match_id, admin)
    return {"ok": True, "created": created}


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
        account=f"judge:{admin.get('judge_id')}" if admin.get("judge_id") else f"login:{admin.get('sub')}",
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

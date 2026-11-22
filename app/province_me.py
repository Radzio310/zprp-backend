"""Ustawienia panelu okręgowego dla każdego zalogowanego - /province/me/*.

Kontrakt: `kontrakt_ustawienia.md` (22.11.2026).

* `GET /province/me/profile` - kim jestem w okręgu: role z odznak, czy jestem
  administratorem aplikacji, które okręgi mogę wybrać.
* `GET|PUT /province/me/availability` - moja dyspozycyjność dla Automatu:
  dni tygodnia, rola w obsadzie, notatka. Zapis WYŁĄCZNIE do własnego wiersza
  `province_judge_settings` (numer z tokenu, nigdy z treści). Pola
  `needs_experienced` i `no_solo` zostają w gestii obsadowego - nie ruszamy ich.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, select

from app.deps import get_jwt_payload

log = logging.getLogger("province_me")

router = APIRouter(prefix="/province/me", tags=["Ustawienia okręgu"])

ROLES_ORDER = ("sedzia", "obsadowy", "komisja", "calendar_master", "admin", "vip")
ASSIGN_ROLES = ("both", "field", "table")


def _s(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _row(row: Any) -> Dict[str, Any]:
    if row is None:
        return {}
    return dict(row._mapping) if hasattr(row, "_mapping") else dict(row)


def _days(raw: Any) -> List[int]:
    import json

    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = []
    out = set()
    for day in raw if isinstance(raw, list) else []:
        try:
            value = int(day)
        except (TypeError, ValueError):
            continue
        if 0 <= value <= 6:
            out.add(value)
    return sorted(out)


def roles_from(badges: List[str], *, judge_id: str, is_admin: bool, vip: bool) -> List[str]:
    """Role do ekranu Ustawień - z odznak okręgu (nazwy bez ogonków i wielkości liter)."""
    from app.assignment_people import fold

    found = set()
    if judge_id:
        found.add("sedzia")
    for badge in badges:
        name = fold(badge)
        if "obsad" in name:
            found.add("obsadowy")
        if "komisj" in name:
            found.add("komisja")
        if "calendar" in name:
            found.add("calendar_master")
    if is_admin:
        found.add("admin")
    if vip:
        found.add("vip")
    return [r for r in ROLES_ORDER if r in found]


async def _judge_row(judge_id: str) -> Dict[str, Any]:
    if not judge_id:
        return {}
    from app.db import database, province_judges

    return _row(await database.fetch_one(select(province_judges).where(province_judges.c.judge_id == judge_id)))


async def _is_app_admin(judge_id: str) -> bool:
    if not judge_id:
        return False
    try:
        from app.admin_alerts import admin_judge_ids

        return judge_id in await admin_judge_ids()
    except Exception:  # noqa: BLE001
        return False


async def _vip(login: str) -> Optional[Dict[str, Any]]:
    if not login:
        return None
    try:
        from app.db import baza_vips, database

        row = await database.fetch_one(select(baza_vips).where(baza_vips.c.username == login))
        return _row(row) or None
    except Exception:  # noqa: BLE001
        return None


@router.get("/profile", summary="Mój profil w okręgu (role, uprawnienia)")
async def get_profile(province: str = Query(""), payload: dict = Depends(get_jwt_payload)) -> Dict[str, Any]:
    from app.match_market_access import badge_names
    from app.settlement_province import DISPLAY, display

    judge_id = _s(payload.get("judge_id"))
    login = _s(payload.get("sub"))
    account_type = _s(payload.get("account_type")) or ("judge" if judge_id else "org")
    row = await _judge_row(judge_id)
    vip = await _vip(login)
    is_admin = await _is_app_admin(judge_id)
    own = _s(row.get("province")) or _s((vip or {}).get("province"))
    chosen = display(province or own) if (province or own) else ""
    badges = badge_names(row.get("badges")) if row else []
    return {
        "province": chosen,
        "judge_id": judge_id or None,
        "display_name": _s(row.get("full_name")) or _s(payload.get("full_name")) or login,
        "account_type": account_type,
        "roles": roles_from(badges, judge_id=judge_id, is_admin=is_admin, vip=bool(vip) or account_type == "org"),
        "badges": badges,
        "provinces_available": list(DISPLAY.values()) if is_admin else ([display(own)] if own else ([chosen] if chosen else [])),
        "is_app_admin": is_admin,
    }


async def availability_view(key: str, judge_id: str) -> Dict[str, Any]:
    from app.db import database, province_judge_settings as T

    row = _row(await database.fetch_one(select(T).where(and_(T.c.province == key, T.c.judge_id == judge_id))))
    role = _s(row.get("assign_role")).lower()
    return {
        "preferred_days": _days(row.get("preferred_days")),
        "assign_role": role if role in ASSIGN_ROLES else "both",
        "note": _s(row.get("note")),
        "home_city": await _home_city(key, judge_id),
    }


async def _home_city(key: str, judge_id: str) -> Optional[str]:
    from app.db import database

    try:
        from app.db import province_settlement_judges as S

        city = await database.fetch_val(
            select(S.c.home_city).where(and_(S.c.province == key, S.c.judge_id == judge_id))
        )
        if _s(city):
            return _s(city)
    except Exception:  # noqa: BLE001
        pass
    try:
        from app.db import zprp_judges_seen as Z

        city = await database.fetch_val(select(Z.c.home_city).where(Z.c.judge_id == judge_id))
        return _s(city) or None
    except Exception:  # noqa: BLE001
        return None


def _own_judge(payload: dict) -> str:
    judge_id = _s(payload.get("judge_id"))
    if not judge_id:
        raise HTTPException(403, "Dyspozycyjność ustawia sędzia ze swojego konta - to konto nie ma numeru sędziego.")
    return judge_id


async def _key(province: str, judge_id: str) -> str:
    from app.settlement_province import canonical

    key = canonical(province)
    if not key:
        key = canonical((await _judge_row(judge_id)).get("province"))
    if not key:
        raise HTTPException(400, "Podaj województwo (parametr province).")
    return key


@router.get("/availability", summary="Moja dyspozycyjność dla Automatu obsady")
async def get_availability(province: str = Query(""), payload: dict = Depends(get_jwt_payload)) -> Dict[str, Any]:
    judge_id = _own_judge(payload)
    return await availability_view(await _key(province, judge_id), judge_id)


class AvailabilityRequest(BaseModel):
    province: str = ""
    preferred_days: Optional[List[int]] = None
    assign_role: Optional[str] = None
    note: Optional[str] = None


@router.put("/availability", summary="Zapisz moją dyspozycyjność (tylko własny wiersz)")
async def put_availability(req: AvailabilityRequest, payload: dict = Depends(get_jwt_payload)) -> Dict[str, Any]:
    from app.db import database, province_judge_settings as T

    judge_id = _own_judge(payload)
    key = await _key(req.province, judge_id)
    current = _row(await database.fetch_one(select(T).where(and_(T.c.province == key, T.c.judge_id == judge_id))))
    values: Dict[str, Any] = {}
    if req.preferred_days is not None:
        values["preferred_days"] = _days(req.preferred_days)
    if req.assign_role is not None:
        role = _s(req.assign_role).lower()
        if role not in ASSIGN_ROLES:
            raise HTTPException(400, "Rola w obsadzie: both (boisko i stolik), field (tylko boisko) albo table (tylko stolik).")
        # „both" przy pustej roli (według ZPRP) to ten sam stan na ekranie - nie
        # zamieniamy cichego „według ZPRP" w jawne ustawienie.
        if not (role == "both" and not _s(current.get("assign_role"))):
            values["assign_role"] = role
    if req.note is not None:
        values["note"] = _s(req.note)[:500] or None
    if values:
        values["updated_by"] = f"self:{judge_id}"
        values["updated_at"] = datetime.now(timezone.utc)
        if current:
            await database.execute(
                T.update().where(and_(T.c.province == key, T.c.judge_id == judge_id)).values(**values)
            )
        else:
            row = await _judge_row(judge_id)
            await database.execute(
                T.insert().values(
                    province=key,
                    judge_id=judge_id,
                    full_name=_s(row.get("full_name")) or None,
                    needs_experienced=False,
                    no_solo=False,
                    preferred_days=values.pop("preferred_days", []),
                    **values,
                )
            )
        try:
            from app.assignment_board_cache import bump

            bump(key)
        except Exception:  # noqa: BLE001
            log.info("dyspozycyjność: odświeżenie Obsady nieudane", exc_info=True)
    return await availability_view(key, judge_id)

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import insert, select, update

from app.db import database, beach_admins, beach_judge_availability, beach_users
from app.deps import beach_get_current_user_id
from app.schemas import (
    BeachJudgeAvailabilityItem,
    BeachJudgeAvailabilityListResponse,
    BeachJudgeAvailabilityUpsertRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/beach/availability", tags=["Beach: Judge Availability"])

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_VALID_AVAIL = {"available", "unavailable"}


# ─────────────────── helpers ───────────────────

def _roles_list(roles_raw: Any) -> list:
    if isinstance(roles_raw, list):
        return roles_raw
    if isinstance(roles_raw, str):
        try:
            return json.loads(roles_raw)
        except Exception:
            return []
    return []


def _is_approved_judge(roles_raw: Any) -> bool:
    """Return True if the user has an approved judge role."""
    for r in _roles_list(roles_raw):
        if isinstance(r, dict):
            if r.get("type") == "judge" and r.get("verified") == "approved":
                return True
    return False


async def _require_judge(user_id: int) -> None:
    row = await database.fetch_one(
        select(beach_users.c.roles).where(beach_users.c.id == user_id)
    )
    if not row or not _is_approved_judge(row["roles"]):
        raise HTTPException(
            403, "Funkcja dostępna tylko dla zweryfikowanych sędziów"
        )


async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    return bool(row)


def _parse_avail(raw: Any) -> Dict[str, str]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _sanitize_avail(data: Dict[str, str]) -> Dict[str, str]:
    """Validate and clean availability dict before storing."""
    out: Dict[str, str] = {}
    for k, v in data.items():
        if _DATE_RE.match(str(k)) and v in _VALID_AVAIL:
            out[str(k)] = v
    return out


async def _fetch_user_info(user_id: int):
    return await database.fetch_one(
        select(beach_users.c.full_name, beach_users.c.judge_id).where(
            beach_users.c.id == user_id
        )
    )


def _build_item(user_id: int, user_row: Any, avail_row: Any) -> BeachJudgeAvailabilityItem:
    return BeachJudgeAvailabilityItem(
        user_id=user_id,
        full_name=user_row["full_name"] if user_row else "",
        judge_id=user_row["judge_id"] if user_row else None,
        availability_json=_parse_avail(avail_row["availability_json"]) if avail_row else {},
        updated_at=avail_row["updated_at"] if avail_row else datetime.now(timezone.utc),
    )


# ─────────────────── endpoints ───────────────────

@router.get(
    "/me",
    response_model=BeachJudgeAvailabilityItem,
    summary="Pobierz własną dyspozycyjność — wymaga roli sędzia (approved)",
)
async def get_my_availability(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    await _require_judge(current_user_id)

    avail_row = await database.fetch_one(
        select(beach_judge_availability).where(
            beach_judge_availability.c.user_id == current_user_id
        )
    )
    user_row = await _fetch_user_info(current_user_id)
    return _build_item(current_user_id, user_row, avail_row)


@router.put(
    "/me",
    response_model=BeachJudgeAvailabilityItem,
    summary="Zapisz/zaktualizuj własną dyspozycyjność — wymaga roli sędzia (approved)",
)
async def put_my_availability(
    req: BeachJudgeAvailabilityUpsertRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    await _require_judge(current_user_id)

    sanitized = _sanitize_avail(dict(req.availability_json))
    now = datetime.now(timezone.utc)

    existing = await database.fetch_one(
        select(beach_judge_availability.c.user_id).where(
            beach_judge_availability.c.user_id == current_user_id
        )
    )

    if existing:
        await database.execute(
            update(beach_judge_availability)
            .where(beach_judge_availability.c.user_id == current_user_id)
            .values(availability_json=sanitized, updated_at=now)
        )
    else:
        await database.execute(
            insert(beach_judge_availability).values(
                user_id=current_user_id,
                availability_json=sanitized,
                updated_at=now,
            )
        )

    user_row = await _fetch_user_info(current_user_id)

    # Build a mock row to reuse _build_item
    class _AvailRow:
        def __init__(self, aj, ud):
            self.__getitem__ = lambda self, k: aj if k == "availability_json" else ud
    avail_data = {"availability_json": sanitized, "updated_at": now}

    return BeachJudgeAvailabilityItem(
        user_id=current_user_id,
        full_name=user_row["full_name"] if user_row else "",
        judge_id=user_row["judge_id"] if user_row else None,
        availability_json=sanitized,
        updated_at=now,
    )


@router.get(
    "/",
    response_model=BeachJudgeAvailabilityListResponse,
    summary="Lista dyspozycyjności wszystkich sędziów — tylko admin",
)
async def list_availability(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    all_user_rows = await database.fetch_all(
        select(
            beach_users.c.id,
            beach_users.c.full_name,
            beach_users.c.judge_id,
            beach_users.c.roles,
        )
    )

    judge_ids: List[int] = [
        r["id"] for r in all_user_rows if _is_approved_judge(r["roles"])
    ]

    if not judge_ids:
        return BeachJudgeAvailabilityListResponse(items=[])

    avail_rows = await database.fetch_all(
        select(beach_judge_availability).where(
            beach_judge_availability.c.user_id.in_(judge_ids)
        )
    )
    avail_map = {r["user_id"]: r for r in avail_rows}
    user_map = {r["id"]: r for r in all_user_rows}

    items = []
    for uid in judge_ids:
        u = user_map[uid]
        a = avail_map.get(uid)
        items.append(
            BeachJudgeAvailabilityItem(
                user_id=uid,
                full_name=u["full_name"],
                judge_id=u["judge_id"],
                availability_json=_parse_avail(a["availability_json"]) if a else {},
                updated_at=a["updated_at"] if a else datetime.now(timezone.utc),
            )
        )

    items.sort(key=lambda x: (x.full_name or "").lower())
    return BeachJudgeAvailabilityListResponse(items=items)


@router.get(
    "/{user_id}",
    response_model=BeachJudgeAvailabilityItem,
    summary="Dyspozycyjność konkretnego sędziego — admin lub właściciel",
)
async def get_availability_by_user(
    user_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if current_user_id != user_id and not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    user_row = await database.fetch_one(
        select(
            beach_users.c.full_name,
            beach_users.c.judge_id,
            beach_users.c.roles,
        ).where(beach_users.c.id == user_id)
    )
    if not user_row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    # Non-admins can only see judges
    if current_user_id != user_id and not _is_approved_judge(user_row["roles"]):
        raise HTTPException(404, "Użytkownik nie jest sędzią")

    avail_row = await database.fetch_one(
        select(beach_judge_availability).where(
            beach_judge_availability.c.user_id == user_id
        )
    )
    return _build_item(user_id, user_row, avail_row)

from __future__ import annotations

from datetime import datetime, timezone
import logging
import traceback
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import select, delete
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import database, beach_admins, beach_users
from app.schemas import (
    BeachAdminUpsertRequest,
    BeachAdminItem,
    BeachAdminsListResponse,
)
from app.deps import beach_get_current_user_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/admins", tags=["Beach: Admins"])


async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id))
    return bool(row)


@router.get("/", response_model=BeachAdminsListResponse, summary="Lista adminów (BEACH)")
async def list_admins():
    rows = await database.fetch_all(select(beach_admins).order_by(beach_admins.c.created_at.desc()))
    admins: List[BeachAdminItem] = [
        BeachAdminItem(
            user_id=int(r["user_id"]),
            judge_id=r.get("judge_id"),
            full_name=r["full_name"],
            province=r.get("province"),
            created_at=r["created_at"],
        )
        for r in rows
    ]
    return BeachAdminsListResponse(admins=admins)


@router.post("/", response_model=dict, summary="Dodaj admina (BEACH) — wymaga admina")
async def upsert_admin(req: BeachAdminUpsertRequest, current_user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    user_row = await database.fetch_one(select(beach_users).where(beach_users.c.id == req.user_id))
    if not user_row:
        raise HTTPException(404, "Użytkownik nie istnieje")

    now = datetime.now(timezone.utc)
    u = dict(user_row)

    stmt = (
        pg_insert(beach_admins)
        .values(
            user_id=int(u["id"]),
            judge_id=u.get("judge_id"),
            full_name=u["full_name"],
            province=u.get("province"),
            created_at=now,
        )
        .on_conflict_do_update(
            index_elements=[beach_admins.c.user_id],
            set_={
                "judge_id": u.get("judge_id"),
                "full_name": u["full_name"],
                "province": u.get("province"),
            },
        )
    )

    try:
        await database.execute(stmt)
        return {"success": True}
    except Exception as e:
        logger.error("upsert_admin failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(500, f"upsert_admin failed: {e}")


@router.delete("/{user_id}", response_model=dict, summary="Usuń admina (BEACH) — wymaga admina")
async def delete_admin(user_id: int, current_user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    await database.execute(delete(beach_admins).where(beach_admins.c.user_id == user_id))
    return {"success": True}


@router.get("/me", response_model=dict, summary="Czy jestem adminem? (BEACH)")
async def am_i_admin(current_user_id: int = Depends(beach_get_current_user_id)):
    return {"is_admin": await _is_admin(current_user_id)}
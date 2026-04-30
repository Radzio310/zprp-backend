from __future__ import annotations

from datetime import datetime, timezone
import logging
import traceback
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import select, delete
from sqlalchemy.dialects.postgresql import insert as pg_insert

import asyncio
from app.db import database, beach_admins, beach_users
from app.beach.notifications import notify_admins
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
            user_id=int(d["user_id"]),
            judge_id=d.get("judge_id"),
            full_name=d["full_name"],
            province=d.get("province"),
            created_at=d["created_at"],
        )
        for r in rows
        for d in [dict(r)]
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
        asyncio.ensure_future(notify_admins(
            notif_type="admin_new_admin",
            title="Nowy administrator",
            body=f"{u['full_name']} został dodany jako administrator",
            data={"user_id": int(u['id'])},
            exclude_user_id=current_user_id,
        ))
        return {"success": True}
    except Exception as e:
        logger.error("upsert_admin failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(500, f"upsert_admin failed: {e}")


@router.delete("/{user_id}", response_model=dict, summary="Usuń admina (BEACH) — wymaga admina")
async def delete_admin(user_id: int, current_user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    removed_row = await database.fetch_one(
        select(beach_admins.c.full_name).where(beach_admins.c.user_id == user_id)
    )
    await database.execute(delete(beach_admins).where(beach_admins.c.user_id == user_id))
    if removed_row:
        asyncio.ensure_future(notify_admins(
            notif_type="admin_removed_admin",
            title="Usunięto administratora",
            body=f"{removed_row['full_name']} nie jest już administratorem",
            data={"user_id": user_id},
            exclude_user_id=current_user_id,
        ))
    return {"success": True}


@router.get("/me", response_model=dict, summary="Czy jestem adminem? (BEACH)")
async def am_i_admin(current_user_id: int = Depends(beach_get_current_user_id)):
    return {"is_admin": await _is_admin(current_user_id)}
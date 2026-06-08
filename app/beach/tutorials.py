from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import database, beach_tutorials, beach_tutorial_views, beach_admins, beach_users
from app.deps import beach_get_current_user_id
from app.beach.activity_log import log_activity
from app.beach.notifications import create_notification
from app.schemas import (
    BeachTutorialItem,
    BeachTutorialsListResponse,
    CreateBeachTutorialRequest,
    UpdateBeachTutorialRequest,
    ReorderBeachTutorialsRequest,
    BeachTutorialStatItem,
    BeachTutorialStatsResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/tutorials", tags=["Beach: Tutorials"])


async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    return bool(row)


def _row_to_item(row, my_watched: bool) -> BeachTutorialItem:
    return BeachTutorialItem(
        id=int(row["id"]),
        name=row["name"],
        description=row["description"],
        youtube_id=row["youtube_id"],
        color=row["color"],
        category=row["category"] if row["category"] else "general",
        order_index=int(row["order_index"]),
        view_count=int(row["view_count"]),
        my_watched=my_watched,
        created_at=row["created_at"],
    )


# ─────────────────────────────────────────────
# GET /beach/tutorials/  — lista dla zalogowanego
# ─────────────────────────────────────────────

@router.get("/", response_model=BeachTutorialsListResponse, summary="Lista tutoriali (BEACH)")
async def list_tutorials(current_user_id: int = Depends(beach_get_current_user_id)):
    rows = await database.fetch_all(
        select(beach_tutorials).order_by(beach_tutorials.c.order_index.asc(), beach_tutorials.c.id.asc())
    )
    if not rows:
        return BeachTutorialsListResponse(tutorials=[])

    tutorial_ids = [int(r["id"]) for r in rows]

    viewed_rows = await database.fetch_all(
        select(beach_tutorial_views.c.tutorial_id).where(
            beach_tutorial_views.c.tutorial_id.in_(tutorial_ids),
            beach_tutorial_views.c.user_id == current_user_id,
        )
    )
    watched_ids = {int(r["tutorial_id"]) for r in viewed_rows}

    return BeachTutorialsListResponse(
        tutorials=[_row_to_item(r, int(r["id"]) in watched_ids) for r in rows]
    )


# ─────────────────────────────────────────────
# POST /beach/tutorials/{id}/watch  — oznacz jako obejrzane
# ─────────────────────────────────────────────

@router.post("/{tutorial_id}/watch", response_model=dict, summary="Oznacz tutorial jako obejrzany (BEACH)")
async def mark_watched(tutorial_id: int, current_user_id: int = Depends(beach_get_current_user_id)):
    row = await database.fetch_one(
        select(beach_tutorials.c.id, beach_tutorials.c.view_count).where(beach_tutorials.c.id == tutorial_id)
    )
    if not row:
        raise HTTPException(404, "Tutorial nie istnieje")

    stmt = (
        pg_insert(beach_tutorial_views)
        .values(
            tutorial_id=tutorial_id,
            user_id=current_user_id,
            viewed_at=datetime.now(timezone.utc),
        )
        .on_conflict_do_nothing(index_elements=["tutorial_id", "user_id"])
    )
    result = await database.execute(stmt)

    if result:
        await database.execute(
            update(beach_tutorials)
            .where(beach_tutorials.c.id == tutorial_id)
            .values(view_count=beach_tutorials.c.view_count + 1)
        )

    return {"success": True, "already_watched": not bool(result)}


# ─────────────────────────────────────────────
# POST /beach/tutorials/  — utwórz (admin)
# ─────────────────────────────────────────────

@router.post("/", response_model=BeachTutorialItem, summary="Utwórz tutorial (BEACH, admin)")
async def create_tutorial(req: CreateBeachTutorialRequest, current_user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    max_row = await database.fetch_one(
        select(beach_tutorials.c.order_index).order_by(beach_tutorials.c.order_index.desc()).limit(1)
    )
    next_order = (int(max_row["order_index"]) + 1) if max_row else 0

    now = datetime.now(timezone.utc)
    stmt = (
        insert(beach_tutorials)
        .values(
            name=req.name.strip(),
            description=req.description.strip() if req.description else None,
            youtube_id=req.youtube_id.strip(),
            color=req.color,
            category=(req.category or "general").strip() or "general",
            order_index=next_order,
            view_count=0,
            created_at=now,
            updated_at=now,
        )
        .returning(*beach_tutorials.c)
    )
    row = await database.fetch_one(stmt)
    if not row:
        raise HTTPException(500, "Nie udało się utworzyć tutoriala")

    asyncio.ensure_future(log_activity(
        area="tutorials",
        action="tutorial.created",
        actor_user_id=current_user_id,
        target_id=str(row["id"]),
        target_label=req.name.strip(),
    ))

    return _row_to_item(row, False)


# ─────────────────────────────────────────────
# PUT /beach/tutorials/{id}  — edytuj (admin)
# ─────────────────────────────────────────────

@router.put("/{tutorial_id}", response_model=BeachTutorialItem, summary="Edytuj tutorial (BEACH, admin)")
async def update_tutorial(
    tutorial_id: int,
    req: UpdateBeachTutorialRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    existing = await database.fetch_one(
        select(beach_tutorials).where(beach_tutorials.c.id == tutorial_id)
    )
    if not existing:
        raise HTTPException(404, "Tutorial nie istnieje")

    update_data: dict = {"updated_at": datetime.now(timezone.utc)}
    if req.name is not None:
        update_data["name"] = req.name.strip()
    if req.description is not None:
        update_data["description"] = req.description.strip() or None
    if req.youtube_id is not None:
        update_data["youtube_id"] = req.youtube_id.strip()
    if req.color is not None:
        update_data["color"] = req.color
    if req.category is not None:
        update_data["category"] = req.category.strip() or "general"

    await database.execute(
        update(beach_tutorials).where(beach_tutorials.c.id == tutorial_id).values(**update_data)
    )

    row = await database.fetch_one(select(beach_tutorials).where(beach_tutorials.c.id == tutorial_id))

    viewed = await database.fetch_one(
        select(beach_tutorial_views.c.id).where(
            beach_tutorial_views.c.tutorial_id == tutorial_id,
            beach_tutorial_views.c.user_id == current_user_id,
        )
    )

    asyncio.ensure_future(log_activity(
        area="tutorials",
        action="tutorial.updated",
        actor_user_id=current_user_id,
        target_id=str(tutorial_id),
        target_label=row["name"],
    ))

    return _row_to_item(row, bool(viewed))


# ─────────────────────────────────────────────
# DELETE /beach/tutorials/{id}  — usuń (admin)
# ─────────────────────────────────────────────

@router.delete("/{tutorial_id}", response_model=dict, summary="Usuń tutorial (BEACH, admin)")
async def delete_tutorial(tutorial_id: int, current_user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    row = await database.fetch_one(
        select(beach_tutorials.c.id, beach_tutorials.c.name).where(beach_tutorials.c.id == tutorial_id)
    )
    if not row:
        raise HTTPException(404, "Tutorial nie istnieje")

    await database.execute(delete(beach_tutorials).where(beach_tutorials.c.id == tutorial_id))

    asyncio.ensure_future(log_activity(
        area="tutorials",
        action="tutorial.deleted",
        actor_user_id=current_user_id,
        target_id=str(tutorial_id),
        target_label=row["name"],
    ))

    return {"success": True}


# ─────────────────────────────────────────────
# POST /beach/tutorials/reorder  — zmień kolejność (admin)
# ─────────────────────────────────────────────

@router.post("/reorder", response_model=dict, summary="Zmień kolejność tutoriali (BEACH, admin)")
async def reorder_tutorials(req: ReorderBeachTutorialsRequest, current_user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    for idx, tutorial_id in enumerate(req.ids):
        await database.execute(
            update(beach_tutorials)
            .where(beach_tutorials.c.id == tutorial_id)
            .values(order_index=idx, updated_at=datetime.now(timezone.utc))
        )

    asyncio.ensure_future(log_activity(
        area="tutorials",
        action="tutorials.reordered",
        actor_user_id=current_user_id,
    ))

    return {"success": True}


# ─────────────────────────────────────────────
# GET /beach/tutorials/{id}/stats  — statystyki wyświetleń (admin)
# ─────────────────────────────────────────────

@router.get("/{tutorial_id}/stats", response_model=BeachTutorialStatsResponse, summary="Statystyki tutoriala (BEACH, admin)")
async def get_tutorial_stats(tutorial_id: int, current_user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    exists = await database.fetch_one(
        select(beach_tutorials.c.id).where(beach_tutorials.c.id == tutorial_id)
    )
    if not exists:
        raise HTTPException(404, "Tutorial nie istnieje")

    rows = await database.fetch_all(
        select(
            beach_tutorial_views.c.tutorial_id,
            beach_tutorial_views.c.user_id,
            beach_tutorial_views.c.viewed_at,
            beach_users.c.login,
            beach_users.c.full_name,
        )
        .join(beach_users, beach_users.c.id == beach_tutorial_views.c.user_id)
        .where(beach_tutorial_views.c.tutorial_id == tutorial_id)
        .order_by(beach_tutorial_views.c.viewed_at.desc())
    )

    stats = [
        BeachTutorialStatItem(
            tutorial_id=int(r["tutorial_id"]),
            user_id=int(r["user_id"]),
            user_login=r["login"],
            user_full_name=r["full_name"],
            viewed_at=r["viewed_at"],
        )
        for r in rows
    ]

    return BeachTutorialStatsResponse(stats=stats, unique_viewers=len(stats))


# ─────────────────────────────────────────────
# POST /beach/tutorials/{id}/notify  — wyślij push do wszystkich (admin)
# ─────────────────────────────────────────────

@router.post("/{tutorial_id}/notify", response_model=dict, summary="Wyślij push o tutorialu do wszystkich (BEACH, admin)")
async def notify_about_tutorial(tutorial_id: int, current_user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    row = await database.fetch_one(
        select(beach_tutorials.c.id, beach_tutorials.c.name, beach_tutorials.c.description)
        .where(beach_tutorials.c.id == tutorial_id)
    )
    if not row:
        raise HTTPException(404, "Tutorial nie istnieje")

    all_users = await database.fetch_all(select(beach_users.c.id))
    target_ids = [int(u["id"]) for u in all_users]

    asyncio.ensure_future(create_notification(
        notif_type="new_tutorial",
        title=f"Nowy tutorial: {row['name']}",
        body=row["description"] or "Sprawdź nowy film instruktażowy w BAZA Beach!",
        data={"tutorial_id": tutorial_id},
        target_user_ids=target_ids,
    ))

    return {"success": True, "notified_count": len(target_ids)}

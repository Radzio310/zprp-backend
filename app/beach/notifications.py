"""
Beach Notifications — in-app notification system with optional FCM push.

Dual-path flow:
  1. ALWAYS: insert into beach_notifications (in-app panel)
  2. OPTIONALLY: if user has device_ids → schedule FCM push to all devices
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, insert, select, update, and_, func as sa_func

from app.db import database, beach_notifications, beach_users, push_schedules
from app.deps import beach_get_current_user_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/notifications", tags=["Beach: Notifications"])


# ──────────── Models ────────────

class NotificationItem(BaseModel):
    id: int
    type: str
    title: str
    body: str
    data_json: Dict[str, Any]
    is_read: bool
    created_at: str


class MarkReadRequest(BaseModel):
    notification_ids: List[int]


class NotificationPrefsUpdate(BaseModel):
    prefs: Dict[str, bool]


# ──────────── Helper: create_notification ────────────

async def create_notification(
    *,
    notif_type: str,
    title: str,
    body: str,
    data: Optional[Dict[str, Any]] = None,
    target_user_ids: List[int],
) -> int:
    """
    Creates an in-app notification (ALWAYS) and schedules FCM push for users
    who have device_ids registered (OPTIONAL).

    Returns the notification id.
    """
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=7)
    data = data or {}

    # 1) Always insert in-app notification
    notif_id = await database.execute(
        insert(beach_notifications).values(
            type=notif_type,
            title=title,
            body=body,
            data_json=data,
            target_user_ids=target_user_ids,
            read_user_ids=[],
            created_at=now,
            expires_at=expires_at,
        )
    )

    # 2) Optionally schedule FCM push for users with devices + enabled pref
    asyncio.ensure_future(_schedule_push_for_users(
        notif_type=notif_type,
        title=title,
        body=body,
        data=data,
        target_user_ids=target_user_ids,
        send_at=now,
    ))

    return notif_id


async def _schedule_push_for_users(
    *,
    notif_type: str,
    title: str,
    body: str,
    data: Dict[str, Any],
    target_user_ids: List[int],
    send_at: datetime,
) -> None:
    """Fire-and-forget: schedule push for each user who has devices and pref enabled."""
    try:
        if not target_user_ids:
            return

        rows = await database.fetch_all(
            select(
                beach_users.c.id,
                beach_users.c.device_ids,
                beach_users.c.notification_prefs,
            ).where(beach_users.c.id.in_(target_user_ids))
        )

        now = datetime.now(timezone.utc)
        send_hour = int(send_at.timestamp() // 3600)

        for row in rows:
            user_id = row["id"]
            device_ids: list = list(row["device_ids"] or [])
            prefs: dict = row["notification_prefs"] or {}

            # Skip push if user explicitly disabled this type (but in-app still exists)
            if not prefs.get(notif_type, True):
                continue

            if not device_ids:
                continue

            push_data = {**data, "notif_type": notif_type}

            for installation_id in device_ids:
                try:
                    await database.execute(
                        insert(push_schedules).values(
                            installation_id=installation_id,
                            send_at_utc=send_at,
                            send_hour_utc=send_hour,
                            title=title,
                            body=body,
                            data_json=push_data,
                            status="pending",
                            attempts=0,
                            last_error=None,
                            created_at=now,
                            updated_at=now,
                        )
                    )
                except Exception as e:
                    logger.warning(f"Failed to schedule push for {installation_id}: {e}")

    except Exception as e:
        logger.error(f"_schedule_push_for_users error: {e}")


# ──────────── Endpoints ────────────

@router.get("/unread")
async def get_unread_notifications(
    user_id: int = Depends(beach_get_current_user_id),
):
    """Get all notifications for user that are not read and not expired."""
    now = datetime.now(timezone.utc)

    # target_user_ids @> ARRAY[user_id] AND NOT (read_user_ids @> ARRAY[user_id])
    stmt = (
        select(beach_notifications)
        .where(
            beach_notifications.c.target_user_ids.any(user_id),
        )
        .where(beach_notifications.c.expires_at > now)
        .order_by(beach_notifications.c.created_at.desc())
        .limit(100)
    )
    rows = await database.fetch_all(stmt)

    items = []
    for r in rows:
        read_ids = list(r["read_user_ids"] or [])
        items.append(NotificationItem(
            id=r["id"],
            type=r["type"],
            title=r["title"],
            body=r["body"],
            data_json=r["data_json"] or {},
            is_read=user_id in read_ids,
            created_at=r["created_at"].isoformat() if r["created_at"] else "",
        ))

    unread_count = sum(1 for i in items if not i.is_read)
    return {"items": [i.dict() for i in items], "unread_count": unread_count}


@router.post("/mark-read")
async def mark_notifications_read(
    body: MarkReadRequest,
    user_id: int = Depends(beach_get_current_user_id),
):
    """Mark specific notifications as read for current user."""
    if not body.notification_ids:
        return {"ok": True}

    for nid in body.notification_ids:
        # Append user_id to read_user_ids if not already there
        row = await database.fetch_one(
            select(beach_notifications.c.read_user_ids).where(
                beach_notifications.c.id == nid
            )
        )
        if not row:
            continue
        read_ids = list(row["read_user_ids"] or [])
        if user_id not in read_ids:
            read_ids.append(user_id)
            await database.execute(
                update(beach_notifications)
                .where(beach_notifications.c.id == nid)
                .values(read_user_ids=read_ids)
            )

    return {"ok": True}


@router.post("/mark-all-read")
async def mark_all_read(
    user_id: int = Depends(beach_get_current_user_id),
):
    """Mark all notifications as read for current user."""
    now = datetime.now(timezone.utc)

    rows = await database.fetch_all(
        select(beach_notifications.c.id, beach_notifications.c.read_user_ids)
        .where(beach_notifications.c.target_user_ids.any(user_id))
        .where(beach_notifications.c.expires_at > now)
    )

    for r in rows:
        read_ids = list(r["read_user_ids"] or [])
        if user_id not in read_ids:
            read_ids.append(user_id)
            await database.execute(
                update(beach_notifications)
                .where(beach_notifications.c.id == r["id"])
                .values(read_user_ids=read_ids)
            )

    return {"ok": True}


@router.delete("/{notification_id}")
async def delete_notification_for_user(
    notification_id: int,
    user_id: int = Depends(beach_get_current_user_id),
):
    """Remove current user from target_user_ids (soft-delete per user)."""
    row = await database.fetch_one(
        select(beach_notifications.c.target_user_ids).where(
            beach_notifications.c.id == notification_id
        )
    )
    if not row:
        raise HTTPException(status_code=404, detail="Notification not found")

    target_ids = list(row["target_user_ids"] or [])
    if user_id in target_ids:
        target_ids.remove(user_id)
        await database.execute(
            update(beach_notifications)
            .where(beach_notifications.c.id == notification_id)
            .values(target_user_ids=target_ids)
        )

    return {"ok": True}


@router.delete("/all/mine")
async def delete_all_for_user(
    user_id: int = Depends(beach_get_current_user_id),
):
    """Remove current user from all their notifications (soft-delete)."""
    now = datetime.now(timezone.utc)

    rows = await database.fetch_all(
        select(beach_notifications.c.id, beach_notifications.c.target_user_ids)
        .where(beach_notifications.c.target_user_ids.any(user_id))
        .where(beach_notifications.c.expires_at > now)
    )

    for r in rows:
        target_ids = list(r["target_user_ids"] or [])
        if user_id in target_ids:
            target_ids.remove(user_id)
            await database.execute(
                update(beach_notifications)
                .where(beach_notifications.c.id == r["id"])
                .values(target_user_ids=target_ids)
            )

    return {"ok": True}


# ──────────── Cleanup (called by cron) ────────────

async def cleanup_expired_notifications() -> int:
    """Delete notifications past their expires_at. Returns count deleted."""
    now = datetime.now(timezone.utc)
    result = await database.execute(
        delete(beach_notifications).where(beach_notifications.c.expires_at <= now)
    )
    return result or 0

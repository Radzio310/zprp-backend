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

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import delete, insert, select, update, and_, or_, func as sa_func

from app.db import database, beach_notifications, beach_users, beach_admins, push_schedules
from app.deps import beach_get_current_user_id, beach_get_optional_user_id
from app.beach.activity_log import log_activity, get_actor_name

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/notifications", tags=["Beach: Notifications"])

MAX_IN_APP_NOTIFICATIONS_PER_USER = 100


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

    # 1b) Enforce per-user notification limit.
    asyncio.ensure_future(_enforce_notif_limit(target_user_ids))

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


async def _enforce_notif_limit(
    user_ids: List[int],
    limit: int = MAX_IN_APP_NOTIFICATIONS_PER_USER,
) -> None:
    """Soft-delete oldest notifications beyond `limit` for each user."""
    try:
        now = datetime.now(timezone.utc)
        for user_id in user_ids:
            rows = await database.fetch_all(
                select(beach_notifications.c.id, beach_notifications.c.target_user_ids)
                .where(beach_notifications.c.target_user_ids.any(user_id))
                .where(beach_notifications.c.expires_at > now)
                .order_by(beach_notifications.c.created_at.desc())
            )
            if len(rows) <= limit:
                continue
            for r in rows[limit:]:
                target_ids = list(r["target_user_ids"] or [])
                if user_id in target_ids:
                    target_ids.remove(user_id)
                    await database.execute(
                        update(beach_notifications)
                        .where(beach_notifications.c.id == r["id"])
                        .values(target_user_ids=target_ids)
                    )
    except Exception as e:
        logger.error(f"_enforce_notif_limit error: {e}")


async def notify_admins(
    *,
    notif_type: str,
    title: str,
    body: str,
    data: Optional[Dict[str, Any]] = None,
    exclude_user_id: Optional[int] = None,
) -> None:
    """
    Send an in-app + push notification to ALL beach admins.

    Fire-and-forget safe — wraps everything in try/except.
    Pass `exclude_user_id` to skip the admin who triggered the action.
    """
    try:
        rows = await database.fetch_all(select(beach_admins.c.user_id))
        admin_ids = [
            int(r["user_id"]) for r in rows
            if exclude_user_id is None or int(r["user_id"]) != exclude_user_id
        ]
        if not admin_ids:
            return
        await create_notification(
            notif_type=notif_type,
            title=title,
            body=body,
            data=data or {},
            target_user_ids=admin_ids,
        )
    except Exception as e:
        logger.error(f"notify_admins error ({notif_type}): {e}")


# ──────────── Disqualification alert (field judge → head judge + admins) ────────────

class DisqAlertRequest(BaseModel):
    tournament_id: int
    match_number: str
    player_names: List[str]


@router.post("/disq-alert")
async def send_disq_alert(
    req: DisqAlertRequest,
    user_id: int = Depends(beach_get_current_user_id),
):
    """
    Notify head judge + all admins that a match finished with red-card disqualifications.
    Any authenticated beach user (typically the field judge) may call this.
    """
    from app.db import beach_tournaments  # local import avoids circular dep

    if not req.player_names:
        return {"ok": True, "sent_to": 0}

    # Resolve head judge user_id from tournament data_json
    tour_row = await database.fetch_one(
        select(beach_tournaments.c.data_json).where(beach_tournaments.c.id == req.tournament_id)
    )
    head_judge_id: Optional[int] = None
    if tour_row:
        dj = tour_row["data_json"] or {}
        hj = dj.get("head_judge_id")
        if hj is not None:
            try:
                head_judge_id = int(hj)
            except (TypeError, ValueError):
                pass

    # Collect admin user IDs
    admin_rows = await database.fetch_all(select(beach_admins.c.user_id))
    admin_ids = [int(r["user_id"]) for r in admin_rows]

    target_ids = list({*admin_ids, *([head_judge_id] if head_judge_id else [])})
    if not target_ids:
        return {"ok": True, "sent_to": 0}

    names_str = ", ".join(req.player_names)
    await create_notification(
        notif_type="player_disqualified",
        title="Czerwona kartka — decyzja oczekuje",
        body=f"Mecz {req.match_number}: {names_str}",
        data={"tournament_id": req.tournament_id, "match_id": req.match_number, "tab": "disqualifications"},
        target_user_ids=target_ids,
    )

    return {"ok": True, "sent_to": len(target_ids)}


# ──────────── Disqualification decision notification (player + coaches + judges) ────────────

def _ban_str_pl(n: int) -> str:
    if n == 1:
        return "1 mecz"
    if n in (2, 3, 4):
        return f"{n} mecze"
    return f"{n} meczów"


class DisqDecisionRequest(BaseModel):
    player_id: Optional[int] = None
    person_id: Optional[int] = None
    person_kind: str = "player"
    player_name: str
    team_name: str
    ban_matches: int
    tournament_id: int
    team_id: Optional[int] = None


@router.post("/disq-decision")
async def send_disq_decision_notification(
    req: DisqDecisionRequest,
    user_id: int = Depends(beach_get_current_user_id),
):
    """
    Notify player, team coaches and tournament judges about a disqualification decision.
    Each recipient group receives tailored content.
    """
    from app.db import beach_tournaments, beach_teams  # local import avoids circular dep

    ban_str = _ban_str_pl(req.ban_matches)
    notif_data = {"tournament_id": req.tournament_id, "tab": "disqualifications"}

    is_companion = req.person_kind == "companion"
    person_noun = "osoba towarzysząca" if is_companion else "zawodnik"
    person_noun_acc = "osoby towarzyszącej" if is_companion else "zawodnika"

    # ── 1. Disqualified person ──
    player_row = None
    if req.person_id is not None:
        player_row = await database.fetch_one(
            select(beach_users.c.id).where(beach_users.c.person_id == req.person_id)
        )
    elif req.player_id is not None:
        player_row = await database.fetch_one(
            select(beach_users.c.id).where(
                or_(beach_users.c.player_id == req.player_id, beach_users.c.id == req.player_id)
            )
        )
    player_user_id = int(player_row["id"]) if player_row else None
    player_has_account = player_user_id is not None
    if player_user_id is not None:
        await create_notification(
            notif_type="player_disqualified",
            title="Decyzja o Twojej dyskwalifikacji",
            body=f"Jako {person_noun} otrzymujesz zawieszenie na {ban_str} ({req.team_name})",
            data=notif_data,
            target_user_ids=[player_user_id],
        )

    # ── 2. Team coaches (companions with role TRENER) ──
    coach_user_ids: List[int] = []
    total_coaches = 0
    if req.team_id is not None:
        team_row = await database.fetch_one(
            select(beach_teams.c.companions_json).where(beach_teams.c.id == req.team_id)
        )
        if team_row:
            companions: list = team_row["companions_json"] or []
            coach_person_ids = [
                int(c["person_id"])
                for c in companions
                if isinstance(c, dict)
                and str(c.get("role", "")).upper() == "TRENER"
                and c.get("person_id") is not None
            ]
            total_coaches = len(coach_person_ids)
            if coach_person_ids:
                coach_rows = await database.fetch_all(
                    select(beach_users.c.id).where(
                        beach_users.c.person_id.in_(coach_person_ids)
                    )
                )
                coach_user_ids = [int(r["id"]) for r in coach_rows if int(r["id"]) != player_user_id]

    if coach_user_ids:
        await create_notification(
            notif_type="player_disqualified",
            title=f"Decyzja dyskwalifikacyjna — {person_noun_acc} z Twojej drużyny",
            body=f"{req.player_name} ({req.team_name}): {person_noun}, zawieszenie na {ban_str}",
            data=notif_data,
            target_user_ids=coach_user_ids,
        )

    # ── 3. Tournament judges ──
    judge_user_ids: List[int] = []
    total_judges = 0
    tour_row = await database.fetch_one(
        select(beach_tournaments.c.data_json).where(beach_tournaments.c.id == req.tournament_id)
    )
    if tour_row:
        dj = tour_row["data_json"] or {}
        judges: list = dj.get("judges") or []
        # Total judges = all assigned to tournament, excluding the caller
        total_judges = sum(
            1 for j in judges
            if isinstance(j, dict) and j.get("id") is not None and int(j["id"]) != user_id
        )
        already_notified = {*coach_user_ids}
        if player_user_id is not None:
            already_notified.add(player_user_id)
        judge_user_ids = [
            int(j["id"])
            for j in judges
            if isinstance(j, dict) and j.get("id") is not None
            and int(j["id"]) not in already_notified
            and int(j["id"]) != user_id
        ]

    if judge_user_ids:
        await create_notification(
            notif_type="player_disqualified",
            title="Decyzja zatwierdzona",
            body=f"{req.player_name} ({req.team_name}): {person_noun}, zawieszenie na {ban_str}",
            data=notif_data,
            target_user_ids=judge_user_ids,
        )

    return {
        "ok": True,
        "player": {"notified": player_has_account, "total": 1 if (req.player_id is not None or req.person_id is not None) else 0},
        "coaches": {"notified": len(coach_user_ids), "total": total_coaches},
        "judges": {"notified": len(judge_user_ids), "total": total_judges},
    }


# ──────────── Broadcast notification to tournament participants ────────────

class BroadcastRequest(BaseModel):
    title: str
    body: str
    target_user_ids: List[int]


@router.post("/broadcast")
async def broadcast_notification(
    req: BroadcastRequest,
    user_id: int = Depends(beach_get_current_user_id),
):
    """
    Send a push + in-app notification to specified user IDs.
    Only admins / hosts can call this.
    """
    # Verify admin
    admin_row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    if not admin_row:
        raise HTTPException(status_code=403, detail="Brak uprawnień administratora")

    if not req.title.strip() or not req.body.strip():
        raise HTTPException(status_code=400, detail="Tytuł i treść są wymagane")

    if not req.target_user_ids:
        return {"ok": True, "sent_to": 0}

    # Validate that provided user IDs actually exist
    rows = await database.fetch_all(
        select(beach_users.c.id).where(beach_users.c.id.in_(req.target_user_ids))
    )
    valid_ids = [int(r["id"]) for r in rows]
    if not valid_ids:
        return {"ok": True, "sent_to": 0}

    await create_notification(
        notif_type="admin_broadcast",
        title=req.title.strip(),
        body=req.body.strip(),
        data={"sender_id": user_id},
        target_user_ids=valid_ids,
    )

    # ── Activity log ──
    await log_activity(area="system", action="broadcast.sent", actor_user_id=user_id, actor_name=await get_actor_name(user_id), details={"title": req.title.strip(), "recipients_count": len(valid_ids)})

    return {"ok": True, "sent_to": len(valid_ids)}


# ──────────── Helper: _schedule_push_for_users ────────────

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
    count_only: bool = Query(False),
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user_id: Optional[int] = Depends(beach_get_optional_user_id),
):
    """Get a page of active notifications for the user plus total unread count."""
    if user_id is None:
        if count_only:
            return {"items": [], "unread_count": 0, "total": 0, "limit": limit, "offset": offset}
        raise HTTPException(status_code=401, detail="Brak autoryzacji")

    now = datetime.now(timezone.utc)

    base_stmt = (
        select(beach_notifications)
        .where(
            beach_notifications.c.target_user_ids.any(user_id),
        )
        .where(beach_notifications.c.expires_at > now)
    )
    total = await database.fetch_val(
        select(sa_func.count())
        .select_from(beach_notifications)
        .where(beach_notifications.c.target_user_ids.any(user_id))
        .where(beach_notifications.c.expires_at > now)
    )
    unread_rows = await database.fetch_all(
        select(beach_notifications.c.read_user_ids)
        .where(beach_notifications.c.target_user_ids.any(user_id))
        .where(beach_notifications.c.expires_at > now)
    )
    unread_count = sum(
        1 for r in unread_rows if user_id not in list(r["read_user_ids"] or [])
    )

    rows = []
    if not count_only:
        stmt = (
            base_stmt
            .order_by(beach_notifications.c.created_at.desc())
            .limit(limit)
            .offset(offset)
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

    return {
        "items": [i.dict() for i in items],
        "unread_count": unread_count,
        "total": int(total or 0),
        "limit": limit,
        "offset": offset,
    }


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

import os
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, select, update

from app.db import database, province_match_notifications, push_tokens, push_schedules
from .fcm import send_fcm_message
from .token_cleanup import invalidate_rejected_fcm_token


logger = logging.getLogger("app.push.scheduler")
_scheduler_wakeup = asyncio.Event()


def wake_push_scheduler() -> None:
    """Budzi scheduler po dopisaniu powiadomienia z bliskim terminem wysyłki."""
    _scheduler_wakeup.set()

def _utc_now():
    return datetime.now(timezone.utc)

async def _fetch_due(limit: int = 50):
    now = _utc_now()
    stmt = (
        select(
            push_schedules.c.id,
            push_schedules.c.installation_id,
            push_schedules.c.send_at_utc,
            push_schedules.c.title,
            push_schedules.c.body,
            push_schedules.c.data_json,
            push_schedules.c.status,
            push_schedules.c.attempts,
        )
        .where(push_schedules.c.status == "pending")
        .where(push_schedules.c.send_at_utc <= now)
        .order_by(push_schedules.c.send_at_utc.asc())
        .limit(limit)
    )
    return await database.fetch_all(stmt)

async def _get_token(installation_id: str):
    stmt = select(
        push_tokens.c.token_type,
        push_tokens.c.token,
        push_tokens.c.platform,
        push_tokens.c.app_variant,
    ).where(push_tokens.c.installation_id == installation_id)
    return await database.fetch_one(stmt)


async def _fetch_pending_match_notifications(limit: int = 50):
    now = _utc_now()
    # Rekord przejęty przez proces, który umarł, wraca do kolejki po 10 min.
    await database.execute(
        update(province_match_notifications)
        .where(province_match_notifications.c.status == "processing")
        .where(province_match_notifications.c.updated_at < now - timedelta(minutes=10))
        .values(status="pending", updated_at=now)
    )
    return await database.fetch_all(
        select(
            province_match_notifications.c.id,
            province_match_notifications.c.installation_id,
            province_match_notifications.c.title,
            province_match_notifications.c.body,
            province_match_notifications.c.data_json,
            province_match_notifications.c.attempts,
        )
        .where(province_match_notifications.c.status == "pending")
        .where(province_match_notifications.c.send_at_utc <= now)
        .order_by(province_match_notifications.c.send_at_utc.asc())
        .limit(limit)
    )


async def _next_match_notification_delay(default_seconds: int) -> float:
    next_due = await database.fetch_val(
        select(func.min(province_match_notifications.c.send_at_utc)).where(
            province_match_notifications.c.status == "pending"
        )
    )
    if not next_due:
        return float(default_seconds)
    if next_due.tzinfo is None:
        next_due = next_due.replace(tzinfo=timezone.utc)
    seconds = (next_due - _utc_now()).total_seconds()
    return max(0.1, min(float(default_seconds), seconds))


async def _wait_for_next_pass(default_seconds: int) -> None:
    if _scheduler_wakeup.is_set():
        _scheduler_wakeup.clear()
        return
    try:
        await asyncio.wait_for(
            _scheduler_wakeup.wait(),
            timeout=await _next_match_notification_delay(default_seconds),
        )
    except asyncio.TimeoutError:
        pass
    else:
        _scheduler_wakeup.clear()


async def _claim_match_notification(notification_id: int):
    return await database.fetch_one(
        update(province_match_notifications)
        .where(province_match_notifications.c.id == notification_id)
        .where(province_match_notifications.c.status == "pending")
        .values(status="processing", updated_at=_utc_now())
        .returning(province_match_notifications.c.id)
    )


async def _finish_match_notification(notification_id: int, attempts: int, error: str | None, final: bool):
    now = _utc_now()
    if error is None:
        values = {"status": "sent", "attempts": attempts, "last_error": None, "sent_at": now, "updated_at": now}
    else:
        values = {
            "status": "failed" if final else "pending",
            "attempts": attempts,
            "last_error": error[:900],
            "updated_at": now,
        }
        if not final:
            values["send_at_utc"] = now + timedelta(
                seconds=min(300, 15 * (2 ** max(0, attempts - 1)))
            )
    await database.execute(
        update(province_match_notifications)
        .where(province_match_notifications.c.id == notification_id)
        .values(**values)
    )

async def _mark_sent(sched_id: int):
    now = _utc_now()
    stmt = (
        update(push_schedules)
        .where(push_schedules.c.id == sched_id)
        .values(status="sent", updated_at=now)
    )
    await database.execute(stmt)

async def _mark_failed(sched_id: int, attempts: int, err: str, final: bool):
    now = _utc_now()
    status = "failed" if final else "pending"
    stmt = (
        update(push_schedules)
        .where(push_schedules.c.id == sched_id)
        .values(
            attempts=attempts,
            last_error=err[:900],
            status=status,
            updated_at=now,
        )
    )
    await database.execute(stmt)

async def run_push_scheduler():
    interval = int(os.getenv("PUSH_SCHEDULER_INTERVAL_SECONDS", "15"))
    max_attempts = int(os.getenv("PUSH_MAX_ATTEMPTS", "6"))

    while True:
        try:
            due = await _fetch_due(limit=50)
            for row in due:
                sid = int(row["id"])
                installation_id = row["installation_id"]
                title = row["title"]
                body = row["body"]
                data_json = row["data_json"] or {}
                attempts = int(row["attempts"] or 0) + 1

                tok = await _get_token(installation_id)
                if not tok:
                    await _mark_failed(sid, attempts, "Missing push token for installation_id", final=True)
                    continue

                token_type = (tok["token_type"] or "").strip()
                token = (tok["token"] or "").strip()

                if token_type != "device_fcm":
                    # Ten backend wysyła przez FCM HTTP v1 – bez FCM tokenu nie wyśle.
                    await _mark_failed(
                        sid,
                        attempts,
                        f"Unsupported token_type={token_type} (expected device_fcm)",
                        final=True,
                    )
                    continue

                try:
                    await send_fcm_message(token, title, body, data=data_json)
                    await _mark_sent(sid)
                except Exception as e:
                    invalidated = await invalidate_rejected_fcm_token(
                        installation_id,
                        token,
                        e,
                    )
                    final = invalidated or attempts >= max_attempts
                    await _mark_failed(sid, attempts, f"Send error: {str(e)}", final=final)

            match_notifications = await _fetch_pending_match_notifications(limit=50)
            for row in match_notifications:
                notification_id = int(row["id"])
                if not await _claim_match_notification(notification_id):
                    continue
                attempts = int(row["attempts"] or 0) + 1
                token_row = await _get_token(row["installation_id"])
                if not token_row:
                    await _finish_match_notification(
                        notification_id,
                        attempts,
                        "Missing push token for installation_id",
                        True,
                    )
                    continue
                if _stripped(token_row["token_type"]) != "device_fcm":
                    await _finish_match_notification(
                        notification_id,
                        attempts,
                        f"Unsupported token_type={token_row['token_type']}",
                        True,
                    )
                    continue
                try:
                    await send_fcm_message(
                        _stripped(token_row["token"]),
                        row["title"],
                        row["body"],
                        data=row["data_json"] or {},
                    )
                    await _finish_match_notification(notification_id, attempts, None, True)
                    logger.info("Match push notification %s sent", notification_id)
                except Exception as exc:
                    invalidated = await invalidate_rejected_fcm_token(
                        row["installation_id"],
                        _stripped(token_row["token"]),
                        exc,
                    )
                    await _finish_match_notification(
                        notification_id,
                        attempts,
                        f"Send error: {exc}",
                        invalidated or attempts >= max_attempts,
                    )
                    logger.warning(
                        "Match push notification %s failed on attempt %s: %s",
                        notification_id,
                        attempts,
                        exc,
                    )

        except Exception:
            # Nie przerywamy pętli, ale zostawiamy diagnozę w logach Railway.
            logger.exception("Push scheduler pass failed")

        await _wait_for_next_pass(interval)


def _stripped(value) -> str:
    return str(value or "").strip()

import os
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from sqlalchemy import cast, func, select, update
from sqlalchemy.dialects.postgresql import JSONB

from app.db import database, province_match_events, province_match_judges, province_match_notifications, push_local_match_receipts, push_tokens, push_schedules
from app.match_market_rules import state_dict
from .fcm import send_fcm_message
from .device_policy import dev_pushes_enabled, device_allowed
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
    # Worker, który zginął po przejęciu rekordu, nie może zablokować
    # przypomnienia na zawsze.
    await database.execute(
        update(push_schedules)
        .where(push_schedules.c.status == "processing")
        .where(push_schedules.c.updated_at < now - timedelta(minutes=10))
        .values(status="pending", updated_at=now)
    )
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


async def _claim_schedule(schedule_id: int):
    return await database.fetch_one(
        update(push_schedules)
        .where(push_schedules.c.id == schedule_id)
        .where(push_schedules.c.status == "pending")
        .values(status="processing", updated_at=_utc_now())
        .returning(push_schedules.c.id)
    )

async def _get_token(installation_id: str):
    stmt = select(
        push_tokens.c.token_type,
        push_tokens.c.token,
        push_tokens.c.platform,
        push_tokens.c.app_variant,
        push_tokens.c.app_id,
        push_tokens.c.judge_id,
        push_tokens.c.notification_prefs,
    ).where(push_tokens.c.installation_id == installation_id)
    return await database.fetch_one(stmt)


async def _match_delivery_reason(row, data, token_row):
    """Recheck ownership/preferences at SEND time, including queued retries."""
    if not token_row:
        return "Missing push token for installation_id"
    if _stripped(row["judge_id"]) != _stripped(token_row["judge_id"]):
        return "Push identity changed (inbox retained for original judge)"
    if not _stripped(token_row["token"]):
        return "Inactive push token"
    # Also handles duplicate registrations that predate the registration fix.
    owner = await database.fetch_val(select(push_tokens.c.installation_id).where(
        push_tokens.c.token == token_row["token"],
        push_tokens.c.token_type == token_row["token_type"],
    ).order_by(push_tokens.c.updated_at.desc(), push_tokens.c.installation_id.desc()).limit(1))
    if owner and owner != row["installation_id"]:
        return "Superseded installation for this push token"
    if data.get("kind") == "province_match_change":
        from app.push.preferences import province_event_allowed
        if not province_event_allowed(token_row["notification_prefs"], data.get("event_type", ""),
                                      preference_keys=data.get("preference_keys")):
            return "Notification preference changed before delivery"
        if (data.get("match_id") and data.get("province") and
                data.get("event_type") not in {"assignment_removed", "match_removed"}):
            assigned = await database.fetch_val(select(province_match_judges.c.judge_id).where(
                province_match_judges.c.province == data["province"],
                province_match_judges.c.match_id == str(data["match_id"]),
                province_match_judges.c.judge_id == _stripped(row["judge_id"]),
                province_match_judges.c.active.is_(True),
            ).limit(1))
            if not assigned:
                return "Judge no longer assigned to this match (inbox retained)"
    return None


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
            province_match_notifications.c.judge_id,
            province_match_notifications.c.event_id,
            province_match_notifications.c.created_at,
        )
        .where(province_match_notifications.c.status == "pending")
        .where(province_match_notifications.c.send_at_utc <= now)
        .order_by(province_match_notifications.c.send_at_utc.asc())
        .limit(limit)
    )


async def _local_match_receipt_reason(row, data, now):
    if not data.get("match_id") or not row["judge_id"]:
        return None
    seen = await database.fetch_val(select(push_local_match_receipts.c.observed_at)
        .where(push_local_match_receipts.c.installation_id == row["installation_id"])
        .where(push_local_match_receipts.c.judge_id == row["judge_id"])
        .where(push_local_match_receipts.c.match_id == str(data["match_id"]))
        .where(push_local_match_receipts.c.observed_at >= now - timedelta(days=7)))
    if not seen:
        return None
    # Usunięcie i ponowny przydział otwierają nowy cykl. Potwierdzenie z
    # poprzedniego cyklu nie może wyciszyć nowego przydziału.
    removed_since = await database.fetch_val(
        select(province_match_notifications.c.id)
        .select_from(province_match_notifications.join(province_match_events,
            province_match_events.c.id == province_match_notifications.c.event_id))
        .where(province_match_notifications.c.installation_id == row["installation_id"])
        .where(province_match_notifications.c.judge_id == row["judge_id"])
        .where(province_match_events.c.match_id == str(data["match_id"]))
        .where(province_match_events.c.event_type.in_(["assignment_removed", "match_removed"]))
        .where(province_match_events.c.created_at > seen)
        .where(province_match_events.c.id < row["event_id"])
        .limit(1))
    return None if removed_since else "New match already presented locally (inbox retained)"


async def _match_notification_stale_reason(row, data):
    if data.get("kind") != "province_match_change":
        return None
    now = _utc_now()
    created_at = row["created_at"]
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    added = data.get("event_type") == "match_added"
    if created_at < now - timedelta(days=7 if added else 1):
        return "Expired match notification (inbox retained)"
    if added:
        return await _local_match_receipt_reason(row, data, now)
    if not data.get("match_id") or not data.get("province"):
        return None
    # Event_id odzwierciedla kolejność zmian, send_at może być przesunięty
    # przez retry. Nowsza ważna rewizja unieważnia starszy push, nie historię.
    newer = await database.fetch_val(
        select(province_match_notifications.c.id)
        .select_from(province_match_notifications.join(province_match_events,
            province_match_events.c.id == province_match_notifications.c.event_id))
        .where(province_match_notifications.c.installation_id == row["installation_id"])
        .where(province_match_notifications.c.event_id > row["event_id"])
        .where(province_match_notifications.c.status.in_(["pending", "processing", "sent"]))
        .where(province_match_events.c.province == str(data["province"]))
        .where(province_match_events.c.match_id == str(data["match_id"]))
        .where(province_match_events.c.event_type.notin_(["match_added", "match_info_updated"]))
        # A later lineup edit does not replace an approval or a venue change.
        # Collapse only repetitions of the same semantic category.
        .where(province_match_events.c.event_type == str(data.get("event_type") or ""))
        .where(cast(province_match_events.c.data_json, JSONB)["change_types"] ==
               list(data.get("change_types") or [data.get("event_type")]))
        .limit(1)
    )
    return "Superseded match revision (inbox retained)" if newer else None


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
            allow_dev = await dev_pushes_enabled()
            due = await _fetch_due(limit=50)
            for row in due:
                sid = int(row["id"])
                if not await _claim_schedule(sid):
                    continue
                installation_id = row["installation_id"]
                title = row["title"]
                body = row["body"]
                data_json = state_dict(row["data_json"])
                attempts = int(row["attempts"] or 0) + 1
                if data_json.get("match_start_utc") or data_json.get("type") == "match_reminder":
                    expiry = row["send_at_utc"] + timedelta(minutes=15)
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    if expiry <= _utc_now():
                        await _mark_failed(sid, attempts, "Expired match reminder", final=True)
                        continue
                    data_json = {**data_json, "notificationExpiresAt": str(int(expiry.timestamp()))}

                tok = await _get_token(installation_id)
                if not tok:
                    await _mark_failed(sid, attempts, "Missing push token for installation_id", final=True)
                    continue

                intended = _stripped(data_json.get("judgeId") or data_json.get("judge_id"))
                if intended and intended != _stripped(tok["judge_id"]):
                    await _mark_failed(sid, attempts, "Push identity changed before scheduled delivery", final=True)
                    continue

                if not device_allowed(tok, allow_dev):
                    await _mark_failed(
                        sid,
                        attempts,
                        "DEV notifications disabled by administrator",
                        final=True,
                    )
                    continue

                token_type = (tok["token_type"] or "").strip()
                token = (tok["token"] or "").strip()
                if not token:
                    await _mark_failed(sid, attempts, "Inactive push token", final=True)
                    continue

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
                data = state_dict(row["data_json"])
                stale_reason = await _match_notification_stale_reason(row, data)
                if stale_reason:
                    await _finish_match_notification(notification_id, attempts, stale_reason, True)
                    continue
                token_row = await _get_token(row["installation_id"])
                delivery_reason = await _match_delivery_reason(row, data, token_row)
                if delivery_reason:
                    await _finish_match_notification(notification_id, attempts, delivery_reason, True)
                    continue
                if token_row and not device_allowed(token_row, allow_dev):
                    await _finish_match_notification(
                        notification_id,
                        attempts,
                        "DEV notifications disabled by administrator",
                        True,
                    )
                    continue
                from app.mentoring_notifications import delivery_allowed
                if not await delivery_allowed(row["data_json"] or {}, token_row):
                    await _finish_match_notification(notification_id, attempts, "Mentoring access revoked or muted", True)
                    continue
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
                        data={**data, "judgeId": _stripped(row["judge_id"])},
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

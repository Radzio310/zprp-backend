import os
import asyncio
from datetime import datetime, timezone
from sqlalchemy import select, update

from app.db import database, push_tokens, push_schedules
from .fcm import send_fcm_message

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
                    final = attempts >= max_attempts
                    await _mark_failed(sid, attempts, f"Send error: {str(e)}", final=final)

        except Exception:
            # nie przerywamy pętli
            pass

        await asyncio.sleep(interval)

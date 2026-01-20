import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import delete, insert, select, update

from app.db import database, push_tokens, push_schedules
from .models import (
    PushRegisterRequest,
    PushScheduleBulkRequest,
    PushClearRequest,
)

router = APIRouter(prefix="/push", tags=["push"])

def _utc_now():
    return datetime.now(timezone.utc)

def _send_hour_utc(dt: datetime) -> int:
    return int(dt.timestamp() // 3600)

def _parse_utc_iso(s: str) -> datetime:
    try:
        # expects ISO like 2026-01-20T12:34:56Z or with +00:00
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid send_at_utc format")

@router.post("/register")
async def register(req: PushRegisterRequest):
    if not req.installation_id or not req.token:
        raise HTTPException(status_code=400, detail="Missing installation_id or token")

    now = _utc_now()

    # upsert by installation_id
    stmt = select(push_tokens.c.installation_id).where(
        push_tokens.c.installation_id == req.installation_id
    )
    existing = await database.fetch_one(stmt)

    if existing:
        upd = (
            update(push_tokens)
            .where(push_tokens.c.installation_id == req.installation_id)
            .values(
                token_type=req.token_type,
                token=req.token,
                platform=req.platform,
                app_variant=req.app_variant,
                updated_at=now,
            )
        )
        await database.execute(upd)
    else:
        ins = insert(push_tokens).values(
            installation_id=req.installation_id,
            token_type=req.token_type,
            token=req.token,
            platform=req.platform,
            app_variant=req.app_variant,
            updated_at=now,
        )
        await database.execute(ins)

    return {"ok": True}

@router.post("/schedules/clear")
async def clear(req: PushClearRequest):
    if not req.installation_id:
        raise HTTPException(status_code=400, detail="Missing installation_id")

    stmt = delete(push_schedules).where(
        (push_schedules.c.installation_id == req.installation_id)
        & (push_schedules.c.status == "pending")
    )
    await database.execute(stmt)
    return {"ok": True}

@router.post("/schedule/bulk")
async def bulk(req: PushScheduleBulkRequest):
    if not req.installation_id:
        raise HTTPException(status_code=400, detail="Missing installation_id")

    now = _utc_now()
    items = req.items or []

    # Dedupe: max 1 pending per hour – realizujemy to przez delete + insert per hour
    inserted = 0

    for it in items:
        dt = _parse_utc_iso(it.send_at_utc)
        hour = _send_hour_utc(dt)

        # usuń istniejące pending w tej godzinie
        del_stmt = delete(push_schedules).where(
            (push_schedules.c.installation_id == req.installation_id)
            & (push_schedules.c.send_hour_utc == hour)
            & (push_schedules.c.status == "pending")
        )
        await database.execute(del_stmt)

        ins = insert(push_schedules).values(
            installation_id=req.installation_id,
            send_at_utc=dt,
            send_hour_utc=hour,
            title=it.title,
            body=it.body,
            data_json=it.data or {},
            status="pending",
            attempts=0,
            last_error=None,
            created_at=now,
            updated_at=now,
        )
        await database.execute(ins)
        inserted += 1

    return {"ok": True, "inserted": inserted}

@router.get("/schedules")
async def list_schedules(
    installation_id: str,
    status: Optional[str] = None,
    limit: int = 200,
):
    if not installation_id:
        raise HTTPException(status_code=400, detail="Missing installation_id")
    limit = max(1, min(500, int(limit)))

    stmt = select(
        push_schedules.c.id,
        push_schedules.c.installation_id,
        push_schedules.c.send_at_utc,
        push_schedules.c.title,
        push_schedules.c.body,
        push_schedules.c.data_json,
        push_schedules.c.status,
        push_schedules.c.attempts,
        push_schedules.c.last_error,
        push_schedules.c.created_at,
    ).where(push_schedules.c.installation_id == installation_id)

    if status:
        stmt = stmt.where(push_schedules.c.status == status)

    stmt = stmt.order_by(push_schedules.c.send_at_utc.asc()).limit(limit)
    rows = await database.fetch_all(stmt)

    return {"items": [dict(r) for r in rows]}

@router.get("/schedules/all")
async def list_all(request: Request, limit: int = 200):
    admin_key = os.getenv("PUSH_ADMIN_KEY", "")
    if admin_key:
        got = request.headers.get("X-Admin-Key", "")
        if got != admin_key:
            raise HTTPException(status_code=401, detail="Unauthorized")

    limit = max(1, min(500, int(limit)))
    stmt = select(
        push_schedules.c.id,
        push_schedules.c.installation_id,
        push_schedules.c.send_at_utc,
        push_schedules.c.title,
        push_schedules.c.status,
        push_schedules.c.attempts,
        push_schedules.c.last_error,
        push_schedules.c.created_at,
    ).order_by(push_schedules.c.created_at.desc()).limit(limit)

    rows = await database.fetch_all(stmt)
    return {"items": [dict(r) for r in rows]}

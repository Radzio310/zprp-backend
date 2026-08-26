import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import delete, insert, select, update

from app.db import (
    beach_users,
    database,
    province_match_events,
    province_match_notifications,
    province_match_sync_runs,
    push_schedules,
    push_tokens,
)
from app.province_match_monitor import configured_provinces, normalize_province
from .models import (
    PushRegisterRequest,
    PushIdentityRequest,
    PushScheduleBulkRequest,
    PushClearRequest,
)
from .token_cleanup import invalidate_rejected_fcm_token

router = APIRouter(prefix="/push", tags=["push"])

def _utc_now():
    return datetime.now(timezone.utc)


async def send_push_to_judges(
    judge_ids: List[str],
    title: str,
    body: str,
    data: Optional[Dict[str, Any]] = None,
) -> int:
    """
    Wysyła push NATYCHMIAST na wszystkie urządzenia podanych sędziów.

    W odróżnieniu od push_schedules (który czeka na przebieg schedulera) to jest
    droga dla rzeczy, które muszą dojść od razu — np. odpowiedź admina na
    zgłoszenie. Urządzenia bez zapisanego judge_id (starsze wersje aplikacji)
    po prostu nie dostaną powiadomienia; w aplikacji zostaje im licznik
    nieprzeczytanych.

    Zwraca liczbę urządzeń, do których poszła wysyłka. Nigdy nie rzuca —
    powiadomienie nie może wywalić operacji, przy której powstało.
    """
    ids = [str(j) for j in judge_ids if j]
    if not ids:
        return 0
    try:
        rows = await database.fetch_all(
            select(
                push_tokens.c.installation_id,
                push_tokens.c.token,
                push_tokens.c.token_type,
            ).where(
                push_tokens.c.judge_id.in_(ids)
            )
        )
    except Exception:
        return 0

    from .fcm import send_fcm_message

    sent = 0
    for row in rows:
        if row["token_type"] != "device_fcm":
            continue
        try:
            await send_fcm_message(row["token"], title, body, data=data or {})
            sent += 1
        except Exception as exc:
            await invalidate_rejected_fcm_token(
                row["installation_id"],
                row["token"],
                exc,
            )
            # Wygasły token jednego urządzenia nie może zablokować reszty.
            continue
    return sent

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
        identity_values: Dict[str, Any] = {}
        if req.identity_known:
            identity_values["judge_id"] = req.judge_id or None
            identity_values["province"] = normalize_province(req.province) or None
        elif req.judge_id:
            # Kompatybilność ze starszą wersją, która wysyła judge_id, ale nie
            # zna jeszcze identity_known.
            identity_values["judge_id"] = req.judge_id
        if req.province and not req.identity_known:
            identity_values["province"] = normalize_province(req.province) or None
        if req.notification_prefs:
            identity_values["notification_prefs"] = req.notification_prefs
        upd = (
            update(push_tokens)
            .where(push_tokens.c.installation_id == req.installation_id)
            .values(
                token_type=req.token_type,
                token=req.token,
                platform=req.platform,
                app_variant=req.app_variant,
                # Nie kasujemy zapisanego judge_id, gdy przyjdzie żądanie ze
                # starszej aplikacji, która tego pola nie zna.
                **identity_values,
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
            judge_id=req.judge_id,
            province=normalize_province(req.province) or None,
            notification_prefs=req.notification_prefs or {},
            updated_at=now,
        )
        await database.execute(ins)

    return {"ok": True}


@router.post("/identity")
async def update_push_identity(req: PushIdentityRequest):
    """Aktualizuje/usuwa tożsamość bez ponownego pobierania tokenu FCM."""
    if not req.installation_id:
        raise HTTPException(status_code=400, detail="Missing installation_id")
    values: Dict[str, Any] = {
        "judge_id": req.judge_id or None,
        "province": normalize_province(req.province) or None,
        "updated_at": _utc_now(),
    }
    if req.notification_prefs:
        values["notification_prefs"] = req.notification_prefs
    changed = await database.execute(
        update(push_tokens)
        .where(push_tokens.c.installation_id == req.installation_id)
        .values(**values)
    )
    return {"ok": True, "updated": bool(changed)}


@router.get("/match-events")
async def list_match_events(installation_id: str, limit: int = 100):
    """Trwała skrzynka powiadomień o zmianach meczów dla jednej instalacji.

    Push i skrzynka są niezależne: jeśli system operacyjny nie pokaże pusha,
    aplikacja nadal pobierze wpis i scali go z lokalnym panelem powiadomień.
    """
    if not installation_id:
        raise HTTPException(status_code=400, detail="Missing installation_id")
    limit = max(1, min(200, int(limit)))
    stmt = (
        select(
            province_match_notifications.c.id,
            province_match_notifications.c.event_id,
            province_match_notifications.c.title,
            province_match_notifications.c.body,
            province_match_notifications.c.data_json,
            province_match_notifications.c.status,
            province_match_notifications.c.created_at,
            province_match_notifications.c.sent_at,
            province_match_events.c.match_code,
            province_match_events.c.event_type,
        )
        .select_from(
            province_match_notifications.join(
                province_match_events,
                province_match_notifications.c.event_id == province_match_events.c.id,
            )
        )
        .where(province_match_notifications.c.installation_id == installation_id)
        .where(province_match_notifications.c.send_at_utc <= _utc_now())
        .order_by(province_match_notifications.c.created_at.desc())
        .limit(limit)
    )
    rows = await database.fetch_all(stmt)
    return {"items": [dict(row) for row in rows]}


@router.get("/match-monitor/status")
async def match_monitor_status(request: Request, limit: int = 50):
    """Ostatnie przebiegi i ich rzeczywisty koszt (mecze/detail/eventy)."""
    admin_key = os.getenv("PUSH_ADMIN_KEY", "")
    if admin_key and request.headers.get("X-Admin-Key", "") != admin_key:
        raise HTTPException(status_code=401, detail="Unauthorized")
    rows = await database.fetch_all(
        select(province_match_sync_runs)
        .order_by(province_match_sync_runs.c.started_at.desc())
        .limit(max(1, min(200, int(limit))))
    )
    return {
        "enabled": os.getenv("ZPRP_MATCH_MONITOR_ENABLED", "true").lower()
        in ("1", "true", "yes", "on"),
        "configured_provinces": sorted(configured_provinces().keys()),
        "runs": [dict(row) for row in rows],
    }

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


# ─────────────────── Beach: send push to all devices of a user ───────────────

class NotifyUserRequest(BaseModel):
    user_id: int
    title: str
    body: str
    send_at_utc: str  # ISO UTC, e.g. "2026-05-01T10:00:00Z"
    data: Optional[Dict[str, Any]] = None


@router.post("/beach/notify-user")
async def beach_notify_user(req: NotifyUserRequest, request: Request):
    """
    Planuje powiadomienie push do WSZYSTKICH urządzeń (installation_ids) użytkownika Beach.
    Wymaga nagłówka X-Admin-Key.
    """
    admin_key = os.getenv("PUSH_ADMIN_KEY", "")
    if admin_key:
        got = request.headers.get("X-Admin-Key", "")
        if got != admin_key:
            raise HTTPException(status_code=401, detail="Unauthorized")

    send_at = _parse_utc_iso(req.send_at_utc)

    # Pobierz device_ids użytkownika
    row = await database.fetch_one(
        select(beach_users.c.device_ids).where(beach_users.c.id == req.user_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    device_ids: List[str] = list(row["device_ids"] or [])
    if not device_ids:
        return {"ok": True, "scheduled": 0, "skipped": 0, "reason": "no_devices"}

    now = _utc_now()
    send_hour = _send_hour_utc(send_at)
    scheduled = 0
    skipped = 0

    for installation_id in device_ids:
        # Deduplikacja: jeden push na (installation_id, send_hour_utc)
        existing = await database.fetch_one(
            select(push_schedules.c.id).where(
                (push_schedules.c.installation_id == installation_id)
                & (push_schedules.c.send_hour_utc == send_hour)
                & (push_schedules.c.status == "pending")
            )
        )
        if existing:
            skipped += 1
            continue

        await database.execute(
            insert(push_schedules).values(
                installation_id=installation_id,
                send_at_utc=send_at,
                send_hour_utc=send_hour,
                title=req.title,
                body=req.body,
                data_json=req.data or {},
                status="pending",
                attempts=0,
                last_error=None,
                created_at=now,
                updated_at=now,
            )
        )
        scheduled += 1

    return {"ok": True, "scheduled": scheduled, "skipped": skipped}

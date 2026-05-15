"""
Beach Activity Log — audit history for all beach module actions.

Core features:
  - log_activity()  — fire-and-forget INSERT (non-blocking)
  - compute_diff()  — compare old/new dicts, return changed fields
  - Query endpoints — paginated, filterable by area/user/date/text
  - Retention config — configurable cleanup of old entries
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, func as sa_func, insert, select, text

from app.db import database, beach_activity_log, beach_admins, beach_app_settings, beach_users
from app.deps import beach_get_current_user_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/activity-log", tags=["Beach: Activity Log"])

# ─────────────────── Core helpers ───────────────────

DEFAULT_RETENTION_DAYS = 365
_RETENTION_KEY = "activity_log_retention_days"

# Cache for actor names within the same request lifecycle
_actor_name_cache: Dict[int, str] = {}


async def get_actor_name(user_id: int) -> str:
    """Fetch user full_name for activity log. Cached per process."""
    if user_id in _actor_name_cache:
        return _actor_name_cache[user_id]
    row = await database.fetch_one(
        select(beach_users.c.full_name).where(beach_users.c.id == user_id)
    )
    name = row["full_name"] if row else f"user#{user_id}"
    _actor_name_cache[user_id] = name
    # Evict cache when too large
    if len(_actor_name_cache) > 500:
        _actor_name_cache.clear()
    return name


def _json_safe(val: Any) -> Any:
    """Make a value JSON-serializable."""
    if isinstance(val, datetime):
        return val.isoformat()
    if isinstance(val, (set, frozenset)):
        return sorted(val)
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return val


def compute_diff(
    old: Dict[str, Any],
    new: Dict[str, Any],
    fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Compare two dicts, return {field: {old: ..., new: ...}} for changed fields.
    If `fields` is given, only compare those keys.
    """
    changed: Dict[str, Any] = {}
    keys = fields if fields else sorted(set(list(old.keys()) + list(new.keys())))
    for k in keys:
        ov = _json_safe(old.get(k))
        nv = _json_safe(new.get(k))
        if ov != nv:
            changed[k] = {"old": ov, "new": nv}
    return changed


def compute_list_diff(
    old_items: List[Any],
    new_items: List[Any],
    key_fn=None,
) -> Dict[str, Any]:
    """
    Compare two lists, return {added: [...], removed: [...], count_before, count_after}.
    If key_fn is provided, uses it to identify items; otherwise uses equality.
    """
    if key_fn:
        old_keys = {key_fn(x) for x in old_items}
        new_keys = {key_fn(x) for x in new_items}
        added = [x for x in new_items if key_fn(x) not in old_keys]
        removed = [x for x in old_items if key_fn(x) not in new_keys]
    else:
        old_set = set(str(x) for x in old_items)
        new_set = set(str(x) for x in new_items)
        added = [x for x in new_items if str(x) not in old_set]
        removed = [x for x in old_items if str(x) not in new_set]
    return {
        "added": [_json_safe(x) for x in added],
        "removed": [_json_safe(x) for x in removed],
        "count_before": len(old_items),
        "count_after": len(new_items),
    }


async def log_activity(
    *,
    area: str,
    action: str,
    actor_user_id: Optional[int] = None,
    actor_name: Optional[str] = None,
    target_id: Optional[str] = None,
    target_label: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Fire-and-forget activity log insert.
    Safe to call from any endpoint — never raises, never blocks response.
    """
    async def _insert():
        try:
            await database.execute(
                insert(beach_activity_log).values(
                    area=area,
                    action=action,
                    actor_user_id=actor_user_id,
                    actor_name=actor_name,
                    target_id=str(target_id) if target_id is not None else None,
                    target_label=target_label,
                    details_json=details,
                    created_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            logger.error("Activity log insert failed: %s", e)

    asyncio.ensure_future(_insert())


# ─────────────────── Retention ───────────────────

async def _get_retention_days() -> int:
    row = await database.fetch_one(
        select(beach_app_settings.c.value).where(
            beach_app_settings.c.key == _RETENTION_KEY
        )
    )
    if row and row["value"]:
        try:
            return max(1, int(row["value"]))
        except (ValueError, TypeError):
            pass
    return DEFAULT_RETENTION_DAYS


async def cleanup_old_activity_logs() -> int:
    """Delete activity log entries older than configured retention. Returns count deleted."""
    days = await _get_retention_days()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    result = await database.execute(
        delete(beach_activity_log).where(beach_activity_log.c.created_at < cutoff)
    )
    return result if isinstance(result, int) else 0


# ─────────────────── Auth helper ───────────────────

async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    return bool(row)


# ─────────────────── Query endpoints ───────────────────

@router.get(
    "/",
    response_model=dict,
    summary="Lista historii akcji (admin only, paginated)",
)
async def list_activity_log(
    area: Optional[str] = Query(None, description="Filter by area"),
    actor_user_id: Optional[int] = Query(None, description="Filter by actor"),
    target_id: Optional[str] = Query(None, description="Filter by target entity"),
    date_from: Optional[str] = Query(None, description="ISO date (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="ISO date (YYYY-MM-DD)"),
    search: Optional[str] = Query(None, description="Text search in actor_name/target_label/action"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    t = beach_activity_log
    conditions = []

    if area:
        conditions.append(t.c.area == area)
    if actor_user_id is not None:
        conditions.append(t.c.actor_user_id == actor_user_id)
    if target_id:
        conditions.append(t.c.target_id == target_id)
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from)
            conditions.append(t.c.created_at >= dt_from)
        except ValueError:
            raise HTTPException(400, f"Invalid date_from: {date_from}")
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
            # include the whole day
            if dt_to.hour == 0 and dt_to.minute == 0:
                dt_to = dt_to + timedelta(days=1)
            conditions.append(t.c.created_at < dt_to)
        except ValueError:
            raise HTTPException(400, f"Invalid date_to: {date_to}")
    if search:
        like_pattern = f"%{search}%"
        conditions.append(
            (t.c.actor_name.ilike(like_pattern))
            | (t.c.target_label.ilike(like_pattern))
            | (t.c.action.ilike(like_pattern))
        )

    where = sa_func.coalesce(text("TRUE"))
    base = select(t)
    count_base = select(sa_func.count()).select_from(t)
    for cond in conditions:
        base = base.where(cond)
        count_base = count_base.where(cond)

    total = await database.fetch_val(count_base)
    rows = await database.fetch_all(
        base.order_by(t.c.created_at.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )

    items = []
    for r in rows:
        d = dict(r._mapping)
        if isinstance(d.get("created_at"), datetime):
            d["created_at"] = d["created_at"].isoformat()
        if isinstance(d.get("details_json"), str):
            try:
                d["details_json"] = json.loads(d["details_json"])
            except Exception:
                pass
        items.append(d)

    return {
        "items": items,
        "total": total or 0,
        "page": page,
        "page_size": page_size,
    }


@router.get(
    "/stats",
    response_model=dict,
    summary="Statystyki historii per area (admin only)",
)
async def activity_log_stats(
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    t = beach_activity_log
    conditions = []
    if date_from:
        try:
            conditions.append(t.c.created_at >= datetime.fromisoformat(date_from))
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
            if dt_to.hour == 0 and dt_to.minute == 0:
                dt_to = dt_to + timedelta(days=1)
            conditions.append(t.c.created_at < dt_to)
        except ValueError:
            pass

    q = select(t.c.area, sa_func.count().label("cnt")).group_by(t.c.area)
    for cond in conditions:
        q = q.where(cond)
    rows = await database.fetch_all(q)

    counts = {}
    total = 0
    for r in rows:
        d = dict(r._mapping)
        counts[d["area"]] = d["cnt"]
        total += d["cnt"]

    return {"counts": counts, "total": total}


@router.get(
    "/retention",
    response_model=dict,
    summary="Pobierz konfigurację retencji historii",
)
async def get_retention(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")
    days = await _get_retention_days()
    return {"retention_days": days}


@router.patch(
    "/retention",
    response_model=dict,
    summary="Zmień retencję historii (admin only)",
)
async def set_retention(
    body: dict,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    days = body.get("retention_days")
    if not isinstance(days, int) or days < 1:
        raise HTTPException(400, "retention_days must be a positive integer")

    from sqlalchemy.dialects.postgresql import insert as pg_insert
    stmt = (
        pg_insert(beach_app_settings)
        .values(key=_RETENTION_KEY, value=str(days), updated_at=datetime.now(timezone.utc))
        .on_conflict_do_update(
            index_elements=[beach_app_settings.c.key],
            set_={"value": str(days), "updated_at": datetime.now(timezone.utc)},
        )
    )
    await database.execute(stmt)

    await log_activity(
        area="system",
        action="system.retention_changed",
        actor_user_id=current_user_id,
        details={"retention_days": days},
    )

    return {"retention_days": days}


@router.delete(
    "/cleanup",
    response_model=dict,
    summary="Ręczne czyszczenie starszych wpisów (admin only)",
)
async def manual_cleanup(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    deleted = await cleanup_old_activity_logs()
    return {"deleted": deleted}

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import traceback
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from sqlalchemy import select, update, delete, insert

import asyncio
from app.db import database, beach_badges, beach_users
from app.beach.notifications import notify_admins
from app.schemas import (
    BeachBadgeItem,
    BeachBadgeCreateRequest,
    BeachBadgeUpdateRequest,
    BeachBadgesListResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/badges", tags=["Beach: Badges"])

DEFAULT_LOVER_BADGE_NAME = "Beach Handball Lover"
DEFAULT_LOVER_BADGE_CONFIG = {
    "icon": "heart-circle-outline",
    "color": "#FF8A3D",
    "description": "Domyślny badge dla użytkowników BAZA Beach.",
    "category": "HANDBALL",
}


def _parse_json(raw: Any):
    if raw is None:
        return {}
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _rename_badge_in_user_badges(raw: Any, old_name: str, new_name: str) -> tuple[Any, bool]:
    if old_name == new_name:
        return raw, False

    parsed = _parse_json(raw)
    if isinstance(parsed, dict):
        if old_name not in parsed:
            return parsed, False
        old_value = parsed.pop(old_name)
        if new_name not in parsed or not parsed.get(new_name):
            parsed[new_name] = old_value if old_value is not None else True
        return parsed, True

    if isinstance(parsed, list):
        changed = False
        out: List[Any] = []
        has_new = any(str(x) == new_name for x in parsed if x is not None)
        for item in parsed:
            if item is None:
                continue
            if str(item) == old_name:
                changed = True
                if not has_new:
                    out.append(new_name)
                    has_new = True
            else:
                out.append(item)
        return out, changed

    return raw, False


def _remove_badge_from_user_badges(raw: Any, badge_name: str) -> tuple[Any, bool]:
    parsed = _parse_json(raw)
    if isinstance(parsed, dict):
        if badge_name not in parsed:
            return parsed, False
        parsed.pop(badge_name, None)
        return parsed, True

    if isinstance(parsed, list):
        out = [item for item in parsed if item is not None and str(item) != badge_name]
        return out, len(out) != len(parsed)

    return raw, False


async def ensure_default_lover_badge_definition() -> None:
    existing = await database.fetch_one(
        select(beach_badges.c.id).where(beach_badges.c.name == DEFAULT_LOVER_BADGE_NAME)
    )
    if existing:
        return

    try:
        await database.execute(
            insert(beach_badges).values(
                name=DEFAULT_LOVER_BADGE_NAME,
                config_json=DEFAULT_LOVER_BADGE_CONFIG,
                updated_at=datetime.now(timezone.utc),
            )
        )
    except Exception as e:
        msg = str(e).lower()
        if "unique" not in msg and "duplicate" not in msg:
            raise


async def rename_badge_for_all_users(old_name: str, new_name: str) -> int:
    rows = await database.fetch_all(select(beach_users.c.id, beach_users.c.badges))
    changed_count = 0
    now = datetime.now(timezone.utc)
    for row in rows:
        next_badges, changed = _rename_badge_in_user_badges(row["badges"], old_name, new_name)
        if not changed:
            continue
        await database.execute(
            update(beach_users)
            .where(beach_users.c.id == row["id"])
            .values(badges=next_badges, updated_at=now)
        )
        changed_count += 1
    return changed_count


async def remove_badge_from_all_users(badge_name: str) -> int:
    rows = await database.fetch_all(select(beach_users.c.id, beach_users.c.badges))
    changed_count = 0
    now = datetime.now(timezone.utc)
    for row in rows:
        next_badges, changed = _remove_badge_from_user_badges(row["badges"], badge_name)
        if not changed:
            continue
        await database.execute(
            update(beach_users)
            .where(beach_users.c.id == row["id"])
            .values(badges=next_badges, updated_at=now)
        )
        changed_count += 1
    return changed_count


@router.post("/", response_model=dict, summary="Utwórz nowy badge (BEACH)")
async def create_badge(req: BeachBadgeCreateRequest):
    now = datetime.now(timezone.utc)

    try:
        stmt = (
            insert(beach_badges)
            .values(
                name=req.name.strip(),
                config_json=req.config_json if req.config_json is not None else {},
                updated_at=now,
            )
            .returning(beach_badges.c.id)
        )
        row = await database.fetch_one(stmt)
        if not row:
            raise HTTPException(500, "Nie udało się utworzyć badge'a")
        badge_id = int(row["id"])
        asyncio.ensure_future(notify_admins(
            notif_type="admin_badge_created",
            title="Nowy badge",
            body=f"Dodano badge: {req.name.strip()}",
            data={"badge_id": badge_id, "badge_name": req.name.strip()},
        ))
        return {"success": True, "id": badge_id}
    except Exception as e:
        msg = str(e).lower()
        if "unique" in msg or "duplicate" in msg:
            raise HTTPException(status_code=409, detail="Badge o takiej nazwie już istnieje")
        logger.error("create_badge failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"create_badge failed: {e}")


@router.get("/", response_model=BeachBadgesListResponse, summary="Lista badge'y (BEACH)")
async def list_badges():
    await ensure_default_lover_badge_definition()
    rows = await database.fetch_all(select(beach_badges).order_by(beach_badges.c.id.asc()))
    out: List[BeachBadgeItem] = []
    for r in rows:
        out.append(
            BeachBadgeItem(
                id=int(r["id"]),
                name=r["name"],
                config_json=_parse_json(r["config_json"]),
                updated_at=r["updated_at"],
            )
        )
    return BeachBadgesListResponse(badges=out)


@router.get("/{badge_id}", response_model=BeachBadgeItem, summary="Pobierz badge po ID (BEACH)")
async def get_badge(badge_id: int):
    row = await database.fetch_one(select(beach_badges).where(beach_badges.c.id == badge_id))
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono badge'a")

    return BeachBadgeItem(
        id=int(row["id"]),
        name=row["name"],
        config_json=_parse_json(row["config_json"]),
        updated_at=row["updated_at"],
    )


@router.patch("/{badge_id}", response_model=BeachBadgeItem, summary="Częściowa edycja badge'a (BEACH)")
async def patch_badge(badge_id: int, body: BeachBadgeUpdateRequest):
    existing = await database.fetch_one(select(beach_badges).where(beach_badges.c.id == badge_id))
    if not existing:
        raise HTTPException(status_code=404, detail="Nie znaleziono badge'a")

    update_data: Dict[str, Any] = {}
    if body.name is not None:
        update_data["name"] = body.name.strip()
    if body.config_json is not None:
        update_data["config_json"] = body.config_json

    if not update_data:
        return BeachBadgeItem(
            id=int(existing["id"]),
            name=existing["name"],
            config_json=_parse_json(existing["config_json"]),
            updated_at=existing["updated_at"],
        )

    update_data["updated_at"] = datetime.now(timezone.utc)

    try:
        await database.execute(update(beach_badges).where(beach_badges.c.id == badge_id).values(**update_data))
        if "name" in update_data and update_data["name"] != existing["name"]:
            await rename_badge_for_all_users(str(existing["name"]), str(update_data["name"]))
    except Exception as e:
        msg = str(e).lower()
        if "unique" in msg or "duplicate" in msg:
            raise HTTPException(status_code=409, detail="Badge o takiej nazwie już istnieje")
        raise HTTPException(status_code=500, detail=f"patch_badge failed: {e}")

    row = await database.fetch_one(select(beach_badges).where(beach_badges.c.id == badge_id))
    result = BeachBadgeItem(
        id=int(row["id"]),
        name=row["name"],
        config_json=_parse_json(row["config_json"]),
        updated_at=row["updated_at"],
    )
    if update_data:  # only notify if something actually changed
        asyncio.ensure_future(notify_admins(
            notif_type="admin_badge_edited",
            title="Edytowano badge",
            body=f"Badge '{result.name}' został zaktualizowany",
            data={"badge_id": badge_id, "badge_name": result.name},
        ))
    return result


@router.put("/{badge_id}", response_model=BeachBadgeItem, summary="Pełna aktualizacja badge'a (BEACH)")
async def put_badge(badge_id: int, req: BeachBadgeCreateRequest):
    existing = await database.fetch_one(select(beach_badges).where(beach_badges.c.id == badge_id))
    if not existing:
        raise HTTPException(status_code=404, detail="Nie znaleziono badge'a")

    now = datetime.now(timezone.utc)
    old_name = str(existing["name"])
    new_name = req.name.strip()
    try:
        await database.execute(
            update(beach_badges)
            .where(beach_badges.c.id == badge_id)
            .values(
                name=new_name,
                config_json=req.config_json if req.config_json is not None else {},
                updated_at=now,
            )
        )
        if new_name != old_name:
            await rename_badge_for_all_users(old_name, new_name)
    except Exception as e:
        msg = str(e).lower()
        if "unique" in msg or "duplicate" in msg:
            raise HTTPException(status_code=409, detail="Badge o takiej nazwie już istnieje")
        raise HTTPException(status_code=500, detail=f"put_badge failed: {e}")

    row = await database.fetch_one(select(beach_badges).where(beach_badges.c.id == badge_id))
    result = BeachBadgeItem(
        id=int(row["id"]),
        name=row["name"],
        config_json=_parse_json(row["config_json"]),
        updated_at=row["updated_at"],
    )
    asyncio.ensure_future(notify_admins(
        notif_type="admin_badge_edited",
        title="Edytowano badge",
        body=f"Badge '{result.name}' został zaktualizowany",
        data={"badge_id": badge_id, "badge_name": result.name},
    ))
    return result


@router.delete("/{badge_id}", response_model=dict, summary="Usuń badge (BEACH)")
async def delete_badge(badge_id: int):
    row = await database.fetch_one(
        select(beach_badges.c.id, beach_badges.c.name).where(beach_badges.c.id == badge_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono badge'a")

    badge_name = str(row["name"])
    removed_from_users = await remove_badge_from_all_users(badge_name)
    await database.execute(delete(beach_badges).where(beach_badges.c.id == badge_id))
    asyncio.ensure_future(notify_admins(
        notif_type="admin_badge_deleted",
        title="Usunięto badge",
        body=f"Badge '{badge_name}' został usunięty",
        data={"badge_id": badge_id, "badge_name": badge_name},
    ))
    return {"success": True, "removed_from_users": removed_from_users}

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import traceback
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from sqlalchemy import select, update, delete, insert

from app.db import database, beach_badges
from app.schemas import (
    BeachBadgeItem,
    BeachBadgeCreateRequest,
    BeachBadgeUpdateRequest,
    BeachBadgesListResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/badges", tags=["Beach: Badges"])


def _parse_json(raw: Any):
    if raw is None:
        return {}
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return {}


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
        return {"success": True, "id": int(row["id"])}
    except Exception as e:
        msg = str(e).lower()
        if "unique" in msg or "duplicate" in msg:
            raise HTTPException(status_code=409, detail="Badge o takiej nazwie już istnieje")
        logger.error("create_badge failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"create_badge failed: {e}")


@router.get("/", response_model=BeachBadgesListResponse, summary="Lista badge'y (BEACH)")
async def list_badges():
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
    except Exception as e:
        msg = str(e).lower()
        if "unique" in msg or "duplicate" in msg:
            raise HTTPException(status_code=409, detail="Badge o takiej nazwie już istnieje")
        raise HTTPException(status_code=500, detail=f"patch_badge failed: {e}")

    row = await database.fetch_one(select(beach_badges).where(beach_badges.c.id == badge_id))
    return BeachBadgeItem(
        id=int(row["id"]),
        name=row["name"],
        config_json=_parse_json(row["config_json"]),
        updated_at=row["updated_at"],
    )


@router.put("/{badge_id}", response_model=BeachBadgeItem, summary="Pełna aktualizacja badge'a (BEACH)")
async def put_badge(badge_id: int, req: BeachBadgeCreateRequest):
    existing = await database.fetch_one(select(beach_badges).where(beach_badges.c.id == badge_id))
    if not existing:
        raise HTTPException(status_code=404, detail="Nie znaleziono badge'a")

    now = datetime.now(timezone.utc)
    try:
        await database.execute(
            update(beach_badges)
            .where(beach_badges.c.id == badge_id)
            .values(
                name=req.name.strip(),
                config_json=req.config_json if req.config_json is not None else {},
                updated_at=now,
            )
        )
    except Exception as e:
        msg = str(e).lower()
        if "unique" in msg or "duplicate" in msg:
            raise HTTPException(status_code=409, detail="Badge o takiej nazwie już istnieje")
        raise HTTPException(status_code=500, detail=f"put_badge failed: {e}")

    row = await database.fetch_one(select(beach_badges).where(beach_badges.c.id == badge_id))
    return BeachBadgeItem(
        id=int(row["id"]),
        name=row["name"],
        config_json=_parse_json(row["config_json"]),
        updated_at=row["updated_at"],
    )


@router.delete("/{badge_id}", response_model=dict, summary="Usuń badge (BEACH)")
async def delete_badge(badge_id: int):
    row = await database.fetch_one(select(beach_badges.c.id).where(beach_badges.c.id == badge_id))
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono badge'a")

    await database.execute(delete(beach_badges).where(beach_badges.c.id == badge_id))
    return {"success": True}
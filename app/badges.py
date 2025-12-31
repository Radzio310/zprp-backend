# app/badges.py
from datetime import datetime, timezone
import json
import logging
import traceback
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from sqlalchemy import select, update, delete, insert

from app.db import database, badges
from app.schemas import (
    BadgeItem,
    CreateBadgeRequest,
    UpdateBadgeRequest,
    ListBadgesResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/badges", tags=["Badges"])


def _parse_json(raw: Any):
    if raw is None:
        return {}
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return {}


@router.post("/", response_model=dict, summary="Utwórz nowy badge")
async def create_badge(req: CreateBadgeRequest):
    """
    Tworzy definicję badge'a.
    - name: unikalna nazwa
    - meta_json: dowolny JSON
    """
    now = datetime.now(timezone.utc)

    try:
        stmt = (
            insert(badges)
            .values(
                name=req.name.strip(),
                meta_json=req.meta_json if req.meta_json is not None else {},
                updated_at=now,
            )
            .returning(badges.c.id)
        )
        row = await database.fetch_one(stmt)
        if not row:
            raise HTTPException(500, "Nie udało się utworzyć badge'a")
        return {"success": True, "id": int(row["id"])}
    except Exception as e:
        # typowy konflikt unique(name)
        msg = str(e)
        if "unique" in msg.lower() or "duplicate" in msg.lower():
            raise HTTPException(status_code=409, detail="Badge o takiej nazwie już istnieje")
        logger.error("create_badge failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"create_badge failed: {e}")


@router.get("/", response_model=ListBadgesResponse, summary="Lista wszystkich badge'y")
async def list_badges():
    rows = await database.fetch_all(select(badges).order_by(badges.c.id.asc()))
    out: List[BadgeItem] = []
    for r in rows:
        out.append(
            BadgeItem(
                id=r["id"],
                name=r["name"],
                meta_json=_parse_json(r["meta_json"]),
                updated_at=r["updated_at"],
            )
        )
    return ListBadgesResponse(badges=out)


@router.get("/{badge_id}", response_model=BadgeItem, summary="Pobierz badge po ID")
async def get_badge(badge_id: int):
    row = await database.fetch_one(select(badges).where(badges.c.id == badge_id))
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono badge'a")

    return BadgeItem(
        id=row["id"],
        name=row["name"],
        meta_json=_parse_json(row["meta_json"]),
        updated_at=row["updated_at"],
    )


@router.patch("/{badge_id}", response_model=BadgeItem, summary="Częściowa edycja badge'a")
async def patch_badge(badge_id: int, body: UpdateBadgeRequest):
    existing = await database.fetch_one(select(badges).where(badges.c.id == badge_id))
    if not existing:
        raise HTTPException(status_code=404, detail="Nie znaleziono badge'a")

    update_data: Dict[str, Any] = {}
    if body.name is not None:
        update_data["name"] = body.name.strip()
    if body.meta_json is not None:
        update_data["meta_json"] = body.meta_json

    if not update_data:
        # nic do zmiany – zwróć aktualny rekord
        return BadgeItem(
            id=existing["id"],
            name=existing["name"],
            meta_json=_parse_json(existing["meta_json"]),
            updated_at=existing["updated_at"],
        )

    update_data["updated_at"] = datetime.now(timezone.utc)

    try:
        await database.execute(
            update(badges).where(badges.c.id == badge_id).values(**update_data)
        )
    except Exception as e:
        msg = str(e)
        if "unique" in msg.lower() or "duplicate" in msg.lower():
            raise HTTPException(status_code=409, detail="Badge o takiej nazwie już istnieje")
        raise HTTPException(status_code=500, detail=f"patch_badge failed: {e}")

    row = await database.fetch_one(select(badges).where(badges.c.id == badge_id))
    return BadgeItem(
        id=row["id"],
        name=row["name"],
        meta_json=_parse_json(row["meta_json"]),
        updated_at=row["updated_at"],
    )


@router.put("/{badge_id}", response_model=BadgeItem, summary="Pełna aktualizacja badge'a")
async def put_badge(badge_id: int, req: CreateBadgeRequest):
    """
    PUT = pełna aktualizacja (wymaga istnienia zasobu).
    """
    existing = await database.fetch_one(select(badges).where(badges.c.id == badge_id))
    if not existing:
        raise HTTPException(status_code=404, detail="Nie znaleziono badge'a")

    now = datetime.now(timezone.utc)
    try:
        await database.execute(
            update(badges)
            .where(badges.c.id == badge_id)
            .values(
                name=req.name.strip(),
                meta_json=req.meta_json if req.meta_json is not None else {},
                updated_at=now,
            )
        )
    except Exception as e:
        msg = str(e)
        if "unique" in msg.lower() or "duplicate" in msg.lower():
            raise HTTPException(status_code=409, detail="Badge o takiej nazwie już istnieje")
        raise HTTPException(status_code=500, detail=f"put_badge failed: {e}")

    row = await database.fetch_one(select(badges).where(badges.c.id == badge_id))
    return BadgeItem(
        id=row["id"],
        name=row["name"],
        meta_json=_parse_json(row["meta_json"]),
        updated_at=row["updated_at"],
    )


@router.delete("/{badge_id}", response_model=dict, summary="Usuń badge")
async def delete_badge(badge_id: int):
    row = await database.fetch_one(select(badges.c.id).where(badges.c.id == badge_id))
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono badge'a")

    await database.execute(delete(badges).where(badges.c.id == badge_id))
    return {"success": True}

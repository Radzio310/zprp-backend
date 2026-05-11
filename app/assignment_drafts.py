# app/assignment_drafts.py
"""CRUD for assignment drafts — local planning before submitting to ZPRP."""
from __future__ import annotations

import datetime
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, delete, func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import database, assignment_drafts

router = APIRouter(prefix="/assignment-drafts", tags=["assignment-drafts"])

logger = logging.getLogger("app.assignment_drafts")


# ---- Request / Response models ----

class DraftAssignmentItem(BaseModel):
    IdZawody: str
    slots: Dict[str, Optional[str]] = {}  # { sedzia1: "5512", sedzia2: "1234", ... }
    hall_id: Optional[str] = None
    status: str = "draft"  # "draft" | "submitted"


class CreateDraftRequest(BaseModel):
    province: str
    created_by: str
    id_rozgr: Optional[str] = None
    label: Optional[str] = None
    assignments: List[DraftAssignmentItem] = []


class UpdateDraftRequest(BaseModel):
    label: Optional[str] = None
    assignments: Optional[List[DraftAssignmentItem]] = None


class DraftResponse(BaseModel):
    id: int
    province: str
    created_by: str
    id_rozgr: Optional[str]
    label: Optional[str]
    assignments: list
    created_at: str
    updated_at: str


# ---- Endpoints ----

@router.get("")
async def list_drafts(province: str, created_by: Optional[str] = None):
    """List all drafts for a province (optionally filtered by creator)."""
    q = select(assignment_drafts).where(assignment_drafts.c.province == province)
    if created_by:
        q = q.where(assignment_drafts.c.created_by == created_by)
    q = q.order_by(assignment_drafts.c.updated_at.desc())
    rows = await database.fetch_all(q)
    return [_row_to_dict(r) for r in rows]


@router.get("/{draft_id}")
async def get_draft(draft_id: int):
    """Get a single draft by ID."""
    q = select(assignment_drafts).where(assignment_drafts.c.id == draft_id)
    row = await database.fetch_one(q)
    if not row:
        raise HTTPException(404, "Draft not found")
    return _row_to_dict(row)


@router.post("")
async def create_draft(payload: CreateDraftRequest):
    """Create a new assignment draft."""
    now = datetime.datetime.now(datetime.timezone.utc)
    values = {
        "province": payload.province,
        "created_by": payload.created_by,
        "id_rozgr": payload.id_rozgr,
        "label": payload.label,
        "assignments": [a.dict() for a in payload.assignments],
        "created_at": now,
        "updated_at": now,
    }
    q = assignment_drafts.insert().values(**values).returning(assignment_drafts.c.id)
    new_id = await database.execute(q)
    return {"id": new_id}


@router.put("/{draft_id}")
async def update_draft(draft_id: int, payload: UpdateDraftRequest):
    """Update an existing draft."""
    q = select(assignment_drafts).where(assignment_drafts.c.id == draft_id)
    row = await database.fetch_one(q)
    if not row:
        raise HTTPException(404, "Draft not found")

    updates: Dict[str, Any] = {"updated_at": datetime.datetime.now(datetime.timezone.utc)}
    if payload.label is not None:
        updates["label"] = payload.label
    if payload.assignments is not None:
        updates["assignments"] = [a.dict() for a in payload.assignments]

    q = assignment_drafts.update().where(assignment_drafts.c.id == draft_id).values(**updates)
    await database.execute(q)
    return {"ok": True}


@router.delete("/{draft_id}")
async def delete_draft(draft_id: int):
    """Delete a draft."""
    q = delete(assignment_drafts).where(assignment_drafts.c.id == draft_id)
    await database.execute(q)
    return {"ok": True}


# ---- Internal helpers ----

def _row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "province": row["province"],
        "created_by": row["created_by"],
        "id_rozgr": row["id_rozgr"],
        "label": row["label"],
        "assignments": row["assignments"] or [],
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
    }

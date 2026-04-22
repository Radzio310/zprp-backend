"""
Beach Guidelines & Interpretations — CRUD + review workflow.

Permissions:
  - admin / Rulemaker badge  → full CRUD, auto-verified on create
  - head judge of tournament → create (pending), edit own pending
  - all authenticated users  → read verified + own pending/rejected
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, HTTPException, Query, Depends
from sqlalchemy import select, insert, update, delete

from app.db import database, beach_guidelines, beach_users, beach_admins, beach_tournaments
from app.schemas import (
    BeachGuidelineCreateRequest,
    BeachGuidelineUpdateRequest,
    BeachGuidelineReviewRequest,
    BeachGuidelineItem,
    BeachGuidelinesListResponse,
)
from app.deps import beach_get_current_user_id

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/beach/guidelines", tags=["Beach: Guidelines"])


# ─────────────────── helpers ───────────────────

def _parse_json(raw: Any) -> dict:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _extract_badge_names(badges_raw: Any) -> List[str]:
    if badges_raw is None:
        return []
    if isinstance(badges_raw, dict):
        return [str(k) for k, v in badges_raw.items() if v is not None and v]
    if isinstance(badges_raw, list):
        return [str(x) for x in badges_raw if x is not None]
    return []


async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    return bool(row)


async def _is_rulemaker(user_id: int) -> bool:
    """Check if user has the 'Rulemaker' badge."""
    row = await database.fetch_one(
        select(beach_users.c.badges).where(beach_users.c.id == user_id)
    )
    if not row:
        return False
    return "Rulemaker" in _extract_badge_names(row["badges"])


async def _is_head_judge_of_tournament(user_id: int, tournament_id: int) -> bool:
    """Check if user is the head judge of the given tournament."""
    row = await database.fetch_one(
        select(beach_tournaments.c.data_json).where(beach_tournaments.c.id == tournament_id)
    )
    if not row:
        return False
    data = _parse_json(row["data_json"])
    head_judge_id = data.get("head_judge_id")
    return isinstance(head_judge_id, int) and head_judge_id == user_id


async def _get_user_name(user_id: int) -> str:
    row = await database.fetch_one(
        select(beach_users.c.full_name).where(beach_users.c.id == user_id)
    )
    return row["full_name"] if row else "Nieznany"


async def _get_tournament_name(tournament_id: int) -> str:
    row = await database.fetch_one(
        select(beach_tournaments.c.name).where(beach_tournaments.c.id == tournament_id)
    )
    return row["name"] if row else f"Turniej #{tournament_id}"


def _row_to_item(row: Any) -> BeachGuidelineItem:
    d = dict(row) if not isinstance(row, dict) else row
    return BeachGuidelineItem(**d)


# ─────────────────── LIST ───────────────────

@router.get(
    "/",
    response_model=BeachGuidelinesListResponse,
    summary="Lista wytycznych i interpretacji",
)
async def list_guidelines(
    status: Optional[str] = Query(None, description="Filtruj po statusie: verified|pending|rejected"),
    chapter_id: Optional[str] = Query(None, description="Filtruj po rozdziale przepisów"),
    tournament_id: Optional[int] = Query(None, description="Filtruj po turnieju"),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    q = select(beach_guidelines).order_by(
        beach_guidelines.c.created_at.desc()
    )

    if status is not None:
        q = q.where(beach_guidelines.c.status == status)
    if chapter_id is not None:
        q = q.where(beach_guidelines.c.chapter_id == chapter_id)
    if tournament_id is not None:
        q = q.where(beach_guidelines.c.tournament_id == tournament_id)

    rows = await database.fetch_all(q)

    is_admin_flag = await _is_admin(current_user_id)
    is_rm = await _is_rulemaker(current_user_id)
    can_see_all = is_admin_flag or is_rm

    out: List[BeachGuidelineItem] = []
    for r in rows:
        d = dict(r)
        s = d["status"]
        # Everyone sees verified; admin/rulemaker see all; author sees own
        if s == "verified":
            out.append(_row_to_item(d))
        elif s == "rejected":
            # Rejected are visible to everyone (archival) but only with metadata
            out.append(_row_to_item(d))
        elif s == "pending":
            if can_see_all or d["author_id"] == current_user_id:
                out.append(_row_to_item(d))
        else:
            if can_see_all:
                out.append(_row_to_item(d))

    return BeachGuidelinesListResponse(guidelines=out)


# ─────────────────── GET single ───────────────────

@router.get(
    "/{guideline_id}",
    response_model=BeachGuidelineItem,
    summary="Pobierz wytyczną po ID",
)
async def get_guideline(
    guideline_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    row = await database.fetch_one(
        select(beach_guidelines).where(beach_guidelines.c.id == guideline_id)
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono wytycznej")
    return _row_to_item(row)


# ─────────────────── CREATE ───────────────────

@router.post(
    "/",
    response_model=BeachGuidelineItem,
    summary="Dodaj nową wytyczną/interpretację",
)
async def create_guideline(
    body: BeachGuidelineCreateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not body.title or not body.title.strip():
        raise HTTPException(400, "Tytuł jest wymagany")
    if not body.content or not body.content.strip():
        raise HTTPException(400, "Treść jest wymagana")

    is_admin_flag = await _is_admin(current_user_id)
    is_rm = await _is_rulemaker(current_user_id)

    # Determine status based on author's role
    if is_admin_flag or is_rm:
        status = "verified"
    elif body.tournament_id is not None:
        # Head judge creating from tournament context
        if not await _is_head_judge_of_tournament(current_user_id, body.tournament_id):
            raise HTTPException(
                403,
                "Tylko admin, Rulemaker lub sędzia główny turnieju może dodawać wytyczne",
            )
        status = "pending"
    else:
        raise HTTPException(
            403,
            "Tylko admin lub Rulemaker może dodawać wytyczne ogólne",
        )

    author_name = await _get_user_name(current_user_id)
    tournament_name = None
    if body.tournament_id is not None:
        tournament_name = await _get_tournament_name(body.tournament_id)

    now = datetime.now(timezone.utc)
    stmt = (
        insert(beach_guidelines)
        .values(
            title=body.title.strip(),
            content=body.content.strip(),
            chapter_id=body.chapter_id,
            status=status,
            author_id=current_user_id,
            author_name=author_name,
            tournament_id=body.tournament_id,
            tournament_name=tournament_name,
            created_at=now,
            updated_at=now,
        )
        .returning(beach_guidelines)
    )

    row = await database.fetch_one(stmt)
    return _row_to_item(row)


# ─────────────────── PATCH (edit) ───────────────────

@router.patch(
    "/{guideline_id}",
    response_model=BeachGuidelineItem,
    summary="Edytuj wytyczną",
)
async def update_guideline(
    guideline_id: int,
    body: BeachGuidelineUpdateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    existing = await database.fetch_one(
        select(beach_guidelines).where(beach_guidelines.c.id == guideline_id)
    )
    if not existing:
        raise HTTPException(404, "Nie znaleziono wytycznej")

    existing_d = dict(existing)
    is_admin_flag = await _is_admin(current_user_id)
    is_rm = await _is_rulemaker(current_user_id)

    # Permission: admin/Rulemaker always; author only if still pending
    if not (is_admin_flag or is_rm):
        if existing_d["author_id"] != current_user_id:
            raise HTTPException(403, "Brak uprawnień do edycji tej wytycznej")
        if existing_d["status"] != "pending":
            raise HTTPException(403, "Można edytować tylko oczekujące wytyczne")

    update_data = {}
    if body.title is not None:
        update_data["title"] = body.title.strip()
    if body.content is not None:
        update_data["content"] = body.content.strip()
    if body.chapter_id is not None:
        update_data["chapter_id"] = body.chapter_id if body.chapter_id else None

    if not update_data:
        return _row_to_item(existing_d)

    update_data["updated_at"] = datetime.now(timezone.utc)

    await database.execute(
        update(beach_guidelines)
        .where(beach_guidelines.c.id == guideline_id)
        .values(**update_data)
    )

    row = await database.fetch_one(
        select(beach_guidelines).where(beach_guidelines.c.id == guideline_id)
    )
    return _row_to_item(row)


# ─────────────────── PATCH review (verify / reject) ───────────────────

@router.patch(
    "/{guideline_id}/review",
    response_model=BeachGuidelineItem,
    summary="Zweryfikuj lub odrzuć wytyczną (admin / Rulemaker)",
)
async def review_guideline(
    guideline_id: int,
    body: BeachGuidelineReviewRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if body.status not in ("verified", "rejected"):
        raise HTTPException(400, "Status musi być 'verified' lub 'rejected'")

    is_admin_flag = await _is_admin(current_user_id)
    is_rm = await _is_rulemaker(current_user_id)

    if not (is_admin_flag or is_rm):
        raise HTTPException(403, "Tylko admin lub Rulemaker może weryfikować wytyczne")

    existing = await database.fetch_one(
        select(beach_guidelines).where(beach_guidelines.c.id == guideline_id)
    )
    if not existing:
        raise HTTPException(404, "Nie znaleziono wytycznej")

    reviewer_name = await _get_user_name(current_user_id)
    now = datetime.now(timezone.utc)

    update_data = {
        "status": body.status,
        "reviewed_by_id": current_user_id,
        "reviewed_by_name": reviewer_name,
        "reviewed_at": now,
        "updated_at": now,
    }

    if body.status == "rejected" and body.rejection_comment:
        update_data["rejection_comment"] = body.rejection_comment.strip()
    elif body.status == "verified":
        update_data["rejection_comment"] = None

    await database.execute(
        update(beach_guidelines)
        .where(beach_guidelines.c.id == guideline_id)
        .values(**update_data)
    )

    row = await database.fetch_one(
        select(beach_guidelines).where(beach_guidelines.c.id == guideline_id)
    )
    return _row_to_item(row)


# ─────────────────── DELETE ───────────────────

@router.delete(
    "/{guideline_id}",
    response_model=dict,
    summary="Usuń wytyczną (admin only)",
)
async def delete_guideline(
    guideline_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Tylko admin może usuwać wytyczne")

    existing = await database.fetch_one(
        select(beach_guidelines.c.id).where(beach_guidelines.c.id == guideline_id)
    )
    if not existing:
        raise HTTPException(404, "Nie znaleziono wytycznej")

    await database.execute(
        delete(beach_guidelines).where(beach_guidelines.c.id == guideline_id)
    )
    return {"success": True}

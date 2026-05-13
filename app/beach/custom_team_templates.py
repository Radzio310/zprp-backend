# app/beach/custom_team_templates.py
"""
CRUD endpoints for custom team templates.
Templates are global – any authenticated user can read them.
Only the owner (coach_user_id) or an admin can update/delete.
"""

from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select, update

from app.db import beach_admins, beach_custom_team_templates, beach_users, database
from app.deps import beach_get_current_user_id

router = APIRouter(prefix="/beach/custom-team-templates", tags=["Beach: Custom Team Templates"])


# ─── helpers ──────────────────────────────────────────────────────────────────

async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    return row is not None


def _row_to_dict(row: Any) -> dict:
    d = dict(row._mapping)
    # Serialize datetimes to ISO strings
    for k in ("created_at", "updated_at"):
        if k in d and isinstance(d[k], datetime):
            d[k] = d[k].isoformat()
    return d


# ─── Pydantic schemas ─────────────────────────────────────────────────────────

class CustomTeamPlayerModel(BaseModel):
    id: str
    lastName: str
    firstName: str
    jerseyNumber: str


class CustomTeamCompanionModel(BaseModel):
    id: str
    lastName: str
    firstName: str


class CreateTemplateRequest(BaseModel):
    name: str
    gender: str                            # "M" | "K"
    category: str = ""
    players: List[CustomTeamPlayerModel] = []
    companions: List[CustomTeamCompanionModel] = []
    default_players: List[str] = []        # player IDs (string)
    default_companions: List[str] = []     # companion IDs (string)


class UpdateTemplateRequest(BaseModel):
    name: Optional[str] = None
    gender: Optional[str] = None
    category: Optional[str] = None
    players: Optional[List[CustomTeamPlayerModel]] = None
    companions: Optional[List[CustomTeamCompanionModel]] = None
    default_players: Optional[List[str]] = None
    default_companions: Optional[List[str]] = None


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/")
async def list_templates(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    """Return all templates (any authenticated user may read)."""
    rows = await database.fetch_all(
        select(beach_custom_team_templates).order_by(
            beach_custom_team_templates.c.updated_at.desc()
        )
    )
    return {"templates": [_row_to_dict(r) for r in rows]}


@router.get("/{template_id}")
async def get_template(
    template_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    row = await database.fetch_one(
        select(beach_custom_team_templates).where(
            beach_custom_team_templates.c.id == template_id
        )
    )
    if not row:
        raise HTTPException(status_code=404, detail="Szablon nie istnieje.")
    return _row_to_dict(row)


@router.post("/", status_code=201)
async def create_template(
    body: CreateTemplateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not body.name.strip():
        raise HTTPException(status_code=422, detail="Nazwa drużyny jest wymagana.")
    if body.gender not in ("M", "K"):
        raise HTTPException(status_code=422, detail="Pole gender musi być 'M' lub 'K'.")

    # Fetch coach name snapshot
    user_row = await database.fetch_one(
        select(beach_users.c.full_name).where(beach_users.c.id == current_user_id)
    )
    coach_name = user_row["full_name"] if user_row else None

    pk = await database.execute(
        beach_custom_team_templates.insert().values(
            name=body.name.strip(),
            gender=body.gender,
            category=body.category,
            players=[p.model_dump() for p in body.players],
            companions=[c.model_dump() for c in body.companions],
            default_players=body.default_players,
            default_companions=body.default_companions,
            coach_user_id=current_user_id,
            coach_name=coach_name,
        )
    )
    row = await database.fetch_one(
        select(beach_custom_team_templates).where(
            beach_custom_team_templates.c.id == pk
        )
    )
    return _row_to_dict(row)


@router.put("/{template_id}")
async def update_template(
    template_id: int,
    body: UpdateTemplateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    row = await database.fetch_one(
        select(beach_custom_team_templates).where(
            beach_custom_team_templates.c.id == template_id
        )
    )
    if not row:
        raise HTTPException(status_code=404, detail="Szablon nie istnieje.")

    # Only owner or admin may update
    if row["coach_user_id"] != current_user_id and not await _is_admin(current_user_id):
        raise HTTPException(status_code=403, detail="Brak uprawnień.")

    patch: dict = {}
    if body.name is not None:
        if not body.name.strip():
            raise HTTPException(status_code=422, detail="Nazwa drużyny jest wymagana.")
        patch["name"] = body.name.strip()
    if body.gender is not None:
        if body.gender not in ("M", "K"):
            raise HTTPException(status_code=422, detail="Pole gender musi być 'M' lub 'K'.")
        patch["gender"] = body.gender
    if body.category is not None:
        patch["category"] = body.category
    if body.players is not None:
        patch["players"] = [p.model_dump() for p in body.players]
    if body.companions is not None:
        patch["companions"] = [c.model_dump() for c in body.companions]
    if body.default_players is not None:
        patch["default_players"] = body.default_players
    if body.default_companions is not None:
        patch["default_companions"] = body.default_companions

    if patch:
        patch["updated_at"] = datetime.now(timezone.utc)
        await database.execute(
            update(beach_custom_team_templates)
            .where(beach_custom_team_templates.c.id == template_id)
            .values(**patch)
        )

    updated = await database.fetch_one(
        select(beach_custom_team_templates).where(
            beach_custom_team_templates.c.id == template_id
        )
    )
    return _row_to_dict(updated)


@router.delete("/{template_id}", status_code=204)
async def delete_template(
    template_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    row = await database.fetch_one(
        select(beach_custom_team_templates).where(
            beach_custom_team_templates.c.id == template_id
        )
    )
    if not row:
        raise HTTPException(status_code=404, detail="Szablon nie istnieje.")

    if row["coach_user_id"] != current_user_id and not await _is_admin(current_user_id):
        raise HTTPException(status_code=403, detail="Brak uprawnień.")

    await database.execute(
        delete(beach_custom_team_templates).where(
            beach_custom_team_templates.c.id == template_id
        )
    )

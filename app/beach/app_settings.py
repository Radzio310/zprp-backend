from __future__ import annotations

import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import insert, select, update

from app.db import database, beach_app_settings, beach_admins
from app.deps import beach_get_current_user_id
from app.beach.activity_log import log_activity, get_actor_name

router = APIRouter(prefix="/beach/app-settings", tags=["Beach: App Settings"])

EMPTY_STATE_IMAGE_KEY = "empty_state_image_url"
ROLE_CAPS_KEY = "role_caps"

DEFAULT_ROLE_CAPS = {
    "judge": {
        "general": ["tournament.docs.use", "tournament.settlements.use"],
        "tournament": [
            "tournament.schedule.score",
            "tournament.results.enterScores",
            "tournament.disqualifications.manage",
        ],
        "match": ["tournament.match.score"],
    },
    "coach": {
        "general": [],
        "tournament": ["tournament.teams.manageSquads", "tournament.tab.myTeam.always"],
        "match": [],
    },
    "player": {
        "general": [],
        "tournament": ["tournament.tab.myTeam.always"],
        "match": [],
    },
}


async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    return bool(row)


# ─── GET empty-state-image (public) ──────────────────────────────────────────

@router.get("/empty-state-image", response_model=dict, summary="Grafika pustego stanu turniejów (publiczne)")
async def get_empty_state_image():
    row = await database.fetch_one(
        select(beach_app_settings).where(beach_app_settings.c.key == EMPTY_STATE_IMAGE_KEY)
    )
    return {"url": dict(row)["value"] if row else None}


# ─── PATCH empty-state-image (admin) ─────────────────────────────────────────

class SetEmptyStateImageRequest(BaseModel):
    url: str


@router.patch("/empty-state-image", response_model=dict, summary="Ustaw grafikę pustego stanu (admin)")
async def set_empty_state_image(
    req: SetEmptyStateImageRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    url = req.url.strip()
    if not url:
        raise HTTPException(400, "Brak URL grafiki")

    existing = await database.fetch_one(
        select(beach_app_settings).where(beach_app_settings.c.key == EMPTY_STATE_IMAGE_KEY)
    )
    if existing:
        await database.execute(
            update(beach_app_settings)
            .where(beach_app_settings.c.key == EMPTY_STATE_IMAGE_KEY)
            .values(value=url, updated_at=datetime.now(timezone.utc))
        )
    else:
        await database.execute(
            insert(beach_app_settings).values(
                key=EMPTY_STATE_IMAGE_KEY,
                value=url,
                updated_at=datetime.now(timezone.utc),
            )
        )
    await log_activity(area="system", action="app_settings.changed", actor_user_id=current_user_id, actor_name=await get_actor_name(current_user_id), details={"key": EMPTY_STATE_IMAGE_KEY, "action": "set"})
    return {"success": True, "url": url}


# ─── DELETE empty-state-image (admin) ────────────────────────────────────────

@router.delete("/empty-state-image", response_model=dict, summary="Usuń grafikę pustego stanu (admin)")
async def delete_empty_state_image(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    await database.execute(
        beach_app_settings.delete().where(beach_app_settings.c.key == EMPTY_STATE_IMAGE_KEY)
    )
    await log_activity(area="system", action="app_settings.changed", actor_user_id=current_user_id, actor_name=await get_actor_name(current_user_id), details={"key": EMPTY_STATE_IMAGE_KEY, "action": "delete"})
    return {"success": True}


# ─── GET role-caps (public) ───────────────────────────────────────────────────

@router.get("/role-caps", response_model=dict, summary="Uprawnienia ról (publiczne)")
async def get_role_caps():
    row = await database.fetch_one(
        select(beach_app_settings).where(beach_app_settings.c.key == ROLE_CAPS_KEY)
    )
    if row:
        try:
            return json.loads(dict(row)["value"])
        except Exception:
            pass
    return DEFAULT_ROLE_CAPS


# ─── PATCH role-caps (admin) ──────────────────────────────────────────────────

class RoleCapsRequest(BaseModel):
    config: dict


@router.patch("/role-caps", response_model=dict, summary="Ustaw uprawnienia ról (admin)")
async def set_role_caps(
    req: RoleCapsRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    value = json.dumps(req.config, ensure_ascii=False)
    existing = await database.fetch_one(
        select(beach_app_settings).where(beach_app_settings.c.key == ROLE_CAPS_KEY)
    )
    if existing:
        await database.execute(
            update(beach_app_settings)
            .where(beach_app_settings.c.key == ROLE_CAPS_KEY)
            .values(value=value, updated_at=datetime.now(timezone.utc))
        )
    else:
        await database.execute(
            insert(beach_app_settings).values(
                key=ROLE_CAPS_KEY,
                value=value,
                updated_at=datetime.now(timezone.utc),
            )
        )
    await log_activity(
        area="system",
        action="app_settings.changed",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        details={"key": ROLE_CAPS_KEY, "action": "set"},
    )
    return req.config

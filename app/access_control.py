"""Shared strict authorization dependencies for administrative routes."""

from __future__ import annotations

from fastapi import Depends, HTTPException, status

from app.admin_alerts import admin_judge_ids
from app.deps import get_jwt_payload


async def require_app_admin(payload: dict = Depends(get_jwt_payload)) -> dict:
    """Require a valid BAZA JWT belonging to an application administrator."""
    judge_id = str(payload.get("judge_id") or "").strip()
    if not judge_id or judge_id not in await admin_judge_ids():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ta operacja jest dostepna tylko dla administratora aplikacji.",
        )
    return payload

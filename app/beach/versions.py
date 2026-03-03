from __future__ import annotations

from datetime import datetime, timezone
import logging
import re
import traceback
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, insert, select, update

from app.db import database, beach_app_versions, beach_admins
from app.schemas import (
    BeachCreateVersionRequest,
    BeachUpdateVersionRequest,
    BeachVersionItem,
    BeachListVersionsResponse,
)
from app.deps import beach_get_current_user_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/versions", tags=["Beach: Versions"])

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id))
    return bool(row)


def _row_to_item(r: Any) -> BeachVersionItem:
    d = dict(r)
    return BeachVersionItem(
        id=int(d["id"]),
        version=str(d.get("version") or ""),
        name=str(d.get("name") or ""),
        description=d.get("description"),
        to_show=bool(d.get("to_show") or False),
        created_at=d["created_at"],
        updated_at=d["updated_at"],
    )


@router.get("/", response_model=BeachListVersionsResponse, summary="Lista wersji widocznych w aplikacji (BEACH)")
async def list_visible_versions():
    rows = await database.fetch_all(
        select(beach_app_versions)
        .where(beach_app_versions.c.to_show == True)  # noqa: E712
        .order_by(beach_app_versions.c.id.desc())
    )
    return BeachListVersionsResponse(versions=[_row_to_item(r) for r in rows])


@router.get("/all", response_model=BeachListVersionsResponse, summary="Lista wszystkich wersji (BEACH) — wymaga admina")
async def list_all_versions(current_user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    rows = await database.fetch_all(select(beach_app_versions).order_by(beach_app_versions.c.id.desc()))
    return BeachListVersionsResponse(versions=[_row_to_item(r) for r in rows])


@router.post("/", response_model=dict, summary="Dodaj wersję (BEACH) — wymaga admina")
async def create_version(req: BeachCreateVersionRequest, current_user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    version = (req.version or "").strip()
    name = (req.name or "").strip()
    description = (req.description or None)
    to_show = bool(req.to_show or False)

    if not SEMVER_RE.match(version):
        raise HTTPException(422, 'Wersja musi być w formacie X.Y.Z (np. "1.23.14")')
    if not name:
        raise HTTPException(422, "Podaj nazwę wersji")

    now = datetime.now(timezone.utc)

    try:
        stmt = (
            insert(beach_app_versions)
            .values(
                version=version,
                name=name,
                description=description,
                to_show=to_show,
                created_at=now,
                updated_at=now,
            )
            .returning(beach_app_versions.c.id)
        )
        row = await database.fetch_one(stmt)
        if not row:
            raise HTTPException(500, "Nie udało się utworzyć wersji")
        return {"success": True, "id": int(row["id"])}
    except Exception as e:
        msg = str(e).lower()
        if "unique" in msg or "duplicate" in msg:
            raise HTTPException(409, detail="Taka wersja już istnieje")
        logger.error("create_version failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(500, detail=f"create_version failed: {e}")


@router.put("/{version_id}", response_model=dict, summary="Zaktualizuj wersję (BEACH) — wymaga admina")
async def update_version(version_id: int, req: BeachUpdateVersionRequest, current_user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    existing = await database.fetch_one(select(beach_app_versions).where(beach_app_versions.c.id == version_id))
    if not existing:
        raise HTTPException(404, "Nie znaleziono wersji")

    patch: Dict[str, Any] = {}

    if req.version is not None:
        v = req.version.strip()
        if not SEMVER_RE.match(v):
            raise HTTPException(422, 'Wersja musi być w formacie X.Y.Z (np. "1.23.14")')
        patch["version"] = v

    if req.name is not None:
        n = req.name.strip()
        if not n:
            raise HTTPException(422, "Podaj nazwę wersji")
        patch["name"] = n

    if req.description is not None:
        patch["description"] = req.description

    if req.to_show is not None:
        patch["to_show"] = bool(req.to_show)

    if not patch:
        return {"success": True}

    patch["updated_at"] = datetime.now(timezone.utc)

    try:
        await database.execute(update(beach_app_versions).where(beach_app_versions.c.id == version_id).values(**patch))
        return {"success": True}
    except Exception as e:
        msg = str(e).lower()
        if "unique" in msg or "duplicate" in msg:
            raise HTTPException(409, detail="Taka wersja już istnieje")
        logger.error("update_version failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(500, detail=f"update_version failed: {e}")


@router.delete("/{version_id}", response_model=dict, summary="Usuń wersję (BEACH) — wymaga admina")
async def delete_version(version_id: int, current_user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    row = await database.fetch_one(select(beach_app_versions.c.id).where(beach_app_versions.c.id == version_id))
    if not row:
        # analogicznie do Twojego zachowania: 404 można potraktować jako OK, ale tu zwracam 404 jawnie
        raise HTTPException(404, "Nie znaleziono wersji")

    await database.execute(delete(beach_app_versions).where(beach_app_versions.c.id == version_id))
    return {"success": True}
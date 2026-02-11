from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.sql import and_

from app.db import database, baza_vips
from app.schemas import (
    BazaVipUpsertRequest,
    BazaVipUpsertResponse,
    BazaVipItem,
    BazaVipUpdateRequest,
    ListBazaVipsResponse,
)

router = APIRouter(prefix="/baza_vips", tags=["baza_vips"])


def _norm_username(u: str) -> str:
    return (u or "").strip()


@router.post("/upsert_from_login", response_model=BazaVipUpsertResponse)
async def upsert_from_login(payload: BazaVipUpsertRequest):
    """
    Tworzy rekord VIP jeśli nie istnieje (permissions_json = {}).
    Jeśli istnieje: aktualizuje last_login_at, opcjonalnie judge_id/province/login_info_json.

    Zwraca rekord, żeby app mogła:
    - przy pierwszym logowaniu dostać puste uprawnienia
    - przy kolejnym wczytać province i permissions_json
    """
    username = _norm_username(payload.username)
    if not username:
        raise HTTPException(status_code=400, detail="username is required")

    now = datetime.utcnow()

    # 1) czy istnieje?
    row = await database.fetch_one(
        select(baza_vips).where(baza_vips.c.username == username)
    )

    if not row:
        created = True
        insert_values = {
            "username": username,
            "judge_id": (payload.judge_id or None),
            "province": (payload.province or None),
            "permissions_json": {},  # puste przy pierwszym razie
            "login_info_json": payload.login_info_json or {},
            "created_at": now,
            "updated_at": now,
            "last_login_at": now,
        }

        new_id = await database.execute(baza_vips.insert().values(**insert_values))
        row = await database.fetch_one(
            select(baza_vips).where(baza_vips.c.id == int(new_id))
        )
    else:
        created = False

        update_values = {
            "last_login_at": now,
            "updated_at": now,
        }

        # opcjonalne uzupełnienia
        if payload.judge_id is not None and str(payload.judge_id).strip():
            update_values["judge_id"] = str(payload.judge_id).strip()

        if payload.province is not None:
            # pozwalamy nadpisać jeśli app już zna województwo
            update_values["province"] = (payload.province or None)

        if payload.login_info_json is not None:
            update_values["login_info_json"] = payload.login_info_json or {}

        await database.execute(
            baza_vips.update()
            .where(baza_vips.c.username == username)
            .values(**update_values)
        )

        row = await database.fetch_one(
            select(baza_vips).where(baza_vips.c.username == username)
        )

    if not row:
        return BazaVipUpsertResponse(success=False, created=False, record=None)

    return BazaVipUpsertResponse(
        success=True,
        created=created,
        record=BazaVipItem(**dict(row)),
    )


@router.get("/{username}", response_model=BazaVipItem)
async def get_vip(username: str):
    username = _norm_username(username)
    if not username:
        raise HTTPException(status_code=400, detail="username is required")

    row = await database.fetch_one(
        select(baza_vips).where(baza_vips.c.username == username)
    )
    if not row:
        raise HTTPException(status_code=404, detail="VIP user not found")

    return BazaVipItem(**dict(row))


@router.patch("/{username}", response_model=BazaVipItem)
async def update_vip(username: str, payload: BazaVipUpdateRequest):
    """
    Endpoint do ustawienia province i permissions_json (np. panel/admin).
    Uwaga: tu docelowo dodaj autoryzację (JWT/admin).
    """
    username = _norm_username(username)
    if not username:
        raise HTTPException(status_code=400, detail="username is required")

    row = await database.fetch_one(
        select(baza_vips).where(baza_vips.c.username == username)
    )
    if not row:
        raise HTTPException(status_code=404, detail="VIP user not found")

    now = datetime.utcnow()
    update_values: dict[str, Any] = {"updated_at": now}

    if payload.judge_id is not None:
        update_values["judge_id"] = payload.judge_id or None

    if payload.province is not None:
        update_values["province"] = payload.province or None

    if payload.permissions_json is not None:
        update_values["permissions_json"] = payload.permissions_json or {}

    if payload.login_info_json is not None:
        update_values["login_info_json"] = payload.login_info_json or {}

    if len(update_values.keys()) == 1:
        # tylko updated_at => nic nie zmieniono
        return BazaVipItem(**dict(row))

    await database.execute(
        baza_vips.update()
        .where(baza_vips.c.username == username)
        .values(**update_values)
    )

    row2 = await database.fetch_one(
        select(baza_vips).where(baza_vips.c.username == username)
    )
    return BazaVipItem(**dict(row2))


@router.get("/", response_model=ListBazaVipsResponse)
async def list_vips(
    q: Optional[str] = Query(None, description="opcjonalny filtr po username (contains)"),
    province: Optional[str] = Query(None, description="opcjonalny filtr po province (exact)"),
    limit: int = Query(200, ge=1, le=2000),
):
    """
    Prosta lista (do panelu). Docelowo: autoryzacja.
    """
    stmt = select(baza_vips).order_by(baza_vips.c.updated_at.desc()).limit(limit)

    conds = []
    if q:
        conds.append(baza_vips.c.username.ilike(f"%{q.strip()}%"))
    if province:
        conds.append(baza_vips.c.province == province.strip())

    if conds:
        stmt = stmt.where(and_(*conds))

    rows = await database.fetch_all(stmt)
    return ListBazaVipsResponse(records=[BazaVipItem(**dict(r)) for r in rows])

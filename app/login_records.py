# app/routers/login_records.py
from datetime import datetime, timezone
import logging
import traceback

from fastapi import APIRouter, HTTPException
from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import database, login_records
from app.schemas import (
    CreateLoginRecordRequest,
    LoginRecordItem,
    ListLoginRecordsResponse,
    UpdateLoginRecordRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/login_records", tags=["LoginRecords"])


@router.post("/", response_model=dict, summary="Upsert ostatniego logowania")
async def upsert_login(req: CreateLoginRecordRequest):
    """
    Wstawia lub uaktualnia rekord ostatniego logowania.
    - Zawsze nadpisuje: full_name, last_login_at
    - Nadpisuje app_version / last_open_at / province tylko, jeśli zostały przesłane (COALESCE na EXCLUDED)
    - app_opens inkrementuje o wartość z payloadu (tu w praktyce wysyłasz już policzoną liczbę,
      ale logika pozostaje kompatybilna z inkrementem)
    """
    now = datetime.now(timezone.utc)

    try:
        stmt = pg_insert(login_records).values(
            judge_id=req.judge_id,
            full_name=req.full_name,
            last_login_at=now,
            app_version=req.app_version,
            app_opens=req.app_opens,
            last_open_at=req.last_open_at,
            province=req.province,  # ✅ NOWE
        )

        stmt = stmt.on_conflict_do_update(
            index_elements=[login_records.c.judge_id],
            set_={
                "full_name": req.full_name,
                "last_login_at": now,
                "app_version": func.coalesce(
                    stmt.excluded.app_version, login_records.c.app_version
                ),
                "app_opens": func.coalesce(login_records.c.app_opens, 0)
                + func.coalesce(stmt.excluded.app_opens, 0),
                "last_open_at": func.coalesce(
                    stmt.excluded.last_open_at, login_records.c.last_open_at
                ),
                # ✅ NOWE: tylko gdy przesłane
                "province": func.coalesce(
                    stmt.excluded.province, login_records.c.province
                ),
            },
        )

        await database.execute(stmt)
        return {"success": True}

    except Exception as e:
        logger.error("upsert_login failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"upsert_login failed: {e}")


@router.get("/", response_model=ListLoginRecordsResponse, summary="Lista wszystkich logowań")
async def list_logins():
    q = select(login_records).order_by(login_records.c.last_login_at.desc())
    rows = await database.fetch_all(q)
    return ListLoginRecordsResponse(records=[LoginRecordItem(**dict(r)) for r in rows])


@router.get("/{judge_id}", response_model=LoginRecordItem, summary="Pobierz rekord logowania po judge_id")
async def get_login_record(judge_id: str):
    row = await database.fetch_one(
        select(login_records).where(login_records.c.judge_id == judge_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono rekordu")
    return LoginRecordItem(**dict(row))


@router.delete("/{judge_id}", response_model=dict, summary="Usuń rekord logowania")
async def delete_login(judge_id: str):
    await database.execute(
        login_records.delete().where(login_records.c.judge_id == judge_id)
    )
    return {"success": True}


@router.patch(
    "/{judge_id}",
    response_model=LoginRecordItem,
    summary="Częściowa edycja rekordu logowania",
)
async def patch_login_record(judge_id: str, body: UpdateLoginRecordRequest):
    existing = await database.fetch_one(
        select(login_records).where(login_records.c.judge_id == judge_id)
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Nie znaleziono rekordu")

    update_data = {}
    if body.full_name is not None:
        update_data["full_name"] = body.full_name
    if body.app_version is not None:
        update_data["app_version"] = body.app_version
    if body.app_opens is not None:
        update_data["app_opens"] = func.coalesce(login_records.c.app_opens, 0) + body.app_opens
    if body.last_open_at is not None:
        update_data["last_open_at"] = body.last_open_at
    if body.last_login_at is not None:
        update_data["last_login_at"] = body.last_login_at

    # ✅ NOWE
    if body.province is not None:
        update_data["province"] = body.province

    if not update_data:
        raise HTTPException(status_code=400, detail="Brak pól do aktualizacji")

    await database.execute(
        login_records.update()
        .where(login_records.c.judge_id == judge_id)
        .values(**update_data)
    )

    row = await database.fetch_one(
        select(login_records).where(login_records.c.judge_id == judge_id)
    )
    return LoginRecordItem(**dict(row))


@router.put(
    "/{judge_id}",
    response_model=LoginRecordItem,
    summary="Upsert rekordu logowania po judge_id",
)
async def put_login_record(judge_id: str, req: CreateLoginRecordRequest):
    now = datetime.now(timezone.utc)

    stmt = pg_insert(login_records).values(
        judge_id=judge_id,
        full_name=req.full_name,
        last_login_at=now,
        app_version=req.app_version,
        app_opens=req.app_opens,
        last_open_at=req.last_open_at,
        province=req.province,  # ✅ NOWE
    )

    stmt = stmt.on_conflict_do_update(
        index_elements=[login_records.c.judge_id],
        set_={
            "full_name": req.full_name,
            "last_login_at": now,
            "app_version": func.coalesce(stmt.excluded.app_version, login_records.c.app_version),
            "app_opens": func.coalesce(stmt.excluded.app_opens, login_records.c.app_opens),
            "last_open_at": func.coalesce(stmt.excluded.last_open_at, login_records.c.last_open_at),
            # ✅ NOWE
            "province": func.coalesce(stmt.excluded.province, login_records.c.province),
        },
    )

    await database.execute(stmt)

    row = await database.fetch_one(
        select(login_records).where(login_records.c.judge_id == judge_id)
    )
    return LoginRecordItem(**dict(row))

# app/routers/login_records.py
from datetime import datetime, timezone
import logging
import traceback

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import database, login_records
from app.schemas import (
    CreateLoginRecordRequest,
    LoginRecordItem,
    ListLoginRecordsResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/login_records", tags=["LoginRecords"])


@router.post("/", response_model=dict, summary="Upsert ostatniego logowania")
async def upsert_login(req: CreateLoginRecordRequest):
    """
    Wstawia lub uaktualnia rekord ostatniego logowania.
    - Zawsze nadpisuje: full_name, last_login_at
    - Nadpisuje app_version / app_opens / last_open_at tylko, jeśli zostały przesłane (COALESCE na EXCLUDED)
    """
    now = datetime.now(timezone.utc)

    try:
        # Budujemy INSERT ... ON CONFLICT (judge_id) DO UPDATE ...
        stmt = pg_insert(login_records).values(
            judge_id=req.judge_id,
            full_name=req.full_name,
            last_login_at=now,
            app_version=req.app_version,
            app_opens=req.app_opens,
            last_open_at=req.last_open_at,
        )

        stmt = stmt.on_conflict_do_update(
            index_elements=[login_records.c.judge_id],
            set_={
                "full_name": req.full_name,
                "last_login_at": now,
                # WAŻNE: odwołujemy się do TEGO stmt.excluded, a nie do modułu pg_insert
                "app_version": func.coalesce(
                    stmt.excluded.app_version, login_records.c.app_version
                ),
                "app_opens": func.coalesce(
                    stmt.excluded.app_opens, login_records.c.app_opens
                ),
                "last_open_at": func.coalesce(
                    stmt.excluded.last_open_at, login_records.c.last_open_at
                ),
            },
        )

        await database.execute(stmt)
        return {"success": True}

    except Exception as e:
        logger.error("upsert_login failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(
            status_code=500,
            detail=f"upsert_login failed: {e}",
        )


@router.get("/", response_model=ListLoginRecordsResponse, summary="Lista wszystkich logowań")
async def list_logins():
    # Dla czytelności sortujemy malejąco po last_login_at
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
    result = await database.execute(
        login_records.delete().where(login_records.c.judge_id == judge_id)
    )
    # databases zwraca None dla DELETE w niektórych sterownikach – traktujemy jako OK,
    # ale jeżeli chcesz twardo 404 dla nieistniejącego ID, najpierw sprawdź istnienie.
    return {"success": True}

from fastapi import APIRouter, HTTPException, status
from app.db import database, login_records
from app.schemas import CreateLoginRecordRequest, LoginRecordItem, ListLoginRecordsResponse
from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from datetime import datetime

router = APIRouter(prefix="/login_records", tags=["LoginRecords"])

@router.post("/", response_model=dict, summary="Upsert ostatniego logowania")
async def upsert_login(req: CreateLoginRecordRequest):
    # UWAGA: zakładam, że CreateLoginRecordRequest ma teraz:
    # judge_id: str, full_name: str,
    # app_version: Optional[str] = None,
    # app_opens: Optional[int] = None,
    # last_open_at: Optional[datetime] = None
    now = datetime.utcnow()

    stmt = pg_insert(login_records).values(
        judge_id=req.judge_id,
        full_name=req.full_name,
        last_login_at=now,
        app_version=req.app_version,
        app_opens=req.app_opens,
        last_open_at=req.last_open_at,
    ).on_conflict_do_update(
        index_elements=[login_records.c.judge_id],
        set_={
            "full_name": req.full_name,
            "last_login_at": now,
            # Nadpisuj TYLKO jeśli coś przyszło; w psql robimy CASE WHEN
            "app_version": func.coalesce(pg_insert.excluded.c.app_version, login_records.c.app_version),
            "app_opens": func.coalesce(pg_insert.excluded.c.app_opens, login_records.c.app_opens),
            "last_open_at": func.coalesce(pg_insert.excluded.c.last_open_at, login_records.c.last_open_at),
        }
    )
    await database.execute(stmt)
    return {"success": True}

@router.get("/", response_model=ListLoginRecordsResponse, summary="Lista wszystkich logowań")
async def list_logins():
    rows = await database.fetch_all(select(login_records))
    return ListLoginRecordsResponse(records=[LoginRecordItem(**dict(r)) for r in rows])

@router.get("/{judge_id}", response_model=LoginRecordItem)
async def get_login_record(judge_id: str):
    row = await database.fetch_one(
        select(login_records).where(login_records.c.judge_id == judge_id)
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono rekordu")
    return LoginRecordItem(**dict(row))

@router.delete("/{judge_id}", response_model=dict, summary="Usuń rekord logowania")
async def delete_login(judge_id: str):
    result = await database.execute(login_records.delete().where(login_records.c.judge_id == judge_id))
    if not result:
        raise HTTPException(status_code=404, detail="Nie znaleziono rekordu")
    return {"success": True}

from fastapi import APIRouter, HTTPException, status
from app.db import database, login_records
from app.schemas import CreateLoginRecordRequest, LoginRecordItem, ListLoginRecordsResponse
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from datetime import datetime

router = APIRouter(prefix="/login_records", tags=["LoginRecords"])

@router.post("/", response_model=dict, summary="Upsert ostatniego logowania")
async def upsert_login(req: CreateLoginRecordRequest):
    stmt = pg_insert(login_records).values(
        judge_id=req.judge_id,
        full_name=req.full_name,
        last_login_at=datetime.utcnow()
    ).on_conflict_do_update(
        index_elements=[login_records.c.judge_id],
        set_={
            "full_name": req.full_name,
            "last_login_at": datetime.utcnow()
        }
    )
    await database.execute(stmt)
    return {"success": True}

@router.get("/", response_model=ListLoginRecordsResponse, summary="Lista wszystkich logowań")
async def list_logins():
    rows = await database.fetch_all(select(login_records))
    return ListLoginRecordsResponse(records=[LoginRecordItem(**dict(r)) for r in rows])

@router.delete("/{judge_id}", response_model=dict, summary="Usuń rekord logowania")
async def delete_login(judge_id: str):
    result = await database.execute(login_records.delete().where(login_records.c.judge_id == judge_id))
    if not result:
        raise HTTPException(status_code=404, detail="Nie znaleziono rekordu")
    return {"success": True}

from datetime import datetime, timezone
import logging
import traceback
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import and_, select

from app.db import database, short_result_records
from app.schemas import (
    CreateShortResultRecordRequest,
    ShortResultRecordItem,
    ListShortResultRecordsResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/short_result_records", tags=["ShortResultRecords"])


@router.post("/", response_model=ShortResultRecordItem, summary="Dodaj wpis rejestru wyniku skróconego")
async def create_short_result_record(req: CreateShortResultRecordRequest):
    """
    Tworzy wpis rejestru zawierający:
    - numer meczu,
    - osobę wpisującą (ID + opcjonalnie imię i nazwisko),
    - pełny JSON payloadu wysyłanego na serwer.
    """
    try:
        # INSERT
        new_id = await database.execute(
            short_result_records.insert().values(
                match_number=req.match_number,
                author_id=req.author_id,
                author_name=req.author_name,
                payload=req.payload,
            )
        )

        # SELECT świeżo dodanego wiersza
        row = await database.fetch_one(
            select(short_result_records).where(short_result_records.c.id == new_id)
        )
        return ShortResultRecordItem(**dict(row))  # type: ignore

    except Exception as e:
        logger.error("create_short_result_record failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"create_short_result_record failed: {e}")


@router.get("/", response_model=ListShortResultRecordsResponse, summary="Lista wpisów rejestru")
async def list_short_result_records(
    match_number: Optional[str] = Query(None, description="Filtr: numer meczu"),
    author_id: Optional[str] = Query(None, description="Filtr: ID osoby wpisującej"),
    limit: int = Query(200, ge=1, le=1000, description="Limit wyników (domyślnie 200)"),
    offset: int = Query(0, ge=0, description="Offset (stronicowanie)"),
):
    """
    Zwraca listę wpisów rejestru. Możliwe filtry:
    - `match_number`
    - `author_id`

    Wyniki posortowane malejąco po `created_at`.
    """
    conds = []
    if match_number:
        conds.append(short_result_records.c.match_number == match_number)
    if author_id:
        conds.append(short_result_records.c.author_id == author_id)

    q = select(short_result_records)
    if conds:
        q = q.where(and_(*conds))
    q = q.order_by(short_result_records.c.created_at.desc()).limit(limit).offset(offset)

    rows = await database.fetch_all(q)
    return ListShortResultRecordsResponse(
        records=[ShortResultRecordItem(**dict(r)) for r in rows]  # type: ignore
    )


@router.get("/{record_id}", response_model=ShortResultRecordItem, summary="Pobierz wpis rejestru po ID")
async def get_short_result_record(record_id: int):
    row = await database.fetch_one(
        select(short_result_records).where(short_result_records.c.id == record_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono wpisu")
    return ShortResultRecordItem(**dict(row))  # type: ignore


@router.delete("/{record_id}", response_model=dict, summary="Usuń wpis rejestru po ID")
async def delete_short_result_record(record_id: int):
    # Możesz najpierw sprawdzić istnienie, ale trzymamy styl jak w login_records
    await database.execute(
        short_result_records.delete().where(short_result_records.c.id == record_id)
    )
    return {"success": True}

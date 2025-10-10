from fastapi import APIRouter, HTTPException, status
from typing import List
from app.db import database, partner_offtimes
from app.schemas import (
    CreatePartnerOfftimeRequest,
    UpdatePartnerOfftimeRequest,
    PartnerOfftimeItem,
    ListPartnerOfftimesResponse,
    GetPartnerOfftimeResponse
)
from sqlalchemy import select, insert, update, delete

router = APIRouter(
    prefix="/partner-offtimes",
    tags=["PartnerOfftimes"],
    responses={404: {"description": "Not found"}},
)


@router.post(
    "/",
    response_model=PartnerOfftimeItem,
    status_code=status.HTTP_201_CREATED,
    summary="Dodaj nowego sędziego z niedyspozycjami"
)
async def create_partner_offtime(req: CreatePartnerOfftimeRequest):
    existing = await database.fetch_one(
        select(partner_offtimes)
        .where(partner_offtimes.c.judge_id == req.judge_id)
    )
    if existing:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"Sędzia o ID {req.judge_id} już istnieje"
        )
    stmt = insert(partner_offtimes).values(
        judge_id=req.judge_id,
        full_name=req.full_name,
        partner_id=req.partner_id,
        data_json=req.data_json
    )
    await database.execute(stmt)
    row = await database.fetch_one(
        select(partner_offtimes)
        .where(partner_offtimes.c.judge_id == req.judge_id)
    )
    return PartnerOfftimeItem(**row)


@router.put(
    "/{judge_id}",
    response_model=PartnerOfftimeItem,
    summary="Edytuj istniejącego sędziego po ID"
)
async def update_partner_offtime(judge_id: str, req: UpdatePartnerOfftimeRequest):
    row = await database.fetch_one(
        select(partner_offtimes)
        .where(partner_offtimes.c.judge_id == judge_id)
    )
    if not row:
        raise HTTPException(404, f"Sędzia o ID {judge_id} nie istnieje")
    update_data = req.dict(exclude_unset=True)
    if not update_data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Brak danych do aktualizacji")
    stmt = (
        update(partner_offtimes)
        .where(partner_offtimes.c.judge_id == judge_id)
        .values(**update_data)
    )
    await database.execute(stmt)
    updated = await database.fetch_one(
        select(partner_offtimes)
        .where(partner_offtimes.c.judge_id == judge_id)
    )
    return PartnerOfftimeItem(**updated)


@router.delete(
    "/{judge_id}",
    response_model=dict,
    summary="Usuń sędziego po ID"
)
async def delete_partner_offtime(judge_id: str):
    result = await database.execute(
        delete(partner_offtimes)
        .where(partner_offtimes.c.judge_id == judge_id)
    )
    if result == 0:
        raise HTTPException(404, f"Sędzia o ID {judge_id} nie znaleziony")
    return {"success": True}


@router.get(
    "/",
    response_model=ListPartnerOfftimesResponse,
    summary="Lista wszystkich sędziów z niedyspozycjami"
)
async def list_partner_offtimes():
    rows = await database.fetch_all(select(partner_offtimes))
    return ListPartnerOfftimesResponse(records=[PartnerOfftimeItem(**r) for r in rows])


@router.get(
    "/{judge_id}",
    response_model=GetPartnerOfftimeResponse,
    summary="Pobierz dane sędziego z niedyspozycjami po ID"
)
async def get_partner_offtime(judge_id: str):
    row = await database.fetch_one(
        select(partner_offtimes).where(partner_offtimes.c.judge_id == judge_id)
    )
    if not row:
        raise HTTPException(404, f"Sędzia o ID {judge_id} nie znaleziony")
    return GetPartnerOfftimeResponse(record=PartnerOfftimeItem(**row))

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select, insert, update, delete
from app.db import database, beach_proel_matches
from app.schemas import (
    BeachProElCreateMatchRequest,
    BeachProElMatchItem,
    BeachProElListMatchesResponse,
    BeachProElUpdateMatchRequest,
)
from datetime import datetime
from app.beach.activity_log import log_activity

router = APIRouter(
    prefix="/beach/proel",
    tags=["Beach ProEl"],
    responses={404: {"description": "Not found"}},
)


@router.post(
    "/",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Dodaj nowy mecz do Beach ProEl'a",
)
async def create_beach_proel_match(req: BeachProElCreateMatchRequest):
    existing = await database.fetch_one(
        select(beach_proel_matches).where(
            beach_proel_matches.c.match_number == req.match_number
        )
    )
    if existing:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": "MATCH_EXISTS", "message": "Mecz o takim numerze już istnieje"},
        )

    stmt = insert(beach_proel_matches).values(
        match_number=req.match_number,
        data_json=req.data_json,
        status=req.status,
    )
    await database.execute(stmt)

    await log_activity(
        area="proel",
        action="match.created",
        target_id=req.match_number,
        details={"status": req.status},
    )

    return {"success": True}


@router.put(
    "/{match_number:path}",
    response_model=dict,
    summary="Aktualizuj mecz w Beach ProEl'u",
)
async def update_beach_proel_match(
    match_number: str,
    req: BeachProElUpdateMatchRequest,
):
    row = await database.fetch_one(
        select(beach_proel_matches).where(
            beach_proel_matches.c.match_number == match_number
        )
    )

    if not row:
        # Match doesn't exist — create it (upsert behaviour)
        stmt = insert(beach_proel_matches).values(
            match_number=match_number,
            data_json=req.data_json,
            status=req.status or "IN_GAME",
        )
        await database.execute(stmt)

        await log_activity(
            area="proel",
            action="match.created",
            target_id=match_number,
            details={"status": req.status or "IN_GAME", "upsert": True},
        )

        return {"success": True, "created": True}

    to_update: dict = {"data_json": req.data_json}
    if req.status is not None:
        to_update["status"] = req.status
    to_update["updated_at"] = datetime.utcnow()

    stmt = (
        update(beach_proel_matches)
        .where(beach_proel_matches.c.match_number == match_number)
        .values(**to_update)
    )
    await database.execute(stmt)

    old_status = dict(row).get("status")
    if req.status and req.status != old_status:
        await log_activity(
            area="proel",
            action="match.status_changed",
            target_id=match_number,
            details={"old_status": old_status, "new_status": req.status},
        )

    return {"success": True}


@router.delete(
    "/{match_number:path}",
    response_model=dict,
    summary="Usuń mecz Beach ProEl",
)
async def delete_beach_proel_match(match_number: str):
    result = await database.execute(
        delete(beach_proel_matches).where(
            beach_proel_matches.c.match_number == match_number
        )
    )
    if result == 0:
        raise HTTPException(404, "Nie znaleziono meczu w Beach ProEl'u")

    await log_activity(
        area="proel",
        action="match.deleted",
        target_id=match_number,
    )

    return {"success": True}


@router.get(
    "/",
    response_model=BeachProElListMatchesResponse,
    summary="Lista wszystkich meczów w Beach ProEl'u",
)
async def list_beach_proel_matches(
    status: Optional[str] = Query(
        None,
        description="Filtruj po statusie (np. 'in_progress', 'finished'); domyślnie wszystkie",
    )
):
    stmt = select(beach_proel_matches)

    if status is not None:
        stmt = stmt.where(beach_proel_matches.c.status == status)

    stmt = stmt.order_by(
        beach_proel_matches.c.updated_at.desc(),
        beach_proel_matches.c.match_number.desc(),
    )

    rows = await database.fetch_all(stmt)
    return BeachProElListMatchesResponse(
        matches=[BeachProElMatchItem(**dict(r)) for r in rows]
    )


@router.get(
    "/{match_number:path}",
    response_model=BeachProElMatchItem,
    summary="Pobierz jeden mecz Beach ProEl po numerze",
)
async def get_beach_proel_match(match_number: str):
    row = await database.fetch_one(
        select(beach_proel_matches).where(
            beach_proel_matches.c.match_number == match_number
        )
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono meczu w Beach ProEl'u")
    return BeachProElMatchItem(**dict(row))

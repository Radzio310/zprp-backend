from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select, insert, update, delete
from app.db import database, saved_matches
from app.schemas import (
    CreateSavedMatchRequest,
    UpdateSavedMatchRequest,
    MatchItem,
    ListSavedMatchesResponse,
)
from datetime import datetime

router = APIRouter(
    prefix="/proel",
    tags=["ProEl"],
    responses={404: {"description": "Not found"}},
)

@router.post(
    "/",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Dodaj nowy mecz do ProEl'a"
)
async def create_proel_match(req: CreateSavedMatchRequest):
    existing = await database.fetch_one(
        select(saved_matches)
        .where(saved_matches.c.match_number == req.match_number)
    )
    if existing:
        raise HTTPException(400, "Mecz o takim numerze już istnieje")

    stmt = insert(saved_matches).values(
        match_number=req.match_number,
        data_json=req.data_json,
        is_finished=req.is_finished  # używamy tego, co przyszło (domyślnie False)
    )
    await database.execute(stmt)
    return {"success": True}


@router.put(
    "/{match_number:path}",
    response_model=dict,
    summary="Aktualizuj mecz w ProEl'u (jeśli nie zakończony)"
)
async def update_proel_match(
    match_number: str,
    req: UpdateSavedMatchRequest
):
    row = await database.fetch_one(
        select(saved_matches)
        .where(saved_matches.c.match_number == match_number)
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono meczu w ProEl'u")
    if row["is_finished"]:
        # jeżeli już było zakończone, nie pozwalamy na jakiekolwiek zmiany
        raise HTTPException(400, "Nie można edytować zakończonego meczu")

    # Budujemy słownik pól do aktualizacji
    to_update: dict = {"data_json": req.data_json}
    if req.is_finished is not None:
        to_update["is_finished"] = req.is_finished
    # zawsze przepisujemy updated_at na teraz
    to_update["updated_at"] = datetime.utcnow()

    stmt = (
        update(saved_matches)
        .where(saved_matches.c.match_number == match_number)
        .values(**to_update)
    )
    await database.execute(stmt)
    return {"success": True}


@router.delete(
    "/{match_number:path}",
    response_model=dict,
    summary="Usuń mecz ProEl"
)
async def delete_proel_match(match_number: str):
    result = await database.execute(
        delete(saved_matches)
        .where(saved_matches.c.match_number == match_number)
    )
    if result == 0:
        raise HTTPException(404, "Nie znaleziono meczu w ProEl'u")
    return {"success": True}


@router.get(
    "/",
    response_model=ListSavedMatchesResponse,
    summary="Lista wszystkich meczów w ProEl'u"
)
async def list_proel_matches(
    finished: Optional[bool] = Query(
        None,
        description="Filtruj po zakończonych (true) lub niezakończonych (false); domyślnie wszystkie"
    )
):
    # budujemy bazowy SELECT
    stmt = select(saved_matches)

    # jeżeli użytkownik podał finished, dodajemy WHERE
    if finished is not None:
        stmt = stmt.where(saved_matches.c.is_finished == finished)

    # dodajemy ORDER BY
    stmt = stmt.order_by(saved_matches.c.match_number)

    rows = await database.fetch_all(stmt)
    return ListSavedMatchesResponse(
        matches=[MatchItem(**dict(r)) for r in rows]
    )

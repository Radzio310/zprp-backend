from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select, insert, update, delete
from app.db import database, saved_matches
from app.schemas import (
    CreateSavedMatchRequest,
    PlayerInfo,
    PlayersResponse,
    PlayersSide,
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

_VALID_STATUSES = ("in_progress", "finished", "approved")


def _resolve_status(status: Optional[str], is_finished: Optional[bool], fallback: str) -> str:
    """Ustal status na podstawie (priorytetowo) jawnego pola status, a w jego braku
    starego pola is_finished. is_finished=True z dawnych klientów mapujemy na 'finished'
    (nigdy na 'approved' — zatwierdzenie to świadoma, osobna akcja)."""
    if status:
        s = str(status).strip().lower()
        if s in _VALID_STATUSES:
            return s
    if is_finished is not None:
        return "finished" if is_finished else "in_progress"
    return fallback


def _is_finished_for(status: str) -> bool:
    return status in ("finished", "approved")

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
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": "MATCH_EXISTS", "message": "Mecz o takim numerze już istnieje"},
        )

    new_status = _resolve_status(req.status, req.is_finished, "in_progress")
    stmt = insert(saved_matches).values(
        match_number=req.match_number,
        data_json=req.data_json,
        status=new_status,
        is_finished=_is_finished_for(new_status),
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
    # Blokada DOPIERO po zatwierdzeniu (status="approved"), NIE po zakończeniu.
    try:
        current_status = row["status"] or ("finished" if row["is_finished"] else "in_progress")
    except (KeyError, IndexError):
        current_status = "finished" if row["is_finished"] else "in_progress"
    if current_status == "approved":
        raise HTTPException(
            status.HTTP_423_LOCKED,
            detail={"code": "MATCH_APPROVED", "message": "Nie można edytować zatwierdzonego meczu"},
        )

    # Budujemy słownik pól do aktualizacji
    to_update: dict = {"data_json": req.data_json}
    # status (lub stare is_finished) — jeśli cokolwiek przyszło, przelicz oba pola
    if req.status is not None or req.is_finished is not None:
        new_status = _resolve_status(req.status, req.is_finished, current_status)
        to_update["status"] = new_status
        to_update["is_finished"] = _is_finished_for(new_status)
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
    ),
    status: Optional[str] = Query(
        None,
        description="Filtruj po statusie: in_progress | finished | approved"
    ),
):
    # budujemy bazowy SELECT
    stmt = select(saved_matches)

    # jeżeli użytkownik podał finished, dodajemy WHERE
    if finished is not None:
        stmt = stmt.where(saved_matches.c.is_finished == finished)

    # filtr po statusie (priorytetowy względem finished, jeśli oba podane)
    if status is not None:
        s = str(status).strip().lower()
        if s in _VALID_STATUSES:
            stmt = stmt.where(saved_matches.c.status == s)

    # najnowsze (ostatnio edytowane) najpierw
    stmt = stmt.order_by(
        saved_matches.c.updated_at.desc(),
        saved_matches.c.match_number.desc()
    )

    rows = await database.fetch_all(stmt)
    return ListSavedMatchesResponse(
        matches=[MatchItem(**dict(r)) for r in rows]
    )
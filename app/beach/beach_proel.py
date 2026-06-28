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


def _extract_proel_link(data_json):
    """Wyciąga (tournament_id, schedule_match_id) z data_json meczu ProEl.

    Powiązanie żyje w data_json.matchConfig.extras (BeachMatchState);
    z fallbackiem na top-level extras / pola, na wszelki wypadek.
    """
    if not isinstance(data_json, dict):
        return None, None
    candidates = []
    match_config = data_json.get("matchConfig")
    if isinstance(match_config, dict) and isinstance(match_config.get("extras"), dict):
        candidates.append(match_config["extras"])
    if isinstance(data_json.get("extras"), dict):
        candidates.append(data_json["extras"])
    candidates.append(data_json)  # top-level fallback

    tournament_id = None
    schedule_match_id = None
    for source in candidates:
        if tournament_id is None and source.get("tournamentId") is not None:
            try:
                tournament_id = int(source.get("tournamentId"))
            except (TypeError, ValueError):
                tournament_id = None
        if schedule_match_id is None and source.get("scheduleMatchId") is not None:
            schedule_match_id = str(source.get("scheduleMatchId"))
    return tournament_id, schedule_match_id


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

    tournament_id, schedule_match_id = _extract_proel_link(req.data_json)
    stmt = insert(beach_proel_matches).values(
        match_number=req.match_number,
        data_json=req.data_json,
        status=req.status,
        tournament_id=tournament_id,
        schedule_match_id=schedule_match_id,
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

    tournament_id, schedule_match_id = _extract_proel_link(req.data_json)

    if not row:
        # Match doesn't exist — create it (upsert behaviour)
        stmt = insert(beach_proel_matches).values(
            match_number=match_number,
            data_json=req.data_json,
            status=req.status or "IN_GAME",
            tournament_id=tournament_id,
            schedule_match_id=schedule_match_id,
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
    # Odśwież powiązanie tylko gdy mamy je w nowym payloadzie (nie kasuj istniejącego).
    if tournament_id is not None:
        to_update["tournament_id"] = tournament_id
    if schedule_match_id is not None:
        to_update["schedule_match_id"] = schedule_match_id
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
    ),
    tournament_id: Optional[int] = Query(
        None,
        description="Zwróć tylko mecze tego turnieju (po data_json.matchConfig.extras.tournamentId)",
    ),
    schedule_match_ids: Optional[str] = Query(
        None,
        description="Lista ID meczów terminarza po przecinku — zwróć tylko te mecze",
    ),
):
    stmt = select(beach_proel_matches)

    if status is not None:
        stmt = stmt.where(beach_proel_matches.c.status == status)

    if tournament_id is not None:
        stmt = stmt.where(beach_proel_matches.c.tournament_id == tournament_id)

    if schedule_match_ids is not None:
        wanted = [s.strip() for s in schedule_match_ids.split(",") if s.strip()]
        if wanted:
            stmt = stmt.where(beach_proel_matches.c.schedule_match_id.in_(wanted))
        else:
            # Pusta (ale podana) lista → brak wyników, nie cała tabela.
            return BeachProElListMatchesResponse(matches=[])

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

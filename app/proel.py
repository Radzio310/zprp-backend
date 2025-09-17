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

from app.services.zprp_players_parser import parse_players_from_html
from app.services import zprp_fetch

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
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": "MATCH_EXISTS", "message": "Mecz o takim numerze już istnieje"},
        )

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
        raise HTTPException(
            status.HTTP_423_LOCKED,
            detail={"code": "MATCH_FINISHED", "message": "Nie można edytować zakończonego meczu"},
        )

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

    # najnowsze (ostatnio edytowane) najpierw
    stmt = stmt.order_by(
        saved_matches.c.updated_at.desc(),
        saved_matches.c.match_number.desc()
    )

    rows = await database.fetch_all(stmt)
    return ListSavedMatchesResponse(
        matches=[MatchItem(**dict(r)) for r in rows]
    )

@router.get(
    "/{match_number:path}/players",
    response_model=PlayersResponse,
    summary="Lista zawodników (numer, imię i nazwisko, zdjęcie) – gospodarze/goście/obie drużyny"
)
async def get_match_players(
    match_number: str,
    side: PlayersSide = Query("both", description="home | away | both"),
):
    """
    Zwraca połączone dane zawodników dla meczu wyłącznie na podstawie numeru meczu.
    Źródła: HTML zapisany w bazie lub HTML pobrany spod URL-i zapisanych w data_json.
    Gdy nie ma składu/HTML-a — zwracamy puste listy (frontend pokaże toast).
    """
    html = await zprp_fetch.fetch_match_html_by_number(match_number)

    if not html:
        # brak źródła/HTML — traktujemy jako „brak składu”
        resp = PlayersResponse(match_number=match_number, home=[], away=[])
        if side == "home":
            resp.away = []
        elif side == "away":
            resp.home = []
        return resp

    try:
        home_raw, away_raw = parse_players_from_html(html)
    except Exception:
        # nie udało się sparsować -> „brak składu”
        resp = PlayersResponse(match_number=match_number, home=[], away=[])
        if side == "home":
            resp.away = []
        elif side == "away":
            resp.home = []
        return resp

    resp = PlayersResponse(match_number=match_number)
    if side in ("home", "both"):
        resp.home = [PlayerInfo(**p) for p in (home_raw or [])]
    if side in ("away", "both"):
        resp.away = [PlayerInfo(**p) for p in (away_raw or [])]
    return resp

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, insert, update, delete
from app.db import (
    database,
    beach_admins,
    beach_proel_matches,
    beach_tournaments,
)
from app.schemas import (
    BeachProElCreateMatchRequest,
    BeachProElMatchItem,
    BeachProElListMatchesResponse,
    BeachProElUpdateMatchRequest,
)
from datetime import datetime
from app.beach.activity_log import get_actor_name, log_activity
from app.deps import beach_get_current_user_id

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


async def _is_admin(user_id: int) -> bool:
    return bool(
        await database.fetch_one(
            select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
        )
    )


async def _can_manage_match(tournament_id: Optional[int], user_id: int) -> bool:
    if await _is_admin(user_id):
        return True
    if tournament_id is None:
        return False
    row = await database.fetch_one(
        select(beach_tournaments.c.data_json).where(
            beach_tournaments.c.id == tournament_id
        )
    )
    if not row:
        return False
    data = row["data_json"] if isinstance(row["data_json"], dict) else {}
    allowed_ids = set()
    for item in (data.get("hosts") or []) + (data.get("judges") or []):
        if not isinstance(item, dict):
            continue
        raw_id = item.get("user_id") or item.get("id")
        try:
            allowed_ids.add(int(raw_id))
        except (TypeError, ValueError):
            pass
    try:
        allowed_ids.add(int(data.get("head_judge_id")))
    except (TypeError, ValueError):
        pass
    return int(user_id) in allowed_ids


async def _can_approve(tournament_id: Optional[int], user_id: int) -> bool:
    if await _is_admin(user_id):
        return True
    if tournament_id is None:
        return False


def _selected_team_players(config: dict, side: str) -> tuple[Optional[int], list[int], list[dict]]:
    team_key = "hostTeamId" if side == "host" else "guestTeamId"
    players_key = "hostPlayers" if side == "host" else "guestPlayers"
    try:
        team_id = int(config.get(team_key))
    except (TypeError, ValueError):
        team_id = None
    ids: list[int] = []
    unidentified: list[dict] = []
    for player in config.get(players_key) or []:
        if not isinstance(player, dict) or player.get("selected") is False:
            continue
        try:
            player_id = int(player.get("player_id"))
        except (TypeError, ValueError):
            unidentified.append(player)
            continue
        if team_id is None:
            unidentified.append(player)
        else:
            ids.append(player_id)
    return team_id, ids, unidentified


async def _validate_mp_lineup(
    tournament_id: Optional[int],
    new_data: dict,
    old_data: Optional[dict] = None,
) -> None:
    if tournament_id is None:
        return
    tournament_row = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not tournament_row:
        return
    tournament = dict(tournament_row)
    tournament_data = (
        tournament.get("data_json")
        if isinstance(tournament.get("data_json"), dict)
        else {}
    )
    new_config = (
        new_data.get("matchConfig")
        if isinstance(new_data, dict) and isinstance(new_data.get("matchConfig"), dict)
        else {}
    )
    old_config = (
        old_data.get("matchConfig")
        if isinstance(old_data, dict)
        and isinstance(old_data.get("matchConfig"), dict)
        else {}
    )
    squads = (
        tournament_data.get("team_squads")
        if isinstance(tournament_data.get("team_squads"), dict)
        else {}
    )
    from app.beach.mp_appearances import (
        assert_no_unidentified_final_players,
        validate_final_player_ids,
    )

    for side in ("host", "guest"):
        team_id, new_ids, unidentified = _selected_team_players(new_config, side)
        if team_id is None:
            # Custom teams are intentionally outside this mechanism; an
            # enforced MP final cannot treat them as verified participants.
            if unidentified:
                await assert_no_unidentified_final_players(
                    tournament, unidentified
                )
            continue
        old_team_id, old_ids, old_unidentified = _selected_team_players(
            old_config, side
        )
        old_set = set(old_ids) if old_team_id == team_id else set()
        added_ids = [player_id for player_id in new_ids if player_id not in old_set]
        old_extra_names = {
            str(player.get("name") or "").strip().casefold()
            for player in old_unidentified
        }
        added_unidentified = [
            player
            for player in unidentified
            if str(player.get("name") or "").strip().casefold()
            not in old_extra_names
        ]
        entry = squads.get(str(team_id)) if isinstance(squads.get(str(team_id)), dict) else {}
        accepted_ids = [
            int(value)
            for value in (entry.get("mp_warning_acceptances") or {}).keys()
            if str(value).isdigit()
        ]
        if added_ids:
            await validate_final_player_ids(
                tournament,
                team_id,
                added_ids,
                accepted_ids,
            )
        if added_unidentified:
            await assert_no_unidentified_final_players(
                tournament,
                added_unidentified,
            )
    row = await database.fetch_one(
        select(beach_tournaments.c.data_json).where(
            beach_tournaments.c.id == tournament_id
        )
    )
    data = row["data_json"] if row and isinstance(row["data_json"], dict) else {}
    try:
        return int(data.get("head_judge_id")) == int(user_id)
    except (TypeError, ValueError):
        return False


@router.post(
    "/",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Dodaj nowy mecz do Beach ProEl'a",
)
async def create_beach_proel_match(
    req: BeachProElCreateMatchRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
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
    if not await _can_manage_match(tournament_id, current_user_id):
        raise HTTPException(403, "Brak uprawnień do prowadzenia tego meczu")
    if str(req.status or "").upper() == "APPROVED" and not await _can_approve(
        tournament_id, current_user_id
    ):
        raise HTTPException(403, "Mecz może zatwierdzić tylko sędzia główny lub administrator")
    await _validate_mp_lineup(tournament_id, req.data_json)
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
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
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
    current_user_id: int = Depends(beach_get_current_user_id),
):
    row = await database.fetch_one(
        select(beach_proel_matches).where(
            beach_proel_matches.c.match_number == match_number
        )
    )

    tournament_id, schedule_match_id = _extract_proel_link(req.data_json)
    if tournament_id is None and row:
        tournament_id = dict(row).get("tournament_id")
    if not await _can_manage_match(tournament_id, current_user_id):
        raise HTTPException(403, "Brak uprawnień do prowadzenia tego meczu")
    old_status = str(dict(row).get("status") or "").upper() if row else ""
    new_status = str(req.status or old_status or "IN_GAME").upper()
    if old_status == "APPROVED" and not await _is_admin(current_user_id):
        raise HTTPException(
            423,
            "Zatwierdzony protokół jest niezmienny. Korektę może wykonać tylko administrator.",
        )
    if new_status == "APPROVED" and not await _can_approve(tournament_id, current_user_id):
        raise HTTPException(403, "Mecz może zatwierdzić tylko sędzia główny lub administrator")
    await _validate_mp_lineup(
        tournament_id,
        req.data_json,
        dict(row).get("data_json") if row else None,
    )

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
            actor_user_id=current_user_id,
            actor_name=await get_actor_name(current_user_id),
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
            actor_user_id=current_user_id,
            actor_name=await get_actor_name(current_user_id),
            target_id=match_number,
            details={
                "changed_fields": {
                    "status": {"old": old_status, "new": req.status}
                }
            },
        )

    return {"success": True}


@router.delete(
    "/{match_number:path}",
    response_model=dict,
    summary="Usuń mecz Beach ProEl",
)
async def delete_beach_proel_match(
    match_number: str,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Mecz ProEl może usunąć tylko administrator")
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
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
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
    current_user_id: int = Depends(beach_get_current_user_id),
):
    del current_user_id
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
async def get_beach_proel_match(
    match_number: str,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    del current_user_id
    row = await database.fetch_one(
        select(beach_proel_matches).where(
            beach_proel_matches.c.match_number == match_number
        )
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono meczu w Beach ProEl'u")
    return BeachProElMatchItem(**dict(row))

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import select, insert, delete, func, and_

from app.db import database, beach_mvp_votes
from app.deps import beach_get_current_user_id
from app.beach.activity_log import log_activity, get_actor_name

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/beach/mvp-votes", tags=["Beach: MVP Votes"])

VALID_VOTE_TYPES = {"mvp", "goalkeeper"}


# ─────────────────── Pydantic models ───────────────────

class CastVoteRequest(BaseModel):
    vote_type: str                      # "mvp" | "goalkeeper"
    player_id: Optional[int] = None     # null dla custom team playerów
    custom_player_id: Optional[str] = None  # "ct_<uuid>:<player_uuid>"
    player_name: str
    team_name: str
    jersey_number: Optional[str] = None
    photo_url: Optional[str] = None


# ─────────────────── Helpers ───────────────────

async def _get_tallies(tournament_id: int) -> Dict[str, List[Dict[str, Any]]]:
    """Return vote tallies grouped by vote_type, sorted by count DESC."""
    rows = await database.fetch_all(
        select(
            beach_mvp_votes.c.vote_type,
            beach_mvp_votes.c.player_id,
            beach_mvp_votes.c.custom_player_id,
            beach_mvp_votes.c.player_name,
            beach_mvp_votes.c.team_name,
            beach_mvp_votes.c.jersey_number,
            beach_mvp_votes.c.photo_url,
            func.count(beach_mvp_votes.c.id).label("count"),
        )
        .where(beach_mvp_votes.c.tournament_id == tournament_id)
        .group_by(
            beach_mvp_votes.c.vote_type,
            beach_mvp_votes.c.player_id,
            beach_mvp_votes.c.custom_player_id,
            beach_mvp_votes.c.player_name,
            beach_mvp_votes.c.team_name,
            beach_mvp_votes.c.jersey_number,
            beach_mvp_votes.c.photo_url,
        )
        .order_by(beach_mvp_votes.c.vote_type, func.count(beach_mvp_votes.c.id).desc())
    )

    result: Dict[str, List[Dict[str, Any]]] = {"mvp": [], "goalkeeper": []}
    for r in rows:
        vtype = r["vote_type"]
        if vtype not in result:
            continue
        result[vtype].append({
            "player_id": r["player_id"],
            "custom_player_id": r["custom_player_id"],
            "player_name": r["player_name"],
            "team_name": r["team_name"],
            "jersey_number": r["jersey_number"],
            "photo_url": r["photo_url"],
            "count": r["count"],
        })
    return result


async def _get_my_votes(tournament_id: int, voter_user_id: int) -> Dict[str, Any]:
    """Return this user's votes for the tournament (one per type or null)."""
    rows = await database.fetch_all(
        select(
            beach_mvp_votes.c.vote_type,
            beach_mvp_votes.c.player_id,
            beach_mvp_votes.c.custom_player_id,
            beach_mvp_votes.c.player_name,
            beach_mvp_votes.c.team_name,
            beach_mvp_votes.c.jersey_number,
            beach_mvp_votes.c.photo_url,
        )
        .where(
            and_(
                beach_mvp_votes.c.tournament_id == tournament_id,
                beach_mvp_votes.c.voter_user_id == voter_user_id,
            )
        )
    )
    my: Dict[str, Any] = {"mvp": None, "goalkeeper": None}
    for r in rows:
        vtype = r["vote_type"]
        if vtype in my:
            my[vtype] = {
                "player_id": r["player_id"],
                "custom_player_id": r["custom_player_id"],
                "player_name": r["player_name"],
                "team_name": r["team_name"],
                "jersey_number": r["jersey_number"],
                "photo_url": r["photo_url"],
            }
    return my


async def _build_response(tournament_id: int, voter_user_id: int) -> Dict[str, Any]:
    tallies = await _get_tallies(tournament_id)
    my_votes = await _get_my_votes(tournament_id, voter_user_id)
    return {**tallies, "my_votes": my_votes}


# ─────────────────── Endpoints ───────────────────

@router.get(
    "/{tournament_id}",
    summary="Pobierz wyniki głosowania MVP dla turnieju",
)
async def get_mvp_votes(
    tournament_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    return await _build_response(tournament_id, current_user_id)


@router.post(
    "/{tournament_id}/vote",
    summary="Oddaj lub zmień głos (MVP lub bramkarz)",
)
async def cast_mvp_vote(
    tournament_id: int,
    body: CastVoteRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if body.vote_type not in VALID_VOTE_TYPES:
        raise HTTPException(400, f"vote_type musi być jednym z: {VALID_VOTE_TYPES}")
    if body.player_id is None and not body.custom_player_id:
        raise HTTPException(400, "Wymagane player_id lub custom_player_id")
    if body.player_id is not None and body.custom_player_id:
        raise HTTPException(400, "Podaj tylko player_id lub custom_player_id, nie oba")
    if not body.player_name.strip():
        raise HTTPException(400, "player_name nie może być pusty")

    # Upsert: DELETE existing vote of this type then INSERT new
    await database.execute(
        delete(beach_mvp_votes).where(
            and_(
                beach_mvp_votes.c.tournament_id == tournament_id,
                beach_mvp_votes.c.voter_user_id == current_user_id,
                beach_mvp_votes.c.vote_type == body.vote_type,
            )
        )
    )
    await database.execute(
        insert(beach_mvp_votes).values(
            tournament_id=tournament_id,
            voter_user_id=current_user_id,
            vote_type=body.vote_type,
            player_id=body.player_id,
            custom_player_id=body.custom_player_id or None,
            player_name=body.player_name.strip(),
            team_name=body.team_name.strip(),
            jersey_number=body.jersey_number or None,
            photo_url=body.photo_url or None,
        )
    )

    actor_name = await get_actor_name(current_user_id)
    await log_activity(
        area="tournament",
        action="tournament.mvp_vote",
        actor_user_id=current_user_id,
        actor_name=actor_name,
        target_id=str(tournament_id),
        target_label=None,
        details={
            "vote_type": body.vote_type,
            "player_name": body.player_name.strip(),
            "team_name": body.team_name.strip(),
        },
    )

    return await _build_response(tournament_id, current_user_id)


@router.delete(
    "/{tournament_id}/vote/{vote_type}",
    summary="Cofnij głos (MVP lub bramkarz)",
)
async def revoke_mvp_vote(
    tournament_id: int,
    vote_type: str,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if vote_type not in VALID_VOTE_TYPES:
        raise HTTPException(400, f"vote_type musi być jednym z: {VALID_VOTE_TYPES}")

    result = await database.execute(
        delete(beach_mvp_votes).where(
            and_(
                beach_mvp_votes.c.tournament_id == tournament_id,
                beach_mvp_votes.c.voter_user_id == current_user_id,
                beach_mvp_votes.c.vote_type == vote_type,
            )
        )
    )
    if not result:
        raise HTTPException(404, "Nie znaleziono głosu do usunięcia")

    return await _build_response(tournament_id, current_user_id)

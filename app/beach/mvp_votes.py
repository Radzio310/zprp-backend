from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, insert, delete, func, and_

from app.db import database, beach_mvp_votes
from app.deps import beach_get_current_user_id
from app.beach.activity_log import log_activity, get_actor_name

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/beach/mvp-votes", tags=["Beach: MVP Votes"])

VALID_BASE_TYPES = {"mvp", "goalkeeper"}
VALID_GENDERS = {"M", "K"}

def _effective_vote_type(base_type: str, gender: Optional[str]) -> str:
    """Combines base_type + optional gender into the stored vote_type key."""
    if gender and gender in VALID_GENDERS:
        return f"{base_type}_{gender}"
    return base_type


# ─────────────────── Pydantic models ───────────────────

class CastVoteRequest(BaseModel):
    vote_type: str                      # "mvp" | "goalkeeper"
    gender: Optional[str] = None        # "M" | "K" | null (for multi-gender tournaments)
    player_id: Optional[int] = None     # null dla custom team playerów
    custom_player_id: Optional[str] = None  # "ct_<uuid>:<player_uuid>"
    player_name: str
    team_name: str
    jersey_number: Optional[str] = None
    photo_url: Optional[str] = None


# ─────────────────── Helpers ───────────────────

def _entry_dict(r: Any, include_count: bool = True) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "player_id": r["player_id"],
        "custom_player_id": r["custom_player_id"],
        "player_name": r["player_name"],
        "team_name": r["team_name"],
        "jersey_number": r["jersey_number"],
        "photo_url": r["photo_url"],
    }
    if include_count:
        d["count"] = r["count"]
    return d


async def _get_tallies(tournament_id: int) -> Dict[str, List[Dict[str, Any]]]:
    """Return vote tallies grouped by vote_type, sorted by count DESC.

    Supports both legacy (vote_type="mvp") and gender-aware (vote_type="mvp_M")
    stored values.  The combined "mvp" / "goalkeeper" lists are built by merging
    all matching rows regardless of gender suffix.
    """
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

    result: Dict[str, List[Dict[str, Any]]] = {
        "mvp": [], "goalkeeper": [],
        "mvp_M": [], "mvp_K": [],
        "goalkeeper_M": [], "goalkeeper_K": [],
    }
    for r in rows:
        vtype = r["vote_type"]
        entry = _entry_dict(r)
        if vtype in result:
            result[vtype].append(entry)
        base = vtype.split("_")[0]  # "mvp" from "mvp_M"
        if base != vtype and base in result:
            # Gender-specific vote → also add to combined list
            result[base].append(entry)
        else:
            # Old non-gendered vote ("mvp"/"goalkeeper") → show in ALL gender tabs
            # until the user re-casts it with a gender selected
            for suffix in ("_M", "_K"):
                gk = f"{base}{suffix}"
                if gk in result:
                    result[gk].append(entry)

    # Re-sort combined lists by count desc (may be out of order after merging)
    for base in ("mvp", "goalkeeper"):
        result[base].sort(key=lambda x: -x["count"])

    return result


async def _get_my_votes(tournament_id: int, voter_user_id: int) -> Dict[str, Any]:
    """Return this user's votes for the tournament (one per effective vote_type or null).

    Supports both legacy and gender-aware vote_type values.
    """
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
    my: Dict[str, Any] = {
        "mvp": None, "goalkeeper": None,
        "mvp_M": None, "mvp_K": None,
        "goalkeeper_M": None, "goalkeeper_K": None,
    }
    for r in rows:
        vtype = r["vote_type"]
        entry = _entry_dict(r, include_count=False)
        if vtype in my:
            my[vtype] = entry
        base = vtype.split("_")[0]
        if base != vtype and base in my and my[base] is None:
            # Gender-specific vote → mirror into combined key
            my[base] = entry
        elif base == vtype:
            # Old non-gendered vote → show in all gender-specific slots
            for suffix in ("_M", "_K"):
                gk = f"{base}{suffix}"
                if gk in my and my[gk] is None:
                    my[gk] = entry
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
    if body.vote_type not in VALID_BASE_TYPES:
        raise HTTPException(400, f"vote_type musi być jednym z: {VALID_BASE_TYPES}")
    if body.gender is not None and body.gender not in VALID_GENDERS:
        raise HTTPException(400, f"gender musi być jednym z: {VALID_GENDERS}")
    if body.player_id is None and not body.custom_player_id:
        raise HTTPException(400, "Wymagane player_id lub custom_player_id")
    if body.player_id is not None and body.custom_player_id:
        raise HTTPException(400, "Podaj tylko player_id lub custom_player_id, nie oba")
    if not body.player_name.strip():
        raise HTTPException(400, "player_name nie może być pusty")

    effective_type = _effective_vote_type(body.vote_type, body.gender)

    # Delete the effective type first (upsert)
    await database.execute(
        delete(beach_mvp_votes).where(
            and_(
                beach_mvp_votes.c.tournament_id == tournament_id,
                beach_mvp_votes.c.voter_user_id == current_user_id,
                beach_mvp_votes.c.vote_type == effective_type,
            )
        )
    )
    # Also remove any old non-gendered vote for this base type (migration cleanup)
    if effective_type != body.vote_type:
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
            vote_type=effective_type,
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
            "vote_type": effective_type,
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
    gender: Optional[str] = Query(default=None),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if vote_type not in VALID_BASE_TYPES:
        raise HTTPException(400, f"vote_type musi być jednym z: {VALID_BASE_TYPES}")
    if gender is not None and gender not in VALID_GENDERS:
        raise HTTPException(400, f"gender musi być jednym z: {VALID_GENDERS}")

    effective_type = _effective_vote_type(vote_type, gender)

    result = await database.execute(
        delete(beach_mvp_votes).where(
            and_(
                beach_mvp_votes.c.tournament_id == tournament_id,
                beach_mvp_votes.c.voter_user_id == current_user_id,
                beach_mvp_votes.c.vote_type == effective_type,
            )
        )
    )
    if not result:
        raise HTTPException(404, "Nie znaleziono głosu do usunięcia")

    return await _build_response(tournament_id, current_user_id)

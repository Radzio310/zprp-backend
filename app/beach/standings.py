"""
beach/standings.py — tabela ligowa turniejów plażowych.

Endpointy:
  GET  /beach/standings/                     — lista standings z filtrami
  GET  /beach/standings/competition-types    — distinct competition_types
  GET  /beach/standings/seasons              — distinct season_ids
  POST /beach/standings/preview-tournament   — podgląd punktów (bez zapisu)
  POST /beach/standings/grant-tournament     — przyznanie punktów za turniej
  POST /beach/standings/revoke-tournament    — cofnięcie punktów za turniej
  PATCH /beach/standings/adjust              — manualna korekta (+/-)

Punktacja: (teams_count - position + 1) × 10
Obliczana osobno dla każdej płci (M/K).
"""
from __future__ import annotations

import asyncio
import json
import logging
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, insert, update

from app.db import database, beach_standings, beach_tournaments, beach_users, beach_admins
from app.deps import beach_get_current_user_id
from app.beach.activity_log import log_activity, get_actor_name
from app.beach.notifications import create_notification
from app.schemas import (
    AdjustStandingRequest,
    BeachStandingPreviewEntry,
    BeachStandingPreviewResponse,
    BeachStandingRow,
    BeachStandingsListResponse,
    GrantTournamentRequest,
    RevokeTournamentRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/beach/standings", tags=["Beach: Standings"])


# ─────────────────── helpers ───────────────────

def _parse_json(raw: Any) -> Any:
    if raw is None:
        return []
    if isinstance(raw, (list, dict)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return []


async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    return bool(row)


async def _extract_badge_names(user_id: int) -> set:
    row = await database.fetch_one(
        select(beach_users.c.badges).where(beach_users.c.id == user_id)
    )
    if not row:
        return set()
    badges_raw = row["badges"]
    if isinstance(badges_raw, dict):
        return {str(k) for k, v in badges_raw.items() if v}
    if isinstance(badges_raw, list):
        return {str(x) for x in badges_raw if x}
    return set()


async def _check_komisja_or_admin(user_id: int) -> None:
    """Raises HTTPException 403 if user is neither admin nor has 'Komisja' badge."""
    if await _is_admin(user_id):
        return
    badges = await _extract_badge_names(user_id)
    if "Komisja" not in badges:
        raise HTTPException(403, "Wymagany badge: Komisja lub uprawnienia admina")


def _compute_total_points(entries: List[Dict], top_n: int = 0) -> int:
    """
    Oblicza sumę punktów:
    - top_n > 0: bierze tylko top_n najlepszych turniejowych wpisów
    - manual korekty zawsze doliczane
    - revoked turnieje ignorowane
    """
    tournament_pts: List[int] = []
    manual_pts: int = 0

    for e in entries:
        if e.get("type") == "tournament" and not e.get("revoked", False):
            tournament_pts.append(int(e.get("points", 0)))
        elif e.get("type") == "manual":
            manual_pts += int(e.get("points", 0))

    if top_n > 0 and len(tournament_pts) > top_n:
        tournament_pts.sort(reverse=True)
        tournament_pts = tournament_pts[:top_n]

    return sum(tournament_pts) + manual_pts


def _compute_positions_from_schedule(
    schedule: Dict, gender: str
) -> List[Dict[str, Any]]:
    """
    Oblicza pozycje drużyn dla danej płci z harmonogramu turnieju.
    Zwraca listę: [{team_id, team_name, position, teams_count}]
    posortowaną od 1. miejsca.
    """
    matches = schedule.get("matches") or []
    config = schedule.get("config") or {}
    mode = config.get("mode", "roundRobin")

    gender_matches = [m for m in matches if m.get("gender") == gender]
    if not gender_matches:
        return []

    # Zbierz wszystkie drużyny tej płci
    teams: Dict[int, str] = {}
    for m in gender_matches:
        ta = m.get("teamA")
        tb = m.get("teamB")
        if ta and isinstance(ta.get("id"), int):
            teams[ta["id"]] = ta.get("name", f"#{ta['id']}")
        if tb and isinstance(tb.get("id"), int):
            teams[tb["id"]] = tb.get("name", f"#{tb['id']}")

    if not teams:
        return []

    teams_count = len(teams)

    # Tryb: groupsPlusKnockout — pozycje z meczów finałowych
    if mode == "groupsPlusKnockout":
        return _positions_from_knockout(gender_matches, teams, teams_count)

    # Tryb: roundRobin
    return _positions_from_round_robin(gender_matches, teams, teams_count)


def _positions_from_knockout(
    matches: List[Dict],
    teams: Dict[int, str],
    teams_count: int,
) -> List[Dict[str, Any]]:
    """
    Oblicza pozycje na podstawie meczów finałowych, barażów i tabel o miejsca.
    Obsługuje: final, third_place, fifth_place, seventh_place,
    ninth_place, eleventh_place, thirteenth_place, fifteenth_place,
    playoff tables (baraże), placement_rr tables.
    """
    # Direct knockout matches → winner gets lower position, loser gets higher
    stage_to_positions: Dict[str, List[int]] = {
        "final": [1, 2],
        "third_place": [3, 4],
        "fifth_place": [5, 6],
        "seventh_place": [7, 8],
        "ninth_place": [9, 10],
        "eleventh_place": [11, 12],
        "thirteenth_place": [13, 14],
        "fifteenth_place": [15, 16],
    }

    assigned: Dict[int, int] = {}  # team_id → position

    for stage, positions in stage_to_positions.items():
        m = next((x for x in matches if x.get("stage") == stage), None)
        if not m:
            continue
        ta = m.get("teamA")
        tb = m.get("teamB")
        if not ta or not tb:
            continue
        ta_id = ta.get("id")
        tb_id = tb.get("id")
        if not isinstance(ta_id, int) or not isinstance(tb_id, int):
            continue
        score_a = m.get("scoreA")
        score_b = m.get("scoreB")
        if score_a is None or score_b is None:
            continue
        if score_a >= score_b:
            winner_id, loser_id = ta_id, tb_id
        else:
            winner_id, loser_id = tb_id, ta_id
        assigned[winner_id] = positions[0]
        assigned[loser_id] = positions[1]

    # Playoff (baraż) tables — e.g. playoff_2_M: positions based on table order
    # Find all playoff groups present
    playoff_groups = {}
    for m in matches:
        if m.get("stage") == "playoff" and m.get("group"):
            pg = m["group"]
            if pg not in playoff_groups:
                playoff_groups[pg] = []
            playoff_groups[pg].append(m)

    for pg, pg_matches in sorted(playoff_groups.items()):
        # Determine starting position: teams in this playoff that are NOT
        # already assigned from knockout matches get positions after assigned ones
        table = _compute_mini_table(pg_matches)
        # Find what position this playoff feeds into
        # Already-assigned teams from this playoff get skipped
        unassigned_rows = [r for r in table if r["team_id"] not in assigned]
        if not unassigned_rows:
            continue
        # Starting position = lowest unoccupied position after all assigned
        start_pos = max(assigned.values(), default=0) + 1
        for r in unassigned_rows:
            assigned[r["team_id"]] = start_pos
            start_pos += 1

    # Placement RR tables — e.g. placement_7_K: positions from table order
    placement_groups = {}
    for m in matches:
        if m.get("stage") == "placement_rr" and m.get("group"):
            pg = m["group"]
            if pg not in placement_groups:
                placement_groups[pg] = []
            placement_groups[pg].append(m)

    for pg, pg_matches in sorted(placement_groups.items()):
        # Extract tier number from group name (placement_7_K → 7)
        import re
        tier_m = re.match(r"placement_(\d+)", pg)
        tier_start = int(tier_m.group(1)) if tier_m else (max(assigned.values(), default=0) + 1)
        table = _compute_mini_table(pg_matches)
        pos = tier_start
        for r in table:
            if r["team_id"] not in assigned:
                assigned[r["team_id"]] = pos
            pos += 1

    # Remaining unassigned teams → positions from the end
    unassigned = [tid for tid in teams if tid not in assigned]
    if unassigned:
        next_pos = max(assigned.values(), default=0) + 1
        for tid in sorted(unassigned):
            assigned[tid] = next_pos
            next_pos += 1

    result = []
    for team_id, pos in sorted(assigned.items(), key=lambda x: x[1]):
        result.append({
            "team_id": team_id,
            "team_name": teams.get(team_id, f"#{team_id}"),
            "position": pos,
            "teams_count": teams_count,
        })
    return result


def _compute_mini_table(
    matches: List[Dict],
) -> List[Dict[str, Any]]:
    """Compute a mini standings table from a set of round-robin matches.
    Returns list sorted by match points desc, set diff desc, brk diff desc."""
    stats: Dict[int, Dict] = {}

    for m in matches:
        ta = m.get("teamA")
        tb = m.get("teamB")
        if not ta or not tb:
            continue
        ta_id = ta.get("id")
        tb_id = tb.get("id")
        if not isinstance(ta_id, int) or not isinstance(tb_id, int):
            continue
        for tid, tname in [(ta_id, ta.get("name", "")), (tb_id, tb.get("name", ""))]:
            if tid not in stats:
                stats[tid] = {"team_id": tid, "team_name": tname,
                              "pts": 0, "sw": 0, "sl": 0, "brkp": 0, "brkm": 0}

        sa = m.get("scoreA")
        sb = m.get("scoreB")
        if sa is None or sb is None or m.get("status") != "finished":
            continue
        sa, sb = int(sa), int(sb)
        stats[ta_id]["sw"] += sa
        stats[ta_id]["sl"] += sb
        stats[tb_id]["sw"] += sb
        stats[tb_id]["sl"] += sa

        # Beach scoring: Win = 2 pts, Loss = 0 pts (same as groups in beach)
        if sa > sb:
            stats[ta_id]["pts"] += 2
        else:
            stats[tb_id]["pts"] += 2

        for s in (m.get("sets") or []):
            pa = s.get("ptA", 0) or 0
            pb = s.get("ptB", 0) or 0
            stats[ta_id]["brkp"] += pa
            stats[ta_id]["brkm"] += pb
            stats[tb_id]["brkp"] += pb
            stats[tb_id]["brkm"] += pa

    return sorted(
        stats.values(),
        key=lambda r: (r["pts"], r["sw"] - r["sl"], r["brkp"] - r["brkm"]),
        reverse=True,
    )


def _positions_from_round_robin(
    matches: List[Dict],
    teams: Dict[int, str],
    teams_count: int,
) -> List[Dict[str, Any]]:
    """
    Oblicza tabelę round-robin.
    Sortowanie: matchPoints → setsWon → setsLost → pointsFor → pointsAgainst.
    matchPoints: 3/2/1/0 (2:0 win=3, 2:1 win=2, 1:2 loss=1, 0:2 loss=0)
    """
    stats: Dict[int, Dict] = {
        tid: {
            "team_name": name,
            "match_pts": 0,
            "sets_won": 0,
            "sets_lost": 0,
            "pts_for": 0,
            "pts_against": 0,
        }
        for tid, name in teams.items()
    }

    for m in matches:
        status = m.get("status")
        score_a = m.get("scoreA")
        score_b = m.get("scoreB")
        ta = m.get("teamA")
        tb = m.get("teamB")
        if status != "finished" or score_a is None or score_b is None:
            continue
        if not ta or not tb:
            continue
        ta_id = ta.get("id")
        tb_id = tb.get("id")
        if not isinstance(ta_id, int) or not isinstance(tb_id, int):
            continue
        if ta_id not in stats or tb_id not in stats:
            continue

        sa, sb = int(score_a), int(score_b)

        stats[ta_id]["sets_won"] += sa
        stats[ta_id]["sets_lost"] += sb
        stats[tb_id]["sets_won"] += sb
        stats[tb_id]["sets_lost"] += sa

        # match points
        if sa > sb:
            stats[ta_id]["match_pts"] += 3 if sb == 0 else 2
            stats[tb_id]["match_pts"] += 0 if sb == 0 else 1
        else:
            stats[tb_id]["match_pts"] += 3 if sa == 0 else 2
            stats[ta_id]["match_pts"] += 0 if sa == 0 else 1

        # point breakdown from sets
        sets_data = m.get("sets") or []
        for s in sets_data:
            pa = s.get("scoreA", 0) or 0
            pb = s.get("scoreB", 0) or 0
            stats[ta_id]["pts_for"] += pa
            stats[ta_id]["pts_against"] += pb
            stats[tb_id]["pts_for"] += pb
            stats[tb_id]["pts_against"] += pa

    sorted_teams = sorted(
        stats.items(),
        key=lambda x: (
            -x[1]["match_pts"],
            -x[1]["sets_won"],
            x[1]["sets_lost"],
            -x[1]["pts_for"],
            x[1]["pts_against"],
        ),
    )

    result = []
    for pos, (team_id, s) in enumerate(sorted_teams, start=1):
        result.append({
            "team_id": team_id,
            "team_name": s["team_name"],
            "position": pos,
            "teams_count": teams_count,
        })
    return result


def _all_finished(schedule: Dict, gender: Optional[str] = None) -> bool:
    """Zwraca True gdy wszystkie mecze (danej płci) są zakończone."""
    matches = schedule.get("matches") or []
    if gender:
        matches = [m for m in matches if m.get("gender") == gender]
    for m in matches:
        finished = m.get("status") == "finished"
        has_score = m.get("scoreA") is not None and m.get("scoreB") is not None
        if not finished and not has_score:
            return False
    return True


def _compute_row_total(row_d: Dict, top_n: int = 3) -> int:
    entries = _parse_json(row_d.get("tournaments_json") or [])
    if not isinstance(entries, list):
        entries = []
    return _compute_total_points(entries, top_n)


# ─────────────────── GET /beach/standings/ ───────────────────

@router.get(
    "/",
    response_model=BeachStandingsListResponse,
    summary="Lista tabeli ligowej z filtrami",
)
async def list_standings(
    competition_type: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    season_id: Optional[str] = Query(None),
    gender: Optional[str] = Query(None),
    top_n: int = Query(3, ge=0, le=50),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    q = select(beach_standings)
    if competition_type:
        q = q.where(beach_standings.c.competition_type == competition_type)
    if category:
        q = q.where(beach_standings.c.category == category)
    if season_id:
        q = q.where(beach_standings.c.season_id == season_id)
    if gender:
        q = q.where(beach_standings.c.gender == gender)

    q = q.order_by(beach_standings.c.team_name.asc())
    rows = await database.fetch_all(q)

    out: List[BeachStandingRow] = []
    for r in rows:
        r_d = dict(r)
        entries = _parse_json(r_d.get("tournaments_json") or [])
        if not isinstance(entries, list):
            entries = []
        total = _compute_total_points(entries, top_n)
        out.append(
            BeachStandingRow(
                id=r_d["id"],
                team_id=r_d["team_id"],
                team_name=r_d["team_name"],
                gender=r_d["gender"],
                competition_type=r_d["competition_type"],
                category=r_d["category"],
                season_id=r_d["season_id"],
                tournaments_json=entries,
                updated_at=r_d["updated_at"],
                total_points=total,
            )
        )

    # Sortuj po total_points malejąco (po zebraniu danych)
    out.sort(key=lambda x: -x.total_points)
    return BeachStandingsListResponse(rows=out)


# ─────────────────── GET /beach/standings/competition-types ───────────────────

@router.get(
    "/competition-types",
    response_model=dict,
    summary="Distinct competition_types istniejące w standings",
)
async def list_competition_types(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    from sqlalchemy import distinct
    rows = await database.fetch_all(
        select(distinct(beach_standings.c.competition_type)).order_by(
            beach_standings.c.competition_type.asc()
        )
    )
    types = [r[0] for r in rows if r[0]]
    return {"competition_types": types}


# ─────────────────── GET /beach/standings/seasons ───────────────────

@router.get(
    "/seasons",
    response_model=dict,
    summary="Distinct season_ids istniejące w standings",
)
async def list_seasons(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    from sqlalchemy import distinct
    rows = await database.fetch_all(
        select(distinct(beach_standings.c.season_id)).order_by(
            beach_standings.c.season_id.desc()
        )
    )
    seasons = [r[0] for r in rows if r[0]]
    return {"seasons": seasons}


# ─────────────────── POST /beach/standings/preview-tournament ───────────────────

@router.post(
    "/preview-tournament",
    response_model=BeachStandingPreviewResponse,
    summary="Podgląd punktów za turniej (bez zapisu)",
)
async def preview_tournament(
    body: GrantTournamentRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    await _check_komisja_or_admin(current_user_id)

    tour_row = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == body.tournament_id)
    )
    if not tour_row:
        raise HTTPException(404, "Turniej nie znaleziony")

    tour_d = dict(tour_row)
    data_json = tour_d.get("data_json") or {}
    if isinstance(data_json, str):
        try:
            data_json = json.loads(data_json)
        except Exception:
            data_json = {}
    schedule = data_json.get("schedule") or {}

    all_done = _all_finished(schedule)

    def _build_preview(gender: str) -> List[BeachStandingPreviewEntry]:
        positions = _compute_positions_from_schedule(schedule, gender)
        result = []
        for p in positions:
            pts = (p["teams_count"] - p["position"] + 1) * 10
            # sprawdź czy już rozliczony
            already = False
            existing = database._query_result_cache = None  # reset
            result.append(
                BeachStandingPreviewEntry(
                    team_id=p["team_id"],
                    team_name=p["team_name"],
                    position=p["position"],
                    teams_count=p["teams_count"],
                    points=pts,
                    already_granted=False,  # sprawdzimy poniżej
                )
            )
        return result

    men_preview = _build_preview("M")
    women_preview = _build_preview("K")

    # Sprawdź które drużyny mają już wpis za ten turniej
    all_team_ids = {e.team_id for e in men_preview} | {e.team_id for e in women_preview}
    if all_team_ids:
        existing_rows = await database.fetch_all(
            select(beach_standings).where(
                beach_standings.c.competition_type == body.competition_type,
                beach_standings.c.category == body.category,
                beach_standings.c.season_id == body.season_id,
                beach_standings.c.team_id.in_(list(all_team_ids)),
            )
        )
        granted_teams: set = set()
        for er in existing_rows:
            er_d = dict(er)
            entries = _parse_json(er_d.get("tournaments_json") or [])
            if not isinstance(entries, list):
                continue
            for e in entries:
                if (
                    e.get("type") == "tournament"
                    and e.get("tournament_id") == body.tournament_id
                    and not e.get("revoked", False)
                ):
                    granted_teams.add(f"{er_d['team_id']}_{er_d['gender']}")

        for entry in men_preview:
            entry.already_granted = f"{entry.team_id}_M" in granted_teams
        for entry in women_preview:
            entry.already_granted = f"{entry.team_id}_K" in granted_teams

    date_str = tour_d.get("event_date", "")
    if hasattr(date_str, "isoformat"):
        date_str = date_str.isoformat()[:10]
    elif isinstance(date_str, str):
        date_str = date_str[:10]

    return BeachStandingPreviewResponse(
        tournament_id=body.tournament_id,
        tournament_name=tour_d.get("name", ""),
        date=date_str,
        men=men_preview,
        women=women_preview,
        all_finished=all_done,
        men_count=len(men_preview),
        women_count=len(women_preview),
    )


# ─────────────────── POST /beach/standings/grant-tournament ───────────────────

@router.post(
    "/grant-tournament",
    response_model=dict,
    summary="Przyznanie punktów za turniej",
)
async def grant_tournament(
    body: GrantTournamentRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    await _check_komisja_or_admin(current_user_id)

    tour_row = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == body.tournament_id)
    )
    if not tour_row:
        raise HTTPException(404, "Turniej nie znaleziony")

    tour_d = dict(tour_row)
    data_json = tour_d.get("data_json") or {}
    if isinstance(data_json, str):
        try:
            data_json = json.loads(data_json)
        except Exception:
            data_json = {}
    schedule = data_json.get("schedule") or {}

    if not _all_finished(schedule):
        raise HTTPException(400, "Nie wszystkie mecze w turnieju są zakończone")

    date_str = tour_d.get("event_date", "")
    if hasattr(date_str, "isoformat"):
        date_str = date_str.isoformat()[:10]
    elif isinstance(date_str, str):
        date_str = date_str[:10]

    tour_name = tour_d.get("name", "")
    now = datetime.now(timezone.utc)
    granted_count = 0

    for gender in ("M", "K"):
        positions = _compute_positions_from_schedule(schedule, gender)
        if not positions:
            continue

        for p in positions:
            team_id = p["team_id"]
            team_name = p["team_name"]
            position = p["position"]
            teams_count = p["teams_count"]
            points = (teams_count - position + 1) * 10

            # Pobierz lub utwórz wiersz standings
            existing = await database.fetch_one(
                select(beach_standings).where(
                    beach_standings.c.team_id == team_id,
                    beach_standings.c.competition_type == body.competition_type,
                    beach_standings.c.category == body.category,
                    beach_standings.c.season_id == body.season_id,
                    beach_standings.c.gender == gender,
                )
            )

            new_entry = {
                "type": "tournament",
                "tournament_id": body.tournament_id,
                "tournament_name": tour_name,
                "date": date_str,
                "position": position,
                "teams_count": teams_count,
                "points": points,
                "revoked": False,
            }

            if existing:
                ex_d = dict(existing)
                entries = _parse_json(ex_d.get("tournaments_json") or [])
                if not isinstance(entries, list):
                    entries = []

                # Usuń poprzedni wpis za ten turniej (jeśli był)
                entries = [
                    e for e in entries
                    if not (e.get("type") == "tournament" and e.get("tournament_id") == body.tournament_id)
                ]
                entries.append(new_entry)
                await database.execute(
                    update(beach_standings)
                    .where(beach_standings.c.id == ex_d["id"])
                    .values(tournaments_json=entries, updated_at=now)
                )
            else:
                await database.execute(
                    insert(beach_standings).values(
                        team_id=team_id,
                        team_name=team_name,
                        gender=gender,
                        competition_type=body.competition_type,
                        category=body.category,
                        season_id=body.season_id,
                        tournaments_json=[new_entry],
                        updated_at=now,
                    )
                )

            granted_count += 1

    # Notify tournament participants about points
    if granted_count > 0:
        await _notify_points_awarded(body.tournament_id, tour_name)
        asyncio.ensure_future(
            _notify_tournament_ended_other(body.tournament_id, tour_name)
        )

    # ── Activity log ──
    await log_activity(area="standings", action="standings.points_granted", actor_user_id=current_user_id, actor_name=await get_actor_name(current_user_id), target_id=str(body.tournament_id), target_label=tour_name, details={"granted_count": granted_count})

    return {"success": True, "granted_count": granted_count}


async def _notify_points_awarded(tournament_id: int, tour_name: str):
    """Notify all invited users of a tournament that points were awarded."""
    tour_row = await database.fetch_one(
        select(beach_tournaments.c.data_json).where(beach_tournaments.c.id == tournament_id)
    )
    if not tour_row:
        return
    data_json = tour_row["data_json"] or {}
    if isinstance(data_json, str):
        try:
            data_json = json.loads(data_json)
        except Exception:
            return
    invited = data_json.get("invited_ids") or []
    target_ids = [int(uid) for uid in invited if uid is not None]
    if not target_ids:
        return
    await create_notification(
        notif_type="points_awarded",
        title="🏅 Przyznano punkty rankingowe!",
        body=f"🏆 {tour_name}\nTwoje wyniki z tego turnieju zostały zatwierdzone.",
        data={"tournament_id": tournament_id},
        target_user_ids=target_ids,
    )


async def _notify_tournament_ended_other(tournament_id: int, tour_name: str):
    """Notify all active users NOT in the tournament that it has ended and points were given."""
    try:
        tour_row = await database.fetch_one(
            select(beach_tournaments.c.data_json).where(beach_tournaments.c.id == tournament_id)
        )
        if not tour_row:
            return
        data_json = tour_row["data_json"] or {}
        if isinstance(data_json, str):
            try:
                data_json = json.loads(data_json)
            except Exception:
                return
        invited = data_json.get("invited_ids") or []
        invited_set = {int(uid) for uid in invited if uid is not None}

        all_rows = await database.fetch_all(
            select(beach_users.c.id).where(beach_users.c.is_active == True)  # noqa: E712
        )
        non_participant_ids = [
            int(r["id"]) for r in all_rows if int(r["id"]) not in invited_set
        ]
        if not non_participant_ids:
            return

        await create_notification(
            notif_type="tournament_ended_other",
            title="🏁 Turniej zakończony",
            body=f"🏆 {tour_name}\nZaktualizowano wyniki — sprawdź ranking!",
            data={"tournament_id": tournament_id},
            target_user_ids=non_participant_ids,
        )
    except Exception as e:
        logger.error(f"_notify_tournament_ended_other error: {e}")


# ─────────────────── POST /beach/standings/revoke-tournament ───────────────────

@router.post(
    "/revoke-tournament",
    response_model=dict,
    summary="Cofnięcie punktów za turniej (ustawia revoked=True)",
)
async def revoke_tournament(
    body: RevokeTournamentRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    await _check_komisja_or_admin(current_user_id)

    rows = await database.fetch_all(
        select(beach_standings).where(
            beach_standings.c.competition_type == body.competition_type,
            beach_standings.c.category == body.category,
            beach_standings.c.season_id == body.season_id,
        )
    )

    revoked_count = 0
    now = datetime.now(timezone.utc)

    for r in rows:
        r_d = dict(r)
        entries = _parse_json(r_d.get("tournaments_json") or [])
        if not isinstance(entries, list):
            continue

        changed = False
        for e in entries:
            if (
                e.get("type") == "tournament"
                and e.get("tournament_id") == body.tournament_id
                and not e.get("revoked", False)
            ):
                e["revoked"] = True
                changed = True

        if changed:
            await database.execute(
                update(beach_standings)
                .where(beach_standings.c.id == r_d["id"])
                .values(tournaments_json=entries, updated_at=now)
            )
            revoked_count += 1

    # ── Activity log ──
    await log_activity(area="standings", action="standings.points_revoked", actor_user_id=current_user_id, actor_name=await get_actor_name(current_user_id), target_id=str(body.tournament_id), details={"revoked_count": revoked_count})

    return {"success": True, "revoked_count": revoked_count}


# ─────────────────── PATCH /beach/standings/adjust ───────────────────

@router.patch(
    "/adjust",
    response_model=dict,
    summary="Manualna korekta punktów dla drużyny",
)
async def adjust_standing(
    body: AdjustStandingRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    await _check_komisja_or_admin(current_user_id)

    user_row = await database.fetch_one(
        select(beach_users.c.full_name).where(beach_users.c.id == current_user_id)
    )
    author_name = dict(user_row)["full_name"] if user_row else f"user_{current_user_id}"

    now = datetime.now(timezone.utc)
    manual_entry = {
        "type": "manual",
        "points": body.points,
        "comment": body.comment,
        "created_by_id": current_user_id,
        "created_by_name": author_name,
        "created_at": now.isoformat(),
    }

    existing = await database.fetch_one(
        select(beach_standings).where(
            beach_standings.c.team_id == body.team_id,
            beach_standings.c.competition_type == body.competition_type,
            beach_standings.c.category == body.category,
            beach_standings.c.season_id == body.season_id,
            beach_standings.c.gender == body.gender,
        )
    )

    if existing:
        ex_d = dict(existing)
        entries = _parse_json(ex_d.get("tournaments_json") or [])
        if not isinstance(entries, list):
            entries = []
        entries.append(manual_entry)
        await database.execute(
            update(beach_standings)
            .where(beach_standings.c.id == ex_d["id"])
            .values(tournaments_json=entries, updated_at=now)
        )
    else:
        await database.execute(
            insert(beach_standings).values(
                team_id=body.team_id,
                team_name=body.team_name,
                gender=body.gender,
                competition_type=body.competition_type,
                category=body.category,
                season_id=body.season_id,
                tournaments_json=[manual_entry],
                updated_at=now,
            )
        )

    # ── Activity log ──
    await log_activity(area="standings", action="standings.manual_adjustment", actor_user_id=current_user_id, actor_name=await get_actor_name(current_user_id), target_id=str(body.team_id), details={"points": body.points, "comment": body.comment})

    return {"success": True}


# ─────────────────── DELETE /beach/standings/adjust ───────────────────

@router.delete(
    "/adjust",
    response_model=dict,
    summary="Usuń manualną korektę punktów (po created_at)",
)
async def delete_manual_entry(
    team_id: int = Query(...),
    competition_type: str = Query(...),
    category: str = Query(...),
    season_id: str = Query(...),
    gender: str = Query(...),
    created_at: str = Query(...),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    await _check_komisja_or_admin(current_user_id)

    existing = await database.fetch_one(
        select(beach_standings).where(
            beach_standings.c.team_id == team_id,
            beach_standings.c.competition_type == competition_type,
            beach_standings.c.category == category,
            beach_standings.c.season_id == season_id,
            beach_standings.c.gender == gender,
        )
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Standing not found")

    ex_d = dict(existing)
    entries = _parse_json(ex_d.get("tournaments_json") or [])
    if not isinstance(entries, list):
        entries = []

    new_entries = [
        e for e in entries
        if not (e.get("type") == "manual" and e.get("created_at") == created_at)
    ]
    if len(new_entries) == len(entries):
        raise HTTPException(status_code=404, detail="Manual entry not found")

    now = datetime.now(timezone.utc)
    await database.execute(
        update(beach_standings)
        .where(beach_standings.c.id == ex_d["id"])
        .values(tournaments_json=new_entries, updated_at=now)
    )

    # ── Activity log ──
    await log_activity(area="standings", action="standings.manual_deleted", actor_user_id=current_user_id, actor_name=await get_actor_name(current_user_id), target_id=str(team_id), details={"created_at": created_at})

    return {"success": True}


# ─────────────────── GET /beach/standings/orphan-check ───────────────────

@router.get(
    "/orphan-check",
    response_model=dict,
    summary="Sprawdź osierocone punkty (turnieje usunięte ale punkty zostały) — admin",
)
async def orphan_check(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień admina")

    # Zbierz wszystkie turniej-id wymienione w standings (niezrevokowane)
    all_rows = await database.fetch_all(select(beach_standings))
    tournament_info: dict[int, dict] = {}  # tournament_id -> {name, affected_rows}

    for r in all_rows:
        r_d = dict(r)
        entries = _parse_json(r_d.get("tournaments_json") or [])
        if not isinstance(entries, list):
            continue
        for e in entries:
            if e.get("type") == "tournament" and not e.get("revoked", False):
                tid = e.get("tournament_id")
                tname = e.get("tournament_name", f"Turniej #{tid}")
                if tid is not None:
                    if tid not in tournament_info:
                        tournament_info[tid] = {"name": tname, "affected_rows": 0}
                    tournament_info[tid]["affected_rows"] += 1

    if not tournament_info:
        return {"orphans": []}

    # Sprawdź które z tych turniejów już nie istnieją
    existing_ids_rows = await database.fetch_all(
        select(beach_tournaments.c.id).where(
            beach_tournaments.c.id.in_(list(tournament_info.keys()))
        )
    )
    existing_ids = {r["id"] for r in existing_ids_rows}

    orphans = [
        {
            "tournament_id": tid,
            "tournament_name": info["name"],
            "affected_rows": info["affected_rows"],
        }
        for tid, info in tournament_info.items()
        if tid not in existing_ids
    ]

    return {"orphans": orphans}


# ─────────────────── DELETE /beach/standings/orphan/{tournament_id} ───────────────────

@router.delete(
    "/orphan/{tournament_id}",
    response_model=dict,
    summary="Usuń osierocone punkty za nieistniejący turniej — admin",
)
async def purge_orphaned_tournament(
    tournament_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień admina")

    all_rows = await database.fetch_all(select(beach_standings))
    now = datetime.now(timezone.utc)
    revoked_count = 0

    for r in all_rows:
        r_d = dict(r)
        entries = _parse_json(r_d.get("tournaments_json") or [])
        if not isinstance(entries, list):
            continue
        changed = False
        for e in entries:
            if (
                e.get("type") == "tournament"
                and e.get("tournament_id") == tournament_id
                and not e.get("revoked", False)
            ):
                e["revoked"] = True
                changed = True
        if changed:
            await database.execute(
                update(beach_standings)
                .where(beach_standings.c.id == r_d["id"])
                .values(tournaments_json=entries, updated_at=now)
            )
            revoked_count += 1

    # ── Activity log ──
    await log_activity(area="standings", action="standings.orphan_purged", actor_user_id=current_user_id, actor_name=await get_actor_name(current_user_id), target_id=str(tournament_id), details={"revoked_count": revoked_count})

    return {"success": True, "revoked_count": revoked_count}

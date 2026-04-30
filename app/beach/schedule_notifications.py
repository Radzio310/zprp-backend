"""
Beach Schedule Notifications

Called on every schedule-update (schedule_update_tournament endpoint).
Compares old vs new schedule and fires:

  1. new_match_my_team   — for every match where a team is newly assigned
                           (new match or TBD → known team change)
                           → in-app notification + 30-min push scheduled
  2. new_match_as_judge  — when a referee (fieldA/B/table) is newly assigned
                           to a specific match (more precise than tournament-level)
                           → in-app notification + 30-min push scheduled
  3. match_reminder_30min push — FCM push to device_ids of every concerned user,
                                  scheduled 30 min before match start
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import insert, select

from app.db import database, beach_users, push_schedules
from app.beach.notifications import create_notification

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────

def _parse_match_datetime(
    match: Dict[str, Any],
    days_config: List[Dict[str, Any]],
) -> Optional[datetime]:
    """Compute UTC datetime for a match from dayIndex + startTime + date."""
    day_index = match.get("dayIndex")
    start_time = match.get("startTime")
    if day_index is None or not start_time:
        return None
    try:
        if day_index >= len(days_config):
            return None
        day_cfg = days_config[day_index]
        date_str = day_cfg.get("date")
        if not date_str:
            return None
        hh, mm = start_time.split(":")
        y, mo, d = [int(x) for x in date_str.split("-")]
        return datetime(y, mo, d, int(hh), int(mm), 0, tzinfo=timezone.utc)
    except Exception:
        return None


def _extract_referee_user_ids(match: Dict[str, Any]) -> Set[int]:
    """Get all referee user_ids from match.referees."""
    refs = match.get("referees") or {}
    ids: Set[int] = set()
    for key in ("fieldA", "fieldB", "tableSecretary", "tableTimer"):
        r = refs.get(key)
        if isinstance(r, dict) and isinstance(r.get("id"), int):
            ids.add(r["id"])
    return ids


def _extract_team_ids_from_match(match: Dict[str, Any]) -> Set[int]:
    """Get teamA / teamB IDs (only if not TBD)."""
    ids: Set[int] = set()
    for side in ("teamA", "teamB"):
        team = match.get(side)
        if isinstance(team, dict) and isinstance(team.get("id"), int):
            ids.add(team["id"])
    return ids


def _build_match_index(schedule: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Build {match_id: match_dict} from a schedule."""
    if not schedule:
        return {}
    return {m["id"]: m for m in (schedule.get("matches") or []) if m.get("id")}


async def _get_users_for_teams(team_ids: Set[int]) -> List[int]:
    """Find all active beach_users whose approved roles reference any of the team_ids."""
    if not team_ids:
        return []
    rows = await database.fetch_all(
        select(beach_users.c.id, beach_users.c.roles).where(
            beach_users.c.is_active == True  # noqa: E712
        )
    )
    result: List[int] = []
    for row in rows:
        roles_raw = row["roles"] or []
        roles = roles_raw if isinstance(roles_raw, list) else []
        for role in roles:
            if not isinstance(role, dict):
                continue
            if role.get("verified") != "approved":
                continue
            if role.get("type") not in ("player", "coach"):
                continue
            tid = role.get("team_id")
            if isinstance(tid, int) and tid in team_ids:
                result.append(int(row["id"]))
                break
    return result


async def _schedule_match_push(
    *,
    user_ids: List[int],
    match_dt: datetime,
    title: str,
    body: str,
    data: Dict[str, Any],
    notif_type: str,
) -> None:
    """Schedule a push notification 30 min before a match for every user that has devices."""
    send_at = match_dt - timedelta(minutes=30)
    now = datetime.now(timezone.utc)
    if send_at <= now:
        return  # match already starting soon or in the past

    send_hour = int(send_at.timestamp() // 3600)
    push_data = {**data, "notif_type": notif_type}

    rows = await database.fetch_all(
        select(
            beach_users.c.id,
            beach_users.c.device_ids,
            beach_users.c.notification_prefs,
        ).where(beach_users.c.id.in_(user_ids)).where(
            beach_users.c.is_active == True  # noqa: E712
        )
    )

    for row in rows:
        prefs = row["notification_prefs"] or {}
        # Respect user preference; default True (send) if not set
        if not prefs.get(notif_type, True):
            continue
        device_ids: List[str] = list(row["device_ids"] or [])
        for installation_id in device_ids:
            try:
                await database.execute(
                    insert(push_schedules).values(
                        installation_id=installation_id,
                        send_at_utc=send_at,
                        send_hour_utc=send_hour,
                        title=title,
                        body=body,
                        data_json=push_data,
                        status="pending",
                        attempts=0,
                        last_error=None,
                        created_at=now,
                        updated_at=now,
                    )
                )
            except Exception as e:
                logger.warning(f"schedule_match_push: failed for {installation_id}: {e}")


# ──────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────

async def notify_schedule_updated(
    *,
    tournament_id: int,
    tour_name: str,
    old_schedule: Optional[Dict[str, Any]],
    new_schedule: Optional[Dict[str, Any]],
) -> None:
    """
    Public entry-point — call fire-and-forget via asyncio.ensure_future.
    Compares old and new schedule and fires in-app + push notifications.
    """
    try:
        await _notify_inner(
            tournament_id=tournament_id,
            tour_name=tour_name,
            old_schedule=old_schedule,
            new_schedule=new_schedule,
        )
    except Exception as e:
        logger.error(f"notify_schedule_updated error (tournament #{tournament_id}): {e}")


async def _notify_inner(
    *,
    tournament_id: int,
    tour_name: str,
    old_schedule: Optional[Dict[str, Any]],
    new_schedule: Optional[Dict[str, Any]],
) -> None:
    if not new_schedule:
        return

    # Only fire for published schedules
    if new_schedule.get("status") != "published":
        return

    old_index = _build_match_index(old_schedule)
    new_index = _build_match_index(new_schedule)
    days_config: List[Dict[str, Any]] = (
        (new_schedule.get("config") or {}).get("days") or []
    )

    # ── Categorise matches ──────────────────────────────────
    matches_new_teams: List[Dict[str, Any]] = []  # teams newly set / changed
    judge_assignments: List[Tuple[Dict[str, Any], Set[int]]] = []  # (match, new_judge_ids)

    for match_id, match in new_index.items():
        if match.get("status") == "finished":
            continue

        old_match = old_index.get(match_id)

        # --- Team changes ---
        new_team_ids = _extract_team_ids_from_match(match)
        if new_team_ids:
            old_team_ids = _extract_team_ids_from_match(old_match) if old_match else set()
            if new_team_ids != old_team_ids:
                # Brand-new match or TBD → known team resolved
                matches_new_teams.append(match)

        # --- Referee changes ---
        new_judge_ids = _extract_referee_user_ids(match)
        if new_judge_ids:
            old_judge_ids = (
                _extract_referee_user_ids(old_match) if old_match else set()
            )
            newly_added = new_judge_ids - old_judge_ids
            if newly_added:
                judge_assignments.append((match, newly_added))

    # ── 1. new_match_my_team notifications ──────────────────
    if matches_new_teams:
        all_team_ids: Set[int] = set()
        for m in matches_new_teams:
            all_team_ids |= _extract_team_ids_from_match(m)

        team_user_ids = await _get_users_for_teams(all_team_ids)

        if team_user_ids:
            cnt = len(matches_new_teams)
            await create_notification(
                notif_type="new_match_my_team",
                title="Nowy mecz drużyny",
                body=(
                    f"Twoja drużyna ma {cnt} now"
                    + ("e mecze" if 2 <= cnt <= 4 else "ych meczów" if cnt > 4 else "y mecz")
                    + f" w: {tour_name}"
                ),
                data={"tournament_id": tournament_id, "match_count": cnt},
                target_user_ids=team_user_ids,
            )

        # Schedule 30-min push per match, per team
        for match in matches_new_teams:
            match_dt = _parse_match_datetime(match, days_config)
            if not match_dt:
                continue
            match_team_ids = _extract_team_ids_from_match(match)
            match_user_ids = await _get_users_for_teams(match_team_ids)
            if not match_user_ids:
                continue
            ta = match.get("teamA") or {}
            tb = match.get("teamB") or {}
            match_label = f"{ta.get('name', '?')} – {tb.get('name', '?')}"
            start_time = match.get("startTime") or ""
            asyncio.ensure_future(
                _schedule_match_push(
                    user_ids=match_user_ids,
                    match_dt=match_dt,
                    title="Mecz za 30 min",
                    body=f"{match_label} (g. {start_time}) — {tour_name}",
                    data={"tournament_id": tournament_id, "match_id": match["id"]},
                    notif_type="match_reminder_30min",
                )
            )

    # ── 2. new_match_as_judge notifications (per-match) ─────
    for match, newly_assigned_judge_ids in judge_assignments:
        ta = match.get("teamA") or {}
        tb = match.get("teamB") or {}
        match_label = f"{ta.get('name', '?')} – {tb.get('name', '?')}"
        start_time = match.get("startTime") or ""
        judge_ids_list = list(newly_assigned_judge_ids)

        await create_notification(
            notif_type="new_match_as_judge",
            title="Obsada sędziowska — mecz",
            body=f"{match_label} (g. {start_time}) — {tour_name}",
            data={"tournament_id": tournament_id, "match_id": match["id"]},
            target_user_ids=judge_ids_list,
        )

        match_dt = _parse_match_datetime(match, days_config)
        if match_dt:
            asyncio.ensure_future(
                _schedule_match_push(
                    user_ids=judge_ids_list,
                    match_dt=match_dt,
                    title="Mecz za 30 min",
                    body=f"Twój mecz: {match_label} (g. {start_time}) — {tour_name}",
                    data={"tournament_id": tournament_id, "match_id": match["id"]},
                    notif_type="match_reminder_30min",
                )
            )

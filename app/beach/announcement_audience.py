from __future__ import annotations

from typing import Any, Dict, List, Optional


def announcement_audiences(announcement: Any) -> List[dict]:
    if not isinstance(announcement, dict):
        return []
    audiences = announcement.get("audiences")
    if isinstance(audiences, list) and audiences:
        return [audience for audience in audiences if isinstance(audience, dict)]
    audience = announcement.get("audience")
    return [audience] if isinstance(audience, dict) else []


def announcement_is_visible(
    announcement: Any,
    *,
    user_id: Optional[int],
    user_team_ids: set[int],
    is_tournament_judge: bool,
    is_tournament_team_member: bool,
    can_manage_announcements: bool = False,
) -> bool:
    if can_manage_announcements:
        return True

    audiences = announcement_audiences(announcement)
    if not audiences:
        return True

    for audience in audiences:
        audience_type = audience.get("type")
        audience_id = audience.get("id")
        if audience_type == "all":
            return True
        if audience_type == "judges" and is_tournament_judge:
            return True
        if audience_type == "judge" and user_id is not None:
            try:
                if int(audience_id) == user_id:
                    return True
            except (TypeError, ValueError):
                pass
        if audience_type == "teams" and is_tournament_team_member:
            return True
        if audience_type == "team":
            try:
                if int(audience_id) in user_team_ids:
                    return True
            except (TypeError, ValueError):
                pass
    # Unknown personalized audience types must not become public by accident.
    return False


def filter_announcements_for_viewer(
    data: Dict[str, Any],
    viewer: Dict[str, Any],
) -> Dict[str, Any]:
    announcements = data.get("announcements")
    if not isinstance(announcements, list):
        return data

    user_id = viewer.get("user_id")
    user_team_ids = set(viewer.get("team_ids") or set())
    host_ids = {
        int(host["id"])
        for host in (data.get("hosts") or [])
        if isinstance(host, dict) and isinstance(host.get("id"), int)
    }
    judge_ids = {
        int(judge["id"])
        for judge in (data.get("judges") or [])
        if isinstance(judge, dict) and isinstance(judge.get("id"), int)
    }
    head_judge_id = data.get("head_judge_id")
    if isinstance(head_judge_id, int):
        judge_ids.add(head_judge_id)
    invited_team_ids = {
        int(team_id)
        for team_id in (data.get("invited_team_ids") or [])
        if isinstance(team_id, int)
    }
    custom_coach_ids = {
        int(team["coach_user_id"])
        for team in (data.get("custom_teams") or [])
        if isinstance(team, dict) and isinstance(team.get("coach_user_id"), int)
    }

    capabilities = set(viewer.get("capabilities") or set())
    is_assigned_judge = user_id is not None and user_id in judge_ids
    can_manage = bool(
        viewer.get("is_admin")
        or (user_id is not None and user_id in host_ids)
        or (isinstance(head_judge_id, int) and user_id == head_judge_id)
        or "tournament.announcements.edit" in capabilities
        or "tournament.actAsHostEverywhere" in capabilities
        or (is_assigned_judge and viewer.get("assigned_judge_can_manage"))
    )
    tournament_team_ids = user_team_ids & invited_team_ids
    is_team_member = bool(
        tournament_team_ids
        or (user_id is not None and user_id in custom_coach_ids)
    )

    filtered = [
        announcement
        for announcement in announcements
        if announcement_is_visible(
            announcement,
            user_id=user_id,
            user_team_ids=tournament_team_ids,
            is_tournament_judge=is_assigned_judge,
            is_tournament_team_member=is_team_member,
            can_manage_announcements=can_manage,
        )
    ]
    if len(filtered) == len(announcements):
        return data
    return {**data, "announcements": filtered}

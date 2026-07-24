"""
Beach Activity Log — audit history for all beach module actions.

Core features:
  - log_activity()  — fire-and-forget INSERT (non-blocking)
  - compute_diff()  — compare old/new dicts, return changed fields
  - Query endpoints — paginated, filterable by area/user/date/text
  - Retention config — configurable cleanup of old entries
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, cast, delete, func as sa_func, insert, select, text

from app.db import (
    database,
    beach_activity_log,
    beach_admins,
    beach_app_versions,
    beach_app_settings,
    beach_guidelines,
    beach_password_reset_requests,
    beach_reports,
    beach_teams,
    beach_tournaments,
    beach_users,
    beach_verification_requests,
)
from app.deps import beach_get_current_user_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/activity-log", tags=["Beach: Activity Log"])

# ─────────────────── Core helpers ───────────────────

DEFAULT_RETENTION_DAYS = 365
_RETENTION_KEY = "activity_log_retention_days"

# Cache for actor names within the same request lifecycle
_actor_name_cache: Dict[int, str] = {}


async def get_actor_name(user_id: int) -> str:
    """Fetch user full_name for activity log. Cached per process."""
    if user_id in _actor_name_cache:
        return _actor_name_cache[user_id]
    row = await database.fetch_one(
        select(beach_users.c.full_name).where(beach_users.c.id == user_id)
    )
    name = row["full_name"] if row else f"user#{user_id}"
    _actor_name_cache[user_id] = name
    # Evict cache when too large
    if len(_actor_name_cache) > 500:
        _actor_name_cache.clear()
    return name


def _json_safe(val: Any) -> Any:
    """Make a value JSON-serializable."""
    if isinstance(val, datetime):
        return val.isoformat()
    if isinstance(val, (set, frozenset)):
        return sorted(val)
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return val


def compute_diff(
    old: Dict[str, Any],
    new: Dict[str, Any],
    fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Compare two dicts, return {field: {old: ..., new: ...}} for changed fields.
    If `fields` is given, only compare those keys.
    """
    changed: Dict[str, Any] = {}
    keys = fields if fields else sorted(set(list(old.keys()) + list(new.keys())))
    for k in keys:
        ov = _json_safe(old.get(k))
        nv = _json_safe(new.get(k))
        if ov != nv:
            changed[k] = {"old": ov, "new": nv}
    return changed


def compute_list_diff(
    old_items: List[Any],
    new_items: List[Any],
    key_fn=None,
) -> Dict[str, Any]:
    """
    Compare two lists, return {added: [...], removed: [...], count_before, count_after}.
    If key_fn is provided, uses it to identify items; otherwise uses equality.
    """
    if key_fn:
        old_keys = {key_fn(x) for x in old_items}
        new_keys = {key_fn(x) for x in new_items}
        added = [x for x in new_items if key_fn(x) not in old_keys]
        removed = [x for x in old_items if key_fn(x) not in new_keys]
    else:
        old_set = set(str(x) for x in old_items)
        new_set = set(str(x) for x in new_items)
        added = [x for x in new_items if str(x) not in old_set]
        removed = [x for x in old_items if str(x) not in new_set]
    return {
        "added": [_json_safe(x) for x in added],
        "removed": [_json_safe(x) for x in removed],
        "count_before": len(old_items),
        "count_after": len(new_items),
    }


async def log_activity(
    *,
    area: str,
    action: str,
    actor_user_id: Optional[int] = None,
    actor_name: Optional[str] = None,
    target_id: Optional[str] = None,
    target_label: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Fire-and-forget activity log insert.
    Safe to call from any endpoint — never raises, never blocks response.
    """
    async def _insert():
        try:
            await database.execute(
                insert(beach_activity_log).values(
                    area=area,
                    action=action,
                    actor_user_id=actor_user_id,
                    actor_name=actor_name,
                    target_id=str(target_id) if target_id is not None else None,
                    target_label=target_label,
                    details_json=details,
                    created_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:
            logger.error("Activity log insert failed: %s", e)

    asyncio.ensure_future(_insert())


# ─────────────────── Retention ───────────────────

async def _get_retention_days() -> int:
    row = await database.fetch_one(
        select(beach_app_settings.c.value).where(
            beach_app_settings.c.key == _RETENTION_KEY
        )
    )
    if row and row["value"]:
        try:
            return max(1, int(row["value"]))
        except (ValueError, TypeError):
            pass
    return DEFAULT_RETENTION_DAYS


async def cleanup_old_activity_logs() -> int:
    """Delete activity log entries older than configured retention. Returns count deleted."""
    days = await _get_retention_days()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    result = await database.execute(
        delete(beach_activity_log).where(beach_activity_log.c.created_at < cutoff)
    )
    return result if isinstance(result, int) else 0


# ─────────────────── Auth helper ───────────────────

async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    return bool(row)


def _activity_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _activity_json_object(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
    return {}


def _activity_target_kind(action: str) -> Optional[str]:
    if action.startswith("tournament.") or action == "match.score_saved":
        return "tournament"
    if action in {
        "standings.points_granted",
        "standings.points_revoked",
        "standings.stage_granted",
        "standings.stage_revoked",
        "standings.orphan_purged",
    }:
        return "tournament"
    if action in {"standings.manual_adjustment", "standings.manual_deleted"}:
        return "team"
    if action.startswith("verification."):
        return "verification"
    if action.startswith("password_reset_request."):
        return "password_reset"
    if action.startswith("report."):
        return "report"
    if action.startswith("guideline."):
        return "guideline"
    if action.startswith("version."):
        return "version"
    if (
        action.startswith("user.")
        or action.startswith("admin.")
        or action == "judge.availability_updated"
    ):
        return "user"
    if action.startswith("match."):
        return "match"
    return None


def _activity_field_kind(action: str, key: str, path: List[str]) -> Optional[str]:
    lowered = key.lower()
    joined = ".".join([*path, lowered])

    if lowered in {
        "user_id",
        "user_ids",
        "actor_user_id",
        "target_user_ids",
        "reviewed_by_user_id",
        "coach_user_id",
        "created_by_id",
        "assignee_id",
        "judge_ids",
    } or lowered.endswith("_user_id"):
        return "user"
    if lowered in {"head_judge_id", "judge_id"}:
        return "judge"
    if lowered == "player_id" or lowered in {
        "default_players",
        "match_players",
        "protocol_players",
    }:
        return "player"
    if lowered == "person_id" or lowered in {
        "default_companions",
        "match_companions",
        "protocol_companions",
    }:
        return "person"
    if lowered in {
        "team_id",
        "team_key",
        "custom_team_id",
        "invited_ids",
        "invited_team_ids",
        "present_ids",
    }:
        return "team"
    if lowered == "tournament_id":
        return "tournament"
    if lowered in {"match_id", "schedule_match_id"}:
        return "match"
    if lowered in {"request_id", "password_reset_request_id"}:
        return "password_reset" if "password" in action else "verification"
    if lowered == "report_id":
        return "report"
    if lowered in {"added", "removed"} and "judges_diff" in joined:
        return "user"
    if lowered in {"added", "removed"} and (
        "team" in joined or "invited" in joined
    ):
        return "team"
    return None


def _collect_activity_entity_ids(
    value: Any,
    *,
    action: str,
    path: Optional[List[str]],
    buckets: Dict[str, set],
) -> None:
    current_path = path or []
    if isinstance(value, dict):
        for key, nested in value.items():
            if isinstance(nested, dict) and ("old" in nested or "new" in nested):
                kind = _activity_field_kind(action, str(key), current_path)
                if kind:
                    for diff_value in nested.values():
                        if diff_value is not None and not isinstance(diff_value, (dict, list)):
                            buckets[kind].add(diff_value)
                        elif isinstance(diff_value, (dict, list)):
                            _collect_activity_entity_ids(
                                diff_value,
                                action=action,
                                path=[*current_path, str(key)],
                                buckets=buckets,
                            )
                    continue
            _collect_activity_entity_ids(
                nested,
                action=action,
                path=[*current_path, str(key)],
                buckets=buckets,
            )
        return
    if isinstance(value, list):
        key = current_path[-1] if current_path else ""
        kind = _activity_field_kind(action, key, current_path[:-1])
        for nested in value:
            if kind and not isinstance(nested, (dict, list)):
                buckets[kind].add(nested)
            else:
                _collect_activity_entity_ids(
                    nested,
                    action=action,
                    path=current_path,
                    buckets=buckets,
                )
        return
    if not current_path:
        return
    kind = _activity_field_kind(action, current_path[-1], current_path[:-1])
    if kind and value is not None:
        buckets[kind].add(value)


def _activity_team_ref_name(value: Any) -> Optional[str]:
    if isinstance(value, dict):
        name = value.get("name") or value.get("team_name")
        return str(name).strip() if name else None
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _activity_tournament_entities(data_json: Any) -> Dict[str, Dict[str, str]]:
    data = _activity_json_object(data_json)
    custom_teams: Dict[str, str] = {}
    for team in data.get("custom_teams") or []:
        if not isinstance(team, dict) or team.get("id") is None:
            continue
        name = team.get("name") or team.get("team_name")
        if name:
            custom_teams[str(team["id"])] = str(name)

    matches: Dict[str, str] = {}
    schedule = data.get("schedule") if isinstance(data.get("schedule"), dict) else {}
    for match in schedule.get("matches") or []:
        if not isinstance(match, dict) or match.get("id") is None:
            continue
        if match.get("kind") in {"court_break", "tournament_opening", "special_event"}:
            continue
        team_a = _activity_team_ref_name(match.get("teamA"))
        team_b = _activity_team_ref_name(match.get("teamB"))
        number = match.get("matchNumber")
        prefix = f"Mecz {number}" if number else "Mecz"
        if team_a or team_b:
            matches[str(match["id"])] = (
                f"{prefix}: {team_a or 'nieznana drużyna'} – "
                f"{team_b or 'nieznana drużyna'}"
            )
        elif match.get("knockoutLabel"):
            matches[str(match["id"])] = f"{prefix}: {match['knockoutLabel']}"
        else:
            matches[str(match["id"])] = prefix
    return {"custom_teams": custom_teams, "matches": matches}


async def _hydrate_activity_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Add business-readable entity names to current and historical log entries."""
    if not items:
        return items

    buckets: Dict[str, set] = {
        "user": set(),
        "judge": set(),
        "player": set(),
        "person": set(),
        "team": set(),
        "tournament": set(),
        "match": set(),
        "password_reset": set(),
        "verification": set(),
        "report": set(),
        "guideline": set(),
        "version": set(),
    }

    for item in items:
        action = str(item.get("action") or "")
        if item.get("actor_user_id") is not None:
            buckets["user"].add(item["actor_user_id"])
        target_kind = _activity_target_kind(action)
        if target_kind and item.get("target_id") is not None:
            buckets[target_kind].add(item["target_id"])
        _collect_activity_entity_ids(
            _activity_json_object(item.get("details_json")),
            action=action,
            path=None,
            buckets=buckets,
        )

    reset_ids = {
        value for value in (_activity_int(v) for v in buckets["password_reset"])
        if value is not None
    }
    verification_ids = {
        value for value in (_activity_int(v) for v in buckets["verification"])
        if value is not None
    }
    report_ids = {
        value for value in (_activity_int(v) for v in buckets["report"])
        if value is not None
    }
    guideline_ids = {
        value for value in (_activity_int(v) for v in buckets["guideline"])
        if value is not None
    }
    version_ids = {
        value for value in (_activity_int(v) for v in buckets["version"])
        if value is not None
    }

    reset_rows = await database.fetch_all(
        select(beach_password_reset_requests).where(
            beach_password_reset_requests.c.id.in_(reset_ids)
        )
    ) if reset_ids else []
    verification_rows = await database.fetch_all(
        select(beach_verification_requests).where(
            beach_verification_requests.c.id.in_(verification_ids)
        )
    ) if verification_ids else []
    report_rows = await database.fetch_all(
        select(beach_reports).where(beach_reports.c.id.in_(report_ids))
    ) if report_ids else []
    guideline_rows = await database.fetch_all(
        select(beach_guidelines.c.id, beach_guidelines.c.title).where(
            beach_guidelines.c.id.in_(guideline_ids)
        )
    ) if guideline_ids else []
    version_rows = await database.fetch_all(
        select(
            beach_app_versions.c.id,
            beach_app_versions.c.version,
            beach_app_versions.c.name,
        ).where(beach_app_versions.c.id.in_(version_ids))
    ) if version_ids else []

    resets = {int(row["id"]): dict(row._mapping) for row in reset_rows}
    verifications = {int(row["id"]): dict(row._mapping) for row in verification_rows}
    reports = {int(row["id"]): dict(row._mapping) for row in report_rows}
    guidelines = {int(row["id"]): str(row["title"]) for row in guideline_rows}
    versions = {
        int(row["id"]): f"v{row['version']} · {row['name']}"
        for row in version_rows
    }

    for row in resets.values():
        if row.get("user_id") is not None:
            buckets["user"].add(row["user_id"])
    for row in verifications.values():
        if row.get("user_id") is not None:
            buckets["user"].add(row["user_id"])
    for row in reports.values():
        if row.get("user_id") is not None:
            buckets["user"].add(row["user_id"])

    user_ids = {
        value for value in (_activity_int(v) for v in buckets["user"])
        if value is not None
    }
    user_ids.update(
        value for value in (_activity_int(v) for v in buckets["judge"])
        if value is not None
    )
    player_ids = {
        value for value in (_activity_int(v) for v in buckets["player"])
        if value is not None
    }
    person_ids = {
        value for value in (_activity_int(v) for v in buckets["person"])
        if value is not None
    }
    judge_refs = {str(v) for v in buckets["judge"] if v is not None}

    user_conditions = []
    if user_ids:
        user_conditions.append(beach_users.c.id.in_(user_ids))
    if player_ids:
        user_conditions.append(beach_users.c.player_id.in_(player_ids))
    if person_ids:
        user_conditions.append(beach_users.c.person_id.in_(person_ids))
    if judge_refs:
        user_conditions.append(beach_users.c.judge_id.in_(judge_refs))

    if user_conditions:
        from sqlalchemy import or_
        user_rows = await database.fetch_all(
            select(
                beach_users.c.id,
                beach_users.c.full_name,
                beach_users.c.player_id,
                beach_users.c.person_id,
                beach_users.c.judge_id,
            ).where(or_(*user_conditions))
        )
    else:
        user_rows = []

    users = {int(row["id"]): str(row["full_name"]) for row in user_rows}
    players = {
        int(row["player_id"]): str(row["full_name"])
        for row in user_rows if row["player_id"] is not None
    }
    persons = {
        int(row["person_id"]): str(row["full_name"])
        for row in user_rows if row["person_id"] is not None
    }
    judges = {
        str(row["judge_id"]): str(row["full_name"])
        for row in user_rows if row["judge_id"] is not None
    }

    team_ids = {
        value for value in (_activity_int(v) for v in buckets["team"])
        if value is not None
    }
    tournament_ids = {
        value for value in (_activity_int(v) for v in buckets["tournament"])
        if value is not None
    }
    team_rows = await database.fetch_all(
        select(beach_teams.c.id, beach_teams.c.team_name).where(
            beach_teams.c.id.in_(team_ids)
        )
    ) if team_ids else []
    tournament_rows = await database.fetch_all(
        select(
            beach_tournaments.c.id,
            beach_tournaments.c.name,
            beach_tournaments.c.data_json,
        ).where(beach_tournaments.c.id.in_(tournament_ids))
    ) if tournament_ids else []

    teams = {int(row["id"]): str(row["team_name"]) for row in team_rows}
    tournaments = {int(row["id"]): dict(row._mapping) for row in tournament_rows}
    tournament_entities = {
        tournament_id: _activity_tournament_entities(row.get("data_json"))
        for tournament_id, row in tournaments.items()
    }
    role_labels = {
        "judge": "sędziego",
        "coach": "trenera",
        "player": "zawodnika",
    }

    def context_tournament_id(item: Dict[str, Any]) -> Optional[int]:
        action = str(item.get("action") or "")
        if _activity_target_kind(action) == "tournament":
            return _activity_int(item.get("target_id"))
        details = _activity_json_object(item.get("details_json"))
        return _activity_int(details.get("tournament_id"))

    def reset_label(value: Any) -> str:
        row = resets.get(_activity_int(value) or -1)
        if not row:
            return "Wniosek o reset hasła"
        name = row.get("user_name") or users.get(_activity_int(row.get("user_id")) or -1)
        return f"Wniosek użytkownika {name or row.get('login') or 'nieznanego użytkownika'}"

    def verification_label(value: Any) -> str:
        row = verifications.get(_activity_int(value) or -1)
        if not row:
            return "Wniosek weryfikacyjny"
        name = users.get(_activity_int(row.get("user_id")) or -1) or "Nieznany użytkownik"
        role = role_labels.get(str(row.get("role")), str(row.get("role") or "roli"))
        return f"{name} · weryfikacja {role}"

    def report_label(value: Any) -> str:
        row = reports.get(_activity_int(value) or -1)
        if not row:
            return "Zgłoszenie użytkownika"
        title = row.get("title") or "Zgłoszenie"
        author = row.get("user_name") or users.get(_activity_int(row.get("user_id")) or -1)
        return f"{title}{f' · {author}' if author else ''}"

    def resolve_scalar(
        *,
        item: Dict[str, Any],
        key: str,
        path: List[str],
        value: Any,
    ) -> Any:
        kind = _activity_field_kind(str(item.get("action") or ""), key, path)
        if not kind or value is None:
            return value
        int_value = _activity_int(value)
        tournament_id = context_tournament_id(item)
        entities = tournament_entities.get(tournament_id or -1, {})

        if kind == "user":
            return users.get(int_value or -1, "Nieznany lub usunięty użytkownik")
        if kind == "judge":
            return (
                users.get(int_value or -1)
                or judges.get(str(value))
                or "Nieznany lub usunięty sędzia"
            )
        if kind == "player":
            return players.get(int_value or -1, "Nieznany zawodnik")
        if kind == "person":
            return persons.get(int_value or -1, "Nieznana osoba towarzysząca")
        if kind == "team":
            custom_name = entities.get("custom_teams", {}).get(str(value))
            return custom_name or teams.get(int_value or -1, "Nieznana lub usunięta drużyna")
        if kind == "tournament":
            row = tournaments.get(int_value or -1)
            return str(row["name"]) if row else "Nieznany lub usunięty turniej"
        if kind == "match":
            return entities.get("matches", {}).get(str(value), "Mecz turniejowy")
        if kind == "password_reset":
            return reset_label(value)
        if kind == "verification":
            return verification_label(value)
        if kind == "report":
            return report_label(value)
        return value

    def humanize_details(
        item: Dict[str, Any],
        value: Any,
        path: Optional[List[str]] = None,
    ) -> Any:
        current_path = path or []
        if isinstance(value, dict):
            result: Dict[str, Any] = {}
            for key, nested in value.items():
                if (
                    isinstance(nested, dict)
                    and ("old" in nested or "new" in nested)
                    and _activity_field_kind(
                        str(item.get("action") or ""),
                        str(key),
                        current_path,
                    )
                ):
                    result[key] = {
                        diff_key: (
                            humanize_details(
                                item,
                                diff_value,
                                [*current_path, str(key)],
                            )
                            if isinstance(diff_value, (dict, list))
                            else resolve_scalar(
                                item=item,
                                key=str(key),
                                path=current_path,
                                value=diff_value,
                            )
                        )
                        for diff_key, diff_value in nested.items()
                    }
                else:
                    result[key] = humanize_details(
                        item,
                        nested,
                        [*current_path, str(key)],
                    )
            return result
        if isinstance(value, list):
            key = current_path[-1] if current_path else ""
            return [
                resolve_scalar(
                    item=item,
                    key=key,
                    path=current_path[:-1],
                    value=nested,
                ) if not isinstance(nested, (dict, list)) else humanize_details(
                    item,
                    nested,
                    current_path,
                )
                for nested in value
            ]
        if not current_path:
            return value
        return resolve_scalar(
            item=item,
            key=current_path[-1],
            path=current_path[:-1],
            value=value,
        )

    for item in items:
        action = str(item.get("action") or "")
        actor_id = _activity_int(item.get("actor_user_id"))
        actor_name = str(item.get("actor_name") or "")
        if actor_id is not None and (
            not actor_name
            or actor_name.lower().startswith(("user#", "user_", "użytkownik #"))
        ):
            item["actor_name"] = users.get(actor_id or -1, "Nieznany lub usunięty użytkownik")

        target_id = item.get("target_id")
        target_kind = _activity_target_kind(action)
        resolved_target: Optional[str] = None
        if target_kind == "tournament":
            row = tournaments.get(_activity_int(target_id) or -1)
            resolved_target = str(row["name"]) if row else None
        elif target_kind == "team":
            resolved_target = teams.get(_activity_int(target_id) or -1)
        elif target_kind == "user":
            resolved_target = users.get(_activity_int(target_id) or -1)
        elif target_kind == "password_reset":
            resolved_target = reset_label(target_id)
        elif target_kind == "verification":
            resolved_target = verification_label(target_id)
        elif target_kind == "report":
            resolved_target = report_label(target_id)
        elif target_kind == "guideline":
            resolved_target = guidelines.get(_activity_int(target_id) or -1)
        elif target_kind == "version":
            resolved_target = versions.get(_activity_int(target_id) or -1)
        elif target_kind == "match" and target_id:
            resolved_target = f"Mecz {target_id}"

        if resolved_target and not item.get("target_label"):
            item["target_label"] = resolved_target
        item["display_details_json"] = humanize_details(
            item,
            _activity_json_object(item.get("details_json")),
        )

    return items


# ─────────────────── Query endpoints ───────────────────

@router.get(
    "/",
    response_model=dict,
    summary="Lista historii akcji (admin only, paginated)",
)
async def list_activity_log(
    area: Optional[str] = Query(None, description="Filter by area"),
    actor_user_id: Optional[int] = Query(None, description="Filter by actor"),
    target_id: Optional[str] = Query(None, description="Filter by target entity"),
    date_from: Optional[str] = Query(None, description="ISO date (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="ISO date (YYYY-MM-DD)"),
    search: Optional[str] = Query(None, description="Text search in actor_name/target_label/action"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    t = beach_activity_log
    conditions = []

    if area:
        area_list = [a.strip() for a in area.split(",") if a.strip()]
        if len(area_list) == 1:
            conditions.append(t.c.area == area_list[0])
        elif len(area_list) > 1:
            conditions.append(t.c.area.in_(area_list))
    if actor_user_id is not None:
        conditions.append(t.c.actor_user_id == actor_user_id)
    if target_id:
        conditions.append(t.c.target_id == target_id)
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from)
            conditions.append(t.c.created_at >= dt_from)
        except ValueError:
            raise HTTPException(400, f"Invalid date_from: {date_from}")
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
            # include the whole day
            if dt_to.hour == 0 and dt_to.minute == 0:
                dt_to = dt_to + timedelta(days=1)
            conditions.append(t.c.created_at < dt_to)
        except ValueError:
            raise HTTPException(400, f"Invalid date_to: {date_to}")
    if search:
        like_pattern = f"%{search}%"
        conditions.append(
            (t.c.actor_name.ilike(like_pattern))
            | (t.c.target_label.ilike(like_pattern))
            | (t.c.action.ilike(like_pattern))
            | (cast(t.c.details_json, String).ilike(like_pattern))
        )

    where = sa_func.coalesce(text("TRUE"))
    base = select(t)
    count_base = select(sa_func.count()).select_from(t)
    for cond in conditions:
        base = base.where(cond)
        count_base = count_base.where(cond)

    total = await database.fetch_val(count_base)
    rows = await database.fetch_all(
        base.order_by(t.c.created_at.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )

    items = []
    for r in rows:
        d = dict(r._mapping)
        if isinstance(d.get("created_at"), datetime):
            d["created_at"] = d["created_at"].isoformat()
        if isinstance(d.get("details_json"), str):
            try:
                d["details_json"] = json.loads(d["details_json"])
            except Exception:
                pass
        items.append(d)

    items = await _hydrate_activity_items(items)

    return {
        "items": items,
        "total": total or 0,
        "page": page,
        "page_size": page_size,
    }


@router.get(
    "/stats",
    response_model=dict,
    summary="Statystyki historii per area (admin only)",
)
async def activity_log_stats(
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    t = beach_activity_log
    conditions = []
    if date_from:
        try:
            conditions.append(t.c.created_at >= datetime.fromisoformat(date_from))
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
            if dt_to.hour == 0 and dt_to.minute == 0:
                dt_to = dt_to + timedelta(days=1)
            conditions.append(t.c.created_at < dt_to)
        except ValueError:
            pass

    q = select(t.c.area, sa_func.count().label("cnt")).group_by(t.c.area)
    for cond in conditions:
        q = q.where(cond)
    rows = await database.fetch_all(q)

    counts = {}
    total = 0
    for r in rows:
        d = dict(r._mapping)
        counts[d["area"]] = d["cnt"]
        total += d["cnt"]

    return {"counts": counts, "total": total}


@router.get(
    "/retention",
    response_model=dict,
    summary="Pobierz konfigurację retencji historii",
)
async def get_retention(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")
    days = await _get_retention_days()
    return {"retention_days": days}


@router.patch(
    "/retention",
    response_model=dict,
    summary="Zmień retencję historii (admin only)",
)
async def set_retention(
    body: dict,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    days = body.get("retention_days")
    if not isinstance(days, int) or days < 1:
        raise HTTPException(400, "retention_days must be a positive integer")

    old_days = await _get_retention_days()
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    stmt = (
        pg_insert(beach_app_settings)
        .values(key=_RETENTION_KEY, value=str(days), updated_at=datetime.now(timezone.utc))
        .on_conflict_do_update(
            index_elements=[beach_app_settings.c.key],
            set_={"value": str(days), "updated_at": datetime.now(timezone.utc)},
        )
    )
    await database.execute(stmt)

    await log_activity(
        area="system",
        action="system.retention_changed",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        details={
            "retention_days": days,
            "changed_fields": {
                "retention_days": {"old": old_days, "new": days}
            },
        },
    )

    return {"retention_days": days}


@router.delete(
    "/cleanup",
    response_model=dict,
    summary="Ręczne czyszczenie starszych wpisów (admin only)",
)
async def manual_cleanup(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    deleted = await cleanup_old_activity_logs()
    await log_activity(
        area="system",
        action="system.cleanup",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        details={
            "deleted_count": deleted,
            "retention_days": await _get_retention_days(),
        },
    )
    return {"deleted": deleted, "deleted_count": deleted}

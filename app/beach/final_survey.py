from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError

from app.beach.activity_log import get_actor_name, log_activity
from app.db import (
    beach_admins,
    beach_app_settings,
    beach_teams,
    beach_tournament_survey_responses,
    beach_tournaments,
    beach_users,
    database,
    login_records,
)
from app.deps import beach_get_current_user_id


router = APIRouter(
    prefix="/beach/tournament-surveys",
    tags=["Beach: Tournament final surveys"],
)

WARSAW = ZoneInfo("Europe/Warsaw")

ROLE_LABELS = {
    "coach": "Trener",
    "field_judge": "Sędzia boiskowy",
    "host": "Gospodarz zawodów",
    "head_judge": "Sędzia główny",
    "table_judge": "Sędzia stolikowy",
    "player": "Zawodnik",
}
VALID_ROLES = set(ROLE_LABELS)

VALID_QUESTION_TYPES = {"rating", "nps", "single", "multi", "ranking", "boolean", "text"}
SURVEY_TEMPLATE_KEY = "final_survey_template_registry"
SURVEY_TEMPLATE_FILE = Path(__file__).with_name("final_survey_default_template.json")


def _load_file_template_raw() -> Dict[str, Any]:
    try:
        with SURVEY_TEMPLATE_FILE.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise ValueError("Korzeń szablonu musi być obiektem")
        return value
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Nie można wczytać domyślnego szablonu ankiety: {SURVEY_TEMPLATE_FILE}"
        ) from exc


FILE_TEMPLATE_RAW = _load_file_template_raw()
TEMPLATE_VERSION = int(FILE_TEMPLATE_RAW.get("version") or 1)
DEFAULT_ROLES = [
    str(role)
    for role in FILE_TEMPLATE_RAW.get("default_roles", [])
    if str(role) in VALID_ROLES
]
_FILE_QUESTIONS = [
    dict(question)
    for question in FILE_TEMPLATE_RAW.get("questions", [])
    if isinstance(question, dict)
]
CORE_QUESTIONS = [
    {**question, "additional": False}
    for question in _FILE_QUESTIONS
    if bool(question.get("enabled_by_default", True))
]
ADDITIONAL_QUESTIONS = [
    {**question, "additional": True}
    for question in _FILE_QUESTIONS
    if not bool(question.get("enabled_by_default", True))
]
CORE_IDS = [question["id"] for question in CORE_QUESTIONS]
ADDITIONAL_BY_ID = {
    question["id"]: question for question in ADDITIONAL_QUESTIONS
}


class SurveyConfigRequest(BaseModel):
    enabled_roles: List[str]
    additional_question_ids: List[str] = Field(default_factory=list)
    custom_questions: List[Dict[str, Any]] = Field(default_factory=list)
    question_order: List[str] = Field(default_factory=list)
    open_offset_minutes: int = 0
    close_after_hours: int = 48


class SurveyResponseRequest(BaseModel):
    answers: Dict[str, Any]
    perspective_roles: List[str] = Field(default_factory=list)
    submit: bool = False
    expected_updated_at: Optional[datetime] = None


class SurveyTemplateRequest(BaseModel):
    expected_version: Optional[int] = None
    default_roles: List[str] = Field(default_factory=list)
    open_offset_minutes: int = 0
    close_after_hours: int = 48
    questions: List[Dict[str, Any]] = Field(default_factory=list)


def _obj(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return dict(parsed) if isinstance(parsed, dict) else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
    return {}


def _list(raw: Any) -> List[Any]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, tuple):
        return list(raw)
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, list) else []
        except (TypeError, ValueError, json.JSONDecodeError):
            return []
    return []


def _as_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sanitize_template_question(raw: Dict[str, Any], index: int) -> Dict[str, Any]:
    qtype = str(raw.get("type") or "text").strip()
    if qtype not in VALID_QUESTION_TYPES:
        raise HTTPException(422, f"Nieobsługiwany typ pytania: {qtype}")
    qid = str(raw.get("id") or "").strip()
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{2,79}", qid):
        raise HTTPException(422, f"Nieprawidłowy identyfikator pytania {index + 1}")
    title = str(raw.get("title") or "").strip()
    if not title:
        raise HTTPException(422, f"Pytanie {index + 1} nie ma treści")
    if qid == "schedule" and "sprawiedliw" in title.casefold():
        title = "Układ meczów, czytelność i przebieg terminarza zawodów"
    if len(title) > 240:
        raise HTTPException(422, f"Treść pytania {index + 1} jest za długa")
    section = str(raw.get("section") or "Pozostałe").strip()[:80] or "Pozostałe"
    if section == "Twoim głosem":
        section = "W kilku słowach"
    question: Dict[str, Any] = {
        "id": qid,
        "title": title,
        "description": str(raw.get("description") or "").strip()[:500],
        "type": qtype,
        "required": bool(raw.get("required", False)),
        "section": section,
        "enabled_by_default": bool(raw.get("enabled_by_default", True)),
        "additional": not bool(raw.get("enabled_by_default", True)),
    }
    if qtype in {"rating", "nps"}:
        minimum = _as_int(raw.get("min"))
        maximum = _as_int(raw.get("max"))
        minimum = 1 if minimum is None else minimum
        maximum = 5 if maximum is None else maximum
        if minimum < 0 or maximum > 10 or maximum <= minimum:
            raise HTTPException(
                422,
                f"Skala pytania „{title}” musi mieścić się w zakresie 0–10",
            )
        question.update(
            {
                "min": minimum,
                "max": maximum,
                "allow_na": bool(raw.get("allow_na", False)),
                "min_label": str(raw.get("min_label") or "").strip()[:80],
                "max_label": str(raw.get("max_label") or "").strip()[:80],
            }
        )
    elif qtype in {"single", "multi", "ranking"}:
        options: List[Dict[str, str]] = []
        used_values: set[str] = set()
        for option_index, option in enumerate(_list(raw.get("options"))):
            if isinstance(option, dict):
                label = str(option.get("label") or "").strip()
                value = str(option.get("value") or "").strip()
            else:
                label = str(option).strip()
                value = ""
            if not value:
                value = f"option_{option_index + 1}"
            value = re.sub(r"[^a-zA-Z0-9_-]+", "_", value).strip("_")[:80]
            if not label or not value or value in used_values:
                continue
            used_values.add(value)
            options.append({"label": label[:120], "value": value})
        if len(options) < 2:
            raise HTTPException(
                422,
                f"Pytanie „{title}” wymaga co najmniej dwóch odpowiedzi",
            )
        question["options"] = options
        if qtype in {"multi", "ranking"}:
            maximum = _as_int(raw.get("max_selections")) or len(options)
            minimum = _as_int(raw.get("min_selections"))
            minimum = (1 if question["required"] else 0) if minimum is None else minimum
            maximum = max(1, min(maximum, len(options)))
            minimum = max(0, min(minimum, maximum))
            question["min_selections"] = minimum
            question["max_selections"] = maximum
    elif qtype == "text":
        question["voice"] = bool(raw.get("voice", True))
    return question


def _normalize_template(
    raw: Any,
    *,
    version: Optional[int] = None,
    created_at: Optional[str] = None,
    created_by: Optional[int] = None,
) -> Dict[str, Any]:
    incoming = _obj(raw)
    questions = [
        _sanitize_template_question(question, index)
        for index, question in enumerate(_list(incoming.get("questions")))
        if isinstance(question, dict)
    ]
    if not questions:
        raise HTTPException(422, "Szablon ankiety musi zawierać co najmniej jedno pytanie")
    ids = [question["id"] for question in questions]
    if len(ids) != len(set(ids)):
        raise HTTPException(422, "Identyfikatory pytań w szablonie nie mogą się powtarzać")
    roles = [
        str(role)
        for role in _list(incoming.get("default_roles"))
        if str(role) in VALID_ROLES
    ]
    open_offset = _as_int(incoming.get("open_offset_minutes"))
    close_after = _as_int(incoming.get("close_after_hours"))
    resolved_version = version or _as_int(incoming.get("version")) or 1
    return {
        "schema_version": 1,
        "version": max(1, resolved_version),
        "default_roles": list(dict.fromkeys(roles)),
        "open_offset_minutes": max(-720, min(720, open_offset if open_offset is not None else 0)),
        "close_after_hours": max(1, min(168, close_after if close_after is not None else 48)),
        "questions": questions,
        "created_at": created_at or str(incoming.get("created_at") or ""),
        "created_by": created_by if created_by is not None else _as_int(incoming.get("created_by")),
    }


FILE_TEMPLATE = _normalize_template(FILE_TEMPLATE_RAW)


async def _load_template_registry() -> Dict[str, Any]:
    row = await database.fetch_one(
        select(beach_app_settings.c.value).where(
            beach_app_settings.c.key == SURVEY_TEMPLATE_KEY
        )
    )
    stored = _obj(row["value"]) if row else {}
    templates: List[Dict[str, Any]] = []
    for raw_template in _list(stored.get("templates")):
        if not isinstance(raw_template, dict):
            continue
        try:
            templates.append(_normalize_template(raw_template))
        except HTTPException:
            continue
    if not any(template["version"] == FILE_TEMPLATE["version"] for template in templates):
        templates.insert(0, dict(FILE_TEMPLATE))
    templates.sort(key=lambda template: template["version"])
    active_version = _as_int(stored.get("active_version"))
    if active_version not in {template["version"] for template in templates}:
        active_version = templates[-1]["version"]
    return {
        "schema_version": 1,
        "active_version": active_version,
        "templates": templates,
        "source": "database" if row else "file",
        "updated_at": row["updated_at"].isoformat() if row and row["updated_at"] else None,
    }


async def _load_survey_template(version: Optional[int] = None) -> Dict[str, Any]:
    registry = await _load_template_registry()
    target = version or registry["active_version"]
    template = next(
        (item for item in registry["templates"] if item["version"] == target),
        None,
    )
    if template is None:
        raise HTTPException(409, f"Nie znaleziono wersji {target} szablonu ankiety")
    return template


def _badge_names(value: Any) -> set[str]:
    if isinstance(value, list):
        return {str(x).strip() for x in value if str(x).strip()}
    if isinstance(value, dict):
        return {str(k).strip() for k, enabled in value.items() if enabled and str(k).strip()}
    return set()


def _template_question_sets(
    template: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    source = template or FILE_TEMPLATE
    core = [
        {**question, "additional": False}
        for question in source["questions"]
        if question.get("enabled_by_default", True)
    ]
    additional = [
        {**question, "additional": True}
        for question in source["questions"]
        if not question.get("enabled_by_default", True)
    ]
    return core, additional


def _default_config(template: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    source = template or FILE_TEMPLATE
    core, _additional = _template_question_sets(source)
    return {
        "version": 1,
        "template_version": source["version"],
        "enabled_roles": list(source["default_roles"]),
        "additional_question_ids": [],
        "custom_questions": [],
        "question_order": [question["id"] for question in core],
        "open_offset_minutes": source["open_offset_minutes"],
        "close_after_hours": source["close_after_hours"],
    }


def _sanitize_custom_question(raw: Dict[str, Any], index: int) -> Dict[str, Any]:
    qtype = str(raw.get("type") or "text")
    if qtype not in VALID_QUESTION_TYPES:
        raise HTTPException(422, f"Nieobsługiwany typ pytania: {qtype}")
    title = str(raw.get("title") or "").strip()
    if not title:
        raise HTTPException(422, "Własne pytanie musi mieć treść")
    if len(title) > 240:
        raise HTTPException(422, "Treść własnego pytania jest za długa")
    raw_id = str(raw.get("id") or "")
    qid = raw_id if re.fullmatch(r"custom_[a-zA-Z0-9_-]{4,80}", raw_id) else f"custom_{uuid.uuid4().hex}"
    question: Dict[str, Any] = {
        "id": qid,
        "title": title,
        "description": str(raw.get("description") or "").strip()[:500],
        "type": qtype,
        "required": bool(raw.get("required", False)),
        "section": str(raw.get("section") or "Pytania organizatora").strip()[:80],
        "additional": False,
        "custom": True,
    }
    if qtype in {"rating", "nps"}:
        minimum = _as_int(raw.get("min"))
        maximum = _as_int(raw.get("max"))
        minimum = 0 if minimum is None else minimum
        maximum = 10 if maximum is None else maximum
        if minimum < 0 or maximum > 10 or maximum <= minimum:
            raise HTTPException(422, f"Nieprawidłowa skala pytania {index + 1}")
        question.update({"min": minimum, "max": maximum, "allow_na": bool(raw.get("allow_na", False))})
    elif qtype in {"single", "multi", "ranking"}:
        options: List[Dict[str, str]] = []
        for option in _list(raw.get("options")):
            if isinstance(option, dict):
                label = str(option.get("label") or "").strip()
                value = str(option.get("value") or "").strip()
            else:
                label = str(option).strip()
                value = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
            if label and value:
                options.append({"label": label[:120], "value": value[:80]})
        if len(options) < 2:
            raise HTTPException(422, f"Pytanie „{title}” wymaga co najmniej dwóch odpowiedzi")
        question["options"] = options
        if qtype in {"multi", "ranking"}:
            limit = _as_int(raw.get("max_selections")) or len(options)
            question["max_selections"] = max(1, min(limit, len(options)))
    elif qtype == "text":
        question["voice"] = True
    return question


def _normalized_config(
    raw: Any,
    template: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    incoming = _obj(raw)
    source = template or FILE_TEMPLATE
    core_questions, additional_questions = _template_question_sets(source)
    core_ids = [question["id"] for question in core_questions]
    additional_by_id = {
        question["id"]: question for question in additional_questions
    }
    base = _default_config(source)
    roles = [str(x) for x in _list(incoming.get("enabled_roles")) if str(x) in VALID_ROLES]
    if "enabled_roles" in incoming:
        base["enabled_roles"] = list(dict.fromkeys(roles))
    additional = [
        str(x)
        for x in _list(incoming.get("additional_question_ids"))
        if str(x) in additional_by_id
    ]
    base["additional_question_ids"] = list(dict.fromkeys(additional))
    custom: List[Dict[str, Any]] = []
    for index, q in enumerate(_list(incoming.get("custom_questions"))):
        if isinstance(q, dict):
            custom.append(_sanitize_custom_question(q, index))
    base["custom_questions"] = custom
    active_ids = set(core_ids + additional + [q["id"] for q in custom])
    order = [str(x) for x in _list(incoming.get("question_order")) if str(x) in active_ids]
    for qid in core_ids + additional + [q["id"] for q in custom]:
        if qid not in order:
            order.append(qid)
    base["question_order"] = list(dict.fromkeys(order))
    open_offset_minutes = _as_int(incoming.get("open_offset_minutes"))
    close_after_hours = _as_int(incoming.get("close_after_hours"))
    base["open_offset_minutes"] = max(
        -720,
        min(720, 0 if open_offset_minutes is None else open_offset_minutes),
    )
    base["close_after_hours"] = max(
        1,
        min(168, 48 if close_after_hours is None else close_after_hours),
    )
    base["version"] = 1
    base["template_version"] = source["version"]
    return base


def _questions(
    config: Dict[str, Any],
    template: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    core_questions, additional_questions = _template_question_sets(template)
    additional_by_id = {
        question["id"]: question for question in additional_questions
    }
    available: Dict[str, Dict[str, Any]] = {
        question["id"]: dict(question) for question in core_questions
    }
    for qid in config["additional_question_ids"]:
        if qid in additional_by_id:
            available[qid] = dict(additional_by_id[qid])
    for q in config["custom_questions"]:
        available[q["id"]] = dict(q)
    return [available[qid] for qid in config["question_order"] if qid in available]


def _parse_hhmm(value: Any) -> Optional[Tuple[int, int]]:
    match = re.fullmatch(r"(\d{1,2}):(\d{2})", str(value or "").strip())
    if not match:
        return None
    hour, minute = int(match.group(1)), int(match.group(2))
    if hour > 23 or minute > 59:
        return None
    return hour, minute


def _survey_window(
    tournament: Dict[str, Any],
    data: Dict[str, Any],
    survey_config: Dict[str, Any],
) -> Tuple[Optional[datetime], Optional[datetime]]:
    schedule = _obj(data.get("schedule"))
    config = _obj(schedule.get("config"))
    days = _list(config.get("days"))
    matches = _list(schedule.get("matches"))
    starts: List[datetime] = []
    ends: List[datetime] = []
    fallback_duration = _as_int(config.get("slotInterval")) or 40
    for raw_match in matches:
        if not isinstance(raw_match, dict):
            continue
        if raw_match.get("kind") in {"court_break", "tournament_opening", "special_event"}:
            continue
        start_hm = _parse_hhmm(raw_match.get("startTime"))
        if start_hm is None:
            continue
        day_index = _as_int(raw_match.get("dayIndex")) or 0
        day = days[day_index] if 0 <= day_index < len(days) and isinstance(days[day_index], dict) else {}
        date_text = str(day.get("date") or "")[:10]
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_text):
            continue
        try:
            start = datetime.fromisoformat(
                f"{date_text}T{start_hm[0]:02d}:{start_hm[1]:02d}:00"
            ).replace(tzinfo=WARSAW)
        except ValueError:
            continue
        end_hm = _parse_hhmm(raw_match.get("endTime"))
        if end_hm is None:
            end = start + timedelta(minutes=fallback_duration)
        else:
            end = datetime.fromisoformat(
                f"{date_text}T{end_hm[0]:02d}:{end_hm[1]:02d}:00"
            ).replace(tzinfo=WARSAW)
            if end <= start:
                end += timedelta(days=1)
        starts.append(start)
        ends.append(end)
    if not starts:
        return None, None
    opens_at = min(starts) + timedelta(
        minutes=int(survey_config.get("open_offset_minutes") or 0)
    )
    closes_at = max(ends) + timedelta(
        hours=int(survey_config.get("close_after_hours") or 48)
    )
    return opens_at.astimezone(timezone.utc), closes_at.astimezone(timezone.utc)


def _phase(opens_at: Optional[datetime], closes_at: Optional[datetime], now: Optional[datetime] = None) -> str:
    if opens_at is None or closes_at is None:
        return "no_schedule"
    current = now or datetime.now(timezone.utc)
    if current < opens_at:
        return "upcoming"
    if current <= closes_at:
        return "open"
    return "closed"


def _ids(items: Iterable[Any]) -> set[int]:
    result: set[int] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        value = _as_int(item.get("id") if item.get("id") is not None else item.get("user_id"))
        if value is not None:
            result.add(value)
    return result


def _user_roles(user: Dict[str, Any], data: Dict[str, Any]) -> Tuple[List[str], List[int], List[str]]:
    user_id = _as_int(user.get("id"))
    if user_id is None:
        return [], [], []
    result: List[str] = []
    team_ids: List[int] = []
    custom_team_names: List[str] = []
    hosts = _list(data.get("hosts"))
    judges = _list(data.get("judges"))
    invited_ids = {_as_int(x) for x in _list(data.get("invited_team_ids"))}
    invited_ids.discard(None)
    head_judge_id = _as_int(data.get("head_judge_id"))

    if user_id in _ids(hosts):
        result.append("host")
    if user_id == head_judge_id:
        result.append("head_judge")
    judge = next(
        (
            item
            for item in judges
            if isinstance(item, dict)
            and _as_int(item.get("id") if item.get("id") is not None else item.get("user_id")) == user_id
        ),
        None,
    )
    if judge:
        result.append("table_judge" if judge.get("role") == "table" else "field_judge")

    for role in _list(user.get("roles")):
        if not isinstance(role, dict) or role.get("verified") != "approved":
            continue
        team_id = _as_int(role.get("team_id"))
        if team_id is None or team_id not in invited_ids:
            continue
        if role.get("type") == "coach":
            result.append("coach")
            team_ids.append(team_id)
        elif role.get("type") == "player":
            result.append("player")
            team_ids.append(team_id)

    for custom in _list(data.get("custom_teams")):
        if not isinstance(custom, dict) or _as_int(custom.get("coach_user_id")) != user_id:
            continue
        result.append("coach")
        custom_team_names.append(str(custom.get("name") or "Drużyna własna"))

    return list(dict.fromkeys(result)), list(dict.fromkeys(team_ids)), list(dict.fromkeys(custom_team_names))


async def _load_tournament(tournament_id: int) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    row = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono turnieju")
    tournament = dict(row)
    data = _obj(tournament.get("data_json"))
    return tournament, data


async def _load_user(user_id: int) -> Dict[str, Any]:
    row = await database.fetch_one(
        select(
            beach_users.c.id,
            beach_users.c.full_name,
            beach_users.c.judge_id,
            beach_users.c.player_id,
            beach_users.c.roles,
            beach_users.c.badges,
            beach_users.c.is_active,
        ).where(beach_users.c.id == user_id)
    )
    if not row or not row["is_active"]:
        raise HTTPException(404, "Nie znaleziono użytkownika")
    return dict(row)


async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    return bool(row)


def _template_admin_payload(registry: Dict[str, Any]) -> Dict[str, Any]:
    active = next(
        template
        for template in registry["templates"]
        if template["version"] == registry["active_version"]
    )
    return {
        "template": active,
        "active_version": registry["active_version"],
        "versions": [
            {
                "version": template["version"],
                "question_count": len(template["questions"]),
                "created_at": template.get("created_at") or None,
                "created_by": template.get("created_by"),
            }
            for template in reversed(registry["templates"])
        ],
        "source": registry["source"],
        "updated_at": registry.get("updated_at"),
        "fallback_file": SURVEY_TEMPLATE_FILE.name,
    }


async def _persist_template_registry(
    registry: Dict[str, Any],
) -> None:
    now = datetime.now(timezone.utc)
    payload = {
        "schema_version": 1,
        "active_version": registry["active_version"],
        "templates": registry["templates"],
    }
    statement = pg_insert(beach_app_settings).values(
        key=SURVEY_TEMPLATE_KEY,
        value=json.dumps(payload, ensure_ascii=False),
        updated_at=now,
    )
    statement = statement.on_conflict_do_update(
        index_elements=[beach_app_settings.c.key],
        set_={
            "value": statement.excluded.value,
            "updated_at": now,
        },
    )
    await database.execute(statement)


@router.get("/admin/template")
async def get_admin_survey_template(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień do szablonu ankiety")
    return _template_admin_payload(await _load_template_registry())


@router.get("/defaults")
async def get_survey_template_defaults(
    _current_user_id: int = Depends(beach_get_current_user_id),
):
    template = await _load_survey_template()
    return {
        "template_version": template["version"],
        "default_roles": template["default_roles"],
    }


@router.patch("/admin/template")
async def update_admin_survey_template(
    body: SurveyTemplateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień do szablonu ankiety")
    invalid_roles = sorted(set(body.default_roles) - VALID_ROLES)
    if invalid_roles:
        raise HTTPException(
            422,
            f"Nieobsługiwane role: {', '.join(invalid_roles)}",
        )
    registry = await _load_template_registry()
    if (
        body.expected_version is not None
        and body.expected_version != registry["active_version"]
    ):
        raise HTTPException(
            409,
            "Szablon został w międzyczasie zmieniony przez innego administratora. Odśwież widok.",
        )
    old_template = next(
        template
        for template in registry["templates"]
        if template["version"] == registry["active_version"]
    )
    next_version = max(template["version"] for template in registry["templates"]) + 1
    now = datetime.now(timezone.utc)
    next_template = _normalize_template(
        body.model_dump(),
        version=next_version,
        created_at=now.isoformat(),
        created_by=current_user_id,
    )
    registry["templates"].append(next_template)
    registry["active_version"] = next_version
    registry["source"] = "database"
    registry["updated_at"] = now.isoformat()
    await _persist_template_registry(registry)
    await log_activity(
        area="system",
        action="app_settings.final_survey_template_updated",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        details={
            "template_version_before": old_template["version"],
            "template_version_after": next_version,
            "questions_before": len(old_template["questions"]),
            "questions_after": len(next_template["questions"]),
            "default_roles": next_template["default_roles"],
        },
    )
    return _template_admin_payload(registry)


@router.post("/admin/template/reset")
async def reset_admin_survey_template(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień do szablonu ankiety")
    registry = await _load_template_registry()
    old_version = registry["active_version"]
    next_version = max(template["version"] for template in registry["templates"]) + 1
    now = datetime.now(timezone.utc)
    reset_template = _normalize_template(
        FILE_TEMPLATE_RAW,
        version=next_version,
        created_at=now.isoformat(),
        created_by=current_user_id,
    )
    registry["templates"].append(reset_template)
    registry["active_version"] = next_version
    registry["source"] = "database"
    registry["updated_at"] = now.isoformat()
    await _persist_template_registry(registry)
    await log_activity(
        area="system",
        action="app_settings.final_survey_template_reset",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        details={
            "template_version_before": old_version,
            "template_version_after": next_version,
            "questions_after": len(reset_template["questions"]),
        },
    )
    return _template_admin_payload(registry)


@router.post("/admin/template/{version}/activate")
async def activate_admin_survey_template_version(
    version: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień do szablonu ankiety")
    registry = await _load_template_registry()
    selected = next(
        (template for template in registry["templates"] if template["version"] == version),
        None,
    )
    if selected is None:
        raise HTTPException(404, "Nie znaleziono wybranej wersji szablonu")
    old_version = registry["active_version"]
    next_version = max(template["version"] for template in registry["templates"]) + 1
    now = datetime.now(timezone.utc)
    restored = _normalize_template(
        selected,
        version=next_version,
        created_at=now.isoformat(),
        created_by=current_user_id,
    )
    registry["templates"].append(restored)
    registry["active_version"] = next_version
    registry["source"] = "database"
    registry["updated_at"] = now.isoformat()
    await _persist_template_registry(registry)
    await log_activity(
        area="system",
        action="app_settings.final_survey_template_restored",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        details={
            "template_version_before": old_version,
            "restored_from_version": version,
            "template_version_after": next_version,
            "questions_after": len(restored["questions"]),
        },
    )
    return _template_admin_payload(registry)


async def _access(
    tournament_id: int,
    user_id: int,
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    tournament, data = await _load_tournament(tournament_id)
    user = await _load_user(user_id)
    roles, team_ids, custom_team_names = _user_roles(user, data)
    custom_team_genders = [
        str(team.get("gender"))
        for team in _list(data.get("custom_teams"))
        if isinstance(team, dict)
        and _as_int(team.get("coach_user_id")) == user_id
        and team.get("gender")
    ]
    raw_config = _obj(data.get("final_survey"))
    requested_template_version = _as_int(raw_config.get("template_version"))
    template = await _load_survey_template(requested_template_version)
    config = _normalized_config(raw_config, template)
    manager = (
        await _is_admin(user_id)
        or "host" in roles
        or "head_judge" in roles
    )
    enabled = [role for role in roles if role in set(config["enabled_roles"])]
    opens_at, closes_at = _survey_window(tournament, data, config)
    access = {
        "roles": roles,
        "enabled_roles": enabled,
        "team_ids": team_ids,
        "custom_team_names": custom_team_names,
        "custom_team_genders": list(dict.fromkeys(custom_team_genders)),
        "can_respond": bool(enabled),
        "can_manage": manager,
        "can_view_results": manager,
        "opens_at": opens_at,
        "closes_at": closes_at,
        "phase": _phase(opens_at, closes_at),
        "template": template,
    }
    return tournament, data, config, {**access, "user": user}


async def _team_snapshot(team_ids: List[int]) -> Tuple[List[str], List[str]]:
    if not team_ids:
        return [], []
    rows = await database.fetch_all(
        select(beach_teams.c.id, beach_teams.c.team_name, beach_teams.c.gender).where(
            beach_teams.c.id.in_(team_ids)
        )
    )
    return (
        [str(row["team_name"]) for row in rows if row["team_name"]],
        list(dict.fromkeys(str(row["gender"]) for row in rows if row["gender"])),
    )


async def _respondent_photo(user: Dict[str, Any], team_ids: List[int]) -> Optional[str]:
    judge_id = str(user.get("judge_id") or "").strip()
    if judge_id:
        row = await database.fetch_one(
            select(login_records.c.photo_url).where(login_records.c.judge_id == judge_id)
        )
        if row and str(row["photo_url"] or "").strip():
            return str(row["photo_url"]).strip()

    player_id = _as_int(user.get("player_id"))
    if player_id is None or not team_ids:
        return None
    rows = await database.fetch_all(
        select(
            beach_teams.c.roster_json,
            beach_teams.c.historical_players_json,
        ).where(beach_teams.c.id.in_(team_ids))
    )
    for row in rows:
        players = _list(row["roster_json"]) + _list(row["historical_players_json"])
        for player in players:
            if (
                isinstance(player, dict)
                and _as_int(player.get("player_id")) == player_id
                and str(player.get("photo_url") or "").strip()
            ):
                return str(player["photo_url"]).strip()
    return None


def _serialize_response(row: Any) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    data = dict(row)
    for key in ("created_at", "updated_at", "submitted_at"):
        if data.get(key) is not None:
            data[key] = data[key].isoformat()
    data["answers"] = _obj(data.pop("answers_json", {}))
    data["respondent"] = _obj(data.pop("respondent_snapshot_json", {}))
    data["perspective_roles"] = _list(data.get("perspective_roles"))
    return data


def _context_payload(
    tournament: Dict[str, Any],
    config: Dict[str, Any],
    access: Dict[str, Any],
    my_response: Any,
) -> Dict[str, Any]:
    opens_at = access["opens_at"]
    closes_at = access["closes_at"]
    return {
        "tournament_id": tournament["id"],
        "tournament_name": tournament.get("name") or "",
        "phase": access["phase"],
        "opens_at": opens_at.isoformat() if opens_at else None,
        "closes_at": closes_at.isoformat() if closes_at else None,
        "server_now": datetime.now(timezone.utc).isoformat(),
        "roles": access["roles"],
        "eligible_roles": access["enabled_roles"],
        "can_respond": access["can_respond"],
        "can_manage": access["can_manage"],
        "can_view_results": access["can_view_results"],
        "config": config,
        "role_labels": ROLE_LABELS,
        "questions": _questions(config, access["template"]),
        "additional_question_bank": _template_question_sets(access["template"])[1],
        "my_response": _serialize_response(my_response),
    }


def _option_values(question: Dict[str, Any]) -> set[str]:
    return {
        str(option.get("value"))
        for option in _list(question.get("options"))
        if isinstance(option, dict) and option.get("value") is not None
    }


def _validate_answers(
    answers: Dict[str, Any],
    questions: List[Dict[str, Any]],
    submit: bool,
) -> Dict[str, Any]:
    by_id = {q["id"]: q for q in questions}
    normalized: Dict[str, Any] = {}
    for qid, question in by_id.items():
        value = answers.get(qid)
        empty = value is None or value == "" or value == []
        if submit and question.get("required") and empty:
            raise HTTPException(422, f"Uzupełnij odpowiedź: {question['title']}")
        if empty:
            continue
        qtype = question["type"]
        if value == "na" and question.get("allow_na"):
            normalized[qid] = "na"
            continue
        if qtype in {"rating", "nps"}:
            number = _as_int(value)
            minimum = int(question.get("min", 0))
            maximum = int(question.get("max", 10))
            if number is None or number < minimum or number > maximum:
                raise HTTPException(422, f"Nieprawidłowa ocena: {question['title']}")
            normalized[qid] = number
        elif qtype in {"single", "boolean"}:
            if qtype == "boolean":
                if not isinstance(value, bool):
                    raise HTTPException(422, f"Nieprawidłowa odpowiedź: {question['title']}")
                normalized[qid] = value
            else:
                text_value = str(value)
                if text_value not in _option_values(question):
                    raise HTTPException(422, f"Nieprawidłowa odpowiedź: {question['title']}")
                normalized[qid] = text_value
        elif qtype in {"multi", "ranking"}:
            values = [str(x) for x in _list(value)]
            allowed = _option_values(question)
            limit = int(question.get("max_selections") or len(allowed))
            minimum = (
                int(question.get("min_selections") or (1 if question.get("required") else 0))
                if submit
                else 0
            )
            if (
                len(values) > limit
                or len(values) < minimum
                or len(values) != len(set(values))
                or any(item not in allowed for item in values)
            ):
                raise HTTPException(422, f"Nieprawidłowy wybór: {question['title']}")
            if submit and question.get("required") and not values:
                raise HTTPException(422, f"Uzupełnij odpowiedź: {question['title']}")
            normalized[qid] = values
        elif qtype == "text":
            text_value = str(value).strip()
            if len(text_value) > 4000:
                raise HTTPException(422, f"Odpowiedź jest za długa: {question['title']}")
            if text_value:
                normalized[qid] = text_value
    return normalized


async def _my_response(tournament_id: int, user_id: int) -> Any:
    return await database.fetch_one(
        select(beach_tournament_survey_responses).where(
            and_(
                beach_tournament_survey_responses.c.tournament_id == tournament_id,
                beach_tournament_survey_responses.c.user_id == user_id,
            )
        )
    )


@router.get("/{tournament_id}")
async def get_survey_context(
    tournament_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    tournament, _data, config, access = await _access(tournament_id, current_user_id)
    my_response = await _my_response(tournament_id, current_user_id)
    if not access["can_respond"] and not access["can_manage"]:
        raise HTTPException(403, "Ankieta nie jest udostępniona dla Twojej roli")
    return _context_payload(tournament, config, access, my_response)


@router.patch("/{tournament_id}/config")
async def update_survey_config(
    tournament_id: int,
    body: SurveyConfigRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    tournament, data, _old_config, access = await _access(tournament_id, current_user_id)
    if not access["can_manage"]:
        raise HTTPException(403, "Brak uprawnień do konfiguracji ankiety")
    invalid_roles = sorted(set(body.enabled_roles) - VALID_ROLES)
    if invalid_roles:
        raise HTTPException(
            422,
            f"Nieobsługiwane role ankiety: {', '.join(invalid_roles)}",
        )
    new_config = _normalized_config(body.model_dump(), access["template"])
    if access["phase"] == "closed":
        raise HTTPException(409, "Zamkniętej ankiety nie można już konfigurować")
    data["final_survey"] = new_config
    await database.execute(
        update(beach_tournaments)
        .where(beach_tournaments.c.id == tournament_id)
        .values(data_json=data, updated_at=datetime.now(timezone.utc))
    )
    await log_activity(
        area="tournament",
        action="tournament.final_survey_config_updated",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(tournament_id),
        target_label=tournament.get("name") or "",
        details={
            "enabled_roles": new_config["enabled_roles"],
            "additional_questions": new_config["additional_question_ids"],
            "custom_question_count": len(new_config["custom_questions"]),
            "open_offset_minutes": new_config["open_offset_minutes"],
            "close_after_hours": new_config["close_after_hours"],
        },
    )
    tournament, _data, config, access = await _access(tournament_id, current_user_id)
    return _context_payload(
        tournament,
        config,
        access,
        await _my_response(tournament_id, current_user_id),
    )


@router.put("/{tournament_id}/response")
async def save_survey_response(
    tournament_id: int,
    body: SurveyResponseRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    tournament, data, config, access = await _access(tournament_id, current_user_id)
    if not access["can_respond"]:
        raise HTTPException(403, "Ankieta nie jest udostępniona dla Twojej roli")
    if access["phase"] != "open":
        if access["phase"] == "upcoming":
            raise HTTPException(409, "Ankieta nie jest jeszcze otwarta")
        if access["phase"] == "closed":
            raise HTTPException(409, "Ankieta jest już zamknięta")
        raise HTTPException(409, "Ankieta oczekuje na gotowy terminarz")

    answers = _validate_answers(
        body.answers,
        _questions(config, access["template"]),
        body.submit,
    )
    if not _obj(data.get("final_survey")):
        data["final_survey"] = config
        await database.execute(
            update(beach_tournaments)
            .where(beach_tournaments.c.id == tournament_id)
            .values(data_json=data, updated_at=datetime.now(timezone.utc))
        )
    perspectives = [
        role
        for role in dict.fromkeys(body.perspective_roles)
        if role in set(access["enabled_roles"])
    ]
    if not perspectives:
        perspectives = list(access["enabled_roles"])
    team_names, genders = await _team_snapshot(access["team_ids"])
    team_names = list(dict.fromkeys(team_names + access["custom_team_names"]))
    genders = list(dict.fromkeys(genders + access["custom_team_genders"]))
    user = access["user"]
    snapshot = {
        "user_id": current_user_id,
        "full_name": user.get("full_name") or f"Użytkownik #{current_user_id}",
        "photo_url": await _respondent_photo(user, access["team_ids"]),
        "roles": perspectives,
        "role_labels": [ROLE_LABELS[role] for role in perspectives],
        "team_ids": access["team_ids"],
        "team_names": team_names,
        "genders": genders,
    }
    now = datetime.now(timezone.utc)
    existing = await _my_response(tournament_id, current_user_id)
    if existing and body.expected_updated_at is None:
        raise HTTPException(
            409,
            "Na innym urządzeniu istnieje już nowszy szkic. Odśwież ankietę przed zapisem.",
        )
    if not existing and body.expected_updated_at is not None:
        raise HTTPException(
            409,
            "Szkic został usunięty lub zmieniony. Odśwież ankietę przed zapisem.",
        )
    if existing and body.expected_updated_at is not None:
        expected = body.expected_updated_at
        if expected.tzinfo is None:
            expected = expected.replace(tzinfo=timezone.utc)
        actual = existing["updated_at"]
        if actual.tzinfo is None:
            actual = actual.replace(tzinfo=timezone.utc)
        if abs((actual.astimezone(timezone.utc) - expected.astimezone(timezone.utc)).total_seconds()) > 0.001:
            raise HTTPException(
                409,
                "Odpowiedź została w międzyczasie zmieniona na innym urządzeniu. Odśwież ankietę i spróbuj ponownie.",
            )
    status = "submitted" if body.submit else "draft"
    values = {
        "status": status,
        "perspective_roles": perspectives,
        "answers_json": answers,
        "respondent_snapshot_json": snapshot,
        "template_version": config["template_version"],
        "updated_at": now,
        "submitted_at": now if body.submit else (existing["submitted_at"] if existing else None),
    }
    if existing:
        await database.execute(
            update(beach_tournament_survey_responses)
            .where(beach_tournament_survey_responses.c.id == existing["id"])
            .values(**values)
        )
    else:
        try:
            await database.execute(
                insert(beach_tournament_survey_responses).values(
                    tournament_id=tournament_id,
                    user_id=current_user_id,
                    created_at=now,
                    **values,
                )
            )
        except IntegrityError as exc:
            raise HTTPException(
                409,
                "Szkic został właśnie utworzony na innym urządzeniu. Odśwież ankietę przed kolejnym zapisem.",
            ) from exc
    if body.submit:
        await log_activity(
            area="tournament",
            action=(
                "tournament.final_survey_updated"
                if existing and existing["status"] == "submitted"
                else "tournament.final_survey_submitted"
            ),
            actor_user_id=current_user_id,
            actor_name=await get_actor_name(current_user_id),
            target_id=str(tournament_id),
            target_label=tournament.get("name") or "",
            details={
                "answer_count": len(answers),
                "roles": perspectives,
            },
        )
    return _context_payload(
        tournament,
        config,
        access,
        await _my_response(tournament_id, current_user_id),
    )


def _matches_filter(
    snapshot: Dict[str, Any],
    role: Optional[str],
    team: Optional[str],
    gender: Optional[str],
) -> bool:
    if role and role not in _list(snapshot.get("roles")):
        return False
    if team:
        normalized = team.casefold()
        if not any(normalized in str(name).casefold() for name in _list(snapshot.get("team_names"))):
            return False
    if gender and gender not in _list(snapshot.get("genders")):
        return False
    return True


def _question_aggregate(question: Dict[str, Any], rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    values = [row["answers"].get(question["id"]) for row in rows]
    values = [value for value in values if value not in (None, "", [], "na")]
    result: Dict[str, Any] = {
        "id": question["id"],
        "title": question["title"],
        "type": question["type"],
        "count": len(values),
    }
    qtype = question["type"]
    if qtype in {"rating", "nps"}:
        result["min"] = int(question.get("min", 0))
        result["max"] = int(question.get("max", 10))
        numeric = [float(value) for value in values if isinstance(value, (int, float))]
        result["average"] = round(sum(numeric) / len(numeric), 2) if numeric else None
        distribution = Counter(str(int(value)) for value in numeric)
        result["distribution"] = dict(sorted(distribution.items(), key=lambda x: int(x[0])))
        if question["id"] == "return_likelihood" and numeric:
            minimum = int(question.get("min", 0))
            maximum = int(question.get("max", 10))
            span = max(1, maximum - minimum)
            promoter_threshold = maximum - max(1, round(span * 0.1))
            detractor_threshold = minimum + round(span * 0.6)
            promoters = sum(1 for value in numeric if value >= promoter_threshold)
            detractors = sum(1 for value in numeric if value <= detractor_threshold)
            result["nps"] = round((promoters - detractors) * 100 / len(numeric))
    elif qtype in {"single", "boolean", "multi"}:
        counter: Counter[str] = Counter()
        for value in values:
            if isinstance(value, list):
                counter.update(str(x) for x in value)
            else:
                counter[str(value).lower() if isinstance(value, bool) else str(value)] += 1
        result["distribution"] = dict(counter.most_common())
    elif qtype == "ranking":
        counter: Counter[str] = Counter()
        points: Counter[str] = Counter()
        for value in values:
            if not isinstance(value, list):
                continue
            for index, item in enumerate(value):
                counter[str(item)] += 1
                points[str(item)] += max(1, len(value) - index)
        result["distribution"] = dict(counter.most_common())
        result["ranking_points"] = dict(points.most_common())
    elif qtype == "text":
        result["filled"] = len(values)
    return result


async def _eligible_total(
    data: Dict[str, Any],
    config: Dict[str, Any],
    role_filter: Optional[str] = None,
    team_filter: Optional[str] = None,
    gender_filter: Optional[str] = None,
) -> int:
    rows = await database.fetch_all(
        select(
            beach_users.c.id,
            beach_users.c.roles,
            beach_users.c.badges,
            beach_users.c.full_name,
        ).where(beach_users.c.is_active.is_(True))
    )
    enabled = set(config["enabled_roles"])
    invited_team_ids = [
        team_id
        for team_id in (_as_int(value) for value in _list(data.get("invited_team_ids")))
        if team_id is not None
    ]
    team_rows = (
        await database.fetch_all(
            select(beach_teams.c.id, beach_teams.c.team_name, beach_teams.c.gender).where(
                beach_teams.c.id.in_(invited_team_ids)
            )
        )
        if invited_team_ids
        else []
    )
    team_meta = {
        int(row["id"]): {
            "name": str(row["team_name"] or ""),
            "gender": str(row["gender"] or ""),
        }
        for row in team_rows
    }
    custom_gender_by_name = {
        str(team.get("name") or "Drużyna własna"): str(team.get("gender") or "")
        for team in _list(data.get("custom_teams"))
        if isinstance(team, dict)
    }
    total = 0
    for row in rows:
        user_roles, team_ids, custom_names = _user_roles(dict(row), data)
        if not enabled.intersection(user_roles):
            continue
        if role_filter and role_filter not in user_roles:
            continue
        names = custom_names + [
            team_meta[team_id]["name"]
            for team_id in team_ids
            if team_id in team_meta and team_meta[team_id]["name"]
        ]
        genders = [
            team_meta[team_id]["gender"]
            for team_id in team_ids
            if team_id in team_meta and team_meta[team_id]["gender"]
        ]
        genders.extend(
            custom_gender_by_name[name]
            for name in custom_names
            if custom_gender_by_name.get(name)
        )
        if team_filter and not any(
            team_filter.casefold() in name.casefold() for name in names
        ):
            continue
        if gender_filter and gender_filter not in genders:
            continue
        total += 1
    return total


@router.get("/{tournament_id}/results")
async def get_survey_results(
    tournament_id: int,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=30, ge=1, le=100),
    role: Optional[str] = Query(default=None),
    team: Optional[str] = Query(default=None),
    gender: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    tournament, data, config, access = await _access(tournament_id, current_user_id)
    if not access["can_view_results"]:
        raise HTTPException(403, "Brak uprawnień do wyników ankiety")
    db_rows = await database.fetch_all(
        select(beach_tournament_survey_responses)
        .where(
            and_(
                beach_tournament_survey_responses.c.tournament_id == tournament_id,
                beach_tournament_survey_responses.c.status == "submitted",
            )
        )
        .order_by(beach_tournament_survey_responses.c.updated_at.desc())
    )
    rows: List[Dict[str, Any]] = []
    for db_row in db_rows:
        serialized = _serialize_response(db_row)
        if not serialized:
            continue
        snapshot = serialized["respondent"]
        if not _matches_filter(snapshot, role, team, gender):
            continue
        rows.append(serialized)

    questions = _questions(config, access["template"])
    aggregates = [_question_aggregate(question, rows) for question in questions]
    role_counts: Counter[str] = Counter()
    team_counts: Counter[str] = Counter()
    gender_counts: Counter[str] = Counter()
    for row in rows:
        role_counts.update(str(x) for x in _list(row["respondent"].get("roles")))
        team_counts.update(str(x) for x in _list(row["respondent"].get("team_names")))
        gender_counts.update(str(x) for x in _list(row["respondent"].get("genders")))
    rating_by_role: Dict[str, Dict[str, float]] = {}
    for role_key in VALID_ROLES:
        role_rows = [row for row in rows if role_key in _list(row["respondent"].get("roles"))]
        if not role_rows:
            continue
        role_values: Dict[str, float] = {}
        for question in questions:
            if question["type"] != "rating":
                continue
            numbers = [
                float(row["answers"][question["id"]])
                for row in role_rows
                if isinstance(row["answers"].get(question["id"]), (int, float))
            ]
            if numbers:
                role_values[question["id"]] = round(sum(numbers) / len(numbers), 2)
        rating_by_role[role_key] = role_values

    overall = next((item for item in aggregates if item["id"] == "overall"), {})
    nps = next((item for item in aggregates if item["id"] == "return_likelihood"), {})
    eligible_total = await _eligible_total(data, config, role, team, gender)
    respondent_items: List[Dict[str, Any]] = []
    search_folded = (search or "").strip().casefold()
    visible_rows = rows
    if search_folded:
        visible_rows = [
            row
            for row in visible_rows
            if search_folded in str(row["respondent"].get("full_name") or "").casefold()
            or any(
                search_folded in str(name).casefold()
                for name in _list(row["respondent"].get("team_names"))
            )
        ]
    total_matching = len(visible_rows)
    start = (page - 1) * page_size
    for row in visible_rows[start : start + page_size]:
        respondent_items.append(
            {
                "id": row["id"],
                "user_id": row["user_id"],
                "respondent": row["respondent"],
                "submitted_at": row["submitted_at"],
                "updated_at": row["updated_at"],
                "overall": row["answers"].get("overall"),
            }
        )

    open_answers: List[Dict[str, Any]] = []
    for question in questions:
        if question["type"] != "text":
            continue
        answers = [
            {
                "response_id": row["id"],
                "respondent": row["respondent"],
                "text": row["answers"].get(question["id"]),
            }
            for row in rows
            if str(row["answers"].get(question["id"]) or "").strip()
        ]
        open_answers.append(
            {
                "question_id": question["id"],
                "title": question["title"],
                "answers": answers,
            }
        )

    return {
        "tournament_id": tournament_id,
        "phase": access["phase"],
        "response_count": len(rows),
        "eligible_total": eligible_total,
        "completion_rate": round(len(rows) * 100 / eligible_total, 1) if eligible_total else 0,
        "average_overall": overall.get("average"),
        "nps": nps.get("nps"),
        "aggregates": aggregates,
        "role_counts": dict(role_counts),
        "team_counts": dict(team_counts.most_common()),
        "gender_counts": dict(gender_counts),
        "rating_by_role": rating_by_role,
        "open_answers": open_answers,
        "respondents_locked": False,
        "respondents": respondent_items,
        "page": page,
        "page_size": page_size,
        "total_respondents": total_matching,
        "questions": questions,
        "role_labels": ROLE_LABELS,
    }


@router.get("/{tournament_id}/results/{response_id}")
async def get_survey_response_detail(
    tournament_id: int,
    response_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    _tournament, _data, config, access = await _access(tournament_id, current_user_id)
    if not access["can_view_results"]:
        raise HTTPException(403, "Brak uprawnień do wyników ankiety")
    row = await database.fetch_one(
        select(beach_tournament_survey_responses).where(
            and_(
                beach_tournament_survey_responses.c.id == response_id,
                beach_tournament_survey_responses.c.tournament_id == tournament_id,
                beach_tournament_survey_responses.c.status == "submitted",
            )
        )
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono odpowiedzi")
    return {
        "response": _serialize_response(row),
        "questions": _questions(config, access["template"]),
    }

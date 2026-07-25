from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import json
import re
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, insert, select, update

from app.beach.activity_log import get_actor_name, log_activity
from app.db import (
    beach_admins,
    beach_teams,
    beach_tournament_survey_responses,
    beach_tournaments,
    beach_users,
    database,
)
from app.deps import beach_get_current_user_id


router = APIRouter(
    prefix="/beach/tournament-surveys",
    tags=["Beach: Tournament final surveys"],
)

WARSAW = ZoneInfo("Europe/Warsaw")
TEMPLATE_VERSION = 1

ROLE_LABELS = {
    "coach": "Trener",
    "field_judge": "Sędzia boiskowy",
    "host": "Gospodarz zawodów",
    "head_judge": "Sędzia główny",
    "table_judge": "Sędzia stolikowy",
    "player": "Zawodnik",
}
VALID_ROLES = set(ROLE_LABELS)
DEFAULT_ROLES = ["coach", "field_judge", "host", "head_judge"]

AREA_OPTIONS = [
    {"value": "courts", "label": "Przygotowanie boisk"},
    {"value": "sand", "label": "Piasek"},
    {"value": "organization", "label": "Organizacja"},
    {"value": "information", "label": "Obieg informacji"},
    {"value": "schedule", "label": "Terminarz"},
    {"value": "refereeing", "label": "Obsada sędziowska"},
    {"value": "accommodation", "label": "Zakwaterowanie"},
    {"value": "catering", "label": "Wyżywienie"},
    {"value": "facilities", "label": "Zaplecze obiektu"},
    {"value": "atmosphere", "label": "Atmosfera i oprawa"},
    {"value": "safety", "label": "Bezpieczeństwo"},
    {"value": "app", "label": "Komunikaty i aplikacja"},
]


def _rating(
    key: str,
    title: str,
    *,
    description: str = "",
    allow_na: bool = False,
    additional: bool = False,
    section: str = "Ocena turnieju",
) -> Dict[str, Any]:
    return {
        "id": key,
        "title": title,
        "description": description,
        "type": "rating",
        "required": not additional,
        "section": section,
        "min": 1,
        "max": 5,
        "allow_na": allow_na,
        "additional": additional,
    }


CORE_QUESTIONS: List[Dict[str, Any]] = [
    {
        "id": "overall",
        "title": "Jak oceniasz cały turniej?",
        "description": "Przeciągnij lub dotknij liczby, która najlepiej oddaje Twoje wrażenia.",
        "type": "nps",
        "required": True,
        "section": "Pierwsze wrażenie",
        "min": 1,
        "max": 10,
        "additional": False,
    },
    _rating("courts", "Przygotowanie boisk"),
    _rating("sand", "Jakość, głębokość i bezpieczeństwo piasku"),
    _rating("organization", "Organizacja zawodów"),
    _rating("information", "Szybkość i czytelność obiegu informacji"),
    _rating("schedule", "Czytelność, punktualność i sprawiedliwość terminarza"),
    _rating("refereeing", "Profesjonalizm, komunikacja i spójność obsady sędziowskiej"),
    _rating("accommodation", "Zakwaterowanie", allow_na=True),
    _rating("catering", "Wyżywienie", allow_na=True),
    {
        "id": "return_likelihood",
        "title": "Jak bardzo prawdopodobne jest, że ponownie weźmiesz udział?",
        "description": "0 oznacza „zdecydowanie nie”, 10 — „zdecydowanie tak”.",
        "type": "nps",
        "required": True,
        "section": "Podsumowanie",
        "min": 0,
        "max": 10,
        "additional": False,
    },
    {
        "id": "strengths",
        "title": "Wybierz maksymalnie trzy najmocniejsze elementy",
        "type": "multi",
        "required": True,
        "section": "Podsumowanie",
        "options": AREA_OPTIONS,
        "min_selections": 3,
        "max_selections": 3,
        "additional": False,
    },
    {
        "id": "priorities",
        "title": "Ułóż trzy najważniejsze obszary do poprawy",
        "description": "Kolejność ma znaczenie — pierwszy element jest najpilniejszy.",
        "type": "ranking",
        "required": True,
        "section": "Podsumowanie",
        "options": AREA_OPTIONS,
        "max_selections": 3,
        "additional": False,
    },
    {
        "id": "open_best",
        "title": "Co podczas turnieju zadziałało najlepiej?",
        "type": "text",
        "required": False,
        "section": "Twoim głosem",
        "voice": True,
        "additional": False,
    },
    {
        "id": "open_improve",
        "title": "Co powinniśmy poprawić w pierwszej kolejności?",
        "type": "text",
        "required": False,
        "section": "Twoim głosem",
        "voice": True,
        "additional": False,
    },
    {
        "id": "open_schedule",
        "title": "Czy masz uwagi do terminarza lub obiegu informacji?",
        "type": "text",
        "required": False,
        "section": "Twoim głosem",
        "voice": True,
        "additional": False,
    },
    {
        "id": "open_refereeing",
        "title": "Czy chcesz przekazać uwagę dotyczącą sędziowania?",
        "type": "text",
        "required": False,
        "section": "Twoim głosem",
        "voice": True,
        "additional": False,
    },
    {
        "id": "open_other",
        "title": "Co jeszcze chcesz przekazać organizatorom?",
        "type": "text",
        "required": False,
        "section": "Twoim głosem",
        "voice": True,
        "additional": False,
    },
]

ADDITIONAL_QUESTIONS: List[Dict[str, Any]] = [
    _rating("facilities", "Sanitariaty, prysznice i czystość obiektu", additional=True, section="Dodatkowe obszary"),
    _rating("access", "Parking, dojazd i oznaczenie terenu", additional=True, allow_na=True, section="Dodatkowe obszary"),
    _rating("accreditation", "Akredytacja i przyjęcie drużyn", additional=True, allow_na=True, section="Dodatkowe obszary"),
    _rating("warmup", "Strefa rozgrzewki i dostępność sprzętu", additional=True, allow_na=True, section="Dodatkowe obszary"),
    _rating("staff", "Pomoc organizatorów i wolontariuszy", additional=True, section="Dodatkowe obszary"),
    _rating("safety", "Zabezpieczenie medyczne i bezpieczeństwo", additional=True, allow_na=True, section="Dodatkowe obszary"),
    _rating("atmosphere", "Atmosfera, oprawa, muzyka i kibice", additional=True, section="Dodatkowe obszary"),
    _rating("ceremony", "Ceremonia otwarcia, dekoracja i nagrody", additional=True, allow_na=True, section="Dodatkowe obszary"),
    _rating("app", "Wyniki na żywo, komunikaty i działanie aplikacji", additional=True, allow_na=True, section="Dodatkowe obszary"),
    _rating("judge_conditions", "Warunki pracy, odpoczynku i odpraw dla sędziów", additional=True, allow_na=True, section="Dodatkowe obszary"),
    _rating("table_work", "Wyposażenie stolików i obsługa protokołów", additional=True, allow_na=True, section="Dodatkowe obszary"),
    _rating("team_communication", "Komunikacja z trenerami i drużynami", additional=True, allow_na=True, section="Dodatkowe obszary"),
]

CORE_IDS = [q["id"] for q in CORE_QUESTIONS]
ADDITIONAL_BY_ID = {q["id"]: q for q in ADDITIONAL_QUESTIONS}
VALID_QUESTION_TYPES = {"rating", "nps", "single", "multi", "ranking", "boolean", "text"}


class SurveyConfigRequest(BaseModel):
    enabled_roles: List[str]
    additional_question_ids: List[str] = Field(default_factory=list)
    custom_questions: List[Dict[str, Any]] = Field(default_factory=list)
    question_order: List[str] = Field(default_factory=list)


class SurveyResponseRequest(BaseModel):
    answers: Dict[str, Any]
    perspective_roles: List[str] = Field(default_factory=list)
    submit: bool = False


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


def _badge_names(value: Any) -> set[str]:
    if isinstance(value, list):
        return {str(x).strip() for x in value if str(x).strip()}
    if isinstance(value, dict):
        return {str(k).strip() for k, enabled in value.items() if enabled and str(k).strip()}
    return set()


def _default_config() -> Dict[str, Any]:
    return {
        "version": 1,
        "template_version": TEMPLATE_VERSION,
        "enabled_roles": list(DEFAULT_ROLES),
        "additional_question_ids": [],
        "custom_questions": [],
        "question_order": list(CORE_IDS),
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


def _normalized_config(raw: Any) -> Dict[str, Any]:
    incoming = _obj(raw)
    base = _default_config()
    roles = [str(x) for x in _list(incoming.get("enabled_roles")) if str(x) in VALID_ROLES]
    if roles:
        base["enabled_roles"] = list(dict.fromkeys(roles))
    additional = [
        str(x)
        for x in _list(incoming.get("additional_question_ids"))
        if str(x) in ADDITIONAL_BY_ID
    ]
    base["additional_question_ids"] = list(dict.fromkeys(additional))
    custom: List[Dict[str, Any]] = []
    for index, q in enumerate(_list(incoming.get("custom_questions"))):
        if isinstance(q, dict):
            custom.append(_sanitize_custom_question(q, index))
    base["custom_questions"] = custom
    active_ids = set(CORE_IDS + additional + [q["id"] for q in custom])
    order = [str(x) for x in _list(incoming.get("question_order")) if str(x) in active_ids]
    for qid in CORE_IDS + additional + [q["id"] for q in custom]:
        if qid not in order:
            order.append(qid)
    base["question_order"] = list(dict.fromkeys(order))
    base["version"] = 1
    base["template_version"] = TEMPLATE_VERSION
    return base


def _questions(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    available: Dict[str, Dict[str, Any]] = {q["id"]: dict(q) for q in CORE_QUESTIONS}
    for qid in config["additional_question_ids"]:
        available[qid] = dict(ADDITIONAL_BY_ID[qid])
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


def _survey_window(tournament: Dict[str, Any], data: Dict[str, Any]) -> Tuple[Optional[datetime], Optional[datetime]]:
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
    return min(starts).astimezone(timezone.utc), (max(ends) + timedelta(hours=48)).astimezone(timezone.utc)


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
    config = _normalized_config(data.get("final_survey"))
    manager = (
        await _is_admin(user_id)
        or "host" in roles
        or "head_judge" in roles
    )
    enabled = [role for role in roles if role in set(config["enabled_roles"])]
    opens_at, closes_at = _survey_window(tournament, data)
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
        "questions": _questions(config),
        "additional_question_bank": ADDITIONAL_QUESTIONS,
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
    unknown = set(answers) - set(by_id)
    if unknown:
        raise HTTPException(422, f"Nieznane pytania: {', '.join(sorted(unknown))}")
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
    tournament, data, old_config, access = await _access(tournament_id, current_user_id)
    if not access["can_manage"]:
        raise HTTPException(403, "Brak uprawnień do konfiguracji ankiety")
    if not body.enabled_roles:
        raise HTTPException(422, "Udostępnij ankietę co najmniej jednej roli")
    new_config = _normalized_config(body.model_dump())
    if access["phase"] == "closed":
        raise HTTPException(409, "Zamkniętej ankiety nie można już konfigurować")
    if access["phase"] == "open":
        old_roles = set(old_config["enabled_roles"])
        new_roles = set(new_config["enabled_roles"])
        comparable_old = {k: v for k, v in old_config.items() if k != "enabled_roles"}
        comparable_new = {k: v for k, v in new_config.items() if k != "enabled_roles"}
        if not old_roles.issubset(new_roles) or comparable_old != comparable_new:
            raise HTTPException(
                409,
                "Po otwarciu ankiety można tylko udostępnić ją dodatkowym rolom",
            )
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
    tournament, _data, config, access = await _access(tournament_id, current_user_id)
    if not access["can_respond"]:
        raise HTTPException(403, "Ankieta nie jest udostępniona dla Twojej roli")
    if access["phase"] != "open":
        if access["phase"] == "upcoming":
            raise HTTPException(409, "Ankieta nie jest jeszcze otwarta")
        if access["phase"] == "closed":
            raise HTTPException(409, "Ankieta jest już zamknięta")
        raise HTTPException(409, "Ankieta oczekuje na gotowy terminarz")

    answers = _validate_answers(body.answers, _questions(config), body.submit)
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
        "roles": perspectives,
        "role_labels": [ROLE_LABELS[role] for role in perspectives],
        "team_ids": access["team_ids"],
        "team_names": team_names,
        "genders": genders,
    }
    now = datetime.now(timezone.utc)
    existing = await _my_response(tournament_id, current_user_id)
    status = "submitted" if body.submit else "draft"
    values = {
        "status": status,
        "perspective_roles": perspectives,
        "answers_json": answers,
        "respondent_snapshot_json": snapshot,
        "template_version": TEMPLATE_VERSION,
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
        await database.execute(
            insert(beach_tournament_survey_responses).values(
                tournament_id=tournament_id,
                user_id=current_user_id,
                created_at=now,
                **values,
            )
        )
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
        numeric = [float(value) for value in values if isinstance(value, (int, float))]
        result["average"] = round(sum(numeric) / len(numeric), 2) if numeric else None
        distribution = Counter(str(int(value)) for value in numeric)
        result["distribution"] = dict(sorted(distribution.items(), key=lambda x: int(x[0])))
        if question["id"] == "return_likelihood" and numeric:
            promoters = sum(1 for value in numeric if value >= 9)
            detractors = sum(1 for value in numeric if value <= 6)
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

    questions = _questions(config)
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
    total_matching = len(rows)
    if access["phase"] == "closed":
        search_folded = (search or "").strip().casefold()
        visible_rows = rows
        if search_folded:
            visible_rows = [
                row
                for row in visible_rows
                if search_folded in str(row["respondent"].get("full_name") or "").casefold()
                or any(search_folded in str(name).casefold() for name in _list(row["respondent"].get("team_names")))
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
    if access["phase"] == "closed":
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
        "respondents_locked": access["phase"] != "closed",
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
    if access["phase"] != "closed":
        raise HTTPException(409, "Odpowiedzi imienne będą dostępne po zamknięciu ankiety")
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
        "questions": _questions(config),
    }

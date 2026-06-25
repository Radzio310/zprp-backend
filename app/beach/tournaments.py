from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import base64
import json
import logging
import os
from pathlib import Path
import random
import re
import traceback
import unicodedata
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Depends, File, Form, UploadFile
import httpx
from pydantic import BaseModel
from sqlalchemy import select, insert, update, delete

from app.db import database, beach_tournaments, beach_users, beach_admins, beach_proel_matches, beach_standings, beach_teams
from app.schemas import (
    CreateBeachTournamentRequest,
    UpdateBeachTournamentRequest,
    UpdateBeachTournamentAttendanceRequest,
    BeachTournamentItem,
    BeachTournamentsListResponse,
)
from app.deps import beach_get_current_user_id, beach_get_optional_user_id, get_settings
from app.beach.calendar import (
    delete_beach_tournament_google_for_users,
    sync_beach_tournament_google_for_users,
)
from app.beach.notifications import create_notification
from app.beach.capabilities import resolve_user_capabilities
from app.beach.schedule_notifications import notify_schedule_updated
from app.beach.activity_log import log_activity, get_actor_name, compute_diff, compute_list_diff

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/beach/tournaments", tags=["Beach: Tournaments"])


# ─────────────────── Pydantic models dla nowych endpointów ───────────────────

class HostUpdateRequest(BaseModel):
    """Dozwolone pola dla Gospodarza zawodów."""
    announcements: Optional[list] = None
    invited_team_ids: Optional[list] = None
    custom_teams: Optional[list] = None


class CoachCustomTeamUpdateRequest(BaseModel):
    """Trener aktualizuje swoją własną drużynę (custom team)."""
    custom_team_id: str
    custom_team: dict


class JudgeUpdateRequest(BaseModel):
    """Dozwolone pola dla Obsadowego."""
    judges: Optional[list] = None
    head_judge_id: Optional[int] = None
    required_judges: Optional[int] = None
    required_head_judges: Optional[int] = None
    judge_colors: Optional[dict] = None


class ScheduleUpdateRequest(BaseModel):
    """Harmonogram zawodów — admin lub Gospodarz zawodów."""
    schedule: Optional[dict] = None


class SettlementsUpdateRequest(BaseModel):
    """Zapis konfiguracji rozliczen sedziowskich w data_json.settlements."""
    settlements: Dict[str, Any]
    judge_id: Optional[int] = None


class SquadUpdateRequest(BaseModel):
    """Aktualizacja selekcji składu dla drużyny w turnieju."""
    team_id: Optional[int] = None                    # regular team id
    custom_team_id: Optional[str] = None             # custom team id (e.g. "ct_xxx")
    default_players: Optional[List] = None           # player_ids, max 10
    default_companions: Optional[List] = None        # person_ids, max 4
    default_companion_roles: Optional[Dict[str, str]] = None  # personId(str) → "A"|"B"|"C"|"D"
    protocol_players: Optional[List] = None          # player_ids for protocol sheet (max 15 Senior / 12 other)
    match_id: Optional[str] = None                   # jeśli override dla konkretnego meczu
    match_players: Optional[List] = None
    match_companions: Optional[List] = None
    match_companion_roles: Optional[Dict[str, str]] = None  # personId(str) → "A"|"B"|"C"|"D"
    signature_url: Optional[str] = None              # per-match coach signature URL


class TournamentTitleImageRequest(BaseModel):
    """Dane potrzebne do wygenerowania grafiki tytułowej turnieju."""
    tournament_id: Optional[int] = None
    name: str
    event_date: Optional[str] = None
    end_date: Optional[str] = None
    location: Optional[str] = None
    category: Optional[str] = None
    competition_type: Optional[str] = None
    regenerate: bool = False
    extra_prompt: Optional[str] = None


# ─────────────────── helpers ───────────────────

def _parse_json(raw: Any) -> dict:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, (list, tuple)):
        return {"_list": raw}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _static_root_dir() -> Path:
    volume_path = os.getenv("RAILWAY_VOLUME_MOUNT_PATH")
    if volume_path:
        return Path(volume_path) / "static"
    return Path(__file__).resolve().parents[2] / "static"


def _public_static_url(path: Path) -> str:
    rel = path.relative_to(_static_root_dir()).as_posix()
    return f"/static/{rel}"


_TITLE_IMAGE_VARIANTS = [
    {
        "scene": "one beach handball player seen from behind during a jump shot, ball raised, sand flying subtly",
        "camera": "medium close-up from a low sideline angle with shallow depth of field",
        "light": "golden evening sunset light",
    },
    {
        "scene": "wide empty beach handball court with a ball in the foreground and soft goal lines in the sand, no people",
        "camera": "wide cinematic establishing shot from court level",
        "light": "quiet early morning light with long soft shadows",
    },
    {
        "scene": "two athletes in natural motion, one defending and one preparing to shoot, seen from a diagonal side angle",
        "camera": "telephoto sports photo, slightly compressed background",
        "light": "bright midday beach sun with clean contrast",
    },
    {
        "scene": "single female athlete diving or landing on sand after a shot, dynamic but realistic, no posed team photo",
        "camera": "close action photograph with sand texture visible",
        "light": "warm late afternoon light",
    },
    {
        "scene": "beach handball ball and court markings dominating the frame, athletes blurred far in the background",
        "camera": "close foreground focus with natural background blur",
        "light": "soft morning sun",
    },
    {
        "scene": "one male player sprinting across the sand, photographed from behind and slightly to the side",
        "camera": "low tracking sports angle, motion implied but not blurry",
        "light": "sunny summer afternoon",
    },
    {
        "scene": "distant beach court scene with small silhouettes of players and more emphasis on sand, court, sky, and atmosphere",
        "camera": "far wide shot with clean negative space for app text",
        "light": "blue-hour evening light after sunset",
    },
    {
        "scene": "goal area and court lines with a ball rolling on sand, no visible faces, only partial athlete legs in the distance",
        "camera": "documentary-style sports detail shot",
        "light": "clear morning beach light",
    },
]


async def _check_name_unique(name: str, year: int, exclude_id: Optional[int] = None) -> None:
    """
    Raises HTTPException(409) if a tournament with the same name (case-insensitive, stripped)
    already exists in the same calendar year.
    """
    name_norm = name.strip().lower()
    all_rows = await database.fetch_all(
        select(beach_tournaments.c.id, beach_tournaments.c.name, beach_tournaments.c.event_date)
    )
    for row in all_rows:
        if exclude_id is not None and row["id"] == exclude_id:
            continue
        row_year = None
        if row["event_date"]:
            try:
                row_year = int(str(row["event_date"])[:4])
            except (ValueError, TypeError):
                pass
        if row_year == year and (row["name"] or "").strip().lower() == name_norm:
            raise HTTPException(
                409,
                detail={
                    "code": "DUPLICATE_TOURNAMENT_NAME",
                    "message": f"Turniej o nazwie \"{name.strip()}\" już istnieje w sezonie {year}.",
                },
            )


def _infer_gender_hint(name: str) -> str:
    """
    Infer athlete gender from Polish tournament name keywords.
    Returns an explicit gender instruction for the image prompt.
    """
    lower = name.lower()

    # Strong female indicators (Polish grammar: feminine forms)
    female_keywords = [
        "juniorek", "juniorki", "juniorka",
        "kobiet", "kobieca", "kobiecy",
        "pań", "panie",
        "seniorek", "seniorki",
        "dziewcząt", "dziewczyny", "dziewczyna",
        "uczniów szkół"  # context: often mixed but lean neutral
    ]
    # Strong male indicators (Polish grammar: masculine forms)
    male_keywords = [
        "juniorów", "juniora", "junior mł",
        "mężczyzn", "panów",
        "seniorów",
        "chłopców", "chłopiec",
    ]

    female_score = sum(1 for kw in female_keywords if kw in lower)
    male_score = sum(1 for kw in male_keywords if kw in lower)

    if female_score > male_score:
        return (
            "The athletes in this image MUST be female. Show only women players. "
            "Female beach handball players only, no men visible."
        )
    elif male_score > female_score:
        return (
            "The athletes in this image MUST be male. Show only men players. "
            "Male beach handball players only, no women visible."
        )
    else:
        return "Athletes may be male or female — choose freely based on the scene variant."


def _build_title_image_prompt(req: TournamentTitleImageRequest) -> str:
    location_hint = (req.location or "").strip()
    category_hint = (req.category or "turniej").strip()
    competition_hint = (req.competition_type or "").strip()
    date_hint = " ".join(
        x for x in [(req.event_date or "").strip(), (req.end_date or "").strip()] if x
    )
    variant = random.choice(_TITLE_IMAGE_VARIANTS)
    gender_hint = _infer_gender_hint(req.name)
    extra = (req.extra_prompt or "").strip()

    return (
        "Landscape realistic photo-style title image for a Polish beach handball tournament. "
        "It should look like a real editorial sports photograph, not a cartoon, not CGI, not artificial "
        "characters, not plastic-looking people. Avoid repetitive front-facing group poses and avoid always showing "
        "three people facing the camera. "
        f"Randomized scene direction: {variant['scene']}. "
        f"Camera direction: {variant['camera']}. "
        f"Time and light: {variant['light']}. "
        "Use natural athletes only if this variant includes people; otherwise focus on the ball, court, sand, goal lines, "
        "beach atmosphere, and real-world photographic lighting. "
        f"IMPORTANT — athlete gender: {gender_hint} "
        "Keep the composition minimalist and premium, with natural poses and believable sports photography. "
        "No text, no letters, no logos, no badges, no watermarks. "
        "Leave darker open space in the lower-left area for app overlay text. "
        "Use a premium mobile app tile composition, high contrast, readable background. "
        f"Tournament name inspiration: {req.name.strip()}. "
        f"Category: {category_hint}. "
        f"Date context: {date_hint or 'summer tournament'}. "
        f"Location inspiration: {location_hint or 'Polish beach town'}; "
        "if location is recognizable, include only a very subtle local reference in the scenery. "
        f"Competition type: {competition_hint or 'beach handball event'}."
        + (f" Additional context from organizer: {extra}" if extra else "")
    )


async def _get_title_image_regeneration_count(tournament_id: int) -> int:
    row = await database.fetch_one(
        select(beach_tournaments.c.data_json).where(beach_tournaments.c.id == tournament_id)
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono turnieju")
    data = _parse_json(dict(row)["data_json"])
    title_image = data.get("title_image") if isinstance(data.get("title_image"), dict) else {}
    try:
        return int(title_image.get("regeneration_count") or 0)
    except Exception:
        return 0


async def _generate_openai_title_image(prompt: str) -> bytes:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(500, "Brak OPENAI_API_KEY w środowisku serwera")

    model = os.getenv("OPENAI_IMAGE_MODEL", "gpt-image-1")
    payload = {
        "model": model,
        "prompt": prompt,
        "size": "1536x1024",
        "quality": os.getenv("OPENAI_IMAGE_QUALITY", "medium"),
        "n": 1,
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                "https://api.openai.com/v1/images/generations",
                headers=headers,
                json=payload,
            )
    except Exception:
        logger.exception("OpenAI title image request failed")
        raise HTTPException(502, "Nie udało się połączyć z OpenAI Images API")

    if resp.status_code >= 400:
        logger.error("OpenAI title image error %s: %s", resp.status_code, resp.text[:700])
        raise HTTPException(502, "OpenAI nie wygenerował grafiki turnieju")

    data = resp.json()
    image_item = (data.get("data") or [{}])[0]
    b64 = image_item.get("b64_json")
    if not b64 and image_item.get("url"):
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                image_resp = await client.get(image_item["url"])
            if image_resp.status_code < 400 and image_resp.content:
                return image_resp.content
        except Exception:
            logger.exception("OpenAI title image download failed")
    if not b64:
        raise HTTPException(502, "OpenAI zwrócił pustą grafikę")

    try:
        return base64.b64decode(b64)
    except Exception:
        raise HTTPException(502, "Nie udało się odczytać wygenerowanej grafiki")


def _extract_badge_names(badges_raw: Any) -> List[str]:
    if badges_raw is None:
        return []
    if isinstance(badges_raw, dict):
        return [str(k) for k, v in badges_raw.items() if v is not None and v]
    if isinstance(badges_raw, list):
        return [str(x) for x in badges_raw if x is not None]
    return []


def _roles_list(roles_raw: Any) -> List[dict]:
    if isinstance(roles_raw, list):
        return [r for r in roles_raw if isinstance(r, dict)]
    if isinstance(roles_raw, str):
        try:
            parsed = json.loads(roles_raw)
            if isinstance(parsed, list):
                return [r for r in parsed if isinstance(r, dict)]
        except Exception:
            return []
    return []


def _extract_team_ids(roles_raw: Any) -> List[int]:
    team_ids: List[int] = []
    for role in _roles_list(roles_raw):
        if role.get("verified") != "approved":
            continue
        if role.get("type") not in {"coach", "player"}:
            continue
        team_id = role.get("team_id")
        if isinstance(team_id, int) and team_id not in team_ids:
            team_ids.append(team_id)
    return team_ids


def _normalize_event_data(data_json: Any) -> Dict[str, Any]:
    base = _parse_json(data_json)

    target = base.get("target") if isinstance(base.get("target"), dict) else {}
    badge = target.get("badge")
    include_all = bool(target.get("include_all") or False)

    base["target"] = {
        "badge": (str(badge).strip() if badge else None),
        "include_all": include_all,
    }

    invited_ids = base.get("invited_ids") or []
    present_ids = base.get("present_ids") or []
    if not isinstance(invited_ids, list):
        invited_ids = []
    if not isinstance(present_ids, list):
        present_ids = []

    base["invited_ids"] = [str(x).strip() for x in invited_ids if str(x).strip()]
    base["present_ids"] = [str(x).strip() for x in present_ids if str(x).strip()]
    return base


async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    return bool(row)


async def _compute_invited_ids_for_badge(
    badge: Optional[str], data: Dict[str, Any]
) -> List[str]:
    target = data.get("target") or {}
    include_all = bool(target.get("include_all") or False)
    badge_eff = badge or target.get("badge") or None
    badge_eff = str(badge_eff).strip() if badge_eff else None

    rows = await database.fetch_all(select(beach_users.c.id, beach_users.c.badges))

    invited: List[str] = []
    for r in rows:
        uid = str(r["id"])
        if include_all or not badge_eff:
            invited.append(uid)
            continue
        bnames = set(_extract_badge_names(r["badges"]))
        if badge_eff in bnames:
            invited.append(uid)

    return sorted(list(set(invited)), key=lambda x: int(x) if x.isdigit() else x)


def _attach_computed_fields(
    row: Any,
    data: Dict[str, Any],
    user_id: Optional[int],
) -> BeachTournamentItem:
    row_d: Dict[str, Any] = dict(row) if not isinstance(row, dict) else row

    invited_ids = data.get("invited_ids") or []
    present_ids = data.get("present_ids") or []
    invited_set = set(str(x) for x in invited_ids)
    present_set = set(str(x) for x in present_ids)

    uid = str(user_id) if user_id is not None else None
    user_invited = bool(uid and uid in invited_set)
    user_present = bool(uid and uid in present_set)

    return BeachTournamentItem(
        id=int(row_d["id"]),
        badge=row_d.get("badge"),
        event_date=row_d["event_date"],
        end_date=row_d.get("end_date"),
        name=row_d["name"],
        description=row_d.get("description"),
        location=row_d.get("location"),
        category=row_d.get("category"),
        competition_type=row_d.get("competition_type"),
        data_json=data,
        updated_at=row_d["updated_at"],
        invited_total=len(invited_set),
        present_total=len(present_set & invited_set) if invited_set else len(present_set),
        user_invited=user_invited,
        user_present=user_present,
    )


def _calendar_involved_user_ids(data: Dict[str, Any]) -> List[int]:
    ids: set[int] = set()
    for value in data.get("invited_ids") or []:
        try:
            ids.add(int(value))
        except Exception:
            pass
    for host in data.get("hosts") or []:
        if isinstance(host, dict):
            value = host.get("id") or host.get("user_id")
            try:
                ids.add(int(value))
            except Exception:
                pass
    for judge in data.get("judges") or []:
        if isinstance(judge, dict):
            value = judge.get("user_id") or judge.get("id")
            try:
                ids.add(int(value))
            except Exception:
                pass
    try:
        if data.get("head_judge_id") is not None:
            ids.add(int(data.get("head_judge_id")))
    except Exception:
        pass
    return sorted(ids)


async def _sync_tournament_calendar_background(row_d: Dict[str, Any], data: Dict[str, Any]) -> None:
    tournament = {**row_d, "data_json": data}
    user_ids = _calendar_involved_user_ids(data)
    if not user_ids:
        return
    try:
        await sync_beach_tournament_google_for_users(
            tournament=tournament,
            user_ids=user_ids,
            settings=get_settings(),
        )
    except Exception:
        logger.exception("Failed scheduling calendar sync for tournament %s", row_d.get("id"))


async def _delete_tournament_calendar_background(tournament_id: int, data: Dict[str, Any]) -> None:
    user_ids = _calendar_involved_user_ids(data)
    if not user_ids:
        return
    try:
        await delete_beach_tournament_google_for_users(
            tournament_id=tournament_id,
            user_ids=user_ids,
            settings=get_settings(),
        )
    except Exception:
        logger.exception("Failed scheduling calendar delete for tournament %s", tournament_id)


async def _can_manage_tournament_schedule(
    data: Dict[str, Any],
    current_user_id: int,
) -> bool:
    if await _is_admin(current_user_id):
        return True

    user_row = await database.fetch_one(
        select(beach_users.c.badges).where(beach_users.c.id == current_user_id)
    )
    if not user_row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    caps = await resolve_user_capabilities(user_row["badges"])
    host_ids = {
        int(h["id"])
        for h in (data.get("hosts") or [])
        if isinstance(h, dict) and isinstance(h.get("id"), int)
    }
    judge_ids = {
        int(j["id"])
        for j in (data.get("judges") or [])
        if isinstance(j, dict) and isinstance(j.get("id"), int)
    }
    head_judge_id = data.get("head_judge_id")

    # Obsadowy / uprawnienie "gospodarz wszędzie" — zarządza każdym turniejem.
    if "tournament.actAsHostEverywhere" in caps:
        return True
    if "tournament.schedule.edit" in caps and current_user_id in host_ids:
        return True
    if isinstance(head_judge_id, int) and head_judge_id == current_user_id:
        return True
    if current_user_id in judge_ids:
        return True

    return False


# ─────────────────── CREATE ───────────────────

@router.post("/", response_model=dict, summary="Utwórz turniej (BEACH) — wymaga admina")
async def create_tournament(
    req: CreateBeachTournamentRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    user_row = await database.fetch_one(
        select(
            beach_users.c.id,
            beach_users.c.full_name,
            beach_users.c.judge_id,
            beach_users.c.badges,
        ).where(beach_users.c.id == current_user_id)
    )
    if not user_row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    is_admin_user = await _is_admin(current_user_id)
    caps = await resolve_user_capabilities(user_row["badges"])
    can_create = "tournament.create" in caps or "tournament.actAsHostEverywhere" in caps
    if not (is_admin_user or can_create):
        raise HTTPException(403, "Brak uprawnień")

    # "Gospodarz zawodów" tworzy turniej przez uprawnienie tournament.create,
    # ale nie ma globalnego tournament.actAsHostEverywhere — wtedy dopisujemy go
    # automatycznie do listy gospodarzy, by mógł zarządzać własnym turniejem.
    is_host_badge_user = (
        can_create and "tournament.actAsHostEverywhere" not in caps
    )

    if not req.name or not req.name.strip():
        raise HTTPException(400, "Brak nazwy")

    # Unique name per calendar year
    _event_year: Optional[int] = None
    if req.event_date:
        try:
            _event_year = int(str(req.event_date)[:4])
        except (ValueError, TypeError):
            pass
    if _event_year:
        await _check_name_unique(req.name.strip(), _event_year)

    now = datetime.now(timezone.utc)
    data = _normalize_event_data(req.data_json)

    if is_host_badge_user and not is_admin_user:
        hosts = [
            h
            for h in (data.get("hosts") or [])
            if isinstance(h, dict) and isinstance(h.get("id"), int)
        ]
        if not any(int(h["id"]) == current_user_id for h in hosts):
            hosts.append(
                {
                    "id": current_user_id,
                    "full_name": user_row["full_name"],
                    "judge_id": user_row["judge_id"] or None,
                }
            )
        data["hosts"] = hosts

    if not data.get("invited_ids"):
        data["invited_ids"] = await _compute_invited_ids_for_badge(req.badge, data)

    try:
        stmt = (
            insert(beach_tournaments)
            .values(
                badge=(req.badge.strip() if req.badge else None),
                event_date=req.event_date,
                end_date=req.end_date,
                name=req.name.strip(),
                description=(req.description or "").strip() or None,
                location=(req.location or "").strip() or None,
                category=req.category,
                competition_type=req.competition_type,
                data_json=data,
                updated_at=now,
            )
            .returning(beach_tournaments.c.id)
        )
        row = await database.fetch_one(stmt)
        if not row:
            raise HTTPException(500, "Nie udało się utworzyć turnieju")

        tournament_id = int(row["id"])

        # Notify all active users about new tournament in calendar
        all_users = await database.fetch_all(
            select(beach_users.c.id).where(beach_users.c.is_active == True)
        )
        all_user_ids = [int(r["id"]) for r in all_users]
        if all_user_ids:
            # Build detail line from available fields
            _cat = (req.category or "").strip()
            _ct = (req.competition_type or "").strip()
            _loc = (req.location or "").strip().split("|", 1)[0].strip()
            _date_from = str(req.event_date)[:10] if req.event_date else ""
            _date_to = str(req.end_date)[:10] if req.end_date else ""
            _dates = f"{_date_from} – {_date_to}" if _date_to and _date_to != _date_from else _date_from
            _detail_parts = [p for p in [_cat, _ct] if p]
            _detail = " · ".join(_detail_parts)
            _body_parts = [req.name.strip()]
            if _dates:
                _body_parts.append(f"📅 {_dates}")
            if _loc:
                _body_parts.append(f"📍 {_loc}")
            if _detail:
                _body_parts.append(_detail)
            await create_notification(
                notif_type="new_tournament_calendar",
                title="🏆 Nowy turniej w kalendarzu!",
                body="\n".join(_body_parts),
                data={"tournament_id": tournament_id},
                target_user_ids=all_user_ids,
            )

        await log_activity(
            area="tournament",
            action="tournament.created",
            actor_user_id=current_user_id,
            actor_name=await get_actor_name(current_user_id),
            target_id=str(tournament_id),
            target_label=req.name.strip(),
            details={
                "category": req.category,
                "competition_type": req.competition_type,
                "event_date": str(req.event_date)[:10] if req.event_date else None,
                "end_date": str(req.end_date)[:10] if req.end_date else None,
                "location": (req.location or "").strip() or None,
                "badge": (req.badge.strip() if req.badge else None),
            },
        )

        created_row = await database.fetch_one(
            select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
        )
        if created_row:
            created_d = dict(created_row)
            created_data = _normalize_event_data(created_d["data_json"])
            asyncio.ensure_future(_sync_tournament_calendar_background(created_d, created_data))

        return {"success": True, "id": tournament_id}
    except Exception as e:
        logger.error("create_tournament failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(500, f"create_tournament failed: {e}")


# ─────────────────── LIST (all tournaments) ───────────────────

@router.get(
    "/",
    response_model=BeachTournamentsListResponse,
    summary="Lista wszystkich turniejów dla zalogowanego użytkownika",
)
async def list_tournaments(
    badge: Optional[str] = Query(None),
    with_user: Optional[int] = Query(None),
    current_user_id: Optional[int] = Depends(beach_get_optional_user_id),
):
    q = select(beach_tournaments).order_by(
        beach_tournaments.c.event_date.asc(), beach_tournaments.c.id.asc()
    )
    if badge is not None:
        if badge.strip() == "":
            q = q.where(beach_tournaments.c.badge == None)  # noqa: E711
        else:
            q = q.where(beach_tournaments.c.badge == badge.strip())

    rows = await database.fetch_all(q)

    out: List[BeachTournamentItem] = []
    for r in rows:
        r_d = dict(r)
        data = _normalize_event_data(r_d["data_json"])
        if current_user_id is None and not bool((data.get("target") or {}).get("include_all", False)):
            continue
        if not data.get("invited_ids"):
            data["invited_ids"] = await _compute_invited_ids_for_badge(r_d.get("badge"), data)
        out.append(_attach_computed_fields(r_d, data, with_user))
    return BeachTournamentsListResponse(tournaments=out)


# ─────────────────── PUBLIC FEED (read-only, no auth) ───────────────────

@router.get(
    "/public_feed",
    response_model=BeachTournamentsListResponse,
    summary="Publiczny, read-only feed wszystkich turniejów (np. dla BAZA — bez logowania)",
)
async def list_public_feed_tournaments():
    """Zwraca wszystkie turnieje w trybie tylko-do-odczytu, bez wymogu logowania
    i bez filtra `include_all`. Wykorzystywane przez ekran „Co słychać na plaży?"
    w aplikacji BAZA do prezentacji nadchodzących turniejów."""
    rows = await database.fetch_all(
        select(beach_tournaments).order_by(
            beach_tournaments.c.event_date.asc(), beach_tournaments.c.id.asc()
        )
    )
    out: List[BeachTournamentItem] = []
    for r in rows:
        r_d = dict(r)
        data = _normalize_event_data(r_d["data_json"])
        out.append(_attach_computed_fields(r_d, data, None))
    return BeachTournamentsListResponse(tournaments=out)


# ─────────────────── LIST (visible for user) ───────────────────

@router.get(
    "/visible",
    response_model=BeachTournamentsListResponse,
    summary="Lista turniejów widocznych dla zalogowanego użytkownika",
)
async def list_visible_tournaments(
    current_user_id: Optional[int] = Depends(beach_get_optional_user_id),
):
    user_row = None
    if current_user_id is not None:
        user_row = await database.fetch_one(
            select(beach_users).where(beach_users.c.id == current_user_id)
        )
    if current_user_id is not None and not user_row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    user_team_ids = set(_extract_team_ids(user_row["roles"])) if user_row else set()

    rows = await database.fetch_all(
        select(beach_tournaments).order_by(
            beach_tournaments.c.event_date.asc(), beach_tournaments.c.id.asc()
        )
    )

    out: List[BeachTournamentItem] = []
    for r in rows:
        r_d = dict(r)

        data = _normalize_event_data(r_d["data_json"])
        if not data.get("invited_ids"):
            data["invited_ids"] = await _compute_invited_ids_for_badge(r_d.get("badge"), data)

        host_ids = {
            int(h["id"])
            for h in (data.get("hosts") or [])
            if isinstance(h, dict) and isinstance(h.get("id"), int)
        }
        judge_ids = {
            int(j["id"])
            for j in (data.get("judges") or [])
            if isinstance(j, dict) and isinstance(j.get("id"), int)
        }
        invited_set = set(str(x) for x in (data.get("invited_ids") or []))
        invited_team_ids = {
            int(team_id)
            for team_id in (data.get("invited_team_ids") or [])
            if isinstance(team_id, int)
        }
        custom_team_coach_ids = {
            int(ct["coach_user_id"])
            for ct in (data.get("custom_teams") or [])
            if isinstance(ct, dict) and isinstance(ct.get("coach_user_id"), int)
        }
        include_all = bool((data.get("target") or {}).get("include_all", False))
        if current_user_id is None:
            if include_all:
                out.append(_attach_computed_fields(r_d, data, None))
            continue

        user_is_host = current_user_id in host_ids
        user_is_judge = current_user_id in judge_ids
        user_team_invited = bool(user_team_ids & invited_team_ids)
        user_is_invited = str(current_user_id) in invited_set
        user_is_custom_coach = current_user_id in custom_team_coach_ids
        if not (
            include_all
            or user_is_invited
            or user_is_host
            or user_is_judge
            or user_team_invited
            or user_is_custom_coach
        ):
            continue

        out.append(_attach_computed_fields(r_d, data, current_user_id))

    return BeachTournamentsListResponse(tournaments=out)


# ─────────────────── GENERATE TITLE IMAGE ───────────────────

@router.post(
    "/generate-title-image",
    response_model=dict,
    summary="Wygeneruj grafikę tytułową turnieju (admin)",
)
async def generate_tournament_title_image(
    req: TournamentTitleImageRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    if not req.name or not req.name.strip():
        raise HTTPException(400, "Brak nazwy turnieju")

    current_regen_count = 0
    if req.tournament_id is not None:
        current_regen_count = await _get_title_image_regeneration_count(req.tournament_id)
        if req.regenerate and current_regen_count >= 2:
            raise HTTPException(400, "Limit regeneracji grafiki dla tego turnieju został wykorzystany")

    prompt = _build_title_image_prompt(req)
    image_bytes = await _generate_openai_title_image(prompt)

    out_dir = _static_root_dir() / "beach" / "tournaments" / "title-images"
    out_dir.mkdir(parents=True, exist_ok=True)
    file_path = out_dir / f"{uuid.uuid4().hex}.png"
    file_path.write_bytes(image_bytes)

    result = {
        "url": _public_static_url(file_path),
        "prompt": prompt,
        "model": os.getenv("OPENAI_IMAGE_MODEL", "gpt-image-1"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "regeneration_count": current_regen_count + 1 if req.regenerate else current_regen_count,
    }

    # ── Activity log ──
    await log_activity(
        area="tournament",
        action="tournament.title_image_generated",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(req.tournament_id) if req.tournament_id else None,
        target_label=req.name.strip(),
        details={"regenerate": req.regenerate, "model": result["model"]},
    )

    return result


# ─────────────────── GET single ───────────────────

@router.get(
    "/{tournament_id}",
    response_model=BeachTournamentItem,
    summary="Pobierz turniej po ID",
)
async def get_tournament(
    tournament_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    row = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono turnieju")

    row_d = dict(row)
    data = _normalize_event_data(row_d["data_json"])
    if not data.get("invited_ids"):
        data["invited_ids"] = await _compute_invited_ids_for_badge(row_d.get("badge"), data)

    if row_d.get("badge"):
        user_row = await database.fetch_one(
            select(beach_users.c.badges, beach_users.c.roles).where(
                beach_users.c.id == current_user_id
            )
        )
        if not user_row:
            raise HTTPException(404, "Użytkownik nie znaleziony")

        user_badges = set(_extract_badge_names(user_row["badges"]))
        user_team_ids = set(_extract_team_ids(user_row["roles"]))
        host_ids = {
            int(h["id"])
            for h in (data.get("hosts") or [])
            if isinstance(h, dict) and isinstance(h.get("id"), int)
        }
        judge_ids = {
            int(j["id"])
            for j in (data.get("judges") or [])
            if isinstance(j, dict) and isinstance(j.get("id"), int)
        }
        invited_team_ids = {
            int(team_id)
            for team_id in (data.get("invited_team_ids") or [])
            if isinstance(team_id, int)
        }
        invited_set = set(str(x) for x in (data.get("invited_ids") or []))
        include_all = bool((data.get("target") or {}).get("include_all", False))
        caps = await resolve_user_capabilities(user_row["badges"])
        has_access = (
            "tournament.actAsHostEverywhere" in caps
            or row_d.get("badge") in user_badges
            or include_all
            or str(current_user_id) in invited_set
            or current_user_id in host_ids
            or current_user_id in judge_ids
            or bool(user_team_ids & invited_team_ids)
        )
        if not has_access:
            raise HTTPException(403, "Brak dostępu")

    return _attach_computed_fields(row_d, data, current_user_id)


# ─────────────────── PATCH (admin) ───────────────────

@router.patch(
    "/{tournament_id}",
    response_model=BeachTournamentItem,
    summary="Częściowa edycja turnieju — wymaga admina",
)
async def patch_tournament(
    tournament_id: int,
    body: UpdateBeachTournamentRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    existing = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not existing:
        raise HTTPException(404, "Nie znaleziono turnieju")

    existing_d = dict(existing)
    old_invited = set(str(x) for x in (_normalize_event_data(existing_d["data_json"]).get("invited_ids") or []))

    update_data: Dict[str, Any] = {}
    fields = getattr(body, "__fields_set__", set())

    if "badge" in fields:
        update_data["badge"] = body.badge.strip() if body.badge else None
    if body.event_date is not None:
        update_data["event_date"] = body.event_date
    if "end_date" in fields:
        update_data["end_date"] = body.end_date
    if body.name is not None:
        new_name = body.name.strip()
        # Unique name per calendar year — use the event_date being set or the existing one
        _eff_date = body.event_date if body.event_date is not None else existing_d.get("event_date")
        _year: Optional[int] = None
        if _eff_date:
            try:
                _year = int(str(_eff_date)[:4])
            except (ValueError, TypeError):
                pass
        if _year and new_name.lower() != (existing_d.get("name") or "").strip().lower():
            await _check_name_unique(new_name, _year, exclude_id=tournament_id)
        update_data["name"] = new_name
    if "description" in fields:
        update_data["description"] = (body.description or "").strip() or None
        update_data["location"] = (body.location or "").strip() or None
    if "category" in fields:
        update_data["category"] = body.category
    if "competition_type" in fields:
        update_data["competition_type"] = body.competition_type
    if body.data_json is not None:
        update_data["data_json"] = _normalize_event_data(body.data_json)

    if not update_data:
        data = _normalize_event_data(existing_d["data_json"])
        if not data.get("invited_ids"):
            data["invited_ids"] = await _compute_invited_ids_for_badge(
                existing_d.get("badge"), data
            )
        return _attach_computed_fields(existing_d, data, None)

    update_data["updated_at"] = datetime.now(timezone.utc)

    if "data_json" in update_data or "badge" in update_data:
        badge_eff = update_data.get("badge", existing_d.get("badge"))
        data_eff = _normalize_event_data(update_data.get("data_json", existing_d["data_json"]))
        if not data_eff.get("invited_ids"):
            data_eff["invited_ids"] = await _compute_invited_ids_for_badge(badge_eff, data_eff)
        update_data["data_json"] = data_eff

    await database.execute(
        update(beach_tournaments)
        .where(beach_tournaments.c.id == tournament_id)
        .values(**update_data)
    )

    row = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    row_d = dict(row)
    data2 = _normalize_event_data(row_d["data_json"])
    if not data2.get("invited_ids"):
        data2["invited_ids"] = await _compute_invited_ids_for_badge(row_d.get("badge"), data2)

    # Notify newly invited users about tournament assignment
    new_invited = set(str(x) for x in (data2.get("invited_ids") or []))
    newly_added = new_invited - old_invited
    if newly_added:
        tour_name = row_d.get("name", "Turniej")
        _ev = row_d.get("event_date")
        _end = row_d.get("end_date")
        _loc = (row_d.get("location") or "").strip().split("|", 1)[0].strip()
        _cat = (row_d.get("category") or "").strip()
        _date_from = str(_ev)[:10] if _ev else ""
        _date_to = str(_end)[:10] if _end else ""
        _dates = f"{_date_from} – {_date_to}" if _date_to and _date_to != _date_from else _date_from
        _body_parts = [tour_name]
        if _dates:
            _body_parts.append(f"📅 {_dates}")
        if _loc:
            _body_parts.append(f"📍 {_loc}")
        if _cat:
            _body_parts.append(_cat)
        await create_notification(
            notif_type="tournament_assigned",
            title="🏆 Zostałeś przypisany do turnieju!",
            body="\n".join(_body_parts),
            data={"tournament_id": tournament_id},
            target_user_ids=[int(uid) for uid in newly_added],
        )

    # ── Activity log ──
    diff_fields = {}
    for key in ("name", "event_date", "end_date", "location", "category", "competition_type", "badge", "description"):
        old_val = existing_d.get(key)
        new_val = row_d.get(key)
        if key in ("event_date", "end_date"):
            old_val = str(old_val)[:10] if old_val else None
            new_val = str(new_val)[:10] if new_val else None
        if old_val != new_val:
            diff_fields[key] = {"old": old_val, "new": new_val}
    if old_invited != new_invited:
        diff_fields["invited_ids"] = {"added": sorted(newly_added), "removed": sorted(old_invited - new_invited), "count_before": len(old_invited), "count_after": len(new_invited)}

    await log_activity(
        area="tournament",
        action="tournament.updated",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(tournament_id),
        target_label=row_d.get("name", ""),
        details={"changed_fields": diff_fields} if diff_fields else None,
    )

    asyncio.ensure_future(_sync_tournament_calendar_background(row_d, data2))
    return _attach_computed_fields(row_d, data2, None)


# ─────────────────── PATCH host-update (Gospodarz zawodów) ───────────────────

@router.patch(
    "/{tournament_id}/host-update",
    response_model=BeachTournamentItem,
    summary="Aktualizacja przez Gospodarza zawodów (ogłoszenia, drużyny)",
)
async def host_update_tournament(
    tournament_id: int,
    body: HostUpdateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    """
    Endpoint dla Gospodarza zawodów. Pozwala aktualizować:
    - data_json.announcements
    - data_json.invited_team_ids

    Wymaga: badge "Gospodarz zawodów" + user.id w data_json.hosts[].id
    """
    existing = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not existing:
        raise HTTPException(404, "Nie znaleziono turnieju")

    existing_d = dict(existing)
    data = _parse_json(existing_d["data_json"])

    # Admin może używać tego endpointu bez badge'a "Gospodarz zawodów"
    user_is_admin = await _is_admin(current_user_id)

    if not user_is_admin:
        user_row = await database.fetch_one(
            select(beach_users.c.badges).where(beach_users.c.id == current_user_id)
        )
        if not user_row:
            raise HTTPException(404, "Użytkownik nie znaleziony")

        caps = await resolve_user_capabilities(user_row["badges"])

        # "Gospodarz wszędzie" (Obsadowy) zarządza każdym turniejem.
        if "tournament.actAsHostEverywhere" not in caps:
            if "tournament.announcements.edit" not in caps:
                raise HTTPException(403, "Brak uprawnień do edycji ogłoszeń")

            # Sprawdź czy user jest hostem tego konkretnego turnieju
            hosts = data.get("hosts") or []
            host_ids = {int(h["id"]) for h in hosts if isinstance(h, dict) and "id" in h}
            if current_user_id not in host_ids:
                raise HTTPException(403, "Nie jesteś gospodarzem tych zawodów")

    # Scal tylko dozwolone pola (nie nadpisuj reszty data_json)
    old_announcements_count = len(data.get("announcements") or [])

    if body.announcements is not None:
        data["announcements"] = body.announcements
    if body.invited_team_ids is not None:
        data["invited_team_ids"] = body.invited_team_ids
    if body.custom_teams is not None:
        data["custom_teams"] = body.custom_teams

    await database.execute(
        update(beach_tournaments)
        .where(beach_tournaments.c.id == tournament_id)
        .values(data_json=data, updated_at=datetime.now(timezone.utc))
    )

    # Notify invited users about new announcement
    if body.announcements is not None and len(body.announcements) > old_announcements_count:
        invited_ids = data.get("invited_ids") or []
        target_ids = [int(uid) for uid in invited_ids if uid is not None]
        if target_ids:
            tour_name = existing_d.get("name", "Turniej")
            new_ann = body.announcements[old_announcements_count:]
            ann_preview = new_ann[0].get("text", "") if new_ann and isinstance(new_ann[0], dict) else ""
            if ann_preview and len(ann_preview) > 100:
                ann_preview = ann_preview[:100] + "…"
            ann_body = f"📯 {tour_name}"
            if ann_preview:
                ann_body += f"\n\u201c{ann_preview}\u201d"
            await create_notification(
                notif_type="new_announcement",
                title="📢 Nowe ogłoszenie od Gospodarza",
                body=ann_body,
                data={"tournament_id": tournament_id},
                target_user_ids=target_ids,
            )

    row = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    row_d = dict(row)
    data2 = _normalize_event_data(row_d["data_json"])
    if not data2.get("invited_ids"):
        data2["invited_ids"] = await _compute_invited_ids_for_badge(row_d.get("badge"), data2)

    # ── Activity log ──
    details: Dict[str, Any] = {}
    if body.announcements is not None:
        details["announcements_count_before"] = old_announcements_count
        details["announcements_count_after"] = len(body.announcements)
    if body.invited_team_ids is not None:
        details["invited_team_ids"] = body.invited_team_ids
    if body.custom_teams is not None:
        details["custom_teams_count"] = len(body.custom_teams)
    await log_activity(
        area="tournament",
        action="tournament.host_updated",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(tournament_id),
        target_label=row_d.get("name", ""),
        details=details or None,
    )

    asyncio.ensure_future(_sync_tournament_calendar_background(row_d, data2))
    return _attach_computed_fields(row_d, data2, current_user_id)


# ─────────────── PATCH coach-custom-team-update (Trener) ─────────────────

@router.patch(
    "/{tournament_id}/coach-custom-team-update",
    response_model=BeachTournamentItem,
    summary="Trener aktualizuje swoją własną drużynę (custom team)",
)
async def coach_custom_team_update(
    tournament_id: int,
    body: CoachCustomTeamUpdateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    existing = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not existing:
        raise HTTPException(404, "Nie znaleziono turnieju")

    existing_d = dict(existing)
    data = _parse_json(existing_d["data_json"])

    user_is_admin = await _is_admin(current_user_id)

    # Find the custom team and verify coach ownership (or admin)
    custom_teams = data.get("custom_teams") or []
    team_idx = None
    for idx, ct in enumerate(custom_teams):
        if isinstance(ct, dict) and ct.get("id") == body.custom_team_id:
            team_idx = idx
            break

    if team_idx is None:
        raise HTTPException(404, "Nie znaleziono drużyny")

    if not user_is_admin:
        existing_ct = custom_teams[team_idx]
        if existing_ct.get("coach_user_id") != current_user_id:
            raise HTTPException(403, "Nie jesteś trenerem tej drużyny")

    # Merge: preserve the id and coach_user_id from existing, update the rest
    updated_ct = body.custom_team
    updated_ct["id"] = body.custom_team_id
    # Preserve coach_user_id unless admin explicitly changes it
    if not user_is_admin and "coach_user_id" in custom_teams[team_idx]:
        updated_ct["coach_user_id"] = custom_teams[team_idx]["coach_user_id"]

    custom_teams[team_idx] = updated_ct
    data["custom_teams"] = custom_teams

    await database.execute(
        update(beach_tournaments)
        .where(beach_tournaments.c.id == tournament_id)
        .values(data_json=data, updated_at=datetime.now(timezone.utc))
    )

    row = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    row_d = dict(row)
    data2 = _normalize_event_data(row_d["data_json"])
    if not data2.get("invited_ids"):
        data2["invited_ids"] = await _compute_invited_ids_for_badge(row_d.get("badge"), data2)

    # ── Activity log ──
    await log_activity(
        area="tournament",
        action="tournament.coach_team_updated",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(tournament_id),
        target_label=row_d.get("name", ""),
        details={"custom_team_id": body.custom_team_id, "team_name": updated_ct.get("name")},
    )

    asyncio.ensure_future(_sync_tournament_calendar_background(row_d, data2))
    return _attach_computed_fields(row_d, data2, current_user_id)


# ─────────────────── PATCH judge-update (Obsadowy) ───────────────────

@router.patch(
    "/{tournament_id}/judge-update",
    response_model=BeachTournamentItem,
    summary="Aktualizacja obsady sędziowskiej (Obsadowy lub admin)",
)
async def judge_update_tournament(
    tournament_id: int,
    body: JudgeUpdateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    """
    Endpoint dla Obsadowego (lub admina). Pozwala aktualizować:
    - data_json.judges
    - data_json.head_judge_id

    Wymaga: badge "Obsadowy" lub bycia adminem.
    """
    existing = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not existing:
        raise HTTPException(404, "Nie znaleziono turnieju")

    existing_d = dict(existing)
    data = _parse_json(existing_d["data_json"])

    # Sprawdź uprawnienia: admin lub uprawnienia do zarządzania sędziami
    is_admin_flag = await _is_admin(current_user_id)
    if not is_admin_flag:
        user_row = await database.fetch_one(
            select(beach_users.c.badges).where(beach_users.c.id == current_user_id)
        )
        if not user_row:
            raise HTTPException(404, "Użytkownik nie znaleziony")
        caps = await resolve_user_capabilities(user_row["badges"])
        judge_mgmt_caps = {
            "tournament.actAsHostEverywhere",
            "tournament.judges.manageHead",
            "tournament.judges.addField",
            "tournament.judges.addTable",
            "tournament.judges.assignField",
            "tournament.judges.assignTable",
        }
        if not (caps & judge_mgmt_caps):
            raise HTTPException(403, "Brak uprawnień do zarządzania sędziami")

    # Aktualizuj tylko dozwolone pola
    old_judge_ids = set()
    for j in (data.get("judges") or []):
        if isinstance(j, dict) and j.get("user_id"):
            old_judge_ids.add(int(j["user_id"]))

    if body.judges is not None:
        data["judges"] = body.judges

    # head_judge_id: obsługa explicit None (reset) vs. brak w body
    fields_set = getattr(body, "model_fields_set", None) or getattr(body, "__fields_set__", set())
    if "head_judge_id" in fields_set:
        data["head_judge_id"] = body.head_judge_id  # może być None = reset

    if body.required_judges is not None:
        data["required_judges"] = body.required_judges
    if body.required_head_judges is not None:
        data["required_head_judges"] = body.required_head_judges
    if body.judge_colors is not None:
        data["judge_colors"] = body.judge_colors

    await database.execute(
        update(beach_tournaments)
        .where(beach_tournaments.c.id == tournament_id)
        .values(data_json=data, updated_at=datetime.now(timezone.utc))
    )

    # Notify newly assigned judges
    if body.judges is not None:
        new_judge_ids = set()
        for j in body.judges:
            if isinstance(j, dict) and j.get("user_id"):
                new_judge_ids.add(int(j["user_id"]))
        newly_assigned = new_judge_ids - old_judge_ids
        if newly_assigned:
            tour_name = existing_d.get("name", "Turniej")
            _ev2 = existing_d.get("event_date")
            _loc2 = (existing_d.get("location") or "").strip().split("|", 1)[0].strip()
            _date2 = str(_ev2)[:10] if _ev2 else ""
            _body_j = f"🏆 {tour_name}"
            if _date2:
                _body_j += f"\n📅 {_date2}"
            if _loc2:
                _body_j += f" · 📍 {_loc2}"
            await create_notification(
                notif_type="new_match_as_judge",
                title="🧑\u200d⚖️ Zostałeś wyznaczony na sędziego!",
                body=_body_j,
                data={"tournament_id": tournament_id},
                target_user_ids=list(newly_assigned),
            )

    row = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    row_d = dict(row)
    data2 = _normalize_event_data(row_d["data_json"])
    if not data2.get("invited_ids"):
        data2["invited_ids"] = await _compute_invited_ids_for_badge(row_d.get("badge"), data2)

    # ── Activity log ──
    new_judge_ids_log = set()
    if body.judges is not None:
        for j in body.judges:
            if isinstance(j, dict) and j.get("user_id"):
                new_judge_ids_log.add(int(j["user_id"]))
    judge_diff = compute_list_diff(
        sorted(old_judge_ids), sorted(new_judge_ids_log)
    ) if body.judges is not None else None
    await log_activity(
        area="tournament",
        action="tournament.judges_updated",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(tournament_id),
        target_label=existing_d.get("name", ""),
        details={
            "judges_diff": judge_diff,
            "head_judge_id": data.get("head_judge_id"),
        },
    )

    asyncio.ensure_future(_sync_tournament_calendar_background(row_d, data2))
    return _attach_computed_fields(row_d, data2, current_user_id)


# ─────────────────── helpers for schedule-update logging ───────────────────

def _detect_score_changes(
    old_schedule: Optional[Dict],
    new_schedule: Optional[Dict],
) -> List[Dict[str, Any]]:
    """Return list of matches whose score or status changed between two schedule versions."""
    if not old_schedule or not new_schedule:
        return []
    old_matches = {
        m["id"]: m for m in (old_schedule.get("matches") or [])
        if m.get("id") and m.get("kind") not in ("court_break", "tournament_opening")
    }
    changes = []
    for m in (new_schedule.get("matches") or []):
        mid = m.get("id")
        if not mid or m.get("kind") in ("court_break", "tournament_opening"):
            continue
        om = old_matches.get(mid)
        if not om:
            continue
        if (
            om.get("scoreA") != m.get("scoreA")
            or om.get("scoreB") != m.get("scoreB")
            or om.get("status") != m.get("status")
        ):
            ta = m.get("teamA") or om.get("teamA") or {}
            tb = m.get("teamB") or om.get("teamB") or {}
            changes.append({
                "match_id": mid,
                "team_a": ta.get("name", "TBD") if isinstance(ta, dict) else "TBD",
                "team_b": tb.get("name", "TBD") if isinstance(tb, dict) else "TBD",
                "score_a": m.get("scoreA"),
                "score_b": m.get("scoreB"),
                "sets": m.get("sets"),
                "status": m.get("status"),
                "gender": m.get("gender", ""),
            })
    return changes


# ─────────────────── PATCH schedule-update (Admin / Gospodarz zawodów) ───────────────────

@router.patch(
    "/{tournament_id}/schedule-update",
    response_model=BeachTournamentItem,
    summary="Aktualizacja harmonogramu zawodów (admin lub Gospodarz zawodów)",
)
async def schedule_update_tournament(
    tournament_id: int,
    body: ScheduleUpdateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    """
    Endpoint do zapisu/aktualizacji harmonogramu turnieju.
    Pozwala aktualizować: data_json.schedule

    Wymaga: admin LUB (badge "Gospodarz zawodów" + user.id w data_json.hosts[].id)
    """
    existing = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not existing:
        raise HTTPException(404, "Nie znaleziono turnieju")

    existing_d = dict(existing)
    data = _parse_json(existing_d["data_json"])

    if not await _can_manage_tournament_schedule(data, current_user_id):
        raise HTTPException(403, "Brak uprawnień do aktualizacji harmonogramu")

    # Capture old schedule before overwriting (for diff-based notifications)
    old_schedule = data.get("schedule") if isinstance(data.get("schedule"), dict) else None

    # Basic sanity check
    if body.schedule is not None:
        if not isinstance(body.schedule, dict):
            raise HTTPException(422, "schedule musi być obiektem")

        # Conflict detection: odrzuć jeśli serwer ma nowszą wersję niż klient.
        # Zapobiega sytuacji gdy stary terminarz (np. sprzed zmiany kolejności)
        # nadpisze nowszy (już zapisany przez tego lub innego użytkownika).
        existing_schedule = data.get("schedule") or {}
        server_saved_at = existing_schedule.get("saved_at")
        client_saved_at = body.schedule.get("saved_at")
        if (
            server_saved_at
            and client_saved_at
            and server_saved_at > client_saved_at
        ):
            raise HTTPException(
                409,
                detail={
                    "code": "SCHEDULE_CONFLICT",
                    "message": "Harmonogram zmieniony przez innego użytkownika. Odśwież dane.",
                    "server_saved_at": server_saved_at,
                },
            )

        # Serwer stempluje czas zapisu — klient nie ustawia saved_at samodzielnie
        new_schedule = dict(body.schedule)
        new_schedule["saved_at"] = datetime.now(timezone.utc).isoformat()
        data["schedule"] = new_schedule
    else:
        # Explicit null → delete schedule
        data.pop("schedule", None)

    await database.execute(
        update(beach_tournaments)
        .where(beach_tournaments.c.id == tournament_id)
        .values(data_json=data, updated_at=datetime.now(timezone.utc))
    )

    # Fire schedule notifications (fire-and-forget)
    tour_name = existing_d.get("name", "Turniej")
    asyncio.ensure_future(
        notify_schedule_updated(
            tournament_id=tournament_id,
            tour_name=tour_name,
            old_schedule=old_schedule,
            new_schedule=body.schedule,
        )
    )

    row = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    row_d = dict(row)
    data2 = _normalize_event_data(row_d["data_json"])
    if not data2.get("invited_ids"):
        data2["invited_ids"] = await _compute_invited_ids_for_badge(row_d.get("badge"), data2)

    # ── Activity log ──
    def _real_match_count(sched):
        if not isinstance(sched, dict):
            return 0
        return sum(1 for m in sched.get("matches", []) if m.get("kind") not in ("court_break", "tournament_opening"))

    old_match_count = _real_match_count(old_schedule)
    new_match_count = _real_match_count(body.schedule)
    actor_name = await get_actor_name(current_user_id)

    # Score save: detect which match scores changed → log as match.score_saved (not schedule_updated)
    score_changes = _detect_score_changes(old_schedule, body.schedule)

    # Schedule published: status flipped to "published"
    is_publish = (
        old_schedule is not None
        and old_schedule.get("status") != "published"
        and isinstance(body.schedule, dict)
        and body.schedule.get("status") == "published"
    )

    if score_changes:
        for change in score_changes:
            sa, sb = change["score_a"], change["score_b"]
            score_str = f"{sa}:{sb}" if sa is not None and sb is not None else "—"
            sets = change.get("sets") or []
            sets_str = " ".join(f"{s.get('ptA', '?')}:{s.get('ptB', '?')}" for s in sets) if sets else ""
            await log_activity(
                area="tournament",
                action="match.score_saved",
                actor_user_id=current_user_id,
                actor_name=actor_name,
                target_id=str(tournament_id),
                target_label=tour_name,
                details={
                    "match": f"{change['team_a']} vs {change['team_b']}",
                    "score": score_str,
                    "sets": sets_str or None,
                    "gender": change["gender"],
                    "status": change["status"],
                },
            )
        # If score save also changed match count (rare), log structural change too
        if old_match_count != new_match_count:
            await log_activity(
                area="tournament",
                action="tournament.schedule_updated",
                actor_user_id=current_user_id,
                actor_name=actor_name,
                target_id=str(tournament_id),
                target_label=tour_name,
                details={"matches_before": old_match_count, "matches_after": new_match_count, "schedule_cleared": False},
            )
    elif is_publish:
        await log_activity(
            area="tournament",
            action="tournament.schedule_published",
            actor_user_id=current_user_id,
            actor_name=actor_name,
            target_id=str(tournament_id),
            target_label=tour_name,
            details=None,
        )
    else:
        await log_activity(
            area="tournament",
            action="tournament.schedule_updated",
            actor_user_id=current_user_id,
            actor_name=actor_name,
            target_id=str(tournament_id),
            target_label=tour_name,
            details={"matches_before": old_match_count, "matches_after": new_match_count, "schedule_cleared": body.schedule is None},
        )

    asyncio.ensure_future(_sync_tournament_calendar_background(row_d, data2))
    return _attach_computed_fields(row_d, data2, current_user_id)


# ─────────────────── AI SCHEDULE IMPORT ───────────────────

@router.patch(
    "/{tournament_id}/settlements-update",
    response_model=BeachTournamentItem,
    summary="Zapis rozliczen sedziowskich turnieju",
)
async def settlements_update_tournament(
    tournament_id: int,
    body: SettlementsUpdateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    existing = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not existing:
        raise HTTPException(404, "Nie znaleziono turnieju")

    existing_d = dict(existing)
    data = _parse_json(existing_d["data_json"])
    incoming = body.settlements or {}
    if not isinstance(incoming, dict):
        raise HTTPException(422, "settlements musi byc obiektem")

    is_admin_flag = await _is_admin(current_user_id)
    head_judge_id = data.get("head_judge_id")
    is_head_judge = isinstance(head_judge_id, int) and head_judge_id == current_user_id
    judge_ids = {
        int(j.get("id"))
        for j in (data.get("judges") or [])
        if isinstance(j, dict) and j.get("id") is not None
    }
    is_assigned_judge = current_user_id in judge_ids

    if not (is_admin_flag or is_head_judge or is_assigned_judge):
        raise HTTPException(403, "Brak uprawnien do zapisu rozliczen")

    current_store = data.get("settlements") if isinstance(data.get("settlements"), dict) else {}
    if is_admin_flag or is_head_judge:
        data["settlements"] = incoming
    else:
        target_id = body.judge_id or current_user_id
        if int(target_id) != current_user_id:
            raise HTTPException(403, "Mozesz zapisac tylko swoje rozliczenie")
        next_store = dict(current_store)
        next_store["version"] = 1
        if current_store.get("categoryOverride") is not None:
            next_store["categoryOverride"] = current_store.get("categoryOverride")
        judges_current = current_store.get("judges") if isinstance(current_store.get("judges"), dict) else {}
        judges_incoming = incoming.get("judges") if isinstance(incoming.get("judges"), dict) else {}
        target_key = str(current_user_id)
        judges_next = dict(judges_current)
        judges_next[target_key] = judges_incoming.get(target_key, judges_current.get(target_key, {}))
        next_store["judges"] = judges_next
        data["settlements"] = next_store

    await database.execute(
        update(beach_tournaments)
        .where(beach_tournaments.c.id == tournament_id)
        .values(data_json=data, updated_at=datetime.now(timezone.utc))
    )

    row = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    row_d = dict(row)
    data2 = _normalize_event_data(row_d["data_json"])
    await log_activity(
        area="tournament",
        action="tournament.settlements_updated",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(tournament_id),
        target_label=row_d.get("name", ""),
        details={"judge_id": body.judge_id},
    )
    return _attach_computed_fields(row_d, data2, current_user_id)


# ─────────────────── PATCH disq-update (Sędzia główny / boiskowy / admin) ───────────────────

class DisqUpdateRequest(BaseModel):
    """Zapis decyzji dyskwalifikacyjnych w data_json.disqualifications."""
    disqualifications: list


@router.patch(
    "/{tournament_id}/disq-update",
    response_model=BeachTournamentItem,
    summary="Aktualizacja decyzji dyskwalifikacyjnych turnieju",
)
async def disq_update_tournament(
    tournament_id: int,
    body: DisqUpdateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    """
    Endpoint dla sędziego głównego, sędziego boiskowego lub admina.
    Zapisuje data_json.disqualifications.
    Po zapisaniu nowej decyzji (decided_at ustawione) wysyła push do zawodnika i trenerów drużyny.
    """
    existing = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not existing:
        raise HTTPException(404, "Nie znaleziono turnieju")

    existing_d = dict(existing)
    data = _parse_json(existing_d["data_json"])

    is_admin_flag = await _is_admin(current_user_id)
    head_judge_id = data.get("head_judge_id")
    is_head_judge = isinstance(head_judge_id, int) and head_judge_id == current_user_id
    judge_ids = {
        int(j.get("id"))
        for j in (data.get("judges") or [])
        if isinstance(j, dict) and j.get("id") is not None
    }
    is_assigned_judge = current_user_id in judge_ids

    if not (is_admin_flag or is_head_judge or is_assigned_judge):
        raise HTTPException(403, "Brak uprawnień do zapisu decyzji dyskwalifikacyjnych")

    # Znajdź nowo zdecydowane wpisy (compared to old list)
    old_decided_ids = {
        d.get("id")
        for d in (data.get("disqualifications") or [])
        if isinstance(d, dict) and d.get("decided_at")
    }
    data["disqualifications"] = body.disqualifications

    await database.execute(
        update(beach_tournaments)
        .where(beach_tournaments.c.id == tournament_id)
        .values(data_json=data, updated_at=datetime.now(timezone.utc))
    )

    # Wyślij powiadomienia dla nowo zdecydowanych dyskwalifikacji
    tour_name = existing_d.get("name", "Turniej")
    for disq in body.disqualifications:
        if not isinstance(disq, dict):
            continue
        if not disq.get("decided_at"):
            continue
        if disq.get("id") in old_decided_ids:
            continue  # Already notified before

        player_name = disq.get("player_name", "Zawodnik")
        ban_matches = disq.get("ban_matches", 0)
        ban_str = f"{ban_matches} meczów" if ban_matches else "decyzja w toku"
        notif_title = "Decyzja o dyskwalifikacji"
        notif_body = f"{player_name}: zawieszenie na {ban_str} — {tour_name}"

        target_ids: list[int] = []
        # Player
        if disq.get("player_id"):
            try:
                target_ids.append(int(disq["player_id"]))
            except (ValueError, TypeError):
                pass

        # Coaches of the team (via beach_users.roles JSON array)
        team_id = disq.get("team_id")
        if team_id:
            try:
                from sqlalchemy import text as sa_text
                coach_rows = await database.fetch_all(
                    sa_text("""
                        SELECT id FROM beach_users
                        WHERE EXISTS (
                            SELECT 1 FROM jsonb_array_elements(roles) r
                            WHERE r->>'type' = 'coach'
                            AND r->>'verified' = 'approved'
                            AND (r->>'team_id')::int = :team_id
                        )
                    """).bindparams(team_id=int(team_id))
                )
                for row in coach_rows:
                    uid = row["id"]
                    if uid and uid not in target_ids:
                        target_ids.append(uid)
            except Exception:
                pass  # Błąd zapytania — pomijamy trenerów

        if target_ids:
            await create_notification(
                notif_type="player_disqualified",
                title=notif_title,
                body=notif_body,
                data={"tournament_id": tournament_id, "disq_id": disq.get("id"), "tab": "disqualifications"},
                target_user_ids=target_ids,
            )

    row = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    row_d = dict(row)
    data2 = _normalize_event_data(row_d["data_json"])
    if not data2.get("invited_ids"):
        data2["invited_ids"] = await _compute_invited_ids_for_badge(row_d.get("badge"), data2)

    await log_activity(
        area="tournament",
        action="tournament.disqualifications_updated",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(tournament_id),
        target_label=existing_d.get("name", ""),
        details={"count": len(body.disqualifications)},
    )
    return _attach_computed_fields(row_d, data2, current_user_id)


_SCHEDULE_JSON_SCHEMA = """\
{
  "config": {
    "mode": "roundRobin" | "groupsPlusKnockout",
    "courts": 1 | 2 | 3,
    "slotInterval": <number, minutes between matches on same court, default 40>,
    "minTeamBreak": <number, default 15>,
    "thirdPlace": <boolean>,
    "fifthPlace": <boolean, optional>,
    "knockoutFormat": "semis" | "quarters" (optional),
    "knockoutFormatM": "semis" | "quarters" (optional, per-gender override),
    "knockoutFormatK": "semis" | "quarters" (optional, per-gender override),
    "groups": {
      "M": { "count": 2|3|4, "teams": { "A": [<teamId>, ...], "B": [...], ... } },
      "K": { "count": 2|3|4, "teams": { "A": [<teamId>, ...], "B": [...], ... } }
    },
    "days": [
      { "date": "YYYY-MM-DD" (optional), "startTime": "HH:mm", "endTime": "HH:mm" }
    ]
  },
  "matches": [
    {
      "id": "<unique uuid string>",
      "stage": "group"
            | "playoff"
            | "quarterfinal"
            | "semifinal"
            | "fifth_semifinal"
            | "ninth_semifinal"
            | "thirteenth_semifinal"
            | "final"
            | "third_place"
            | "fifth_place"
            | "seventh_place"
            | "ninth_place"
            | "eleventh_place"
            | "thirteenth_place"
            | "fifteenth_place"
            | "placement_rr",
      "gender": "M" | "K",
      "group": "A"|"B"|"C"|"D"|"placement_7"|"placement_9"|"placement_13"|null,
      "round": <number, optional>,
      "court": <number, 1-based>,
      "dayIndex": <number, 0-based index into days array>,
      "startTime": "HH:mm" | null,
      "endTime": "HH:mm" | null,
      "teamA": { "id": <number>, "name": "<team name>", "gender": "M"|"K" } | null,
      "teamB": { "id": <number>, "name": "<team name>", "gender": "M"|"K" } | null,
      "knockoutLabel": "<description of who plays>" | null,
      "status": "scheduled",
      "order": <number, sequential>
    }
  ],
  "generated_at": "<ISO timestamp>",
  "status": "draft"
}
"""


def _extract_text_from_pdf(file_bytes: bytes) -> str:
    """Extract text from a PDF file using pymupdf."""
    import fitz  # pymupdf
    text_parts = []
    with fitz.open(stream=file_bytes, filetype="pdf") as doc:
        for page in doc:
            text_parts.append(page.get_text())
    return "\n".join(text_parts)


def _normalize_team_name(name: str) -> str:
    """Normalize a team name for fuzzy matching: lowercase, remove accents, extra spaces."""
    s = unicodedata.normalize("NFKD", name.lower().strip())
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = re.sub(r"[^a-z0-9 ]", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def _fuzzy_match_score(a: str, b: str) -> float:
    """Simple token-based similarity score between two normalized strings."""
    tokens_a = set(a.split())
    tokens_b = set(b.split())
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    return len(intersection) / len(union)


@router.post(
    "/{tournament_id}/ai-schedule-import",
    response_model=dict,
    summary="AI-powered schedule import from PDF files",
)
async def ai_schedule_import(
    tournament_id: int,
    files: List[UploadFile] = File(..., description="PDF files with schedule (max 3)"),
    description: str = Form(""),
    mode: str = Form("groupsPlusKnockout"),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    """
    Upload PDF files → extract text → GPT-4o generates ScheduleData JSON → fuzzy-match teams.
    Returns { schedule, already_invited_ids, new_teams_to_invite, unmatched_teams, warnings }.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(500, "Brak OPENAI_API_KEY w środowisku serwera")

    if len(files) > 3:
        raise HTTPException(422, "Maksymalnie 3 pliki")

    # ── Auth check ──
    existing = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not existing:
        raise HTTPException(404, "Nie znaleziono turnieju")

    existing_d = dict(existing)
    data = _parse_json(existing_d["data_json"])

    if not await _can_manage_tournament_schedule(data, current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    # ── Extract text from PDFs ──
    all_text_parts = []
    for f in files:
        if not f.filename:
            continue
        file_bytes = await f.read()
        if not file_bytes:
            continue
        try:
            text = _extract_text_from_pdf(file_bytes)
            all_text_parts.append(f"--- Plik: {f.filename} ---\n{text}")
        except Exception as exc:
            logger.warning("Failed to extract text from %s: %s", f.filename, exc)
            all_text_parts.append(f"--- Plik: {f.filename} --- (nie udało się odczytać)")

    if not any(t.strip() for t in all_text_parts):
        raise HTTPException(422, "Nie udało się wyodrębnić tekstu z żadnego pliku")

    extracted_text = "\n\n".join(all_text_parts)
    # Limit text to ~30k chars to stay within context limits
    if len(extracted_text) > 30000:
        extracted_text = extracted_text[:30000] + "\n...(tekst obcięty)"

    # ── Fetch tournament info ──
    tour_name = existing_d.get("name", "Turniej")
    tour_category = existing_d.get("category", "")
    tour_date = str(existing_d.get("event_date", ""))[:10]
    tour_end_date = str(existing_d.get("end_date", ""))[:10] if existing_d.get("end_date") else tour_date

    # ── Fetch teams ──
    invited_team_ids = set()
    for tid in (data.get("invited_team_ids") or []):
        try:
            invited_team_ids.add(int(tid))
        except (ValueError, TypeError):
            pass

    if not invited_team_ids:
        raise HTTPException(422, "Brak zaproszonych drużyn w turnieju. Dodaj drużyny przed importem AI.")

    # Fetch invited teams
    invited_teams = []
    if invited_team_ids:
        rows = await database.fetch_all(
            select(beach_teams.c.id, beach_teams.c.team_name, beach_teams.c.gender)
            .where(beach_teams.c.id.in_(list(invited_team_ids)))
        )
        invited_teams = [dict(r) for r in rows]

    # Build team list strings for the prompt
    invited_teams_str = "\n".join(
        f"  ID={t['id']}, name=\"{t['team_name']}\", gender={t['gender']}"
        for t in invited_teams
    )

    invited_ids_set = {t['id'] for t in invited_teams}

    # ── Build prompt ──
    system_prompt = f"""\
Jesteś ekspertem od terminarzów turniejów piłki ręcznej plażowej. Twoim zadaniem jest przeczytanie
wyekstrahowanego tekstu z PDF-ów zawierających terminarz turnieju i wygenerowanie kompletnego
obiektu ScheduleData w formacie JSON.

WYKRYWANIE TRYBU DOKUMENTU:
- Jeśli dokument zawiera PEŁNY terminarz meczów z godzinami i boiskmi → wygeneruj kompletny ScheduleData z meczami.
- Jeśli dokument zawiera TYLKO podział drużyn na grupy (bez terminarza meczów z godzinami) → ustaw "groups_only": true \
na poziomie root JSON-a. W tym przypadku wygeneruj "schedule" z poprawnym config (mode, groups, knockoutFormatM/K itp.) \
ale z PUSTĄ listą meczów (matches: []).

KLUCZOWE ZASADY STRUKTURY TURNIEJU:
1. Przeanalizuj dokładnie jak wygląda turniej: ile jest grup per płeć, ile drużyn w każdej, jakie mecze pucharowe.
2. Grupy MUSZĄ być identyczne jak w dokumencie — te same drużyny w tych samych grupach.
3. Rozmiary grup muszą być jak najbardziej symetryczne (np. 14 drużyn na 4 grupy = 4,4,3,3 — NIE 5,3,3,3).
4. TYLKO mecze grupowe (stage="group") mają wypełnione teamA i teamB konkretnymi drużynami.
5. Mecze pucharowe (semifinal, quarterfinal, final, third_place, fifth_place, seventh_place, fifth_semifinal) \
ZAWSZE mają teamA=null i teamB=null z opisowym knockoutLabel (np. "1. z gr. A vs 2. z gr. B").
6. Baraże eliminacyjne (stage="playoff") mają teamA=null, teamB=null z knockoutLabel opisującym kto gra. \
Używaj "playoff" TYLKO dla baraży eliminacyjnych (np. 2. z gr. A vs 2. z gr. B, żeby awansować do ćwierćfinałów).
7. MECZE O MIEJSCA — BARDZO WAŻNE: Jeśli turniej ma mecze o niższe miejsca (VII-IX, IX-XI, XII-XV itp.), \
użyj odpowiednich stage'ów ZAMIAST "playoff":
   - Miniturnieje round-robin "O msc. VII-IX" / "O msc. IX-XI" / "O msc. XIII-XVI" → stage="placement_rr", \
     group="placement_7" (lub "placement_9", "placement_13" itd. od pierwszego miejsca danego miniturnieju), \
     knockoutLabel="O msc. VII-IX: X. z gr. A vs Y. z gr. B"
   - Mecz o 9. miejsce → stage="ninth_place", knockoutLabel="Mecz o 9. miejsce: ..."
   - Mecz o 11. miejsce → stage="eleventh_place", knockoutLabel="Mecz o 11. miejsce: ..."
   - Mecz o 13. miejsce → stage="thirteenth_place", knockoutLabel="Mecz o 13. miejsce: ..."
   - Mecz o 15. miejsce → stage="fifteenth_place", knockoutLabel="Mecz o 15. miejsce: ..."
   - Półfinały o 9. miejsce → stage="ninth_semifinal", knockoutLabel="Półfinał o 9. miejsce: ..."
   - Półfinały o 13. miejsce → stage="thirteenth_semifinal", knockoutLabel="Półfinał o 13. miejsce: ..."
8. Rozpoznaj format fazy pucharowej oddzielnie dla M i K:
   - Jeśli są ćwierćfinały → knockoutFormatM/K = "quarters"
   - Jeśli od razu półfinały → knockoutFormatM/K = "semis"
9. Jeśli widzisz baraże 2. miejsc (3 grupy → półfinały) lub 3. miejsc (3 grupy → ćwierćfinały), dodaj playoffMode="playoff".
10. W config.groups podaj DOKŁADNY podział drużyn na grupy z ich ID (dopasowanymi z bazy).

DOPASOWYWANIE DRUŻYN:
11. Używaj WYŁĄCZNIE drużyn z poniższej listy zaproszonych do turnieju. NIE szukaj drużyn spoza tej listy.
12. Dopasuj nazwy z dokumentu do nazw z listy — mogą się lekko różnić (skróty, literki itp.).
13. Jeśli drużyna z dokumentu nie pasuje do żadnej z zaproszonych — dodaj ją do "unmatched_teams" i NIE używaj w meczach.
14. Każda drużyna może być TYLKO W JEDNEJ grupie. NIE przypisuj tej samej drużyny do wielu grup.

TECHNICZNE:
15. Każdy mecz musi mieć unikalne "id" (wygeneruj UUID v4).
16. Godziny w formacie "HH:mm" (24h).
17. courts = liczba boisk widoczna w terminarzu.
18. dayIndex: 0-based (0 = pierwszy dzień).
19. order: sekwencyjny od 0, zachowaj kolejność z dokumentu.
20. Status wszystkich meczów: "scheduled".
21. Tryb turnieju: {mode}.
22. Jeśli tryb=roundRobin, pole "group" we WSZYSTKICH meczach musi być null — w każdy-z-każdym nie ma podziału na grupy.

SCHEMAT JSON:
{_SCHEDULE_JSON_SCHEMA}

DODATKOWE POLA config:
- knockoutFormatM: "semis"|"quarters" (format pucharowy mężczyzn)
- knockoutFormatK: "semis"|"quarters" (format pucharowy kobiet)
- playoffMode: "bestPlace"|"playoff" (czy baraże czy najlepsza drużyna z tabeli)
- groups.M.count: ile grup męskich, groups.M.teams: {{"A": [id1,id2,...], "B": [id3,id4,...], ...}}
- groups.K.count: ile grup damskich, groups.K.teams: {{"A": [id1,id2,...], "B": [id3,id4,...], ...}}

Turniej: "{tour_name}"
Kategoria: {tour_category}
Data: {tour_date} — {tour_end_date}

DRUŻYNY ZAPROSZONE DO TURNIEJU (używaj WYŁĄCZNIE tych drużyn):
{invited_teams_str}

Dodatkowe instrukcje od użytkownika: {description or "(brak)"}

Odpowiedz WYŁĄCZNIE poprawnym JSON-em z kluczami:
- "groups_only": true/false (czy dokument zawiera TYLKO podział na grupy, bez pełnego terminarza meczów)
- "schedule": pełny obiekt ScheduleData (z meczami jeśli groups_only=false, z pustymi matches jeśli groups_only=true)
- "team_mapping": lista obiektów {{{{ "doc_name": "<nazwa z dokumentu>", "matched_id": <int|null>, "matched_name": "<nazwa z bazy>"|null, "source": "invited"|"unmatched" }}}}
"""

    user_msg = f"Oto tekst wyekstrahowany z dokumentów terminarza:\n\n{extracted_text}"

    # ── Call OpenAI ──
    try:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=api_key)
        response = await client.chat.completions.create(
            model=os.getenv("OPENAI_SCHEDULE_MODEL", "gpt-4o"),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_msg},
            ],
            response_format={"type": "json_object"},
            temperature=0.1,
            timeout=120,
        )
    except Exception as exc:
        logger.exception("OpenAI schedule import request failed")
        raise HTTPException(502, f"Błąd komunikacji z OpenAI: {exc}")

    raw_content = (response.choices[0].message.content or "").strip()
    if not raw_content:
        raise HTTPException(502, "OpenAI zwrócił pustą odpowiedź")

    try:
        result = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        logger.error("OpenAI returned invalid JSON: %s", raw_content[:500])
        raise HTTPException(502, f"OpenAI zwrócił niepoprawny JSON: {exc}")

    schedule = result.get("schedule")
    team_mapping = result.get("team_mapping", [])

    if not schedule or not isinstance(schedule, dict):
        raise HTTPException(502, "OpenAI nie wygenerował poprawnego terminarza")

    # ── Process team mapping ──
    warnings = []
    already_invited_ids = []
    new_teams_to_invite = []
    unmatched_teams = []

    for mapping in team_mapping:
        doc_name = mapping.get("doc_name", "")
        matched_id = mapping.get("matched_id")
        source = mapping.get("source", "unmatched")

        if source == "unmatched" or matched_id is None:
            unmatched_teams.append({
                "doc_name": doc_name,
                "matched_name": mapping.get("matched_name"),
            })
            warnings.append(f"Nie dopasowano drużyny: \"{doc_name}\"")
        elif matched_id in invited_ids_set:
            already_invited_ids.append(matched_id)
        else:
            # Team not in invited list — treat as unmatched
            unmatched_teams.append({
                "doc_name": doc_name,
                "matched_name": mapping.get("matched_name"),
            })
            warnings.append(f'Drużyna "{doc_name}" (ID={matched_id}) nie jest zaproszona do turnieju')

    # ── Validate: no team in multiple groups ──
    config = schedule.get("config", {})
    groups_cfg = config.get("groups", {})
    for gender_key in ["M", "K"]:
        g_cfg = groups_cfg.get(gender_key, {})
        g_teams = g_cfg.get("teams", {})
        seen_ids: set = set()
        for group_name, team_ids_list in g_teams.items():
            deduped = []
            for tid in team_ids_list:
                if tid in seen_ids:
                    warnings.append(f'Drużyna ID={tid} była w wielu grupach ({gender_key}) — usunięto duplikat')
                else:
                    seen_ids.add(tid)
                    deduped.append(tid)
            g_teams[group_name] = deduped

    # ── Groups-only auto-detection ──
    groups_only = result.get("groups_only", False)
    if groups_only:
        # Validate non-invited team IDs in groups
        for gender_key in ["M", "K"]:
            g_cfg = groups_cfg.get(gender_key, {})
            g_teams = g_cfg.get("teams", {})
            for group_name, team_ids_list in g_teams.items():
                cleaned = [tid for tid in team_ids_list if tid in invited_ids_set]
                removed = [tid for tid in team_ids_list if tid not in invited_ids_set]
                for tid in removed:
                    warnings.append(f'Drużyna ID={tid} nie jest zaproszona ({gender_key}, gr. {group_name}) — usunięto')
                g_teams[group_name] = cleaned

        knockout_m = config.get("knockoutFormatM", "semis")
        knockout_k = config.get("knockoutFormatK", "semis")

        group_config = {
            "mode": "groupsPlusKnockout",
            "courts": 2,
            "slotInterval": 40,
            "minTeamBreak": 15,
            "thirdPlace": True,
            "knockoutFormatM": knockout_m,
            "knockoutFormatK": knockout_k,
            "playoffMode": "playoff",
            "groups": groups_cfg,
            "days": [],
        }

        # ── Activity log (groups_only) ──
        await log_activity(
            area="tournament",
            action="tournament.schedule_ai_imported",
            actor_user_id=current_user_id,
            actor_name=await get_actor_name(current_user_id),
            target_id=str(tournament_id),
            target_label=tour_name,
            details={"groups_only": True, "files": [f.filename for f in files if f.filename]},
        )

        return {
            "schedule": None,
            "already_invited_ids": already_invited_ids,
            "new_teams_to_invite": [],
            "unmatched_teams": unmatched_teams,
            "warnings": warnings,
            "group_config": group_config,
        }

    # ── For roundRobin mode: clear group field on all matches (no group labels) ──
    if config.get("mode") == "roundRobin":
        for m in schedule.get("matches", []):
            m["group"] = None

    # ── Validate: only invited team IDs in matches ──
    for m in schedule.get("matches", []):
        for slot in ("teamA", "teamB"):
            team = m.get(slot)
            if team and isinstance(team, dict) and team.get("id"):
                tid = team["id"]
                if tid not in invited_ids_set:
                    warnings.append(f'Mecz {m.get("id","?")}: drużyna ID={tid} nie jest zaproszona — usunięto')
                    m[slot] = None

    # ── Validate schedule has required fields ──
    if "config" not in schedule:
        raise HTTPException(502, "Wygenerowany terminarz nie zawiera konfiguracji (config)")
    if "matches" not in schedule:
        schedule["matches"] = []
    if "generated_at" not in schedule:
        schedule["generated_at"] = datetime.now(timezone.utc).isoformat()
    if "status" not in schedule:
        schedule["status"] = "draft"

    # ── Activity log ──
    await log_activity(
        area="tournament",
        action="tournament.schedule_ai_imported",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(tournament_id),
        target_label=tour_name,
        details={
            "matches_count": sum(1 for m in schedule.get("matches", []) if m.get("kind") not in ("court_break", "tournament_opening")),
            "warnings_count": len(warnings),
            "unmatched_teams": unmatched_teams,
            "files": [f.filename for f in files if f.filename],
        },
    )

    return {
        "schedule": schedule,
        "already_invited_ids": already_invited_ids,
        "new_teams_to_invite": new_teams_to_invite,
        "unmatched_teams": unmatched_teams,
        "warnings": warnings,
    }


# ─────────────────── DELETE ───────────────────

@router.delete(
    "/{tournament_id}",
    response_model=dict,
    summary="Usuń turniej — wymaga admina",
)
async def delete_tournament(
    tournament_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    row = await database.fetch_one(
        select(beach_tournaments.c.id, beach_tournaments.c.name, beach_tournaments.c.data_json).where(beach_tournaments.c.id == tournament_id)
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono turnieju")

    deleted_name = row["name"] or ""
    deleted_data = _normalize_event_data(row["data_json"])
    asyncio.ensure_future(_delete_tournament_calendar_background(tournament_id, deleted_data))

    # Cofnij punkty ze standings za ten turniej przed usunięciem
    import json as _json
    from datetime import datetime, timezone as _tz
    standings_rows = await database.fetch_all(select(beach_standings))
    now = datetime.now(_tz.utc)
    for sr in standings_rows:
        sr_d = dict(sr)
        raw = sr_d.get("tournaments_json") or []
        if isinstance(raw, str):
            try:
                entries = _json.loads(raw)
            except Exception:
                entries = []
        elif isinstance(raw, list):
            entries = raw
        else:
            entries = []
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
                .where(beach_standings.c.id == sr_d["id"])
                .values(tournaments_json=entries, updated_at=now)
            )

    await database.execute(
        delete(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )

    # ── Activity log ──
    await log_activity(
        area="tournament",
        action="tournament.deleted",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(tournament_id),
        target_label=deleted_name,
    )

    return {"success": True}


# ─────────────────── ATTENDANCE ───────────────────

@router.patch(
    "/{tournament_id}/attendance",
    response_model=BeachTournamentItem,
    summary="Aktualizuj obecność (present_ids) — wymaga admina",
)
async def update_tournament_attendance(
    tournament_id: int,
    body: UpdateBeachTournamentAttendanceRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    existing = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not existing:
        raise HTTPException(404, "Nie znaleziono turnieju")

    existing_d = dict(existing)
    data = _normalize_event_data(existing_d["data_json"])
    present_ids = [str(x).strip() for x in (body.present_ids or []) if str(x).strip()]
    data["present_ids"] = sorted(list(set(present_ids)))

    if not data.get("invited_ids"):
        data["invited_ids"] = await _compute_invited_ids_for_badge(
            existing_d.get("badge"), data
        )

    await database.execute(
        update(beach_tournaments)
        .where(beach_tournaments.c.id == tournament_id)
        .values(data_json=data, updated_at=datetime.now(timezone.utc))
    )

    row = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    row_d = dict(row)
    data2 = _normalize_event_data(row_d["data_json"])
    if not data2.get("invited_ids"):
        data2["invited_ids"] = await _compute_invited_ids_for_badge(row_d.get("badge"), data2)

    # ── Activity log ──
    old_present = set(str(x) for x in (_normalize_event_data(existing_d["data_json"]).get("present_ids") or []))
    new_present = set(data2.get("present_ids") or [])
    await log_activity(
        area="tournament",
        action="tournament.attendance_updated",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(tournament_id),
        target_label=existing_d.get("name", ""),
        details={"count_before": len(old_present), "count_after": len(new_present)},
    )

    asyncio.ensure_future(_sync_tournament_calendar_background(row_d, data2))
    return _attach_computed_fields(row_d, data2, None)


# ─────────────────── PREFIX HELPERS ───────────────────

_VOIVODESHIP_CODES: dict[str, str] = {
    "DOLNOŚLĄSKIE": "DS",
    "KUJAWSKO-POMORSKIE": "KP",
    "LUBELSKIE": "LU",
    "LUBUSKIE": "LB",
    "ŁÓDZKIE": "LD",
    "MAŁOPOLSKIE": "MA",
    "MAZOWIECKIE": "MZ",
    "OPOLSKIE": "OP",
    "PODKARPACKIE": "PK",
    "PODLASKIE": "PD",
    "POMORSKIE": "PM",
    "ŚLĄSKIE": "SL",
    "ŚWIĘTOKRZYSKIE": "SK",
    "WARMIŃSKO-MAZURSKIE": "WN",
    "WIELKOPOLSKIE": "WP",
    "ZACHODNIOPOMORSKIE": "ZP",
}

_CATEGORY_CODES: dict[str, str] = {
    "Senior": "S",
    "Junior": "J",
    "Junior mł.": "Jm",
    "Młodzik": "Mł",
    "Dzieci": "Dz",
}


def _collect_schedule_genders(data: Dict[str, Any]) -> set[str]:
    schedule = data.get("schedule") or {}
    matches = schedule.get("matches") or []
    genders = {
        str(m.get("gender"))
        for m in matches
        if isinstance(m, dict) and m.get("gender") in ("M", "K")
    }
    if genders:
        return genders

    groups = (schedule.get("config") or {}).get("groups") or {}
    group_genders: set[str] = set()
    for g in ("M", "K"):
        g_cfg = groups.get(g) or {}
        teams = g_cfg.get("teams") or {}
        if any(teams.get(group_name) for group_name in ("A", "B", "C", "D")):
            group_genders.add(g)
    if group_genders:
        return group_genders

    custom_teams = data.get("custom_teams") or []
    return {
        str(t.get("gender"))
        for t in custom_teams
        if isinstance(t, dict) and t.get("gender") in ("M", "K")
    }


async def _tournament_includes_gender(data_json: Any, gender: str) -> bool:
    data = _parse_json(data_json)
    schedule_genders = _collect_schedule_genders(data)
    if schedule_genders:
        return gender in schedule_genders

    invited_team_ids: list[int] = []
    for raw_id in data.get("invited_team_ids") or []:
        try:
            invited_team_ids.append(int(raw_id))
        except (TypeError, ValueError):
            continue

    if invited_team_ids:
        rows = await database.fetch_all(
            select(beach_teams.c.gender).where(beach_teams.c.id.in_(invited_team_ids))
        )
        invited_genders = {
            str(r["gender"])
            for r in rows
            if r["gender"] in ("M", "K")
        }
        if invited_genders:
            return gender in invited_genders

    # No reliable gender metadata yet: keep it in both baskets to avoid
    # accidental duplicate ordinals for completely empty legacy tournaments.
    return True


def _strip_diacritics(text: str) -> str:
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def _make_initials_prefix(name: str) -> str:
    ascii_name = _strip_diacritics(name).upper()
    words = re.findall(r"[A-Z0-9]+", ascii_name)
    initials = "".join(w[0] for w in words if w)
    return initials[:6] or "TRN"


def _competition_type_to_prefix(competition_type: str | None, name: str) -> str:
    """Derive match-number prefix from competition_type stored on the tournament."""
    if not competition_type:
        return _make_initials_prefix(name)
    ct = competition_type.strip()
    if ct == "MP":
        return "MP"
    if ct in _VOIVODESHIP_CODES:
        return _VOIVODESHIP_CODES[ct]
    if ct.startswith("INNE:"):
        inne_name = ct[5:].strip()
        return _make_initials_prefix(inne_name) if inne_name else "INNE"
    # Unknown value — fall back to initials from tournament name
    return _make_initials_prefix(name)


async def _get_unique_prefix(base: str) -> str:
    candidate = base
    attempt = 2
    while True:
        existing = await database.fetch_one(
            select(beach_tournaments.c.id).where(
                beach_tournaments.c.match_prefix == candidate
            )
        )
        if not existing:
            return candidate
        candidate = f"{base}{attempt}"
        attempt += 1


# ─────────────────── GET match-prefix ───────────────────

@router.get(
    "/{tournament_id}/match-prefix",
    response_model=dict,
    summary="Pobierz prefiks numeracji meczow turnieju",
)
async def get_match_prefix(
    tournament_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    row = await database.fetch_one(
        select(beach_tournaments.c.id, beach_tournaments.c.match_prefix, beach_tournaments.c.name)
        .where(beach_tournaments.c.id == tournament_id)
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono turnieju")
    return {"prefix": dict(row).get("match_prefix")}


# ─────────────────── POST generate-match-number ───────────────────

@router.post(
    "/{tournament_id}/generate-match-number",
    response_model=dict,
    summary="Wygeneruj numer meczu dla turnieju (PROVINCE/CATEGORY_GENDER/N)",
)
async def generate_match_number(
    tournament_id: int,
    gender: str = Query(..., description="M lub K"),
    category: Optional[str] = Query(None, description="Kategoria turnieju (fallback gdy brak w DB)"),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if gender not in ("M", "K"):
        raise HTTPException(422, "gender musi byc 'M' lub 'K'")

    row = await database.fetch_one(
        select(
            beach_tournaments.c.id,
            beach_tournaments.c.name,
            beach_tournaments.c.competition_type,
            beach_tournaments.c.category,
        )
        .where(beach_tournaments.c.id == tournament_id)
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono turnieju")

    row_d = dict(row)
    prefix = _competition_type_to_prefix(row_d.get("competition_type"), row_d["name"] or "TRN")
    # Use DB value first, fall back to query param if DB is NULL
    effective_category = row_d.get("category") or category or ""
    cat_code = _CATEGORY_CODES.get(effective_category, "")
    cat_gender = f"{cat_code}{gender}" if cat_code else gender

    sibling_rows = await database.fetch_all(
        select(
            beach_tournaments.c.id,
            beach_tournaments.c.event_date,
            beach_tournaments.c.competition_type,
            beach_tournaments.c.category,
            beach_tournaments.c.data_json,
        )
    )
    siblings = []
    effective_competition = row_d.get("competition_type")
    for sibling in sibling_rows:
        sd = dict(sibling)
        if (sd.get("competition_type") or "") != (effective_competition or ""):
            continue
        if (sd.get("category") or "") != (effective_category or ""):
            continue
        if not await _tournament_includes_gender(sd.get("data_json"), gender):
            continue
        siblings.append(sd)
    siblings.sort(
        key=lambda x: (
            x.get("event_date") or datetime.max.replace(tzinfo=timezone.utc),
            x.get("id") or 0,
        )
    )
    tournament_ordinal = next(
        (idx + 1 for idx, item in enumerate(siblings) if item.get("id") == tournament_id),
        1,
    )

    pattern = f"{prefix}/{cat_gender}/{tournament_ordinal}/%"

    # 1) Numbers already used in beach_proel_matches for this tournament ordinal.
    existing_rows = await database.fetch_all(
        select(beach_proel_matches.c.match_number).where(
            beach_proel_matches.c.match_number.like(pattern)
        )
    )
    seq_nums: list[int] = []
    for r in existing_rows:
        parts = dict(r)["match_number"].split("/")
        if len(parts) == 4:
            try:
                seq_nums.append(int(parts[3]))
            except ValueError:
                pass

    # 2) Numbers already assigned in this tournament schedule.
    current_tour_rows = await database.fetch_all(
        select(beach_tournaments.c.data_json).where(beach_tournaments.c.id == tournament_id)
    )
    for tour_row in current_tour_rows:
        tour_data = _parse_json(dict(tour_row)["data_json"])
        schedule = tour_data.get("schedule") or {}
        for m in (schedule.get("matches") or []):
            mn = m.get("matchNumber") or m.get("match_number")
            if not mn:
                continue
            parts = str(mn).split("/")
            if (
                len(parts) == 4
                and parts[0] == prefix
                and parts[1] == cat_gender
                and parts[2] == str(tournament_ordinal)
            ):
                try:
                    seq_nums.append(int(parts[3]))
                except ValueError:
                    pass

    next_seq = (max(seq_nums) + 1) if seq_nums else 1
    match_number = f"{prefix}/{cat_gender}/{tournament_ordinal}/{next_seq}"

    return {
        "match_number": match_number,
        "prefix": prefix,
        "tournament_ordinal": tournament_ordinal,
    }


# ─────────────────── PATCH squad-update (Admin / Trener druzyny) ───────────────────

@router.patch(
    "/{tournament_id}/squad-update",
    response_model=dict,
    summary="Aktualizuj selekcje skladu druzyny w turnieju",
)
async def squad_update_tournament(
    tournament_id: int,
    body: SquadUpdateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not body.team_id and not body.custom_team_id:
        raise HTTPException(400, "Wymagane team_id lub custom_team_id")

    existing = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not existing:
        raise HTTPException(404, "Nie znaleziono turnieju")

    existing_d = dict(existing)
    data = _parse_json(existing_d["data_json"])

    is_admin_flag = await _is_admin(current_user_id)

    # Judges assigned to this tournament (head judge or any listed judge) may also
    # edit match squads and collect signatures — the frontend shows this UI to them.
    _head_judge_id = data.get("head_judge_id")
    _judge_user_ids = {
        int(j["user_id"])
        for j in (data.get("judges") or [])
        if isinstance(j, dict) and j.get("user_id")
    }
    is_judge_flag = current_user_id in _judge_user_ids or (
        isinstance(_head_judge_id, int) and _head_judge_id == current_user_id
    )

    if not (is_admin_flag or is_judge_flag):
        if body.custom_team_id:
            # Check if user is coach of this custom team
            custom_teams = data.get("custom_teams") or []
            is_coach_of_custom = any(
                isinstance(ct, dict)
                and ct.get("id") == body.custom_team_id
                and ct.get("coach_user_id") == current_user_id
                for ct in custom_teams
            )
            if not is_coach_of_custom:
                raise HTTPException(403, "Wymagane uprawnienia trenera tej druzyny, sedziego lub admina")
        else:
            user_row = await database.fetch_one(
                select(beach_users.c.roles).where(beach_users.c.id == current_user_id)
            )
            if not user_row:
                raise HTTPException(404, "Uzytkownik nie znaleziony")

            roles = user_row["roles"] or []
            if isinstance(roles, str):
                try:
                    roles = json.loads(roles)
                except Exception:
                    roles = []

            is_coach_of_team = any(
                isinstance(r, dict)
                and r.get("type") in ("coach",)
                and r.get("team_id") == body.team_id
                for r in roles
            )
            if not is_coach_of_team:
                raise HTTPException(403, "Wymagane uprawnienia trenera tej druzyny, sedziego lub admina")

    team_squads: dict = data.get("team_squads") or {}
    team_key = body.custom_team_id if body.custom_team_id else str(body.team_id)
    squad_entry: dict = dict(team_squads.get(team_key) or {})

    if body.match_id:
        match_overrides: dict = dict(squad_entry.get("match_overrides") or {})
        override = dict(match_overrides.get(body.match_id) or {})
        if body.match_players is not None:
            override["players"] = body.match_players
        if body.match_companions is not None:
            override["companions"] = body.match_companions
        if body.match_companion_roles is not None:
            override["companion_roles"] = body.match_companion_roles
        if body.signature_url is not None:
            override["signature_url"] = body.signature_url
        match_overrides[body.match_id] = override
        squad_entry["match_overrides"] = match_overrides
    else:
        if body.default_players is not None:
            squad_entry["default_players"] = body.default_players
        if body.default_companions is not None:
            squad_entry["default_companions"] = body.default_companions
        if body.default_companion_roles is not None:
            squad_entry["default_companion_roles"] = body.default_companion_roles
        if body.protocol_players is not None:
            squad_entry["protocol_players"] = body.protocol_players

    team_squads[team_key] = squad_entry
    data["team_squads"] = team_squads

    await database.execute(
        update(beach_tournaments)
        .where(beach_tournaments.c.id == tournament_id)
        .values(data_json=data, updated_at=datetime.now(timezone.utc))
    )

    # ── Activity log ──
    await log_activity(
        area="tournament",
        action="tournament.squad_updated",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(tournament_id),
        target_label=existing_d.get("name", ""),
        details={"team_key": team_key, "match_id": body.match_id},
    )

    return {"success": True}


# ─────────────────── TITLE IMAGES GALLERY ───────────────────

class StandaloneImageGenerateRequest(BaseModel):
    """Generuj grafikę bez przypisania do turnieju."""
    name: str
    event_date: Optional[str] = None
    end_date: Optional[str] = None
    location: Optional[str] = None
    category: Optional[str] = None
    competition_type: Optional[str] = None
    extra_prompt: Optional[str] = None


@router.get(
    "/title-images/list",
    response_model=dict,
    summary="Lista wszystkich grafik tytułowych (admin)",
)
async def list_title_images(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    images_dir = _static_root_dir() / "beach" / "tournaments" / "title-images"
    if not images_dir.exists():
        return {"images": []}

    # Build map: filename → list of tournaments using it
    tournament_rows = await database.fetch_all(
        select(beach_tournaments.c.id, beach_tournaments.c.name, beach_tournaments.c.data_json)
    )
    filename_to_tours: dict[str, list] = {}
    for row in tournament_rows:
        row_d = dict(row)
        data = _parse_json(row_d["data_json"])
        ti = data.get("title_image")
        if isinstance(ti, dict) and ti.get("url"):
            url: str = ti["url"]
            fname = url.rstrip("/").split("/")[-1]
            if fname not in filename_to_tours:
                filename_to_tours[fname] = []
            filename_to_tours[fname].append({
                "id": row_d["id"],
                "name": row_d["name"],
            })

    images = []
    for p in sorted(images_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.suffix.lower() not in (".png", ".jpg", ".jpeg", ".webp"):
            continue
        stat = p.stat()
        url = _public_static_url(p)
        images.append({
            "filename": p.name,
            "url": url,
            "size_bytes": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "used_by": filename_to_tours.get(p.name, []),
        })

    return {"images": images}


@router.delete(
    "/title-images/{filename}",
    response_model=dict,
    summary="Usuń grafikę tytułową (admin)",
)
async def delete_title_image(
    filename: str,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    # Basic path traversal guard
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(400, "Nieprawidłowa nazwa pliku")

    images_dir = _static_root_dir() / "beach" / "tournaments" / "title-images"
    file_path = images_dir / filename
    if not file_path.exists():
        raise HTTPException(404, "Plik nie istnieje")

    file_path.unlink()

    # ── Activity log ──
    await log_activity(
        area="tournament",
        action="tournament.title_image_deleted",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        details={"filename": filename},
    )

    return {"success": True, "deleted": filename}


@router.post(
    "/title-images/generate",
    response_model=dict,
    summary="Wygeneruj nową grafikę standalone (admin)",
)
async def generate_standalone_title_image(
    req: StandaloneImageGenerateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    prompt_req = TournamentTitleImageRequest(
        name=req.name,
        event_date=req.event_date,
        end_date=req.end_date,
        location=req.location,
        category=req.category,
        competition_type=req.competition_type,
        extra_prompt=req.extra_prompt,
    )
    prompt = _build_title_image_prompt(prompt_req)
    image_bytes = await _generate_openai_title_image(prompt)

    out_dir = _static_root_dir() / "beach" / "tournaments" / "title-images"
    out_dir.mkdir(parents=True, exist_ok=True)
    file_path = out_dir / f"{uuid.uuid4().hex}.png"
    file_path.write_bytes(image_bytes)

    standalone_result = {
        "filename": file_path.name,
        "url": _public_static_url(file_path),
        "prompt": prompt,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    # ── Activity log ──
    await log_activity(
        area="tournament",
        action="tournament.title_image_generated",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_label=req.name.strip(),
        details={"standalone": True},
    )

    return standalone_result


@router.patch(
    "/{tournament_id}/set-title-image",
    response_model=dict,
    summary="Przypisz istniejącą grafikę do turnieju (admin)",
)
async def set_tournament_title_image(
    tournament_id: int,
    body: dict,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    url = (body.get("url") or "").strip()
    if not url:
        raise HTTPException(400, "Brak url grafiki")

    row = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono turnieju")

    data = _parse_json(dict(row)["data_json"])
    existing_ti = data.get("title_image") if isinstance(data.get("title_image"), dict) else {}
    data["title_image"] = {
        **existing_ti,
        "url": url,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    await database.execute(
        update(beach_tournaments)
        .where(beach_tournaments.c.id == tournament_id)
        .values(data_json=json.dumps(data, ensure_ascii=False))
    )

    # ── Activity log ──
    await log_activity(
        area="tournament",
        action="tournament.title_image_set",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(tournament_id),
        target_label=dict(row).get("name", ""),
        details={"url": url},
    )

    return {"success": True, "url": url}


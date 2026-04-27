from __future__ import annotations

from datetime import datetime, timezone
import base64
import json
import logging
import os
from pathlib import Path
import re
import traceback
import unicodedata
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Depends
import httpx
from pydantic import BaseModel
from sqlalchemy import select, insert, update, delete

from app.db import database, beach_tournaments, beach_users, beach_admins, beach_proel_matches
from app.schemas import (
    CreateBeachTournamentRequest,
    UpdateBeachTournamentRequest,
    UpdateBeachTournamentAttendanceRequest,
    BeachTournamentItem,
    BeachTournamentsListResponse,
)
from app.deps import beach_get_current_user_id

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/beach/tournaments", tags=["Beach: Tournaments"])


# ─────────────────── Pydantic models dla nowych endpointów ───────────────────

class HostUpdateRequest(BaseModel):
    """Dozwolone pola dla Gospodarza zawodów."""
    announcements: Optional[list] = None
    invited_team_ids: Optional[list] = None


class JudgeUpdateRequest(BaseModel):
    """Dozwolone pola dla Obsadowego."""
    judges: Optional[list] = None
    head_judge_id: Optional[int] = None


class ScheduleUpdateRequest(BaseModel):
    """Harmonogram zawodów — admin lub Gospodarz zawodów."""
    schedule: Optional[dict] = None


class SquadUpdateRequest(BaseModel):
    """Aktualizacja selekcji składu dla drużyny w turnieju."""
    team_id: int
    default_players: Optional[List[int]] = None      # player_ids, max 10
    default_companions: Optional[List[int]] = None   # person_ids, max 2
    match_id: Optional[str] = None                   # jeśli override dla konkretnego meczu
    match_players: Optional[List[int]] = None
    match_companions: Optional[List[int]] = None


class TournamentTitleImageRequest(BaseModel):
    """Dane potrzebne do wygenerowania grafiki tytulowej turnieju."""
    tournament_id: Optional[int] = None
    name: str
    event_date: Optional[str] = None
    end_date: Optional[str] = None
    location: Optional[str] = None
    category: Optional[str] = None
    competition_type: Optional[str] = None
    regenerate: bool = False


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


def _build_title_image_prompt(req: TournamentTitleImageRequest) -> str:
    location_hint = (req.location or "").strip()
    category_hint = (req.category or "turniej").strip()
    competition_hint = (req.competition_type or "").strip()
    date_hint = " ".join(
        x for x in [(req.event_date or "").strip(), (req.end_date or "").strip()] if x
    )

    return (
        "Landscape realistic photo-style title image for a Polish beach handball tournament. "
        "It should look like a real editorial sports photograph, not a cartoon, not CGI, not artificial "
        "characters, not plastic-looking people. Use natural athletes photographed on a sunny sand court, "
        "a beach handball ball, subtle goal/court lines, warm sunlight, beach atmosphere, tasteful coastal colors. "
        "Keep the composition minimalist and premium, with real-world lighting and natural human poses. "
        "No text, no letters, no logos, no badges, no watermarks. "
        "Leave darker open space in the lower-left area for app overlay text. "
        "Use a premium mobile app tile composition, high contrast, readable background. "
        f"Tournament name inspiration: {req.name.strip()}. "
        f"Category: {category_hint}. "
        f"Date context: {date_hint or 'summer tournament'}. "
        f"Location inspiration: {location_hint or 'Polish beach town'}; "
        "if location is recognizable, include only a very subtle local reference in the scenery. "
        f"Competition type: {competition_hint or 'beach handball event'}."
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

    user_badges = set(_extract_badge_names(user_row["badges"]))
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

    if "Gospodarz zawodów" in user_badges and current_user_id in host_ids:
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
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    if not req.name or not req.name.strip():
        raise HTTPException(400, "Brak nazwy")

    now = datetime.now(timezone.utc)
    data = _normalize_event_data(req.data_json)

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
        return {"success": True, "id": int(row["id"])}
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
    current_user_id: int = Depends(beach_get_current_user_id),
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
        if not data.get("invited_ids"):
            data["invited_ids"] = await _compute_invited_ids_for_badge(r_d.get("badge"), data)
        out.append(_attach_computed_fields(r_d, data, with_user))
    return BeachTournamentsListResponse(tournaments=out)


# ─────────────────── LIST (visible for user) ───────────────────

@router.get(
    "/visible",
    response_model=BeachTournamentsListResponse,
    summary="Lista turniejów widocznych dla zalogowanego użytkownika",
)
async def list_visible_tournaments(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    user_row = await database.fetch_one(
        select(beach_users).where(beach_users.c.id == current_user_id)
    )
    if not user_row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    user_team_ids = set(_extract_team_ids(user_row["roles"]))

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
        include_all = bool((data.get("target") or {}).get("include_all", False))
        user_is_host = current_user_id in host_ids
        user_is_judge = current_user_id in judge_ids
        user_team_invited = bool(user_team_ids & invited_team_ids)
        user_is_invited = str(current_user_id) in invited_set
        if not (
            include_all
            or user_is_invited
            or user_is_host
            or user_is_judge
            or user_team_invited
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

    return {
        "url": _public_static_url(file_path),
        "prompt": prompt,
        "model": os.getenv("OPENAI_IMAGE_MODEL", "gpt-image-1"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "regeneration_count": current_regen_count + 1 if req.regenerate else current_regen_count,
    }


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
        has_access = (
            row_d.get("badge") in user_badges
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

    update_data: Dict[str, Any] = {}
    fields = getattr(body, "__fields_set__", set())

    if "badge" in fields:
        update_data["badge"] = body.badge.strip() if body.badge else None
    if body.event_date is not None:
        update_data["event_date"] = body.event_date
    if "end_date" in fields:
        update_data["end_date"] = body.end_date
    if body.name is not None:
        update_data["name"] = body.name.strip()
    if "description" in fields:
        update_data["description"] = (body.description or "").strip() or None
    if "location" in fields:
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

    # Sprawdź badge "Gospodarz zawodów"
    user_row = await database.fetch_one(
        select(beach_users.c.badges).where(beach_users.c.id == current_user_id)
    )
    if not user_row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    user_badges = set(_extract_badge_names(user_row["badges"]))
    if "Gospodarz zawodów" not in user_badges:
        raise HTTPException(403, "Wymagany badge: Gospodarz zawodów")

    # Sprawdź czy user jest hostem tego konkretnego turnieju
    hosts = data.get("hosts") or []
    host_ids = {int(h["id"]) for h in hosts if isinstance(h, dict) and "id" in h}
    if current_user_id not in host_ids:
        raise HTTPException(403, "Nie jesteś gospodarzem tych zawodów")

    # Scal tylko dozwolone pola (nie nadpisuj reszty data_json)
    if body.announcements is not None:
        data["announcements"] = body.announcements
    if body.invited_team_ids is not None:
        data["invited_team_ids"] = body.invited_team_ids

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

    # Sprawdź uprawnienia: admin lub badge Obsadowy
    is_admin_flag = await _is_admin(current_user_id)
    if not is_admin_flag:
        user_row = await database.fetch_one(
            select(beach_users.c.badges).where(beach_users.c.id == current_user_id)
        )
        if not user_row:
            raise HTTPException(404, "Użytkownik nie znaleziony")
        user_badges = set(_extract_badge_names(user_row["badges"]))
        if "Obsadowy" not in user_badges:
            raise HTTPException(403, "Wymagany badge: Obsadowy")

    # Aktualizuj tylko dozwolone pola
    if body.judges is not None:
        data["judges"] = body.judges

    # head_judge_id: obsługa explicit None (reset) vs. brak w body
    fields_set = getattr(body, "model_fields_set", None) or getattr(body, "__fields_set__", set())
    if "head_judge_id" in fields_set:
        data["head_judge_id"] = body.head_judge_id  # może być None = reset

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
    return _attach_computed_fields(row_d, data2, current_user_id)


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

    # Basic sanity check
    if body.schedule is not None:
        if not isinstance(body.schedule, dict):
            raise HTTPException(422, "schedule musi być obiektem")
        data["schedule"] = body.schedule

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
    return _attach_computed_fields(row_d, data2, current_user_id)


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
        select(beach_tournaments.c.id).where(beach_tournaments.c.id == tournament_id)
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono turnieju")

    await database.execute(
        delete(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
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

    pattern = f"{prefix}/{cat_gender}/%"

    # 1) Numbers already used in beach_proel_matches (global — all tournaments)
    existing_rows = await database.fetch_all(
        select(beach_proel_matches.c.match_number).where(
            beach_proel_matches.c.match_number.like(pattern)
        )
    )
    seq_nums: list[int] = []
    for r in existing_rows:
        parts = dict(r)["match_number"].split("/")
        if len(parts) == 3:
            try:
                seq_nums.append(int(parts[2]))
            except ValueError:
                pass

    # 2) Numbers already assigned in ALL tournament schedules (global uniqueness)
    all_tour_rows = await database.fetch_all(
        select(beach_tournaments.c.data_json)
    )
    for tour_row in all_tour_rows:
        tour_data = _parse_json(dict(tour_row)["data_json"])
        schedule = tour_data.get("schedule") or {}
        for m in (schedule.get("matches") or []):
            mn = m.get("matchNumber") or m.get("match_number")
            if not mn:
                continue
            parts = str(mn).split("/")
            if len(parts) == 3 and parts[0] == prefix and parts[1] == cat_gender:
                try:
                    seq_nums.append(int(parts[2]))
                except ValueError:
                    pass

    next_seq = (max(seq_nums) + 1) if seq_nums else 1
    match_number = f"{prefix}/{cat_gender}/{next_seq}"

    return {"match_number": match_number, "prefix": prefix}


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
    existing = await database.fetch_one(
        select(beach_tournaments).where(beach_tournaments.c.id == tournament_id)
    )
    if not existing:
        raise HTTPException(404, "Nie znaleziono turnieju")

    is_admin_flag = await _is_admin(current_user_id)
    if not is_admin_flag:
        user_row = await database.fetch_one(
            select(beach_users.c.roles_json).where(beach_users.c.id == current_user_id)
        )
        if not user_row:
            raise HTTPException(404, "Uzytkownik nie znaleziony")

        roles = user_row["roles_json"] or []
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
            raise HTTPException(403, "Wymagane uprawnienia trenera tej druzyny lub admina")

    existing_d = dict(existing)
    data = _parse_json(existing_d["data_json"])
    team_squads: dict = data.get("team_squads") or {}
    team_key = str(body.team_id)
    squad_entry: dict = dict(team_squads.get(team_key) or {})

    if body.match_id:
        match_overrides: dict = dict(squad_entry.get("match_overrides") or {})
        override = dict(match_overrides.get(body.match_id) or {})
        if body.match_players is not None:
            override["players"] = body.match_players
        if body.match_companions is not None:
            override["companions"] = body.match_companions
        match_overrides[body.match_id] = override
        squad_entry["match_overrides"] = match_overrides
    else:
        if body.default_players is not None:
            squad_entry["default_players"] = body.default_players
        if body.default_companions is not None:
            squad_entry["default_companions"] = body.default_companions

    team_squads[team_key] = squad_entry
    data["team_squads"] = team_squads

    await database.execute(
        update(beach_tournaments)
        .where(beach_tournaments.c.id == tournament_id)
        .values(data_json=data, updated_at=datetime.now(timezone.utc))
    )

    return {"success": True}

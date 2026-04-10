from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import traceback
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
from sqlalchemy import select, insert, update, delete

from app.db import database, beach_tournaments, beach_users, beach_admins
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


def _extract_badge_names(badges_raw: Any) -> List[str]:
    if badges_raw is None:
        return []
    if isinstance(badges_raw, dict):
        return [str(k) for k, v in badges_raw.items() if v is not None and v]
    if isinstance(badges_raw, list):
        return [str(x) for x in badges_raw if x is not None]
    return []


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
        data_json=data,
        updated_at=row_d["updated_at"],
        invited_total=len(invited_set),
        present_total=len(present_set & invited_set) if invited_set else len(present_set),
        user_invited=user_invited,
        user_present=user_present,
    )


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


# ─────────────────── LIST (admin) ───────────────────

@router.get(
    "/",
    response_model=BeachTournamentsListResponse,
    summary="Lista turniejów (admin view) — wymaga admina",
)
async def list_tournaments_admin(
    badge: Optional[str] = Query(None),
    with_user: Optional[int] = Query(None),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

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

    user_badges = set(_extract_badge_names(user_row["badges"]))

    rows = await database.fetch_all(
        select(beach_tournaments).order_by(
            beach_tournaments.c.event_date.asc(), beach_tournaments.c.id.asc()
        )
    )

    out: List[BeachTournamentItem] = []
    for r in rows:
        r_d = dict(r)
        badge_req = r_d.get("badge")
        if badge_req and badge_req not in user_badges:
            continue

        data = _normalize_event_data(r_d["data_json"])
        if not data.get("invited_ids"):
            data["invited_ids"] = await _compute_invited_ids_for_badge(r_d.get("badge"), data)

        invited_set = set(str(x) for x in (data.get("invited_ids") or []))
        if (
            str(current_user_id) not in invited_set
            and not (data.get("target") or {}).get("include_all", False)
        ):
            continue

        out.append(_attach_computed_fields(r_d, data, current_user_id))

    return BeachTournamentsListResponse(tournaments=out)


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
            select(beach_users.c.badges).where(beach_users.c.id == current_user_id)
        )
        if not user_row:
            raise HTTPException(404, "Użytkownik nie znaleziony")
        if row_d.get("badge") not in set(_extract_badge_names(user_row["badges"])):
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

    is_admin_flag = await _is_admin(current_user_id)
    if not is_admin_flag:
        user_row = await database.fetch_one(
            select(beach_users.c.badges).where(beach_users.c.id == current_user_id)
        )
        if not user_row:
            raise HTTPException(404, "Użytkownik nie znaleziony")

        user_badges = set(_extract_badge_names(user_row["badges"]))
        if "Gospodarz zawodów" not in user_badges:
            raise HTTPException(403, "Wymagany badge: Gospodarz zawodów lub admin")

        hosts = data.get("hosts") or []
        host_ids = {int(h["id"]) for h in hosts if isinstance(h, dict) and "id" in h}
        if current_user_id not in host_ids:
            raise HTTPException(403, "Nie jesteś gospodarzem tych zawodów")

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

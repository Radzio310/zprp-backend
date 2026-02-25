from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import traceback
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Depends
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
        out = []
        for k, v in badges_raw.items():
            try:
                if v:
                    out.append(str(k))
            except Exception:
                continue
        return out
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
    row = await database.fetch_one(select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id))
    return bool(row)

async def _compute_invited_ids_for_badge(badge: Optional[str], data: Dict[str, Any]) -> List[str]:
    """
    invited_ids = lista user_id (string) zaproszonych:
    - jeśli include_all True albo badge None -> wszyscy userzy
    - jeśli badge ustawiony -> userzy posiadający ten badge (w JSON badges)
    """
    target = data.get("target") or {}
    include_all = bool(target.get("include_all") or False)
    badge_eff = (badge or target.get("badge") or None)
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

    invited = sorted(list(set(invited)), key=lambda x: int(x) if x.isdigit() else x)
    return invited

def _attach_computed_fields(row: Any, data: Dict[str, Any], user_id: Optional[int]) -> BeachTournamentItem:
    invited_ids = data.get("invited_ids") or []
    present_ids = data.get("present_ids") or []
    invited_set = set([str(x) for x in invited_ids])
    present_set = set([str(x) for x in present_ids])

    uid = str(user_id) if user_id is not None else None
    user_invited = bool(uid and uid in invited_set)
    user_present = bool(uid and uid in present_set)

    return BeachTournamentItem(
        id=int(row["id"]),
        badge=row.get("badge"),
        event_date=row["event_date"],
        name=row["name"],
        description=row.get("description"),
        data_json=data,
        updated_at=row["updated_at"],
        invited_total=len(invited_set),
        present_total=len(present_set & invited_set) if invited_set else len(present_set),
        user_invited=user_invited,
        user_present=user_present,
    )


@router.post("/", response_model=dict, summary="Utwórz turniej (BEACH) — wymaga admina")
async def create_tournament(req: CreateBeachTournamentRequest, current_user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    if not req.name or not req.name.strip():
        raise HTTPException(400, "Brak nazwy")

    now = datetime.now(timezone.utc)
    data = _normalize_event_data(req.data_json)

    # invited_ids: jeśli puste -> wylicz
    if not data.get("invited_ids"):
        data["invited_ids"] = await _compute_invited_ids_for_badge(req.badge, data)

    try:
        stmt = (
            insert(beach_tournaments)
            .values(
                badge=(req.badge.strip() if req.badge else None),
                event_date=req.event_date,
                name=req.name.strip(),
                description=(req.description or "").strip() or None,
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


@router.get("/", response_model=BeachTournamentsListResponse, summary="Lista turniejów (admin view) — wymaga admina")
async def list_tournaments_admin(
    badge: Optional[str] = Query(None, description="Filtr badge"),
    with_user: Optional[int] = Query(None, description="Opcjonalnie: computed user_* po user_id"),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    q = select(beach_tournaments).order_by(beach_tournaments.c.event_date.asc(), beach_tournaments.c.id.asc())
    if badge is not None:
        if badge.strip() == "":
            q = q.where(beach_tournaments.c.badge == None)
        else:
            q = q.where(beach_tournaments.c.badge == badge.strip())

    rows = await database.fetch_all(q)

    out: List[BeachTournamentItem] = []
    for r in rows:
        data = _normalize_event_data(r["data_json"])
        if not data.get("invited_ids"):
            data["invited_ids"] = await _compute_invited_ids_for_badge(r.get("badge"), data)
        out.append(_attach_computed_fields(r, data, with_user))
    return BeachTournamentsListResponse(tournaments=out)


@router.get("/visible", response_model=BeachTournamentsListResponse, summary="Lista turniejów widocznych dla usera (BEACH)")
async def list_visible_tournaments(
    current_user_id: int = Depends(beach_get_current_user_id),
):
    user_row = await database.fetch_one(select(beach_users).where(beach_users.c.id == current_user_id))
    if not user_row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    user_badges = set(_extract_badge_names(user_row["badges"]))

    rows = await database.fetch_all(
        select(beach_tournaments).order_by(beach_tournaments.c.event_date.asc(), beach_tournaments.c.id.asc())
    )

    out: List[BeachTournamentItem] = []
    for r in rows:
        badge_req = r.get("badge")
        if badge_req and badge_req not in user_badges:
            continue

        data = _normalize_event_data(r["data_json"])
        if not data.get("invited_ids"):
            data["invited_ids"] = await _compute_invited_ids_for_badge(badge_req, data)

        invited_set = set([str(x) for x in (data.get("invited_ids") or [])])
        # jeśli invited_ids liczone, to user musi być w invited_set, chyba że to "include_all"
        if str(current_user_id) not in invited_set and not (data.get("target") or {}).get("include_all", False):
            # w praktyce przy badge=None invited_ids powinno zawierać wszystkich
            continue

        out.append(_attach_computed_fields(r, data, current_user_id))

    return BeachTournamentsListResponse(tournaments=out)


@router.get("/{tournament_id}", response_model=BeachTournamentItem, summary="Pobierz turniej po ID (BEACH)")
async def get_tournament(
    tournament_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    row = await database.fetch_one(select(beach_tournaments).where(beach_tournaments.c.id == tournament_id))
    if not row:
        raise HTTPException(404, "Nie znaleziono turnieju")

    data = _normalize_event_data(row["data_json"])
    if not data.get("invited_ids"):
        data["invited_ids"] = await _compute_invited_ids_for_badge(row.get("badge"), data)

    # user może wejść tylko jeśli widoczny
    if row.get("badge"):
        user_row = await database.fetch_one(select(beach_users.c.badges).where(beach_users.c.id == current_user_id))
        if not user_row:
            raise HTTPException(404, "Użytkownik nie znaleziony")
        if row.get("badge") not in set(_extract_badge_names(user_row["badges"])):
            raise HTTPException(403, "Brak dostępu")

    return _attach_computed_fields(row, data, current_user_id)


@router.patch("/{tournament_id}", response_model=BeachTournamentItem, summary="Częściowa edycja turnieju (BEACH) — wymaga admina")
async def patch_tournament(
    tournament_id: int,
    body: UpdateBeachTournamentRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    existing = await database.fetch_one(select(beach_tournaments).where(beach_tournaments.c.id == tournament_id))
    if not existing:
        raise HTTPException(404, "Nie znaleziono turnieju")

    update_data: Dict[str, Any] = {}

    fields = getattr(body, "__fields_set__", set())

    if "badge" in fields:
        update_data["badge"] = body.badge.strip() if body.badge else None
    if body.event_date is not None:
        update_data["event_date"] = body.event_date
    if body.name is not None:
        update_data["name"] = body.name.strip()
    if body.description is not None:
        update_data["description"] = (body.description or "").strip() or None
    if body.data_json is not None:
        update_data["data_json"] = _normalize_event_data(body.data_json)

    if not update_data:
        data = _normalize_event_data(existing["data_json"])
        if not data.get("invited_ids"):
            data["invited_ids"] = await _compute_invited_ids_for_badge(existing.get("badge"), data)
        return _attach_computed_fields(existing, data, None)

    update_data["updated_at"] = datetime.now(timezone.utc)

    # jeśli target/badge zmieniony i invited_ids puste -> przelicz
    if "data_json" in update_data or "badge" in update_data:
        badge_eff = update_data.get("badge", existing.get("badge"))
        data_eff = _normalize_event_data(update_data.get("data_json", existing["data_json"]))
        if not data_eff.get("invited_ids"):
            data_eff["invited_ids"] = await _compute_invited_ids_for_badge(badge_eff, data_eff)
        update_data["data_json"] = data_eff

    await database.execute(
        update(beach_tournaments).where(beach_tournaments.c.id == tournament_id).values(**update_data)
    )

    row = await database.fetch_one(select(beach_tournaments).where(beach_tournaments.c.id == tournament_id))
    data2 = _normalize_event_data(row["data_json"])
    if not data2.get("invited_ids"):
        data2["invited_ids"] = await _compute_invited_ids_for_badge(row.get("badge"), data2)

    return _attach_computed_fields(row, data2, None)


@router.delete("/{tournament_id}", response_model=dict, summary="Usuń turniej (BEACH) — wymaga admina")
async def delete_tournament(
    tournament_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    row = await database.fetch_one(select(beach_tournaments.c.id).where(beach_tournaments.c.id == tournament_id))
    if not row:
        raise HTTPException(404, "Nie znaleziono turnieju")

    await database.execute(delete(beach_tournaments).where(beach_tournaments.c.id == tournament_id))
    return {"success": True}


@router.patch("/{tournament_id}/attendance", response_model=BeachTournamentItem, summary="Aktualizuj obecność (present_ids) (BEACH) — wymaga admina")
async def update_tournament_attendance(
    tournament_id: int,
    body: UpdateBeachTournamentAttendanceRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    existing = await database.fetch_one(select(beach_tournaments).where(beach_tournaments.c.id == tournament_id))
    if not existing:
        raise HTTPException(404, "Nie znaleziono turnieju")

    data = _normalize_event_data(existing["data_json"])
    present_ids = [str(x).strip() for x in (body.present_ids or []) if str(x).strip()]
    data["present_ids"] = sorted(list(set(present_ids)))

    if not data.get("invited_ids"):
        data["invited_ids"] = await _compute_invited_ids_for_badge(existing.get("badge"), data)

    await database.execute(
        update(beach_tournaments)
        .where(beach_tournaments.c.id == tournament_id)
        .values(data_json=data, updated_at=datetime.now(timezone.utc))
    )

    row = await database.fetch_one(select(beach_tournaments).where(beach_tournaments.c.id == tournament_id))
    data2 = _normalize_event_data(row["data_json"])
    if not data2.get("invited_ids"):
        data2["invited_ids"] = await _compute_invited_ids_for_badge(row.get("badge"), data2)

    return _attach_computed_fields(row, data2, None)
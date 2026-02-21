# app/province_events.py
from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import traceback
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select, insert, update, delete
from sqlalchemy.sql import and_

from app.db import database, province_events, province_judges
from app.schemas import (
    CreateProvinceEventRequest,
    UpdateProvinceEventRequest,
    UpdateProvinceEventAttendanceRequest,
    ProvinceEventItem,
    ListProvinceEventsResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province-events", tags=["Province Events"])


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


def _normalize_province(p: str) -> str:
    return (p or "").strip().upper()


def _extract_badge_names(badges_raw: Any) -> List[str]:
    """
    province_judges.badges u Ciebie jest JSON (server_default="{}").
    Może być:
    - dict: { "Komisja sędziowska": true, "Delegaci": true, ... }
    - list: ["Delegaci","..."]
    - inne -> []
    """
    if badges_raw is None:
        return []
    if isinstance(badges_raw, dict):
        # bierzemy klucze o truthy value
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
    """
    Standaryzujemy strukturę, ale nie blokujemy dodatkowych pól.
    Klucze wspierane:
      - target: { include_badges:[], exclude_badges:[], include_all:boolean }
      - invited_ids:[]
      - present_ids:[]
    """
    base = _parse_json(data_json)

    target = base.get("target") if isinstance(base.get("target"), dict) else {}
    include_badges = target.get("include_badges") or []
    exclude_badges = target.get("exclude_badges") or []
    include_all = bool(target.get("include_all") or False)

    if not isinstance(include_badges, list):
        include_badges = []
    if not isinstance(exclude_badges, list):
        exclude_badges = []

    invited_ids = base.get("invited_ids") or []
    present_ids = base.get("present_ids") or []

    if not isinstance(invited_ids, list):
        invited_ids = []
    if not isinstance(present_ids, list):
        present_ids = []

    # normalizacja stringów
    include_badges = [str(x).strip() for x in include_badges if str(x).strip()]
    exclude_badges = [str(x).strip() for x in exclude_badges if str(x).strip()]
    invited_ids = [str(x).strip() for x in invited_ids if str(x).strip()]
    present_ids = [str(x).strip() for x in present_ids if str(x).strip()]

    base["target"] = {
        "include_badges": include_badges,
        "exclude_badges": exclude_badges,
        "include_all": include_all,
    }
    base["invited_ids"] = invited_ids
    base["present_ids"] = present_ids
    return base


async def _compute_invited_ids_for_province(province: str, data: Dict[str, Any]) -> List[str]:
    """
    Wylicza listę invited_ids na podstawie province_judges.badges i targetu.
    - include_all: zaprasza wszystkich (poza exclude_badges)
    - include_badges: zaprasza tych, którzy mają przynajmniej jeden badge z listy
    - exclude_badges: usuwa tych, którzy mają którykolwiek badge z listy
    """
    province = _normalize_province(province)
    target = data.get("target") or {}
    include_all = bool(target.get("include_all") or False)
    include_badges: List[str] = target.get("include_badges") or []
    exclude_badges: List[str] = target.get("exclude_badges") or []

    rows = await database.fetch_all(
        select(
            province_judges.c.judge_id,
            province_judges.c.badges,
        ).where(province_judges.c.province == province)
    )

    invited: List[str] = []
    include_set = set([x.strip() for x in include_badges if x.strip()])
    exclude_set = set([x.strip() for x in exclude_badges if x.strip()])

    for r in rows:
        jid = str(r["judge_id"])
        bnames = set(_extract_badge_names(r["badges"]))

        # exclude
        if exclude_set and any(b in bnames for b in exclude_set):
            continue

        if include_all:
            invited.append(jid)
            continue

        # include rule
        if include_set:
            if any(b in bnames for b in include_set):
                invited.append(jid)
        else:
            # jeśli include_badges puste i include_all False -> interpretacja:
            # zaproś wszystkich (poza exclude), bo event "dla wszystkich"
            invited.append(jid)

    # stabilna kolejność: po judge_id (string)
    invited = sorted(list(set(invited)))
    return invited


def _attach_computed_fields(
    row: Any,
    data: Dict[str, Any],
    judge_id: Optional[str],
) -> ProvinceEventItem:
    invited_ids = data.get("invited_ids") or []
    present_ids = data.get("present_ids") or []
    invited_set = set([str(x) for x in invited_ids])
    present_set = set([str(x) for x in present_ids])

    jid = str(judge_id) if judge_id else None
    user_invited = bool(jid and jid in invited_set)
    user_present = bool(jid and jid in present_set)

    return ProvinceEventItem(
        id=int(row["id"]),
        province=row["province"],
        event_date=row["event_date"],
        name=row["name"],
        description=row["description"],
        data_json=data,
        updated_at=row["updated_at"],
        invited_total=len(invited_set),
        present_total=len(present_set & invited_set) if invited_set else len(present_set),
        user_invited=user_invited,
        user_present=user_present,
    )


@router.post("/", response_model=dict, summary="Utwórz wydarzenie okręgowe")
async def create_province_event(req: CreateProvinceEventRequest):
    now = datetime.now(timezone.utc)
    province = _normalize_province(req.province)
    if not province:
        raise HTTPException(400, "Brak province")

    if not req.name or not req.name.strip():
        raise HTTPException(400, "Brak nazwy wydarzenia")

    data = _normalize_event_data(req.data_json)

    # jeśli invited_ids puste -> wylicz z targetu
    if not data.get("invited_ids"):
        data["invited_ids"] = await _compute_invited_ids_for_province(province, data)
    # jeśli present_ids zawiera kogoś spoza invited -> zostawimy, ale app i tak liczy invited/present logicznie

    try:
        stmt = (
            insert(province_events)
            .values(
                province=province,
                event_date=req.event_date,
                name=req.name.strip(),
                description=(req.description or "").strip() or None,
                data_json=data,
                updated_at=now,
            )
            .returning(province_events.c.id)
        )
        row = await database.fetch_one(stmt)
        if not row:
            raise HTTPException(500, "Nie udało się utworzyć wydarzenia")
        return {"success": True, "id": int(row["id"])}
    except Exception as e:
        logger.error("create_province_event failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"create_province_event failed: {e}")


@router.get("/", response_model=ListProvinceEventsResponse, summary="Lista wydarzeń okręgowych (admin)")
async def list_province_events(
    province: str = Query(..., description="Województwo, np. ŚLĄSKIE"),
    judge_id: Optional[str] = Query(None, description="Opcjonalnie: do computed user_invited/user_present"),
):
    province_n = _normalize_province(province)
    rows = await database.fetch_all(
        select(province_events)
        .where(province_events.c.province == province_n)
        .order_by(province_events.c.event_date.asc(), province_events.c.id.asc())
    )

    out: List[ProvinceEventItem] = []
    for r in rows:
        data = _normalize_event_data(r["data_json"])
        # jeśli event ma pustą listę invited_ids (np. stare rekordy) -> wylicz „w locie”
        if not data.get("invited_ids"):
            data["invited_ids"] = await _compute_invited_ids_for_province(province_n, data)

        out.append(_attach_computed_fields(r, data, judge_id))
    return ListProvinceEventsResponse(events=out)


@router.get("/visible", response_model=ListProvinceEventsResponse, summary="Lista wydarzeń widocznych dla sędziego")
async def list_visible_events_for_judge(
    judge_id: str = Query(..., description="ID sędziego"),
    province: str = Query(..., description="Województwo sędziego"),
):
    """
    Zwraca tylko te wydarzenia, na które sędzia jest zaproszony (target badge’y).
    """
    province_n = _normalize_province(province)
    jid = str(judge_id).strip()
    if not jid:
        raise HTTPException(400, "Brak judge_id")

    rows = await database.fetch_all(
        select(province_events)
        .where(province_events.c.province == province_n)
        .order_by(province_events.c.event_date.asc(), province_events.c.id.asc())
    )

    out: List[ProvinceEventItem] = []
    for r in rows:
        data = _normalize_event_data(r["data_json"])
        if not data.get("invited_ids"):
            data["invited_ids"] = await _compute_invited_ids_for_province(province_n, data)

        invited_set = set([str(x) for x in (data.get("invited_ids") or [])])
        if jid not in invited_set:
            continue

        out.append(_attach_computed_fields(r, data, jid))

    return ListProvinceEventsResponse(events=out)


@router.get("/{event_id}", response_model=ProvinceEventItem, summary="Pobierz wydarzenie po ID")
async def get_province_event(
    event_id: int,
    judge_id: Optional[str] = Query(None, description="Opcjonalnie: computed user_*"),
):
    row = await database.fetch_one(select(province_events).where(province_events.c.id == event_id))
    if not row:
        raise HTTPException(404, "Nie znaleziono wydarzenia")

    data = _normalize_event_data(row["data_json"])
    if not data.get("invited_ids"):
        data["invited_ids"] = await _compute_invited_ids_for_province(row["province"], data)

    return _attach_computed_fields(row, data, judge_id)


@router.patch("/{event_id}", response_model=ProvinceEventItem, summary="Częściowa edycja wydarzenia")
async def patch_province_event(event_id: int, body: UpdateProvinceEventRequest):
    existing = await database.fetch_one(select(province_events).where(province_events.c.id == event_id))
    if not existing:
        raise HTTPException(404, "Nie znaleziono wydarzenia")

    update_data: Dict[str, Any] = {}
    if body.province is not None:
        update_data["province"] = _normalize_province(body.province)
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
            data["invited_ids"] = await _compute_invited_ids_for_province(existing["province"], data)
        return _attach_computed_fields(existing, data, None)

    update_data["updated_at"] = datetime.now(timezone.utc)

    # Jeśli zmienił się target/province i invited_ids puste -> przelicz
    if "data_json" in update_data:
        p_eff = update_data.get("province") or existing["province"]
        data_eff = update_data["data_json"]
        if not data_eff.get("invited_ids"):
            data_eff["invited_ids"] = await _compute_invited_ids_for_province(p_eff, data_eff)
        update_data["data_json"] = data_eff

    await database.execute(
        update(province_events).where(province_events.c.id == event_id).values(**update_data)
    )

    row = await database.fetch_one(select(province_events).where(province_events.c.id == event_id))
    data = _normalize_event_data(row["data_json"])
    if not data.get("invited_ids"):
        data["invited_ids"] = await _compute_invited_ids_for_province(row["province"], data)
    return _attach_computed_fields(row, data, None)


@router.delete("/{event_id}", response_model=dict, summary="Usuń wydarzenie")
async def delete_province_event(event_id: int):
    row = await database.fetch_one(select(province_events.c.id).where(province_events.c.id == event_id))
    if not row:
        raise HTTPException(404, "Nie znaleziono wydarzenia")

    await database.execute(delete(province_events).where(province_events.c.id == event_id))
    return {"success": True}


@router.patch("/{event_id}/attendance", response_model=ProvinceEventItem, summary="Aktualizuj obecność (present_ids)")
async def update_event_attendance(event_id: int, body: UpdateProvinceEventAttendanceRequest):
    existing = await database.fetch_one(select(province_events).where(province_events.c.id == event_id))
    if not existing:
        raise HTTPException(404, "Nie znaleziono wydarzenia")

    data = _normalize_event_data(existing["data_json"])
    present_ids = [str(x).strip() for x in (body.present_ids or []) if str(x).strip()]
    data["present_ids"] = sorted(list(set(present_ids)))

    # jeśli invited_ids puste (stare rekordy) -> wylicz
    if not data.get("invited_ids"):
        data["invited_ids"] = await _compute_invited_ids_for_province(existing["province"], data)

    await database.execute(
        update(province_events)
        .where(province_events.c.id == event_id)
        .values(
            data_json=data,
            updated_at=datetime.now(timezone.utc),
        )
    )

    row = await database.fetch_one(select(province_events).where(province_events.c.id == event_id))
    data2 = _normalize_event_data(row["data_json"])
    if not data2.get("invited_ids"):
        data2["invited_ids"] = await _compute_invited_ids_for_province(row["province"], data2)

    return _attach_computed_fields(row, data2, None)
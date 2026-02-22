# app/province_travel.py
from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import traceback
from typing import Any, Dict, Optional, List

from fastapi import APIRouter, HTTPException, Query, Path
from sqlalchemy import select, insert, update

from app.db import database, province_travel
from app.schemas import (
    ProvinceTravelUpsertAllRequest,
    ProvinceTravelUpsertSeasonRequest,
    ProvinceTravelItem,
    GetProvinceTravelResponse,
    ListProvinceTravelResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province-travel", tags=["Province Travel"])


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_province(p: str) -> str:
    return (p or "").strip().upper()


def _parse_json(raw: Any) -> dict:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _normalize_root_payload(data_json: Any) -> Dict[str, Any]:
    """
    Trzymamy ustandaryzowaną strukturę, ale nie blokujemy rozszerzeń:
      {
        "seasons": {
           "2024/2025": {...},
           "2025/2026": {...}
        },
        ... (inne pola opcjonalnie)
      }
    """
    base = _parse_json(data_json)
    seasons = base.get("seasons")
    if not isinstance(seasons, dict):
        seasons = {}
    # klucze sezonów jako string
    clean_seasons: Dict[str, Any] = {}
    for k, v in seasons.items():
        kk = str(k).strip()
        if not kk:
            continue
        clean_seasons[kk] = v
    base["seasons"] = clean_seasons
    return base


def _row_to_item(row: Any) -> ProvinceTravelItem:
    return ProvinceTravelItem(
        judge_id=str(row["judge_id"]),
        full_name=row["full_name"],
        province=row["province"],
        data_json=_normalize_root_payload(row["data_json"]),
        updated_at=row["updated_at"],
    )


@router.get(
    "/{judge_id}",
    response_model=GetProvinceTravelResponse,
    summary="Pobierz zapis przejazdów dla sędziego (wszystkie sezony)",
)
async def get_travel_for_judge(judge_id: str = Path(..., description="ID sędziego")):
    jid = str(judge_id).strip()
    if not jid:
        raise HTTPException(400, "Brak judge_id")

    row = await database.fetch_one(select(province_travel).where(province_travel.c.judge_id == jid))
    if not row:
        return GetProvinceTravelResponse(record=None)

    return GetProvinceTravelResponse(record=_row_to_item(row))


@router.get(
    "/",
    response_model=ListProvinceTravelResponse,
    summary="Lista zapisów przejazdów (admin/okręg) – filtrowanie po province",
)
async def list_travel_records(
    province: Optional[str] = Query(None, description="Województwo, np. ŚLĄSKIE"),
    q: Optional[str] = Query(None, description="Szukaj po judge_id lub full_name"),
    limit: int = Query(200, ge=1, le=2000),
):
    stmt = select(province_travel)

    if province:
        stmt = stmt.where(province_travel.c.province == _normalize_province(province))

    if q and q.strip():
        needle = f"%{q.strip()}%"
        # databases + SQLAlchemy: prosto po full_name/judge_id
        stmt = stmt.where(
            (province_travel.c.judge_id.ilike(needle)) | (province_travel.c.full_name.ilike(needle))
        )

    stmt = stmt.order_by(province_travel.c.updated_at.desc()).limit(limit)

    rows = await database.fetch_all(stmt)
    return ListProvinceTravelResponse(records=[_row_to_item(r) for r in rows])


@router.put(
    "/{judge_id}",
    response_model=dict,
    summary="Upsert CAŁOŚCI danych przejazdów (wszystkie sezony) – replace",
)
async def upsert_travel_all(judge_id: str, body: ProvinceTravelUpsertAllRequest):
    """
    UWAGA: to jest replace data_json (pełny stan).
    Do bezpiecznej aktualizacji tylko jednego sezonu użyj PATCH /season.
    """
    jid_path = str(judge_id).strip()
    jid = str(body.judge_id).strip()

    if not jid_path or jid_path != jid:
        raise HTTPException(400, "judge_id w path i body musi być identyczny")

    province = _normalize_province(body.province)
    if not province:
        raise HTTPException(400, "Brak province")

    full_name = (body.full_name or "").strip()
    if not full_name:
        raise HTTPException(400, "Brak full_name")

    data = _normalize_root_payload(body.data_json)

    now = _now_utc()
    existing = await database.fetch_one(select(province_travel.c.judge_id).where(province_travel.c.judge_id == jid))

    try:
        if not existing:
            await database.execute(
                insert(province_travel).values(
                    judge_id=jid,
                    full_name=full_name,
                    province=province,
                    data_json=data,
                    updated_at=now,
                )
            )
            return {"success": True, "created": True}
        else:
            await database.execute(
                update(province_travel)
                .where(province_travel.c.judge_id == jid)
                .values(
                    full_name=full_name,
                    province=province,
                    data_json=data,
                    updated_at=now,
                )
            )
            return {"success": True, "created": False}
    except Exception as e:
        logger.error("upsert_travel_all failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(500, f"upsert_travel_all failed: {e}")


@router.patch(
    "/{judge_id}/season",
    response_model=dict,
    summary="Upsert tylko JEDNEGO sezonu – merge bez usuwania innych sezonów",
)
async def upsert_travel_season(judge_id: str, body: ProvinceTravelUpsertSeasonRequest):
    jid_path = str(judge_id).strip()
    jid = str(body.judge_id).strip()

    if not jid_path or jid_path != jid:
        raise HTTPException(400, "judge_id w path i body musi być identyczny")

    province = _normalize_province(body.province)
    if not province:
        raise HTTPException(400, "Brak province")

    full_name = (body.full_name or "").strip()
    if not full_name:
        raise HTTPException(400, "Brak full_name")

    season_key = (body.season_key or "").strip()
    if not season_key:
        raise HTTPException(400, "Brak season_key")

    season_json = body.season_json if body.season_json is not None else {}
    season_updated_at = body.season_updated_at or _now_utc()

    now = _now_utc()
    row = await database.fetch_one(select(province_travel).where(province_travel.c.judge_id == jid))

    try:
        if not row:
            # create z jednym sezonem
            data = {"seasons": {season_key: {"data": season_json, "updated_at": season_updated_at.isoformat()}}}
            await database.execute(
                insert(province_travel).values(
                    judge_id=jid,
                    full_name=full_name,
                    province=province,
                    data_json=data,
                    updated_at=now,
                )
            )
            return {"success": True, "created": True, "season_key": season_key}

        # merge: zachowaj inne sezony
        data = _normalize_root_payload(row["data_json"])
        seasons = data.get("seasons") if isinstance(data.get("seasons"), dict) else {}
        seasons[season_key] = {"data": season_json, "updated_at": season_updated_at.isoformat()}
        data["seasons"] = seasons

        await database.execute(
            update(province_travel)
            .where(province_travel.c.judge_id == jid)
            .values(
                full_name=full_name,
                province=province,
                data_json=data,
                updated_at=now,
            )
        )
        return {"success": True, "created": False, "season_key": season_key}
    except Exception as e:
        logger.error("upsert_travel_season failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(500, f"upsert_travel_season failed: {e}")
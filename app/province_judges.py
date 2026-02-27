# app/province_judges.py
from datetime import datetime, timezone
import logging
import traceback
from typing import Any

from fastapi import APIRouter, HTTPException
from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import database, province_judges
from app.schemas import (
    CreateProvinceJudgeRequest,
    UpdateProvinceJudgeRequest,
    ProvinceJudgeItem,
    ListProvinceJudgesResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province_judges", tags=["ProvinceJudges"])


def _norm_province(p: str) -> str:
    return (p or "").strip().upper()


def _badges_or_default(badges: Any | None) -> Any:
    return badges if badges is not None else {}


def _photo_or_none(photo_url: Any | None) -> str | None:
    # ✅ pusty string traktujemy jako "nie przesłano" (None) dla UPSERT/COALESCE
    s = (photo_url or "").strip()
    return s if s else None


def _row_to_item(row) -> ProvinceJudgeItem:
    d = dict(row)
    if d.get("photo_url") is None:
        d["photo_url"] = ""
    if d.get("badges") is None:
        d["badges"] = {}
    return ProvinceJudgeItem(**d)


@router.post("/", response_model=dict, summary="Upsert sędziego w tabeli province_judges")
async def upsert_province_judge(req: CreateProvinceJudgeRequest):
    """
    Upsert:
    - judge_id = PK
    - zawsze nadpisuje full_name, province
    - photo_url: nadpisuje TYLKO jeśli przesłano niepuste (inaczej zostawia)
    - badges: jeśli nie podano -> {}
    """
    now = datetime.now(timezone.utc)
    prov = _norm_province(req.province)
    badges = _badges_or_default(req.badges)
    photo_url = _photo_or_none(getattr(req, "photo_url", None))

    try:
        stmt = (
            pg_insert(province_judges)
            .values(
                judge_id=req.judge_id,
                full_name=req.full_name,
                province=prov,
                photo_url=photo_url,   # ✅ None jeśli puste
                badges=badges,
                updated_at=now,
            )
            .on_conflict_do_update(
                index_elements=[province_judges.c.judge_id],
                set_={
                    "full_name": req.full_name,
                    "province": prov,
                    "photo_url": func.coalesce(
                        pg_insert(province_judges).excluded.photo_url,
                        province_judges.c.photo_url,
                    ),
                    "badges": badges,
                    "updated_at": now,
                },
            )
        )

        await database.execute(stmt)
        return {"success": True}

    except Exception as e:
        logger.error("upsert_province_judge failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"upsert_province_judge failed: {e}")


@router.get("/", response_model=ListProvinceJudgesResponse, summary="Lista wszystkich sędziów (province_judges)")
async def list_province_judges():
    q = select(province_judges).order_by(province_judges.c.province.asc(), province_judges.c.full_name.asc())
    rows = await database.fetch_all(q)
    return ListProvinceJudgesResponse(records=[_row_to_item(r) for r in rows])


@router.get("/province/{province}", response_model=ListProvinceJudgesResponse, summary="Lista sędziów dla wybranego województwa")
async def list_province_judges_by_province(province: str):
    prov = _norm_province(province)
    q = (
        select(province_judges)
        .where(func.upper(province_judges.c.province) == prov)
        .order_by(province_judges.c.full_name.asc())
    )
    rows = await database.fetch_all(q)
    return ListProvinceJudgesResponse(records=[_row_to_item(r) for r in rows])


@router.get("/{judge_id}", response_model=ProvinceJudgeItem, summary="Pobierz sędziego po judge_id (province_judges)")
async def get_province_judge(judge_id: str):
    row = await database.fetch_one(
        select(province_judges).where(province_judges.c.judge_id == judge_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono sędziego")
    return _row_to_item(row)


@router.patch("/{judge_id}", response_model=ProvinceJudgeItem, summary="Częściowa edycja sędziego (province_judges)")
async def patch_province_judge(judge_id: str, body: UpdateProvinceJudgeRequest):
    existing = await database.fetch_one(
        select(province_judges).where(province_judges.c.judge_id == judge_id)
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Nie znaleziono sędziego")

    update_data = {}
    if body.full_name is not None:
        update_data["full_name"] = body.full_name
    if body.province is not None:
        update_data["province"] = _norm_province(body.province)

    # ✅ PATCH: pozwalamy wyczyścić zdjęcie pustym stringiem
    if getattr(body, "photo_url", None) is not None:
        update_data["photo_url"] = (body.photo_url or "").strip()

    if body.badges is not None:
        update_data["badges"] = body.badges

    if not update_data:
        raise HTTPException(status_code=400, detail="Brak pól do aktualizacji")

    update_data["updated_at"] = datetime.now(timezone.utc)

    await database.execute(
        province_judges.update()
        .where(province_judges.c.judge_id == judge_id)
        .values(**update_data)
    )

    row = await database.fetch_one(
        select(province_judges).where(province_judges.c.judge_id == judge_id)
    )
    return _row_to_item(row)


@router.put("/{judge_id}", response_model=ProvinceJudgeItem, summary="Upsert sędziego po judge_id (province_judges)")
async def put_province_judge(judge_id: str, req: CreateProvinceJudgeRequest):
    now = datetime.now(timezone.utc)
    prov = _norm_province(req.province)
    badges = _badges_or_default(req.badges)
    photo_url = _photo_or_none(getattr(req, "photo_url", None))

    stmt = (
        pg_insert(province_judges)
        .values(
            judge_id=judge_id,
            full_name=req.full_name,
            province=prov,
            photo_url=photo_url,  # ✅ None jeśli puste
            badges=badges,
            updated_at=now,
        )
        .on_conflict_do_update(
            index_elements=[province_judges.c.judge_id],
            set_={
                "full_name": req.full_name,
                "province": prov,
                "photo_url": func.coalesce(
                    pg_insert(province_judges).excluded.photo_url,
                    province_judges.c.photo_url,
                ),
                "badges": badges,
                "updated_at": now,
            },
        )
    )

    await database.execute(stmt)

    row = await database.fetch_one(
        select(province_judges).where(province_judges.c.judge_id == judge_id)
    )
    return _row_to_item(row)


@router.delete("/{judge_id}", response_model=dict, summary="Usuń sędziego (province_judges)")
async def delete_province_judge(judge_id: str):
    await database.execute(
        province_judges.delete().where(province_judges.c.judge_id == judge_id)
    )
    return {"success": True}
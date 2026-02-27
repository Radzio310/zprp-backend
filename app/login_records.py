# app/routers/login_records.py
from datetime import datetime, timezone
import logging
import traceback

from fastapi import APIRouter, HTTPException
from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import database, login_records, province_judges
from app.schemas import (
    CreateLoginRecordRequest,
    LoginRecordItem,
    ListLoginRecordsResponse,
    UpdateLoginRecordRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/login_records", tags=["LoginRecords"])


def _norm_province(p: str | None) -> str | None:
    t = (p or "").strip()
    return t.upper() if t else None


def _photo_or_none(photo_url: str | None) -> str | None:
    # ✅ traktujemy pusty string jako "nie przesłano" (None) dla UPSERT/COALESCE
    t = (photo_url or "").strip()
    return t if t else None


def _config_or_none(cfg):
    # ✅ jeśli nie przesłano -> None (żeby COALESCE nie nadpisał)
    #    jeśli przesłano {} albo cokolwiek -> zostaw
    return cfg if cfg is not None else None


def _row_to_login_item(row) -> LoginRecordItem:
    d = dict(row)
    if d.get("photo_url") is None:
        d["photo_url"] = ""
    if d.get("config_json") is None:
        d["config_json"] = {}
    return LoginRecordItem(**d)


@router.post("/", response_model=dict, summary="Upsert ostatniego logowania")
async def upsert_login(req: CreateLoginRecordRequest):
    """
    - Zawsze nadpisuje: full_name, last_login_at
    - app_version / last_open_at / province / photo_url / config_json -> TYLKO jeśli przesłane
      (czyli excluded.* != NULL)
    - app_opens inkrementuje
    - Dodatkowo: upsert do province_judges (full_name/province/photo_url), badges bez zmian
    """
    now = datetime.now(timezone.utc)

    try:
        prov_norm = _norm_province(req.province)
        photo_norm = _photo_or_none(getattr(req, "photo_url", None))
        cfg_norm = _config_or_none(getattr(req, "config_json", None))

        stmt = pg_insert(login_records).values(
            judge_id=req.judge_id,
            full_name=req.full_name,
            last_login_at=now,
            app_version=req.app_version,
            app_opens=req.app_opens,
            last_open_at=req.last_open_at,
            province=prov_norm,
            photo_url=photo_norm,          # ✅ None jeśli puste -> nie nadpisze
            config_json=cfg_norm,          # ✅ None jeśli brak -> nie nadpisze
        )

        stmt = stmt.on_conflict_do_update(
            index_elements=[login_records.c.judge_id],
            set_={
                "full_name": req.full_name,
                "last_login_at": now,
                "app_version": func.coalesce(
                    stmt.excluded.app_version, login_records.c.app_version
                ),
                "app_opens": func.coalesce(login_records.c.app_opens, 0)
                + func.coalesce(stmt.excluded.app_opens, 0),
                "last_open_at": func.coalesce(
                    stmt.excluded.last_open_at, login_records.c.last_open_at
                ),
                "province": func.coalesce(
                    stmt.excluded.province, login_records.c.province
                ),
                "photo_url": func.coalesce(
                    stmt.excluded.photo_url, login_records.c.photo_url
                ),
                "config_json": func.coalesce(
                    stmt.excluded.config_json, login_records.c.config_json
                ),
            },
        )

        await database.execute(stmt)

        # ✅ Upsert do province_judges:
        # - province jest wymagane do sensownego wpisu per-województwo
        # - photo_url aktualizujemy TYLKO jeśli przesłano niepuste (czyli photo_norm != None)
        if prov_norm:
            pj_stmt = (
                pg_insert(province_judges)
                .values(
                    judge_id=req.judge_id,
                    full_name=req.full_name,
                    province=prov_norm,
                    photo_url=photo_norm,  # ✅ None jeśli brak
                    badges={},  # tylko przy insert
                    updated_at=now,
                )
                .on_conflict_do_update(
                    index_elements=[province_judges.c.judge_id],
                    set_={
                        "full_name": req.full_name,
                        "province": prov_norm,
                        "photo_url": func.coalesce(
                            pg_insert(province_judges).excluded.photo_url,
                            province_judges.c.photo_url,
                        ),
                        "updated_at": now,
                        "badges": province_judges.c.badges,  # badges bez zmian
                    },
                )
            )
            await database.execute(pj_stmt)

        return {"success": True}

    except Exception as e:
        logger.error("upsert_login failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"upsert_login failed: {e}")


@router.get("/", response_model=ListLoginRecordsResponse, summary="Lista wszystkich logowań")
async def list_logins():
    q = select(login_records).order_by(login_records.c.last_login_at.desc())
    rows = await database.fetch_all(q)
    return ListLoginRecordsResponse(records=[_row_to_login_item(r) for r in rows])


@router.get("/{judge_id}", response_model=LoginRecordItem, summary="Pobierz rekord logowania po judge_id")
async def get_login_record(judge_id: str):
    row = await database.fetch_one(
        select(login_records).where(login_records.c.judge_id == judge_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Nie znaleziono rekordu")
    return _row_to_login_item(row)


@router.delete("/{judge_id}", response_model=dict, summary="Usuń rekord logowania")
async def delete_login(judge_id: str):
    await database.execute(
        login_records.delete().where(login_records.c.judge_id == judge_id)
    )
    return {"success": True}


@router.patch(
    "/{judge_id}",
    response_model=LoginRecordItem,
    summary="Częściowa edycja rekordu logowania",
)
async def patch_login_record(judge_id: str, body: UpdateLoginRecordRequest):
    existing = await database.fetch_one(
        select(login_records).where(login_records.c.judge_id == judge_id)
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Nie znaleziono rekordu")

    update_data = {}
    if body.full_name is not None:
        update_data["full_name"] = body.full_name
    if body.app_version is not None:
        update_data["app_version"] = body.app_version
    if body.app_opens is not None:
        update_data["app_opens"] = func.coalesce(login_records.c.app_opens, 0) + body.app_opens
    if body.last_open_at is not None:
        update_data["last_open_at"] = body.last_open_at
    if body.last_login_at is not None:
        update_data["last_login_at"] = body.last_login_at
    if body.province is not None:
        update_data["province"] = body.province

    # ✅ PATCH: tu pozwalamy wyczyścić zdjęcie przez "", więc zapisujemy string (nie None)
    if getattr(body, "photo_url", None) is not None:
        update_data["photo_url"] = (body.photo_url or "").strip()

    # ✅ PATCH: config_json tylko jeśli przesłane (jak było)
    if body.config_json is not None:
        update_data["config_json"] = body.config_json

    if not update_data:
        raise HTTPException(status_code=400, detail="Brak pól do aktualizacji")

    await database.execute(
        login_records.update()
        .where(login_records.c.judge_id == judge_id)
        .values(**update_data)
    )

    row = await database.fetch_one(
        select(login_records).where(login_records.c.judge_id == judge_id)
    )
    return _row_to_login_item(row)


@router.put(
    "/{judge_id}",
    response_model=LoginRecordItem,
    summary="Upsert rekordu logowania po judge_id",
)
async def put_login_record(judge_id: str, req: CreateLoginRecordRequest):
    now = datetime.now(timezone.utc)

    prov_norm = _norm_province(req.province)
    photo_norm = _photo_or_none(getattr(req, "photo_url", None))
    cfg_norm = _config_or_none(getattr(req, "config_json", None))

    stmt = pg_insert(login_records).values(
        judge_id=judge_id,
        full_name=req.full_name,
        last_login_at=now,
        app_version=req.app_version,
        app_opens=req.app_opens,
        last_open_at=req.last_open_at,
        province=prov_norm,
        photo_url=photo_norm,     # ✅ None jeśli puste
        config_json=cfg_norm,     # ✅ None jeśli brak
    )

    stmt = stmt.on_conflict_do_update(
        index_elements=[login_records.c.judge_id],
        set_={
            "full_name": req.full_name,
            "last_login_at": now,
            "app_version": func.coalesce(stmt.excluded.app_version, login_records.c.app_version),
            "app_opens": func.coalesce(stmt.excluded.app_opens, login_records.c.app_opens),
            "last_open_at": func.coalesce(stmt.excluded.last_open_at, login_records.c.last_open_at),
            "province": func.coalesce(stmt.excluded.province, login_records.c.province),
            "photo_url": func.coalesce(stmt.excluded.photo_url, login_records.c.photo_url),
            "config_json": func.coalesce(stmt.excluded.config_json, login_records.c.config_json),
        },
    )

    await database.execute(stmt)

    row = await database.fetch_one(
        select(login_records).where(login_records.c.judge_id == judge_id)
    )
    return _row_to_login_item(row)
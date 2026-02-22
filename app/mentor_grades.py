# app/mentor_grades.py
from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import traceback
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, Path
from sqlalchemy import select, insert, update, delete

from app.db import database, mentor_grades
from app.schemas import (
    MentorGradesUpsertRequest,
    MentorGradesPatchRequest,
    MentorGradesItem,
    GetMentorGradesResponse,
    ListMentorGradesResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mentor-grades", tags=["Mentor Grades"])


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


def _normalize_grades_json(payload: Any) -> Dict[str, Any]:
    """
    Minimalna normalizacja:
      - oczekujemy intów rated/pending/total (jeśli są)
      - przepuszczamy dodatkowe pola (np. season)
    """
    data = _parse_json(payload)

    def _to_int(x: Any, default: int = 0) -> int:
        try:
            n = int(x)
            return n
        except Exception:
            return default

    # Ustandaryzowane klucze
    rated = _to_int(data.get("rated", 0), 0)
    pending = _to_int(data.get("pending", 0), 0)

    # total opcjonalnie, ale jeśli brak – możemy policzyć (rated+pending)
    total_raw = data.get("total", None)
    total = None
    if total_raw is not None:
        try:
            total = int(total_raw)
        except Exception:
            total = None
    if total is None:
        total = rated + pending

    out: Dict[str, Any] = dict(data)
    out["rated"] = rated
    out["pending"] = pending
    out["total"] = total

    # season opcjonalne (jeśli klient dopina)
    if "season" in out and out["season"] is not None:
        out["season"] = str(out["season"]).strip()

    return out


def _row_to_item(row: Any) -> MentorGradesItem:
    return MentorGradesItem(
        judge_id=str(row["judge_id"]),
        full_name=row["full_name"],
        province=row["province"],
        grades_json=_normalize_grades_json(row["grades_json"]),
        updated_at=row["updated_at"],
    )


@router.get(
    "/{judge_id}",
    response_model=GetMentorGradesResponse,
    summary="Pobierz zapis mentor-grades dla sędziego",
)
async def get_mentor_grades(judge_id: str = Path(..., description="ID sędziego")):
    jid = str(judge_id).strip()
    if not jid:
        raise HTTPException(400, "Brak judge_id")

    row = await database.fetch_one(select(mentor_grades).where(mentor_grades.c.judge_id == jid))
    if not row:
        return GetMentorGradesResponse(record=None)

    return GetMentorGradesResponse(record=_row_to_item(row))


@router.get(
    "/",
    response_model=ListMentorGradesResponse,
    summary="Lista mentor-grades (admin/okręg) – filtrowanie po province + q",
)
async def list_mentor_grades(
    province: Optional[str] = Query(None, description="Województwo, np. ŚLĄSKIE"),
    q: Optional[str] = Query(None, description="Szukaj po judge_id lub full_name"),
    limit: int = Query(200, ge=1, le=2000),
):
    stmt = select(mentor_grades)

    if province:
        stmt = stmt.where(mentor_grades.c.province == _normalize_province(province))

    if q and q.strip():
        needle = f"%{q.strip()}%"
        stmt = stmt.where(
            (mentor_grades.c.judge_id.ilike(needle)) | (mentor_grades.c.full_name.ilike(needle))
        )

    stmt = stmt.order_by(mentor_grades.c.updated_at.desc()).limit(limit)

    rows = await database.fetch_all(stmt)
    return ListMentorGradesResponse(records=[_row_to_item(r) for r in rows])


@router.put(
    "/{judge_id}",
    response_model=dict,
    summary="Upsert CAŁOŚCI rekordu mentor-grades (replace)",
)
async def upsert_mentor_grades(judge_id: str, body: MentorGradesUpsertRequest):
    jid_path = str(judge_id).strip()
    jid = str(body.judge_id).strip()
    if not jid_path or jid_path != jid:
        raise HTTPException(400, "judge_id w path i body musi być identyczny")

    full_name = (body.full_name or "").strip()
    if not full_name:
        raise HTTPException(400, "Brak full_name")

    province = _normalize_province(body.province)
    if not province:
        raise HTTPException(400, "Brak province")

    grades = _normalize_grades_json(body.grades_json)

    now = _now_utc()
    existing = await database.fetch_one(select(mentor_grades.c.judge_id).where(mentor_grades.c.judge_id == jid))

    try:
        if not existing:
            await database.execute(
                insert(mentor_grades).values(
                    judge_id=jid,
                    full_name=full_name,
                    province=province,
                    grades_json=grades,
                    updated_at=now,
                )
            )
            return {"success": True, "created": True}
        else:
            await database.execute(
                update(mentor_grades)
                .where(mentor_grades.c.judge_id == jid)
                .values(
                    full_name=full_name,
                    province=province,
                    grades_json=grades,
                    updated_at=now,
                )
            )
            return {"success": True, "created": False}
    except Exception as e:
        logger.error("upsert_mentor_grades failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(500, f"upsert_mentor_grades failed: {e}")


@router.patch(
    "/{judge_id}",
    response_model=dict,
    summary="Patch rekordu mentor-grades (partial update)",
)
async def patch_mentor_grades(judge_id: str, body: MentorGradesPatchRequest):
    jid = str(judge_id).strip()
    if not jid:
        raise HTTPException(400, "Brak judge_id")

    row = await database.fetch_one(select(mentor_grades).where(mentor_grades.c.judge_id == jid))
    if not row:
        raise HTTPException(404, "Rekord nie istnieje")

    values: Dict[str, Any] = {}
    if body.full_name is not None:
        fn = (body.full_name or "").strip()
        if not fn:
            raise HTTPException(400, "full_name nie może być puste")
        values["full_name"] = fn

    if body.province is not None:
        prov = _normalize_province(body.province)
        if not prov:
            raise HTTPException(400, "province nie może być puste")
        values["province"] = prov

    if body.grades_json is not None:
        values["grades_json"] = _normalize_grades_json(body.grades_json)

    if not values:
        return {"success": True, "updated": False}

    values["updated_at"] = _now_utc()

    try:
        await database.execute(
            update(mentor_grades)
            .where(mentor_grades.c.judge_id == jid)
            .values(**values)
        )
        return {"success": True, "updated": True}
    except Exception as e:
        logger.error("patch_mentor_grades failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(500, f"patch_mentor_grades failed: {e}")


@router.delete(
    "/{judge_id}",
    response_model=dict,
    summary="Usuń rekord mentor-grades",
)
async def delete_mentor_grades(judge_id: str = Path(..., description="ID sędziego")):
    jid = str(judge_id).strip()
    if not jid:
        raise HTTPException(400, "Brak judge_id")

    try:
        res = await database.execute(delete(mentor_grades).where(mentor_grades.c.judge_id == jid))
        # databases dla delete zwraca zwykle liczbę lub None zależnie od drivera, więc zwracamy success always
        return {"success": True}
    except Exception as e:
        logger.error("delete_mentor_grades failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(500, f"delete_mentor_grades failed: {e}")
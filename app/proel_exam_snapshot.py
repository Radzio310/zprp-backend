"""Współdzielona, wersjonowana migawka badań zawodników per mecz."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, insert, select, update

from app.db import database, proel_match_state
from app.proel_auth import Actor, crew_is_known, merge_guard, proel_actor, roles_for
from app.proel_exam_snapshot_rules import (
    clean_snapshot,
    snapshot_hash,
    snapshot_is_frozen,
    valid_date_key,
)
from app.proel_match_key import (
    IDENTITY_CONFLICT,
    identity_verdict,
    local_key_from_guard,
    match_identity,
)

router = APIRouter(prefix="/proel/exam-snapshot", tags=["ProEl"])

# Endpoint ma być lekkim pierwszym obrazem ekranu. `fields_json` i
# `audit_json` rosną przez cały mecz, więc nie pobieramy ich tylko po to, żeby
# odczytać badania.
EXAM_STATE_COLUMNS = (
    proel_match_state.c.match_number,
    proel_match_state.c.zprp_match_id,
    proel_match_state.c.local_key,
    proel_match_state.c.guard_json,
    proel_match_state.c.rev,
    proel_match_state.c.exam_snapshot_json,
    proel_match_state.c.exam_snapshot_rev,
    proel_match_state.c.exam_snapshot_date,
    proel_match_state.c.exam_snapshot_hash,
    proel_match_state.c.exam_snapshot_at,
)


class ExamSnapshotPut(BaseModel):
    match_number: str = Field(..., min_length=1, max_length=100)
    zprp_match_id: Optional[str] = Field(None, max_length=100)
    guard: Optional[Dict[str, Any]] = None
    date_key: str
    host_players: List[Dict[str, Any]] = Field(default_factory=list)
    guest_players: List[Dict[str, Any]] = Field(default_factory=list)


def _as_dict(row: Any) -> Dict[str, Any]:
    if row is None:
        return {}
    return dict(row._mapping) if hasattr(row, "_mapping") else dict(row)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _officials(guard: Any) -> Dict[str, Any]:
    if not isinstance(guard, dict):
        return {}
    officials = guard.get("officials")
    return officials if isinstance(officials, dict) else {}


def _require_match_official(actor: Actor, guard: Any) -> None:
    officials = _officials(guard)
    if not crew_is_known(officials) or not roles_for(actor, officials):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={
                "code": "ROLE_FORBIDDEN",
                "message": "Migawkę badań może zapisać i odczytać osoba z obsady meczu.",
            },
        )


def _identity_conflicts(row: Dict[str, Any], zprp_id: str, local_key: str) -> bool:
    known = match_identity(row.get("zprp_match_id"), row.get("local_key"))
    incoming = match_identity(zprp_id, local_key)
    return identity_verdict(known, incoming) == IDENTITY_CONFLICT


def _response(row: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = row.get("exam_snapshot_json")
    exists = isinstance(snapshot, dict)
    return {
        "exists": exists,
        "match_number": str(row.get("match_number") or ""),
        "zprp_match_id": str(row.get("zprp_match_id") or "") or None,
        "date_key": str(row.get("exam_snapshot_date") or "") or None,
        "revision": int(row.get("exam_snapshot_rev") or 0),
        "updated_at": row.get("exam_snapshot_at"),
        "frozen": bool(
            row.get("exam_snapshot_date")
            and snapshot_is_frozen(str(row["exam_snapshot_date"]), _now())
        ),
        "host_players": list((snapshot or {}).get("hostPlayers") or []),
        "guest_players": list((snapshot or {}).get("guestPlayers") or []),
    }


@router.get("")
async def get_exam_snapshot(
    match: str = Query(..., min_length=1, max_length=100),
    zprp_match_id: Optional[str] = Query(None, max_length=100),
    actor: Actor = Depends(proel_actor),
):
    number = str(match or "").strip()
    row = _as_dict(
        await database.fetch_one(
            select(*EXAM_STATE_COLUMNS).where(
                proel_match_state.c.match_number == number
            )
        )
    )
    if not row:
        return {
            "exists": False,
            "match_number": number,
            "zprp_match_id": str(zprp_match_id or "").strip() or None,
            "date_key": None,
            "revision": 0,
            "updated_at": None,
            "frozen": False,
            "host_players": [],
            "guest_players": [],
        }

    incoming_id = str(zprp_match_id or "").strip()
    if incoming_id and _identity_conflicts(row, incoming_id, ""):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": "MATCH_ID_MISMATCH", "message": "Migawka należy do innego meczu."},
        )
    _require_match_official(actor, row.get("guard_json"))
    return _response(row)


@router.put("")
async def put_exam_snapshot(
    req: ExamSnapshotPut,
    actor: Actor = Depends(proel_actor),
):
    number = str(req.match_number or "").strip()
    zprp_id = str(req.zprp_match_id or "").strip()
    guard = dict(req.guard or {})
    local_key = local_key_from_guard(number, guard) or ""
    if not number:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "MATCH_NUMBER_REQUIRED", "message": "Brakuje numeru meczu."},
        )
    try:
        date_key = valid_date_key(req.date_key)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "INVALID_MATCH_DATE", "message": str(exc)},
        ) from exc
    now = _now()

    snapshot = clean_snapshot(req.host_players, req.guest_players)
    if not snapshot["hostPlayers"] and not snapshot["guestPlayers"]:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "EMPTY_SNAPSHOT", "message": "Migawka nie zawiera zawodników."},
        )
    content_hash = snapshot_hash(date_key, snapshot)

    async with database.transaction():
        row = _as_dict(
            await database.fetch_one(
                select(*EXAM_STATE_COLUMNS)
                .where(proel_match_state.c.match_number == number)
                .with_for_update()
            )
        )
        if not row:
            await database.execute(
                insert(proel_match_state).values(
                    match_number=number,
                    zprp_match_id=zprp_id or None,
                    local_key=local_key or None,
                    guard_json=guard or None,
                    rev=1,
                    fields_json={},
                    audit_json={"log": [], "ops": []},
                )
            )
            row = _as_dict(
                await database.fetch_one(
                    select(*EXAM_STATE_COLUMNS)
                    .where(proel_match_state.c.match_number == number)
                    .with_for_update()
                )
            )
        elif _identity_conflicts(row, zprp_id, local_key):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail={"code": "MATCH_ID_MISMATCH", "message": "Ten numer należy do innego meczu."},
            )

        merged_guard = merge_guard(row.get("guard_json"), guard)
        _require_match_official(actor, merged_guard)

        previous_date = str(row.get("exam_snapshot_date") or "")
        if previous_date == date_key and snapshot_is_frozen(previous_date, now):
            # Po polskiej północy stan zakończonego dnia jest niezmienny.
            return _response(row)
        if snapshot_is_frozen(date_key, now):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail={
                    "code": "EXAM_SNAPSHOT_FROZEN",
                    "message": "Dzień meczu już się zakończył; migawki nie można nadpisać.",
                },
            )

        if (
            previous_date == date_key
            and str(row.get("exam_snapshot_hash") or "") == content_hash
        ):
            return _response(row)

        snapshot_rev = int(row.get("exam_snapshot_rev") or 0) + 1
        values: Dict[str, Any] = {
            "guard_json": merged_guard or None,
            "exam_snapshot_json": snapshot,
            "exam_snapshot_rev": snapshot_rev,
            "exam_snapshot_date": date_key,
            "exam_snapshot_hash": content_hash,
            "exam_snapshot_at": now,
            "rev": int(row.get("rev") or 0) + 1,
            "updated_at": func.now(),
        }
        if zprp_id and not str(row.get("zprp_match_id") or "").strip():
            values["zprp_match_id"] = zprp_id
        if local_key and not str(row.get("local_key") or "").strip():
            values["local_key"] = local_key
        await database.execute(
            update(proel_match_state)
            .where(proel_match_state.c.match_number == number)
            .values(**values)
        )
        row.update(values)
        row["exam_snapshot_at"] = now
        row["exam_snapshot_rev"] = snapshot_rev

    return _response(row)

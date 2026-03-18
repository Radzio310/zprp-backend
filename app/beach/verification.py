from __future__ import annotations

from datetime import datetime, timezone
import traceback
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import select, update

from app.db import database, beach_users, beach_verification_requests
from app.schemas import (
    BeachVerificationCreateRequest,
    BeachVerificationItem,
    BeachVerificationPatchRequest,
    BeachVerificationsListResponse,
)
from app.deps import beach_get_current_user_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/verifications", tags=["Beach: Verifications"])

ALLOWED_ROLES = {"judge", "coach", "player"}
ALLOWED_STATUSES = {"pending", "approved", "rejected"}

# Role type → badge name mapping
ROLE_BADGE_MAP = {
    "judge": "Sędzia",
    "coach": "Trener",
    "player": "Zawodnik",
}


def _to_item(row: dict) -> BeachVerificationItem:
    return BeachVerificationItem(
        id=int(row["id"]),
        user_id=int(row["user_id"]),
        role=row["role"],
        status=row["status"],
        meta=row.get("meta") or {},
        admin_note=row.get("admin_note"),
        reviewed_by_user_id=row.get("reviewed_by_user_id"),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _parse_jsonish(raw: Any, fallback: Any):
    if raw is None:
        return fallback
    if isinstance(raw, (dict, list)):
        return raw
    try:
        import json
        return json.loads(raw)
    except Exception:
        return fallback


# ──────────────────────────────────────────────────
# GET /beach/verifications/pending_count  (admin)
# ──────────────────────────────────────────────────

@router.get(
    "/pending_count",
    response_model=dict,
    summary="Liczba oczekujących wniosków weryfikacyjnych (BEACH)",
)
async def get_pending_count():
    rows = await database.fetch_all(
        select(beach_verification_requests).where(
            beach_verification_requests.c.status == "pending"
        )
    )
    return {"pending_count": len(rows)}


# ──────────────────────────────────────────────────
# GET /beach/verifications/  (admin)
# ──────────────────────────────────────────────────

@router.get(
    "/",
    response_model=BeachVerificationsListResponse,
    summary="Lista wniosków weryfikacyjnych (BEACH) — wymaga admina",
)
async def list_verifications(status: Optional[str] = None):
    q = select(beach_verification_requests).order_by(
        beach_verification_requests.c.created_at.desc()
    )
    rows = await database.fetch_all(q)
    items = [_to_item(dict(r)) for r in rows]

    if status:
        items = [i for i in items if i.status == status]

    pending_count = sum(1 for i in items if i.status == "pending")

    return BeachVerificationsListResponse(
        requests=items,
        total=len(items),
        pending_count=pending_count,
    )


# ──────────────────────────────────────────────────
# POST /beach/verifications/  (auth user)
# ──────────────────────────────────────────────────

@router.post(
    "/",
    response_model=BeachVerificationItem,
    summary="Złóż wniosek o weryfikację roli (BEACH)",
)
async def create_verification(
    req: BeachVerificationCreateRequest,
    user_id: int = Depends(beach_get_current_user_id),
):
    if req.role not in ALLOWED_ROLES:
        raise HTTPException(400, f"Nieznana rola: {req.role}. Dozwolone: {ALLOWED_ROLES}")

    # Sprawdź czy nie ma już pending wniosku dla tej roli
    existing = await database.fetch_one(
        select(beach_verification_requests).where(
            beach_verification_requests.c.user_id == user_id,
            beach_verification_requests.c.role == req.role,
            beach_verification_requests.c.status == "pending",
        )
    )
    if existing:
        raise HTTPException(
            409,
            {
                "code": "VERIFICATION_PENDING",
                "message": f"Masz już złożony wniosek o rolę '{req.role}' oczekujący na rozpatrzenie.",
            },
        )

    now = datetime.now(timezone.utc)
    stmt = beach_verification_requests.insert().values(
        user_id=user_id,
        role=req.role,
        status="pending",
        meta=req.meta or {},
        admin_note=None,
        reviewed_by_user_id=None,
        created_at=now,
        updated_at=now,
    )

    try:
        new_id = await database.execute(stmt)
    except Exception as e:
        logger.error("create_verification failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(500, f"Błąd tworzenia wniosku: {e}")

    row = await database.fetch_one(
        select(beach_verification_requests).where(
            beach_verification_requests.c.id == int(new_id)
        )
    )
    return _to_item(dict(row))


# ──────────────────────────────────────────────────
# PATCH /beach/verifications/{request_id}  (admin)
# ──────────────────────────────────────────────────

@router.patch(
    "/{request_id}",
    response_model=BeachVerificationItem,
    summary="Rozpatrz wniosek weryfikacyjny (BEACH) — wymaga admina",
)
async def patch_verification(
    request_id: int,
    req: BeachVerificationPatchRequest,
    admin_user_id: int = Depends(beach_get_current_user_id),
):
    if req.status not in ("approved", "rejected"):
        raise HTTPException(400, "status musi być 'approved' lub 'rejected'")

    ver_row = await database.fetch_one(
        select(beach_verification_requests).where(
            beach_verification_requests.c.id == request_id
        )
    )
    if not ver_row:
        raise HTTPException(404, "Wniosek nie znaleziony")

    ver = dict(ver_row)
    now = datetime.now(timezone.utc)

    # Aktualizuj wniosek
    await database.execute(
        update(beach_verification_requests)
        .where(beach_verification_requests.c.id == request_id)
        .values(
            status=req.status,
            admin_note=req.admin_note,
            reviewed_by_user_id=admin_user_id,
            updated_at=now,
        )
    )

    # Jeśli APPROVED → aktualizuj beach_users
    if req.status == "approved":
        user_id = int(ver["user_id"])
        role_type = ver["role"]
        meta = _parse_jsonish(ver.get("meta"), {})

        user_row = await database.fetch_one(
            select(beach_users).where(beach_users.c.id == user_id)
        )
        if not user_row:
            raise HTTPException(404, "Użytkownik nie znaleziony")

        user_dict = dict(user_row)
        current_roles: list = _parse_jsonish(user_dict.get("roles"), [])

        # Usuń stary wpis dla tej roli (jeśli był rejected/pending)
        new_roles = [r for r in current_roles if not (isinstance(r, dict) and r.get("type") == role_type)]

        # Buduj nowy wpis roli
        new_role_entry: Dict[str, Any] = {"type": role_type, "verified": "approved"}

        if role_type == "judge":
            judge_id = req.judge_id or (meta.get("judge_id") if isinstance(meta, dict) else None)
            new_role_entry["judge_id"] = judge_id
        elif role_type == "coach":
            person_id = req.person_id or (meta.get("person_id") if isinstance(meta, dict) else None)
            team_id = meta.get("team_id") if isinstance(meta, dict) else None
            new_role_entry["person_id"] = person_id
            new_role_entry["team_id"] = team_id
        elif role_type == "player":
            player_id = req.player_id or (meta.get("player_id") if isinstance(meta, dict) else None)
            team_id = meta.get("team_id") if isinstance(meta, dict) else None
            new_role_entry["player_id"] = player_id
            new_role_entry["team_id"] = team_id

        new_roles.append(new_role_entry)

        # Buduj patch dla beach_users
        user_update: Dict[str, Any] = {
            "roles": new_roles,
            "updated_at": now,
        }

        if role_type == "judge" and new_role_entry.get("judge_id"):
            user_update["judge_id"] = str(new_role_entry["judge_id"])
        elif role_type == "coach" and new_role_entry.get("person_id"):
            user_update["person_id"] = int(new_role_entry["person_id"])
        elif role_type == "player" and new_role_entry.get("player_id"):
            user_update["player_id"] = int(new_role_entry["player_id"])

        # Przyznaj badge jeśli istnieje
        badge_name = ROLE_BADGE_MAP.get(role_type)
        if badge_name:
            from app.db import beach_badges
            badge_row = await database.fetch_one(
                select(beach_badges).where(beach_badges.c.name == badge_name)
            )
            if badge_row:
                current_badges = _parse_jsonish(user_dict.get("badges"), {})
                if isinstance(current_badges, dict):
                    current_badges[badge_name] = True
                elif isinstance(current_badges, list):
                    if badge_name not in current_badges:
                        current_badges.append(badge_name)
                user_update["badges"] = current_badges

        await database.execute(
            update(beach_users)
            .where(beach_users.c.id == user_id)
            .values(**user_update)
        )

    elif req.status == "rejected":
        # Ustaw status roli na "rejected" w beach_users.roles
        user_id = int(ver["user_id"])
        role_type = ver["role"]

        user_row = await database.fetch_one(
            select(beach_users).where(beach_users.c.id == user_id)
        )
        if user_row:
            user_dict = dict(user_row)
            current_roles: list = _parse_jsonish(user_dict.get("roles"), [])

            # Aktualizuj lub dodaj wpis z verified=rejected
            updated = False
            for r in current_roles:
                if isinstance(r, dict) and r.get("type") == role_type:
                    r["verified"] = "rejected"
                    updated = True
                    break
            if not updated:
                current_roles.append({"type": role_type, "verified": "rejected"})

            await database.execute(
                update(beach_users)
                .where(beach_users.c.id == user_id)
                .values(roles=current_roles, updated_at=now)
            )

    updated_row = await database.fetch_one(
        select(beach_verification_requests).where(
            beach_verification_requests.c.id == request_id
        )
    )
    return _to_item(dict(updated_row))


# ──────────────────────────────────────────────────
# DELETE /beach/verifications/{request_id}  (admin)
# ──────────────────────────────────────────────────

@router.delete(
    "/{request_id}",
    response_model=dict,
    summary="Usuń wniosek weryfikacyjny (BEACH) — wymaga admina",
)
async def delete_verification(request_id: int):
    from sqlalchemy import delete
    await database.execute(
        delete(beach_verification_requests).where(
            beach_verification_requests.c.id == request_id
        )
    )
    return {"success": True}

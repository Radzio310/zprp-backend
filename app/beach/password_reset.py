from __future__ import annotations

import asyncio
import logging
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import insert, select, update, func as sa_func

from app.db import (
    database,
    beach_admins,
    beach_password_reset_requests,
    beach_users,
)
from app.deps import beach_get_current_user_id
from app.schemas import (
    BeachPasswordResetAdminItem,
    BeachPasswordResetAdminListResponse,
    BeachPasswordResetAdminStats,
    BeachPasswordResetChallengeRequest,
    BeachPasswordResetChallengeResponse,
    BeachPasswordResetContactOption,
    BeachPasswordResetStatusRequest,
    BeachPasswordResetSubmitRequest,
    BeachPasswordResetSubmitResponse,
)
from app.beach.notifications import notify_admins
from app.beach.activity_log import get_actor_name, log_activity

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/beach/password-reset", tags=["Beach: Password reset"])

MAX_ATTEMPTS = 3
ATTEMPT_WINDOW = timedelta(minutes=30)


async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    return bool(row)


def _norm_login(value: str) -> str:
    return (value or "").strip().lower()


def _norm_text(value: Optional[str]) -> str:
    text = (value or "").strip().lower()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = re.sub(r"\s+", " ", text)
    return text


def _digits(value: Optional[str]) -> str:
    return re.sub(r"\D+", "", value or "")


def _mask_phone(value: str) -> str:
    digits = _digits(value)
    if len(digits) <= 3:
        return "•••"
    return f"••• ••• {digits[-3:]}"


def _mask_email(value: str) -> str:
    email = (value or "").strip()
    if "@" not in email:
        return "•••"
    name, domain = email.split("@", 1)
    if not name:
        return f"•••@{domain}"
    return f"{name[:1]}•••@{domain}"


async def _get_user_by_login(login: str) -> Optional[dict]:
    row = await database.fetch_one(
        select(beach_users).where(sa_func.lower(beach_users.c.login) == _norm_login(login))
    )
    return dict(row) if row else None


async def _failed_attempts(login: str) -> int:
    since = datetime.now(timezone.utc) - ATTEMPT_WINDOW
    row = await database.fetch_one(
        select(sa_func.count(beach_password_reset_requests.c.id)).where(
            (beach_password_reset_requests.c.login == _norm_login(login))
            & (beach_password_reset_requests.c.status == "failed")
            & (beach_password_reset_requests.c.created_at >= since)
        )
    )
    return int(row[0] or 0) if row else 0


async def _remaining_attempts(login: str) -> int:
    return max(0, MAX_ATTEMPTS - await _failed_attempts(login))


def _contact_options(user: dict) -> list[BeachPasswordResetContactOption]:
    options: list[BeachPasswordResetContactOption] = []
    if (user.get("phone") or "").strip():
        options.append(
            BeachPasswordResetContactOption(
                method="phone",
                label="Numer telefonu",
                masked=_mask_phone(user.get("phone") or ""),
            )
        )
    if (user.get("email") or "").strip():
        options.append(
            BeachPasswordResetContactOption(
                method="email",
                label="E-mail",
                masked=_mask_email(user.get("email") or ""),
            )
        )
    return options


def _matches_quiz(user: dict, body: BeachPasswordResetSubmitRequest) -> bool:
    options = _contact_options(user)
    available_methods = {opt.method for opt in options}
    method = body.contact_method

    if len(options) == 1:
        method = options[0].method
    elif len(options) > 1 and method not in available_methods:
        return False

    if method == "phone":
        expected = _digits(user.get("phone"))
        provided = _digits(body.contact_value)
        if expected and not (provided == expected or provided.endswith(expected[-9:])):
            return False
    elif method == "email":
        expected = (user.get("email") or "").strip().lower()
        provided = (body.contact_value or "").strip().lower()
        if expected and provided != expected:
            return False
    elif options:
        return False

    expected_city = _norm_text(user.get("city"))
    if expected_city and _norm_text(body.city) != expected_city:
        return False

    expected_province = _norm_text(user.get("province"))
    if expected_province and _norm_text(body.province) != expected_province:
        return False

    return True


def _row_to_item(row: dict) -> BeachPasswordResetAdminItem:
    return BeachPasswordResetAdminItem(
        id=row["id"],
        user_id=row.get("user_id"),
        login=row["login"],
        user_name=row.get("user_name"),
        user_phone=row.get("user_phone"),
        user_email=row.get("user_email"),
        city=row.get("city"),
        province=row.get("province"),
        contact_method=row.get("contact_method"),
        provided_contact=row.get("provided_contact"),
        provided_city=row.get("provided_city"),
        provided_province=row.get("provided_province"),
        status=row["status"],
        attempt_no=int(row.get("attempt_no") or 1),
        admin_note=row.get("admin_note"),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


async def _stats() -> BeachPasswordResetAdminStats:
    async def count(status: str) -> int:
        row = await database.fetch_one(
            select(sa_func.count(beach_password_reset_requests.c.id)).where(
                beach_password_reset_requests.c.status == status
            )
        )
        return int(row[0] or 0) if row else 0

    return BeachPasswordResetAdminStats(
        pending=await count("pending"),
        resolved=await count("resolved"),
        rejected=await count("rejected"),
        failed=await count("failed"),
    )


@router.post("/challenge", response_model=BeachPasswordResetChallengeResponse)
async def challenge(body: BeachPasswordResetChallengeRequest):
    login = _norm_login(body.login)
    if not login:
        raise HTTPException(status_code=400, detail="Podaj login")

    remaining = await _remaining_attempts(login)
    locked = remaining <= 0
    user = await _get_user_by_login(login)
    if not user:
        return BeachPasswordResetChallengeResponse(
            ok=False,
            user_found=False,
            login=login,
            remaining_attempts=remaining,
            locked=locked,
            message="Nie znaleziono takiego konta.",
        )

    return BeachPasswordResetChallengeResponse(
        ok=not locked,
        user_found=True,
        login=login,
        contact_options=_contact_options(user),
        requires_city=True,
        requires_province=True,
        remaining_attempts=remaining,
        locked=locked,
        message="Zweryfikuj kilka danych z profilu, żeby wysłać wniosek do admina.",
    )


@router.post("/submit", response_model=BeachPasswordResetSubmitResponse)
async def submit(body: BeachPasswordResetSubmitRequest):
    login = _norm_login(body.login)
    remaining = await _remaining_attempts(login)
    if remaining <= 0:
        return BeachPasswordResetSubmitResponse(
            success=False,
            remaining_attempts=0,
            message="Limit prób został wyczerpany. Spróbuj ponownie później.",
        )

    user = await _get_user_by_login(login)
    success = bool(user and _matches_quiz(user, body))
    now = datetime.now(timezone.utc)
    attempt_no = MAX_ATTEMPTS - remaining + 1
    status = "pending" if success else "failed"

    request_id = await database.execute(
        insert(beach_password_reset_requests).values(
            user_id=user.get("id") if user else None,
            login=login,
            user_name=user.get("full_name") if user else None,
            user_phone=user.get("phone") if user else None,
            user_email=user.get("email") if user else None,
            city=user.get("city") if user else None,
            province=user.get("province") if user else None,
            contact_method=body.contact_method,
            provided_contact=(body.contact_value or "").strip() or None,
            provided_city=(body.city or "").strip() or None,
            provided_province=(body.province or "").strip() or None,
            status=status,
            attempt_no=attempt_no,
            created_at=now,
            updated_at=now,
        )
    )

    if not success:
        return BeachPasswordResetSubmitResponse(
            success=False,
            remaining_attempts=max(0, remaining - 1),
            message="Dane nie pasują do profilu. Sprawdź je i spróbuj ponownie.",
        )

    async def _notify() -> None:
        try:
            await notify_admins(
                notif_type="admin_password_reset_request",
                title="🔐 Nowy wniosek resetu hasła",
                body=f"{user.get('full_name') or login} prosi o reset hasła.",
                data={
                    "password_reset_request_id": request_id,
                    "user_id": user.get("id"),
                    "tab": "password_resets",
                },
            )
        except Exception as exc:
            logger.error("password reset admin notification error: %s", exc)

    asyncio.ensure_future(_notify())
    return BeachPasswordResetSubmitResponse(
        success=True,
        remaining_attempts=remaining,
        request_id=request_id,
        message="Wniosek został wysłany do admina.",
    )


@router.get("/admin/stats", response_model=BeachPasswordResetAdminStats)
async def admin_stats(user_id: int = Depends(beach_get_current_user_id)):
    if not await _is_admin(user_id):
        raise HTTPException(status_code=403, detail="Brak uprawnień")
    return await _stats()


@router.get("/admin/", response_model=BeachPasswordResetAdminListResponse)
async def admin_list(
    status: Optional[str] = Query(None),
    user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(user_id):
        raise HTTPException(status_code=403, detail="Brak uprawnień")

    query = select(beach_password_reset_requests).order_by(
        beach_password_reset_requests.c.created_at.desc()
    )
    if status and status != "all":
        query = query.where(beach_password_reset_requests.c.status == status)
    elif not status:
        query = query.where(beach_password_reset_requests.c.status != "failed")

    rows = await database.fetch_all(query)
    items = [_row_to_item(dict(row)) for row in rows]
    return BeachPasswordResetAdminListResponse(
        requests=items,
        total=len(items),
        stats=await _stats(),
    )


@router.patch("/admin/{request_id}/status", response_model=BeachPasswordResetAdminItem)
async def admin_update_status(
    request_id: int,
    body: BeachPasswordResetStatusRequest,
    user_id: int = Depends(beach_get_current_user_id),
):
    if not await _is_admin(user_id):
        raise HTTPException(status_code=403, detail="Brak uprawnień")

    row = await database.fetch_one(
        select(beach_password_reset_requests).where(
            beach_password_reset_requests.c.id == request_id
        )
    )
    if not row:
        raise HTTPException(status_code=404, detail="Wniosek nie istnieje")

    now = datetime.now(timezone.utc)
    await database.execute(
        update(beach_password_reset_requests)
        .where(beach_password_reset_requests.c.id == request_id)
        .values(
            status=body.status,
            admin_note=(body.admin_note or "").strip() or None,
            updated_at=now,
        )
    )

    await log_activity(
        area="system",
        action="password_reset_request.status_changed",
        actor_user_id=user_id,
        actor_name=await get_actor_name(user_id),
        target_id=str(request_id),
        details={"new_status": body.status},
    )

    updated_row = await database.fetch_one(
        select(beach_password_reset_requests).where(
            beach_password_reset_requests.c.id == request_id
        )
    )
    return _row_to_item(dict(updated_row))

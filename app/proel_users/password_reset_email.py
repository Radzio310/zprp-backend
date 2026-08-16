# app/proel_users/password_reset_email.py
#
# Reset hasła konta ProEl przez kod e-mail — flow 1:1 z beachowym
# (app/beach/password_reset_email.py): request → verify-code → confirm.
#
# Reguły przeniesione świadomie:
#  • /request zawsze odpowiada 200 — brak enumeracji kont; `sent=false` mówi
#    aplikacji „ta droga niedostępna" (brak konta / e-mail niezweryfikowany),
#  • /verify-code NIE zużywa kodu (etap „sam kod", potem osobno hasło),
#  • /confirm zużywa kod, ustawia hasło i od razu loguje (zwraca token).
#
# `login_or_email` zamiast samego loginu: użytkownik ProEla częściej pamięta
# e-mail; po e-mailu szukamy wyłącznie kont ze ZWERYFIKOWANYM adresem.

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import and_, func as sa_func, select, update

from app.beach.email_config import get_email_config
from app.beach.email_masking import mask_email
from app.beach.email_security import generate_code, hash_code_for_key, verify_code_for_key
from app.proel_users.email_flows import (
    MAX_CODE_ATTEMPTS,
    VerificationError,
    _aware,
    _enforce_rate,
    _record_rate,
    _SEND_EMAIL_PER_HOUR,
    _VERIFY_IP_PER_15MIN,
)
from app.proel_users.emails import EmailDeliveryError, email_delivery_to_http, send_password_reset_code
from app.proel_users.tokens import create_access_token
from app.proel_users.users import _hash_password, _to_user_item

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/proel/users/auth/password-reset", tags=["ProEl: Password Reset (email)"])

_CODE_RE = re.compile(r"^[0-9]{6}$")


def _db():
    from app.db import database, proel_password_reset_email_codes, proel_users

    return database, proel_users, proel_password_reset_email_codes


def _reset_key(user_id: int) -> str:
    return f"proel-reset:{int(user_id)}"


def _password_strength_error(pw: str) -> Optional[str]:
    if len(pw) < 8:
        return "Hasło musi mieć min. 8 znaków."
    if not re.search(r"[A-ZĄĆĘŁŃÓŚŹŻ]", pw):
        return "Hasło musi zawierać wielką literę."
    if not re.search(r"[a-ząćęłńóśźż]", pw):
        return "Hasło musi zawierać małą literę."
    if not re.search(r"\d", pw):
        return "Hasło musi zawierać cyfrę."
    return None


def _client_ip(request: Request, forwarded: Optional[str]) -> str:
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


async def _find_user(login_or_email: str):
    """Po loginie wprost; po e-mailu tylko konta ze zweryfikowanym adresem."""
    database, users_t, _reset_t = _db()
    value = (login_or_email or "").strip()
    if not value:
        return None
    row = await database.fetch_one(select(users_t).where(users_t.c.login == value))
    if not row and "@" in value:
        row = await database.fetch_one(
            select(users_t).where(
                sa_func.lower(users_t.c.email) == value.lower(),
                users_t.c.email_verified == True,  # noqa: E712
            )
        )
    return row


class ResetRequest(BaseModel):
    login_or_email: str


class ResetVerifyCode(BaseModel):
    login_or_email: str
    code: str


class ResetConfirm(BaseModel):
    login_or_email: str
    code: str
    new_password: str


@router.post("/request", summary="Wyślij kod resetu na e-mail (zawsze 200 — bez enumeracji)")
async def request_reset(
    body: ResetRequest,
    request: Request,
    x_forwarded_for: Optional[str] = Header(default=None),
):
    cfg = get_email_config()
    not_available = {"success": True, "sent": False}

    user = await _find_user(body.login_or_email)
    if not user:
        return JSONResponse(status_code=200, content=not_available)
    u = dict(user)
    email = (u.get("email") or "").strip()
    if not u.get("email_verified") or not email or u.get("email_delivery_blocked") or not u.get("is_active", True):
        return JSONResponse(status_code=200, content=not_available)

    user_id = int(u["id"])
    try:
        await _enforce_rate("send_user", _reset_key(user_id), 1, cfg.resend_seconds)
        await _enforce_rate("send_email", email.lower(), *_SEND_EMAIL_PER_HOUR)
    except VerificationError as exc:
        return JSONResponse(
            status_code=exc.http_status,
            content={"success": False, "error": exc.error, "message": exc.message},
        )

    database, _users_t, reset_t = _db()
    code = generate_code()
    code_hash = hash_code_for_key(_reset_key(user_id), code)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=cfg.ttl_minutes)
    async with database.transaction():
        await database.execute(
            update(reset_t)
            .where(and_(reset_t.c.user_id == user_id, reset_t.c.used_at.is_(None)))
            .values(used_at=now, updated_at=now)
        )
        await database.execute(
            reset_t.insert().values(
                id=uuid.uuid4(),
                user_id=user_id,
                code_hash=code_hash,
                expires_at=expires_at,
                used_at=None,
                attempts=0,
                last_sent_at=now,
                created_at=now,
                updated_at=now,
            )
        )
    await _record_rate("send_user", _reset_key(user_id))
    await _record_rate("send_email", email.lower())

    try:
        message_id = await send_password_reset_code(email, u.get("full_name"), code, cfg.ttl_minutes)
    except EmailDeliveryError as exc:
        status_code, message = email_delivery_to_http(exc)
        return JSONResponse(
            status_code=status_code,
            content={"success": False, "error": "EMAIL_DELIVERY_FAILED", "message": message},
        )

    logger.info("proel reset_code_issued user_id=%s email=%s messageId=%s", user_id, mask_email(email), message_id)
    return {
        "success": True,
        "sent": True,
        "email": mask_email(email),
        "expires_in_seconds": cfg.ttl_seconds,
        "resend_available_in_seconds": cfg.resend_seconds,
    }


@router.post("/verify-code", summary="Sprawdź kod resetu (bez zużywania)")
async def verify_reset_code(
    body: ResetVerifyCode,
    request: Request,
    x_forwarded_for: Optional[str] = Header(default=None),
):
    ip = _client_ip(request, x_forwarded_for)
    code = (body.code or "").strip()
    if not _CODE_RE.match(code):
        return JSONResponse(status_code=400, content={"success": False, "error": "INVALID_VERIFICATION_CODE", "message": "Kod jest nieprawidłowy."})

    try:
        await _enforce_rate("verify_ip", ip or "", *_VERIFY_IP_PER_15MIN)
    except VerificationError as exc:
        return JSONResponse(status_code=exc.http_status, content={"success": False, "error": exc.error, "message": exc.message})

    user = await _find_user(body.login_or_email)
    if not user:
        return JSONResponse(status_code=400, content={"success": False, "error": "INVALID_VERIFICATION_CODE", "message": "Kod jest nieprawidłowy."})
    user_id = int(dict(user)["id"])
    database, _users_t, reset_t = _db()
    now = datetime.now(timezone.utc)

    try:
        async with database.transaction():
            locked = await database.fetch_one(
                select(reset_t)
                .where(and_(reset_t.c.user_id == user_id, reset_t.c.used_at.is_(None)))
                .order_by(reset_t.c.created_at.desc())
                .limit(1)
                .with_for_update()
            )
            if not locked:
                raise VerificationError(error="VERIFICATION_CODE_EXPIRED", message="Kod wygasł. Wyślij nowy kod.", http_status=400)
            if _aware(locked["expires_at"]) < now:
                await database.execute(update(reset_t).where(reset_t.c.id == locked["id"]).values(used_at=now, updated_at=now))
                raise VerificationError(error="VERIFICATION_CODE_EXPIRED", message="Kod wygasł. Wyślij nowy kod.", http_status=400)

            if not verify_code_for_key(_reset_key(user_id), code, locked["code_hash"]):
                attempts = int(locked["attempts"]) + 1
                if attempts >= MAX_CODE_ATTEMPTS:
                    await database.execute(update(reset_t).where(reset_t.c.id == locked["id"]).values(attempts=attempts, used_at=now, updated_at=now))
                    raise VerificationError(error="TOO_MANY_ATTEMPTS", message="Zbyt wiele prób. Wyślij nowy kod.", http_status=400)
                await database.execute(update(reset_t).where(reset_t.c.id == locked["id"]).values(attempts=attempts, updated_at=now))
                raise VerificationError(error="INVALID_VERIFICATION_CODE", message="Kod jest nieprawidłowy.", http_status=400)
            # Poprawny — NIE zużywamy (used_at zostaje None); zużyje go /confirm.
    except VerificationError as exc:
        return JSONResponse(status_code=exc.http_status, content={"success": False, "error": exc.error, "message": exc.message})

    logger.info("proel reset_code_verified user_id=%s", user_id)
    return {"success": True}


@router.post("/confirm", summary="Potwierdź kod i ustaw nowe hasło (loguje)")
async def confirm_reset(
    body: ResetConfirm,
    request: Request,
    x_forwarded_for: Optional[str] = Header(default=None),
):
    ip = _client_ip(request, x_forwarded_for)
    code = (body.code or "").strip()
    if not _CODE_RE.match(code):
        return JSONResponse(status_code=400, content={"success": False, "error": "INVALID_VERIFICATION_CODE", "message": "Kod jest nieprawidłowy."})
    pw_err = _password_strength_error(body.new_password or "")
    if pw_err:
        return JSONResponse(status_code=400, content={"success": False, "error": "WEAK_PASSWORD", "message": pw_err})

    try:
        await _enforce_rate("verify_ip", ip or "", *_VERIFY_IP_PER_15MIN)
    except VerificationError as exc:
        return JSONResponse(status_code=exc.http_status, content={"success": False, "error": exc.error, "message": exc.message})

    user = await _find_user(body.login_or_email)
    if not user:
        return JSONResponse(status_code=400, content={"success": False, "error": "INVALID_VERIFICATION_CODE", "message": "Kod jest nieprawidłowy."})
    u = dict(user)
    user_id = int(u["id"])
    database, users_t, reset_t = _db()
    now = datetime.now(timezone.utc)

    try:
        async with database.transaction():
            locked = await database.fetch_one(
                select(reset_t)
                .where(and_(reset_t.c.user_id == user_id, reset_t.c.used_at.is_(None)))
                .order_by(reset_t.c.created_at.desc())
                .limit(1)
                .with_for_update()
            )
            if not locked:
                raise VerificationError(error="VERIFICATION_CODE_EXPIRED", message="Kod wygasł. Wyślij nowy kod.", http_status=400)
            if _aware(locked["expires_at"]) < now:
                await database.execute(update(reset_t).where(reset_t.c.id == locked["id"]).values(used_at=now, updated_at=now))
                raise VerificationError(error="VERIFICATION_CODE_EXPIRED", message="Kod wygasł. Wyślij nowy kod.", http_status=400)

            attempts = int(locked["attempts"]) + 1
            await database.execute(update(reset_t).where(reset_t.c.id == locked["id"]).values(attempts=attempts, updated_at=now))
            if not verify_code_for_key(_reset_key(user_id), code, locked["code_hash"]):
                if attempts >= MAX_CODE_ATTEMPTS:
                    await database.execute(update(reset_t).where(reset_t.c.id == locked["id"]).values(used_at=now, updated_at=now))
                    raise VerificationError(error="TOO_MANY_ATTEMPTS", message="Zbyt wiele prób. Wyślij nowy kod.", http_status=400)
                raise VerificationError(error="INVALID_VERIFICATION_CODE", message="Kod jest nieprawidłowy.", http_status=400)

            await database.execute(
                update(users_t)
                .where(users_t.c.id == user_id)
                .values(
                    password_hash=_hash_password(body.new_password),
                    must_change_password=False,
                    updated_at=now,
                    last_login_at=now,
                )
            )
            await database.execute(update(reset_t).where(reset_t.c.id == locked["id"]).values(used_at=now, updated_at=now))
            await database.execute(
                update(reset_t)
                .where(and_(reset_t.c.user_id == user_id, reset_t.c.used_at.is_(None)))
                .values(used_at=now, updated_at=now)
            )
    except VerificationError as exc:
        return JSONResponse(status_code=exc.http_status, content={"success": False, "error": exc.error, "message": exc.message})

    refreshed = await database.fetch_one(select(users_t).where(users_t.c.id == user_id))
    user_model = _to_user_item(dict(refreshed))
    logger.info("proel password_reset_success user_id=%s", user_id)
    return {"success": True, "token": create_access_token(user_model.id), "user": user_model}

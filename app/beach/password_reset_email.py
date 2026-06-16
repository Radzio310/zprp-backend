"""
Reset hasła przez kod e-mail (BEACH).

Gdy konto ma zweryfikowany adres e-mail, "Zapomniałem hasła" wysyła 6-cyfrowy
kod na ten adres; po jego wpisaniu użytkownik ustawia nowe hasło i zostaje
zalogowany. Konta bez zweryfikowanego e-maila → ``sent=false`` (aplikacja
pokazuje wtedy dotychczasowy wniosek do administratora).

Router: prefiks ``/beach/auth/password-reset``.
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import and_, select, update

from app.db import database, beach_users, beach_password_reset_email_codes as reset_t
from app.deps import beach_create_access_token
from app.beach.email_config import get_email_config
from app.beach.email_masking import mask_email
from app.beach.email_security import generate_code, hash_code_for_key, verify_code_for_key
from app.beach.brevo_email import send_password_reset_code, EmailDeliveryError
from app.beach.email_verification import (
    VerificationError,
    email_delivery_to_http,
    _enforce_rate,
    _record_rate,
    _aware,
    MAX_CODE_ATTEMPTS,
    _SEND_EMAIL_PER_HOUR,
    _VERIFY_IP_PER_15MIN,
)
from app.beach.users import _to_user_item, _hash_password, _check_is_admin
from app.beach.capabilities import resolve_user_capabilities

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/auth/password-reset", tags=["Beach: Password Reset (email)"])

_CODE_RE = re.compile(r"^[0-9]{6}$")


def _reset_key(user_id: int) -> str:
    return f"reset:{int(user_id)}"


def _password_strength_error(pw: str) -> Optional[str]:
    if len(pw) < 8:
        return "Hasło musi mieć min. 8 znaków."
    if not re.search(r"[A-ZĄĆĘŁŃÓŚŹŻ]", pw):
        return "Hasło musi zawierać wielką literę."
    if not re.search(r"[a-ząćęłńóśźż]", pw):
        return "Hasło musi zawierać małą literę."
    if not re.search(r"\d", pw):
        return "Hasło musi zawierać cyfrę."
    if not re.search(r"[^A-Za-z0-9ĄĆĘŁŃÓŚŹŻąćęłńóśźż]", pw):
        return "Hasło musi zawierać znak specjalny."
    return None


def _client_ip(request: Request, forwarded: Optional[str]) -> str:
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


class ResetRequest(BaseModel):
    login: str


class ResetConfirm(BaseModel):
    login: str
    code: str
    new_password: str


@router.post("/request", summary="Wyślij kod resetu hasła na e-mail (jeśli zweryfikowany)")
async def request_reset(
    body: ResetRequest,
    request: Request,
    x_forwarded_for: Optional[str] = Header(default=None),
):
    ip = _client_ip(request, x_forwarded_for)
    cfg = get_email_config()
    login = (body.login or "").strip()
    not_available = {"success": True, "sent": False}
    if not login:
        return JSONResponse(status_code=200, content=not_available)

    user = await database.fetch_one(select(beach_users).where(beach_users.c.login == login))
    if not user:
        return JSONResponse(status_code=200, content=not_available)
    u = dict(user)
    email = (u.get("email") or "").strip()
    if not u.get("email_verified") or not email or u.get("email_delivery_blocked"):
        # Brak ścieżki e-mail → aplikacja pokaże wniosek do admina.
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
        return JSONResponse(status_code=status_code, content={"success": False, "error": "EMAIL_DELIVERY_FAILED", "message": message})

    logger.info("password_reset_code_issued user_id=%s email=%s messageId=%s", user_id, mask_email(email), message_id)
    return {
        "success": True,
        "sent": True,
        "email": mask_email(email),
        "expires_in_seconds": cfg.ttl_seconds,
        "resend_available_in_seconds": cfg.resend_seconds,
    }


@router.post("/confirm", summary="Potwierdź kod i ustaw nowe hasło (loguje użytkownika)")
async def confirm_reset(
    body: ResetConfirm,
    request: Request,
    x_forwarded_for: Optional[str] = Header(default=None),
):
    ip = _client_ip(request, x_forwarded_for)
    login = (body.login or "").strip()
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

    user = await database.fetch_one(select(beach_users).where(beach_users.c.login == login))
    if not user:
        return JSONResponse(status_code=400, content={"success": False, "error": "INVALID_VERIFICATION_CODE", "message": "Kod jest nieprawidłowy."})
    u = dict(user)
    user_id = int(u["id"])
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

            # Sukces — ustaw nowe hasło, zużyj kod, unieważnij pozostałe.
            await database.execute(
                update(beach_users)
                .where(beach_users.c.id == user_id)
                .values(password_hash=_hash_password(body.new_password), updated_at=now, last_login_at=now)
            )
            await database.execute(update(reset_t).where(reset_t.c.id == locked["id"]).values(used_at=now, updated_at=now))
            await database.execute(
                update(reset_t)
                .where(and_(reset_t.c.user_id == user_id, reset_t.c.used_at.is_(None)))
                .values(used_at=now, updated_at=now)
            )
    except VerificationError as exc:
        return JSONResponse(status_code=exc.http_status, content={"success": False, "error": exc.error, "message": exc.message})

    refreshed = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    is_admin = await _check_is_admin(user_id)
    caps = sorted(await resolve_user_capabilities(dict(refreshed).get("badges")))
    user_model = _to_user_item(dict(refreshed), is_admin=is_admin, effective_capabilities=caps)
    token = beach_create_access_token(user_model.id)
    logger.info("password_reset_success user_id=%s", user_id)
    return {"success": True, "token": token, "user": user_model}

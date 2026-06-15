"""
HTTP layer for e-mail verification (BEACH).

Routes (prefix ``/beach/auth``):
- POST /verify-email                 — public: validate a 6-digit code
- POST /resend-verification-code     — public: neutral resend (no enumeration)
- POST /start-email-verification     — authenticated: set/change e-mail + send code
- GET  /email-status                 — authenticated: current gating state

Business logic lives in ``email_verification`` — this module only does HTTP.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.db import database, beach_users
from app.deps import beach_get_current_user_id
from app.beach.email_masking import mask_email
from app.beach.email_normalization import is_valid_email
from app.beach.email_security import CODE_REGEX
from app.beach.brevo_email import EmailDeliveryError
from app.beach.email_verification import (
    VerificationError,
    email_delivery_to_http,
    issue_and_send_code,
    resend_verification,
    set_email_and_issue,
    verify_email_code,
    verify_email_code_for_user,
    requires_email_gate,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/auth", tags=["Beach: Email Verification"])

_CODE_RE = re.compile(CODE_REGEX)


# ─────────────────────────── Schemas ───────────────────────────

class VerifyEmailRequest(BaseModel):
    email: str
    code: str

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        if not is_valid_email(v):
            raise ValueError("Podaj poprawny adres e-mail.")
        return v

    @field_validator("code")
    @classmethod
    def _code_ok(cls, v: str) -> str:
        if not _CODE_RE.match((v or "").strip()):
            raise ValueError("Kod musi składać się z 6 cyfr.")
        return v.strip()


class ResendRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def _email_ok(cls, v: str) -> str:
        if not is_valid_email(v):
            raise ValueError("Podaj poprawny adres e-mail.")
        return v


class StartVerificationRequest(BaseModel):
    email: Optional[str] = None


class VerifyCodeRequest(BaseModel):
    code: str

    @field_validator("code")
    @classmethod
    def _code_ok(cls, v: str) -> str:
        if not _CODE_RE.match((v or "").strip()):
            raise ValueError("Kod musi składać się z 6 cyfr.")
        return v.strip()


# ─────────────────────────── Helpers ───────────────────────────

def _client_ip(request: Request, forwarded: Optional[str]) -> str:
    if forwarded:
        # X-Forwarded-For: client, proxy1, proxy2 — take the first.
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def _verification_error_response(exc: VerificationError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.http_status,
        content={"success": False, "error": exc.error, "message": exc.message},
    )


def _delivery_error_response(exc: EmailDeliveryError) -> JSONResponse:
    status_code, message = email_delivery_to_http(exc)
    return JSONResponse(
        status_code=status_code,
        content={"success": False, "error": "EMAIL_DELIVERY_FAILED", "message": message},
    )


# ─────────────────────────── Routes ───────────────────────────

@router.post("/verify-email", summary="Potwierdź adres e-mail kodem")
async def verify_email(
    body: VerifyEmailRequest,
    request: Request,
    x_forwarded_for: Optional[str] = Header(default=None),
):
    ip = _client_ip(request, x_forwarded_for)
    try:
        result = await verify_email_code(body.email, body.code, ip)
        return JSONResponse(status_code=200, content=result)
    except VerificationError as exc:
        return _verification_error_response(exc)


@router.post("/resend-verification-code", summary="Wyślij ponownie kod weryfikacyjny")
async def resend_code(
    body: ResendRequest,
    request: Request,
    x_forwarded_for: Optional[str] = Header(default=None),
):
    ip = _client_ip(request, x_forwarded_for)
    try:
        result = await resend_verification(body.email, ip)
        return JSONResponse(status_code=200, content=result)
    except VerificationError as exc:
        # Only the IP rate-limit surfaces here; everything else stays neutral.
        return _verification_error_response(exc)


@router.post("/verify-email-code", summary="Potwierdź e-mail kodem (zalogowany)")
async def verify_email_code_authenticated(
    body: VerifyCodeRequest,
    request: Request,
    x_forwarded_for: Optional[str] = Header(default=None),
    user_id: int = Depends(beach_get_current_user_id),
):
    ip = _client_ip(request, x_forwarded_for)
    try:
        result = await verify_email_code_for_user(user_id, body.code, ip)
        return JSONResponse(status_code=200, content=result)
    except VerificationError as exc:
        return _verification_error_response(exc)


@router.post("/start-email-verification", summary="Ustaw/zmień e-mail i wyślij kod (zalogowany)")
async def start_email_verification(
    body: StartVerificationRequest,
    user_id: int = Depends(beach_get_current_user_id),
):
    try:
        if body.email and is_valid_email(body.email):
            result = await set_email_and_issue(user_id, body.email)
            return JSONResponse(status_code=200, content=result)
        if body.email:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "INVALID_EMAIL", "message": "Podaj poprawny adres e-mail."},
            )
        # No new e-mail → resend to the currently-stored address.
        user = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
        if not user:
            return JSONResponse(status_code=404, content={"success": False, "error": "USER_NOT_FOUND", "message": "Nie znaleziono konta."})
        timers = await issue_and_send_code(user, enforce_cooldown=True)
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "requires_email_verification": True,
                "email": mask_email(user["email"]),
                **timers,
            },
        )
    except VerificationError as exc:
        return _verification_error_response(exc)
    except EmailDeliveryError as exc:
        return _delivery_error_response(exc)


@router.get("/email-status", summary="Stan weryfikacji e-mail (zalogowany)")
async def email_status(user_id: int = Depends(beach_get_current_user_id)):
    user = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not user:
        return JSONResponse(status_code=404, content={"success": False, "error": "USER_NOT_FOUND"})
    return {
        "success": True,
        "email": mask_email(user["email"]),
        "has_email": bool((user["email"] or "").strip()),
        "email_verified": bool(user["email_verified"]),
        "requires_email_verification": requires_email_gate(user),
        "deadline": user["email_verification_deadline"].isoformat()
        if user["email_verification_deadline"]
        else None,
    }

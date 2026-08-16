# app/proel_users/auth_email.py
#
# Cienka warstwa HTTP nad email_flows: mapuje VerificationError/EmailDeliveryError
# na odpowiedzi. Prefiks /proel/users/auth — montowany PRZED proel_routerem
# (catch-all w app/proel.py), patrz komentarz w main.py.

from __future__ import annotations

import logging
import re
from typing import Optional

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from app.proel_users import email_flows
from app.proel_users.email_flows import VerificationError
from app.proel_users.emails import EmailDeliveryError, email_delivery_to_http
from app.proel_users.tokens import proel_get_current_user_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/proel/users/auth", tags=["ProEl: Email Verification"])

_CODE_RE = re.compile(r"^[0-9]{6}$")


def _client_ip(request: Request, forwarded: Optional[str]) -> str:
    if forwarded:
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


class EmailBody(BaseModel):
    email: str


class EmailCodeBody(BaseModel):
    email: str
    code: str

    @field_validator("code")
    @classmethod
    def _code_ok(cls, v: str) -> str:
        if not _CODE_RE.match((v or "").strip()):
            raise ValueError("Kod musi składać się z 6 cyfr.")
        return v.strip()


class CodeBody(BaseModel):
    code: str

    @field_validator("code")
    @classmethod
    def _code_ok(cls, v: str) -> str:
        if not _CODE_RE.match((v or "").strip()):
            raise ValueError("Kod musi składać się z 6 cyfr.")
        return v.strip()


# ─────────────────────── pre-signup (bez konta) ───────────────────────

@router.post("/signup/request-code", summary="Wyślij kod weryfikacyjny PRZED utworzeniem konta")
async def signup_request_code(
    body: EmailBody,
    request: Request,
    x_forwarded_for: Optional[str] = Header(default=None),
):
    ip = _client_ip(request, x_forwarded_for)
    try:
        return await email_flows.request_signup_code(body.email, ip)
    except VerificationError as exc:
        return _verification_error_response(exc)
    except EmailDeliveryError as exc:
        return _delivery_error_response(exc)


@router.post("/signup/verify-code", summary="Potwierdź kod PRZED utworzeniem konta")
async def signup_verify_code(
    body: EmailCodeBody,
    request: Request,
    x_forwarded_for: Optional[str] = Header(default=None),
):
    ip = _client_ip(request, x_forwarded_for)
    try:
        return await email_flows.verify_signup_code(body.email, body.code, ip)
    except VerificationError as exc:
        return _verification_error_response(exc)


# ─────────────────────── zalogowany ───────────────────────

@router.post("/verify", summary="Potwierdź e-mail kodem (zalogowany)")
async def verify_authenticated(
    body: CodeBody,
    request: Request,
    x_forwarded_for: Optional[str] = Header(default=None),
    user_id: int = Depends(proel_get_current_user_id),
):
    ip = _client_ip(request, x_forwarded_for)
    try:
        return await email_flows.verify_email_code_for_user(user_id, body.code, ip)
    except VerificationError as exc:
        return _verification_error_response(exc)


@router.post("/resend", summary="Wyślij ponownie kod (zalogowany; odpowiedź neutralna)")
async def resend_code(
    request: Request,
    x_forwarded_for: Optional[str] = Header(default=None),
    user_id: int = Depends(proel_get_current_user_id),
):
    ip = _client_ip(request, x_forwarded_for)
    try:
        return await email_flows.resend_verification_for_user(user_id, ip)
    except VerificationError as exc:
        return _verification_error_response(exc)


@router.post("/set-email", summary="Ustaw/zmień e-mail i wyślij kod (zalogowany)")
async def set_email(
    body: EmailBody,
    user_id: int = Depends(proel_get_current_user_id),
):
    try:
        return await email_flows.set_email_and_issue(user_id, body.email)
    except VerificationError as exc:
        return _verification_error_response(exc)
    except EmailDeliveryError as exc:
        return _delivery_error_response(exc)


@router.get("/status", summary="Stan weryfikacji e-mail (zalogowany)")
async def email_status(user_id: int = Depends(proel_get_current_user_id)):
    from sqlalchemy import select

    from app.db import database, proel_users as users_t

    row = await database.fetch_one(select(users_t).where(users_t.c.id == user_id))
    if not row:
        return JSONResponse(status_code=404, content={"success": False, "error": "USER_NOT_FOUND"})
    u = dict(row)
    state = await email_flows.active_code_state(user_id)
    deadline = u.get("email_verification_deadline")
    return {
        "email": u.get("email"),
        "email_verified": bool(u.get("email_verified")),
        "requires_email_verification": (not bool(u.get("email_verified"))) and bool((u.get("email") or "").strip()),
        "email_verification_deadline": deadline.isoformat() if deadline else None,
        **state,
    }

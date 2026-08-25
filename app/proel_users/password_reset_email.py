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
import os
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
    SUPERSEDE_GRACE_SECONDS,
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

#: Ile minut żyje kod resetu hasła.
#:
#: Osobno od `EMAIL_VERIFICATION_TTL_MINUTES` (15 min) i celowo dłużej. Kod
#: weryfikacji e-maila wpisuje się od razu, z otwartym modalem; po kod resetu
#: człowiek idzie do skrzynki, czasem na innym urządzeniu, czasem wraca do
#: tego po kwadransie. Kwadrans na tę drogę to za mało, a krótki termin nie
#: kupuje tu bezpieczeństwa: kod jest jednorazowy, sześciocyfrowy, z limitem
#: pięciu prób i limitem wysyłek na godzinę.
_DEFAULT_RESET_TTL_MINUTES = 120


def _reset_ttl_minutes(cfg) -> int:
    raw = (os.getenv("PROEL_PASSWORD_RESET_TTL_MINUTES") or "").strip()
    try:
        minutes = int(raw) if raw else _DEFAULT_RESET_TTL_MINUTES
    except ValueError:
        logger.warning("Bledne PROEL_PASSWORD_RESET_TTL_MINUTES=%r - biore %s", raw, _DEFAULT_RESET_TTL_MINUTES)
        minutes = _DEFAULT_RESET_TTL_MINUTES
    # Nigdy krócej niż kod weryfikacji e-maila - byłby to krok wstecz.
    return max(minutes, int(getattr(cfg, "ttl_minutes", 0) or 0), 1)


async def _live_reset_codes(database, reset_t, user_id: int, now: datetime) -> list:
    """Wszystkie ŻYWE kody użytkownika; wygasłe po drodze oznacza jako zużyte.

    Liczba mnoga jest tu sednem. Do tej pory oba etapy brały wyłącznie
    NAJNOWSZY nieużyty kod, a `/request` unieważniał przy okazji wszystkie
    poprzednie - więc dwa maile pod rząd (albo ponowne otwarcie ekranu)
    sprawiały, że kod z pierwszego maila przestawał działać i użytkownik
    dostawał „Kod wygasł" na kod sprzed minuty. Weryfikacja e-maila w Beachu
    rozwiązała to dawno: akceptuje każdy aktywny kod.
    """
    rows = await database.fetch_all(
        select(reset_t)
        .where(and_(reset_t.c.user_id == user_id, reset_t.c.used_at.is_(None)))
        .order_by(reset_t.c.created_at.desc())
        .with_for_update()
    )
    live = []
    for row in rows:
        if _aware(row["expires_at"]) < now:
            await database.execute(
                update(reset_t).where(reset_t.c.id == row["id"]).values(used_at=now, updated_at=now)
            )
        else:
            live.append(row)
    return live


async def _no_live_code_error(database, reset_t, user_id: int) -> VerificationError:
    """Rozróżnia „kod wygasł" od „kod już zadziałał".

    Kod zużyty ZANIM wygasł i bez wyczerpanych prób znaczy, że ktoś wpisał go
    poprawnie - w praktyce ten sam człowiek chwilę wcześniej. Hasło jest już
    zmienione, więc wysyłanie go po nowy kod to droga donikąd.
    """
    last = await database.fetch_one(
        select(reset_t)
        .where(reset_t.c.user_id == user_id)
        .order_by(reset_t.c.created_at.desc())
        .limit(1)
    )
    if last is not None and last["used_at"] is not None:
        used_at = _aware(last["used_at"])
        if used_at <= _aware(last["expires_at"]) and int(last["attempts"]) < MAX_CODE_ATTEMPTS:
            return VerificationError(
                error="VERIFICATION_CODE_USED",
                message="Ten kod został już wykorzystany, a hasło zmienione. Zaloguj się nowym hasłem.",
                http_status=400,
            )
    return VerificationError(
        error="VERIFICATION_CODE_EXPIRED",
        message="Kod wygasł. Wyślij nowy kod.",
        http_status=400,
    )


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
    ttl_minutes = _reset_ttl_minutes(cfg)
    expires_at = now + timedelta(minutes=ttl_minutes)
    async with database.transaction():
        # Unieważniamy tylko kody STARSZE niż okno karencji. Kod sprzed chwili
        # zostaje ważny równolegle z nowym, bo mail z nim mógł właśnie dojść.
        supersede_before = now - timedelta(seconds=SUPERSEDE_GRACE_SECONDS)
        await database.execute(
            update(reset_t)
            .where(
                and_(
                    reset_t.c.user_id == user_id,
                    reset_t.c.used_at.is_(None),
                    reset_t.c.last_sent_at < supersede_before,
                )
            )
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
        message_id = await send_password_reset_code(email, u.get("full_name"), code, ttl_minutes)
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
        "expires_in_seconds": ttl_minutes * 60,
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
            live = await _live_reset_codes(database, reset_t, user_id, now)
            if not live:
                raise await _no_live_code_error(database, reset_t, user_id)

            matched = next(
                (r for r in live if verify_code_for_key(_reset_key(user_id), code, r["code_hash"])),
                None,
            )
            if matched is None:
                # Próbę liczymy KAŻDEMU żywemu kodowi, żeby zgadywanie było tak
                # samo ograniczone niezależnie od tego, ile ich akurat żyje.
                hit_cap = False
                for row in live:
                    attempts = int(row["attempts"]) + 1
                    await database.execute(
                        update(reset_t).where(reset_t.c.id == row["id"]).values(attempts=attempts, updated_at=now)
                    )
                    if attempts >= MAX_CODE_ATTEMPTS:
                        hit_cap = True
                if hit_cap:
                    await database.execute(
                        update(reset_t)
                        .where(and_(reset_t.c.user_id == user_id, reset_t.c.used_at.is_(None)))
                        .values(used_at=now, updated_at=now)
                    )
                    raise VerificationError(error="TOO_MANY_ATTEMPTS", message="Zbyt wiele prób. Wyślij nowy kod.", http_status=400)
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
            live = await _live_reset_codes(database, reset_t, user_id, now)
            if not live:
                raise await _no_live_code_error(database, reset_t, user_id)

            matched = next(
                (r for r in live if verify_code_for_key(_reset_key(user_id), code, r["code_hash"])),
                None,
            )
            if matched is None:
                hit_cap = False
                for row in live:
                    attempts = int(row["attempts"]) + 1
                    await database.execute(
                        update(reset_t).where(reset_t.c.id == row["id"]).values(attempts=attempts, updated_at=now)
                    )
                    if attempts >= MAX_CODE_ATTEMPTS:
                        hit_cap = True
                if hit_cap:
                    await database.execute(
                        update(reset_t)
                        .where(and_(reset_t.c.user_id == user_id, reset_t.c.used_at.is_(None)))
                        .values(used_at=now, updated_at=now)
                    )
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
            # Zużywamy WSZYSTKIE żywe kody, także rodzeństwo z okna karencji.
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

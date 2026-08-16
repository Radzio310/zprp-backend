# app/proel_users/email_flows.py
#
# Kody e-mail kont ProEl: weryfikacja adresu (po i PRZED rejestracją).
#
# Zachowanie jest przeniesione 1:1 z app/beach/email_verification.py — tamten
# moduł działa na produkcji i każde odstępstwo tutaj byłoby regresją do
# odkrycia w terenie. Różnice są dokładnie dwie i obie CELOWE:
#
#  1. Tabele: własne `proel_*` — kod wydany w Beach nie może niczego odblokować
#     w ProElu, bo weryfikacja w ogóle nie patrzy na jego tabelę.
#  2. Klucz HMAC kodu ma prefiks `proel:` / `proel-signup:` — nawet przy tym
#     samym EMAIL_CODE_SECRET skróty obu światów są nieporównywalne.
#
# Beachowego modułu NIE importujemy: ciągnie app.db przy imporcie (create_all
# wywraca się na SQLite w testach), a sprzężenie światów to dokładnie to, czego
# unikamy.

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

from sqlalchemy import and_, select, update

from app.beach.email_config import get_email_config
from app.beach.email_masking import mask_email
from app.beach.email_normalization import is_valid_email, normalize_email
from app.beach.email_security import generate_code, hash_code_for_key, verify_code_for_key
from app.proel_users import rate_limit
from app.proel_users.emails import EmailDeliveryError, send_verification_code

logger = logging.getLogger(__name__)

MAX_CODE_ATTEMPTS = 5
#: Nowy kod nie unieważnia od razu poprzedniego — mail bywa spóźniony.
SUPERSEDE_GRACE_SECONDS = 3 * 60
#: Okno, w którym pre-weryfikacja e-maila pozwala dokończyć rejestrację.
SIGNUP_VERIFIED_WINDOW_SECONDS = 30 * 60

# (scope, limit, okno s) — scope'y z prefiksem proel_, żeby liczniki nie
# mieszały się z beachowymi w tej samej tabeli zdarzeń.
_SEND_EMAIL_PER_HOUR = (5, 3600)
_VERIFY_IP_PER_15MIN = (10, 900)
_RESEND_IP_PER_HOUR = (20, 3600)


class VerificationError(Exception):
    """Błąd domenowy: kod API + status HTTP + komunikat dla użytkownika."""

    def __init__(self, *, error: str, message: str, http_status: int = 400):
        super().__init__(message)
        self.error = error
        self.message = message
        self.http_status = http_status


def _db():
    """Leniwy import bazy — patrz komentarz w rate_limit._db()."""
    from app.db import (
        database,
        proel_email_verification_codes,
        proel_pre_signup_email_codes,
        proel_users,
    )

    return database, proel_users, proel_email_verification_codes, proel_pre_signup_email_codes


def _as_dict(row: Any) -> dict:
    if row is None:
        return {}
    return row if isinstance(row, dict) else dict(row)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def user_key(user_id: int) -> str:
    return f"proel:{int(user_id)}"


def signup_key(email_normalized: str) -> str:
    return f"proel-signup:{email_normalized}"


async def _enforce_rate(scope: str, ref: str, limit: int, window: int) -> None:
    """Adapter na limiter DB — tłumaczy jego 429 na VerificationError, żeby
    warstwa routerów miała JEDEN typ wyjątku do mapowania."""
    from fastapi import HTTPException

    try:
        await rate_limit.enforce(f"proel_{scope}", ref, limit, window)
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        raise VerificationError(
            error="RATE_LIMITED",
            message=str(detail.get("message") or "Zbyt wiele prób. Spróbuj ponownie później."),
            http_status=429,
        )


async def _record_rate(scope: str, ref: str) -> None:
    await rate_limit.record(f"proel_{scope}", ref)


# ─────────────────────────── stan / wydanie kodu ───────────────────────────

async def active_code_state(user_id: int) -> dict:
    """Czy jest świeży kod i ile do resendu — modal nie wysyła kodu na dzień dobry."""
    database, _users_t, codes_t, _pre_t = _db()
    cfg = get_email_config()
    now = datetime.now(timezone.utc)
    row = await database.fetch_one(
        select(codes_t.c.expires_at, codes_t.c.last_sent_at)
        .where(and_(codes_t.c.user_id == user_id, codes_t.c.used_at.is_(None)))
        .order_by(codes_t.c.created_at.desc())
        .limit(1)
    )
    if not row or _aware(row["expires_at"]) < now:
        return {"has_active_code": False, "resend_available_in_seconds": 0}
    elapsed = (now - _aware(row["last_sent_at"])).total_seconds()
    return {
        "has_active_code": True,
        "resend_available_in_seconds": max(0, int(cfg.resend_seconds - elapsed)),
    }


async def issue_and_send_code(user_row: Mapping[str, Any], *, enforce_cooldown: bool = True) -> dict:
    """Unieważnij stare kody (poza oknem karencji), zapisz nowy i wyślij."""
    database, _users_t, codes_t, _pre_t = _db()
    cfg = get_email_config()
    user_row = _as_dict(user_row)
    user_id = int(user_row["id"])
    email = (user_row.get("email") or "").strip()
    if not email:
        raise VerificationError(
            error="EMAIL_REQUIRED",
            message="Brak adresu e-mail. Podaj adres, aby otrzymać kod.",
            http_status=400,
        )
    email_norm = normalize_email(email)

    if enforce_cooldown:
        await _enforce_rate("send_user", str(user_id), 1, cfg.resend_seconds)
        await _enforce_rate("send_email", email_norm, *_SEND_EMAIL_PER_HOUR)

    code = generate_code()
    code_hash = hash_code_for_key(user_key(user_id), code)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=cfg.ttl_minutes)

    async with database.transaction():
        supersede_before = now - timedelta(seconds=SUPERSEDE_GRACE_SECONDS)
        await database.execute(
            update(codes_t)
            .where(
                and_(
                    codes_t.c.user_id == user_id,
                    codes_t.c.used_at.is_(None),
                    codes_t.c.last_sent_at < supersede_before,
                )
            )
            .values(used_at=now, updated_at=now)
        )
        await database.execute(
            codes_t.insert().values(
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

    await _record_rate("send_user", str(user_id))
    await _record_rate("send_email", email_norm)

    message_id = await send_verification_code(
        recipient_email=email,
        recipient_name=user_row.get("full_name"),
        code=code,
        expires_minutes=cfg.ttl_minutes,
    )
    logger.info(
        "proel verification_issued user_id=%s email=%s messageId=%s",
        user_id, mask_email(email), message_id,
    )
    return {
        "expires_in_seconds": cfg.ttl_seconds,
        "resend_available_in_seconds": cfg.resend_seconds,
        "message_id": message_id,
    }


# ─────────────────────────── weryfikacja kodu (zalogowany) ───────────────────────────

async def verify_email_code_for_user(user_id: int, code: str, ip: str) -> dict:
    database, users_t, _codes_t, _pre_t = _db()
    await _enforce_rate("verify_ip", ip or "", *_VERIFY_IP_PER_15MIN)
    user = await database.fetch_one(select(users_t).where(users_t.c.id == user_id))
    if not user:
        raise VerificationError(error="USER_NOT_FOUND", message="Nie znaleziono konta.", http_status=404)
    return await _verify_with_user(user, code)


async def _verify_with_user(user: Mapping[str, Any], code: str) -> dict:
    database, users_t, codes_t, _pre_t = _db()
    if bool(user["email_verified"]):
        return {"success": True, "message": "Adres e-mail został potwierdzony."}

    user_id = int(user["id"])
    now = datetime.now(timezone.utc)

    async with database.transaction():
        active = await database.fetch_all(
            select(codes_t)
            .where(and_(codes_t.c.user_id == user_id, codes_t.c.used_at.is_(None)))
            .order_by(codes_t.c.created_at.desc())
            .with_for_update()
        )

        live = []
        for row in active:
            if _aware(row["expires_at"]) < now:
                await database.execute(
                    update(codes_t).where(codes_t.c.id == row["id"]).values(used_at=now, updated_at=now)
                )
            else:
                live.append(row)

        if not live:
            raise VerificationError(
                error="VERIFICATION_CODE_EXPIRED", message="Kod wygasł. Wyślij nowy kod.", http_status=400
            )

        matched = next(
            (row for row in live if verify_code_for_key(user_key(user_id), code, row["code_hash"])),
            None,
        )

        if matched is None:
            hit_cap = False
            for row in live:
                attempts = int(row["attempts"]) + 1
                await database.execute(
                    update(codes_t).where(codes_t.c.id == row["id"]).values(attempts=attempts, updated_at=now)
                )
                if attempts >= MAX_CODE_ATTEMPTS:
                    hit_cap = True
            if hit_cap:
                await database.execute(
                    update(codes_t)
                    .where(and_(codes_t.c.user_id == user_id, codes_t.c.used_at.is_(None)))
                    .values(used_at=now, updated_at=now)
                )
                raise VerificationError(
                    error="TOO_MANY_ATTEMPTS", message="Zbyt wiele prób. Wyślij nowy kod.", http_status=400
                )
            raise VerificationError(
                error="INVALID_VERIFICATION_CODE", message="Kod jest nieprawidłowy.", http_status=400
            )

        await database.execute(
            update(users_t)
            .where(users_t.c.id == user_id)
            .values(
                email_verified=True,
                email_verified_at=now,
                email_verification_deadline=None,
                updated_at=now,
            )
        )
        await database.execute(
            update(codes_t)
            .where(and_(codes_t.c.user_id == user_id, codes_t.c.used_at.is_(None)))
            .values(used_at=now, updated_at=now)
        )

    logger.info("proel verification_success user_id=%s", user_id)
    return {"success": True, "message": "Adres e-mail został potwierdzony."}


# ─────────────────────────── resend (neutralny) ───────────────────────────

NEUTRAL_RESEND_RESPONSE = {
    "success": True,
    "message": "Jeśli konto wymaga weryfikacji, nowy kod został wysłany.",
}


async def resend_verification_for_user(user_id: int, ip: str) -> dict:
    """Resend dla zalogowanego — neutralna odpowiedź niezależnie od stanu."""
    database, users_t, _codes_t, _pre_t = _db()
    cfg = get_email_config()
    await _enforce_rate("resend_ip", ip or "", *_RESEND_IP_PER_HOUR)
    response = {**NEUTRAL_RESEND_RESPONSE, "resend_available_in_seconds": cfg.resend_seconds}

    user = await database.fetch_one(select(users_t).where(users_t.c.id == user_id))
    if not user or bool(user["email_verified"]):
        return response
    try:
        await issue_and_send_code(user, enforce_cooldown=True)
    except VerificationError as exc:
        logger.info("proel resend_skipped reason=%s user_id=%s", exc.error, user_id)
    except EmailDeliveryError as exc:
        logger.error("proel resend_delivery_failed kind=%s user_id=%s", exc.kind, user_id)
    return response


# ─────────────────────────── zmiana adresu (zalogowany) ───────────────────────────

async def set_email_and_issue(user_id: int, raw_email: str) -> dict:
    database, users_t, _codes_t, _pre_t = _db()
    if not is_valid_email(raw_email):
        raise VerificationError(error="INVALID_EMAIL", message="Podaj poprawny adres e-mail.", http_status=400)
    email_norm = normalize_email(raw_email)

    clash = await database.fetch_one(
        select(users_t.c.id).where(and_(users_t.c.email_normalized == email_norm, users_t.c.id != user_id))
    )
    if clash:
        raise VerificationError(
            error="EMAIL_EXISTS",
            message="Ten adres e-mail jest już używany przez inne konto.",
            http_status=409,
        )

    now = datetime.now(timezone.utc)
    await database.execute(
        update(users_t)
        .where(users_t.c.id == user_id)
        .values(
            email=raw_email.strip(),
            email_normalized=email_norm,
            email_verified=False,
            email_verified_at=None,
            email_delivery_blocked=False,
            updated_at=now,
        )
    )
    user = await database.fetch_one(select(users_t).where(users_t.c.id == user_id))
    if not user:
        raise VerificationError(error="USER_NOT_FOUND", message="Nie znaleziono konta.", http_status=404)

    result = await issue_and_send_code(user, enforce_cooldown=False)
    return {
        "success": True,
        "requires_email_verification": True,
        "email": mask_email(raw_email),
        **result,
    }


# ─────────────────────────── po rejestracji ───────────────────────────

async def maybe_issue_on_register(user_id: int, deadline_days: int) -> Optional[dict]:
    """Best-effort: termin weryfikacji + kod dla świeżego, niezweryfikowanego konta.

    W ProElu nie ma beachowych „zatwierdzonych ról" zwalniających z weryfikacji —
    bramką jest sam stan `email_verified`.
    """
    database, users_t, _codes_t, _pre_t = _db()
    user = _as_dict(await database.fetch_one(select(users_t).where(users_t.c.id == user_id)))
    if not user or bool(user.get("email_verified")):
        return None
    deadline = datetime.now(timezone.utc) + timedelta(days=deadline_days)
    await database.execute(
        update(users_t)
        .where(and_(users_t.c.id == user_id, users_t.c.email_verification_deadline.is_(None)))
        .values(email_verification_deadline=deadline)
    )
    if not (user.get("email") or "").strip():
        return None  # bez adresu — dokończy w modalu w aplikacji
    try:
        return await issue_and_send_code(user, enforce_cooldown=False)
    except (VerificationError, EmailDeliveryError) as exc:
        kind = getattr(exc, "kind", getattr(exc, "error", "unknown"))
        logger.error("proel register_code_send_failed user_id=%s reason=%s", user_id, kind)
        return None


# ─────────────────────────── pre-signup (przed kontem) ───────────────────────────

async def request_signup_code(email_input: str, ip: str) -> dict:
    database, users_t, _codes_t, pre_t = _db()
    cfg = get_email_config()
    if not is_valid_email(email_input):
        raise VerificationError(error="INVALID_EMAIL", message="Podaj poprawny adres e-mail.", http_status=400)
    email_norm = normalize_email(email_input)

    existing = await database.fetch_one(
        select(users_t.c.id).where(users_t.c.email_normalized == email_norm)
    )
    if existing:
        raise VerificationError(
            error="EMAIL_EXISTS",
            message="Ten adres e-mail jest już używany. Zaloguj się lub użyj innego.",
            http_status=409,
        )

    await _enforce_rate("send_user", f"signup:{email_norm}", 1, cfg.resend_seconds)
    await _enforce_rate("send_email", email_norm, *_SEND_EMAIL_PER_HOUR)

    code = generate_code()
    code_hash = hash_code_for_key(signup_key(email_norm), code)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=cfg.ttl_minutes)

    async with database.transaction():
        supersede_before = now - timedelta(seconds=SUPERSEDE_GRACE_SECONDS)
        await database.execute(
            update(pre_t)
            .where(
                and_(
                    pre_t.c.email_normalized == email_norm,
                    pre_t.c.used_at.is_(None),
                    pre_t.c.last_sent_at < supersede_before,
                )
            )
            .values(used_at=now, updated_at=now)
        )
        await database.execute(
            pre_t.insert().values(
                id=uuid.uuid4(),
                email_normalized=email_norm,
                code_hash=code_hash,
                expires_at=expires_at,
                used_at=None,
                verified_at=None,
                attempts=0,
                last_sent_at=now,
                created_at=now,
                updated_at=now,
            )
        )

    await _record_rate("send_user", f"signup:{email_norm}")
    await _record_rate("send_email", email_norm)

    message_id = await send_verification_code(
        recipient_email=email_input.strip(), recipient_name=None, code=code, expires_minutes=cfg.ttl_minutes
    )
    logger.info("proel signup_code_issued email=%s messageId=%s", mask_email(email_norm), message_id)
    return {
        "success": True,
        "email": mask_email(email_norm),
        "expires_in_seconds": cfg.ttl_seconds,
        "resend_available_in_seconds": cfg.resend_seconds,
    }


async def verify_signup_code(email_input: str, code: str, ip: str) -> dict:
    database, _users_t, _codes_t, pre_t = _db()
    await _enforce_rate("verify_ip", ip or "", *_VERIFY_IP_PER_15MIN)
    email_norm = normalize_email(email_input)
    now = datetime.now(timezone.utc)

    async with database.transaction():
        active = await database.fetch_all(
            select(pre_t)
            .where(and_(pre_t.c.email_normalized == email_norm, pre_t.c.used_at.is_(None)))
            .order_by(pre_t.c.created_at.desc())
            .with_for_update()
        )

        if any(row["verified_at"] is not None for row in active):
            return {"success": True, "message": "Adres e-mail został potwierdzony."}

        live = []
        for row in active:
            if _aware(row["expires_at"]) < now:
                await database.execute(
                    update(pre_t).where(pre_t.c.id == row["id"]).values(used_at=now, updated_at=now)
                )
            else:
                live.append(row)

        if not live:
            raise VerificationError(
                error="VERIFICATION_CODE_EXPIRED", message="Kod wygasł. Wyślij nowy kod.", http_status=400
            )

        matched = next(
            (row for row in live if verify_code_for_key(signup_key(email_norm), code, row["code_hash"])),
            None,
        )

        if matched is None:
            hit_cap = False
            for row in live:
                attempts = int(row["attempts"]) + 1
                await database.execute(
                    update(pre_t).where(pre_t.c.id == row["id"]).values(attempts=attempts, updated_at=now)
                )
                if attempts >= MAX_CODE_ATTEMPTS:
                    hit_cap = True
            if hit_cap:
                await database.execute(
                    update(pre_t)
                    .where(and_(pre_t.c.email_normalized == email_norm, pre_t.c.used_at.is_(None)))
                    .values(used_at=now, updated_at=now)
                )
                raise VerificationError(
                    error="TOO_MANY_ATTEMPTS", message="Zbyt wiele prób. Wyślij nowy kod.", http_status=400
                )
            raise VerificationError(
                error="INVALID_VERIFICATION_CODE", message="Kod jest nieprawidłowy.", http_status=400
            )

        await database.execute(
            update(pre_t).where(pre_t.c.id == matched["id"]).values(verified_at=now, updated_at=now)
        )

    logger.info("proel signup_code_verified email=%s", mask_email(email_norm))
    return {"success": True, "message": "Adres e-mail został potwierdzony."}


async def is_signup_email_verified(email_norm: str) -> bool:
    database, _users_t, _codes_t, pre_t = _db()
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=SIGNUP_VERIFIED_WINDOW_SECONDS)
    row = await database.fetch_one(
        select(pre_t.c.id).where(
            and_(
                pre_t.c.email_normalized == email_norm,
                pre_t.c.used_at.is_(None),
                pre_t.c.verified_at.isnot(None),
                pre_t.c.verified_at >= cutoff,
            )
        )
    )
    return row is not None


async def consume_signup_verification(email_norm: str) -> None:
    database, _users_t, _codes_t, pre_t = _db()
    now = datetime.now(timezone.utc)
    await database.execute(
        update(pre_t)
        .where(and_(pre_t.c.email_normalized == email_norm, pre_t.c.used_at.is_(None)))
        .values(used_at=now, updated_at=now)
    )

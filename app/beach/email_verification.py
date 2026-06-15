"""
Email-verification business logic (BEACH).

Responsibilities:
- issue / resend / verify 6-digit codes (hashed, single-use, 15-min TTL),
- DB-backed rate limiting (works across Railway instances — no in-process state),
- role-based gating (accounts with an approved role are exempt),
- one-time backfill of ``email_normalized`` + safe partial-unique index,
- 90-day grace cleanup of unverified, role-less accounts.

The router layer maps the exceptions raised here to HTTP responses.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional

from sqlalchemy import and_, delete, func, select, update

from app.db import (
    database,
    beach_users,
    beach_email_verification_codes as codes_t,
    beach_email_rate_events as rate_t,
)
from app.beach.email_config import get_email_config
from app.beach.email_masking import mask_email
from app.beach.email_normalization import normalize_email, is_valid_email
from app.beach.email_security import generate_code, hash_code, verify_code
from app.beach.brevo_email import (
    send_verification_code,
    EmailDeliveryError,
    email_delivery_to_http,  # re-exported for the router layer
)

logger = logging.getLogger(__name__)

MAX_CODE_ATTEMPTS = 5

# Rate-limit policy (scope, limit, window seconds)
_SEND_EMAIL_PER_HOUR = (5, 3600)
_VERIFY_IP_PER_15MIN = (10, 900)
_RESEND_IP_PER_HOUR = (20, 3600)


# ─────────────────────────── Errors ───────────────────────────

class VerificationError(Exception):
    """Domain error carrying an API error code + HTTP status + user message."""

    def __init__(self, *, error: str, message: str, http_status: int = 400):
        super().__init__(message)
        self.error = error
        self.message = message
        self.http_status = http_status


# ─────────────────────────── Roles / gating ───────────────────────────

def has_approved_role(roles: Any) -> bool:
    """True when the user has at least one approved person-role (player/coach/judge)."""
    if isinstance(roles, list):
        for role in roles:
            if isinstance(role, dict) and role.get("verified") == "approved":
                return True
    return False


def _as_dict(row: Any) -> dict:
    """Normalize a databases ``Record`` (no ``.get``) or dict into a plain dict."""
    if row is None:
        return {}
    if isinstance(row, dict):
        return row
    return dict(row)


def requires_email_gate(user_row: Mapping[str, Any]) -> bool:
    """Whether this account must verify its e-mail before using the app.

    Accounts with an approved role are exempt ("luz"). Verified accounts are
    exempt. Everyone else must verify.
    """
    row = _as_dict(user_row)
    if bool(row.get("email_verified")):
        return False
    return not has_approved_role(row.get("roles"))


# ─────────────────────────── Rate limiter (DB) ───────────────────────────

async def _count_recent(scope: str, ref: str, window_seconds: int) -> int:
    since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    row = await database.fetch_one(
        select(func.count())
        .select_from(rate_t)
        .where(
            and_(
                rate_t.c.scope == scope,
                rate_t.c.ref == ref,
                rate_t.c.created_at >= since,
            )
        )
    )
    return int(row[0]) if row else 0


async def _record_rate(scope: str, ref: str) -> None:
    await database.execute(
        rate_t.insert().values(
            scope=scope, ref=ref, created_at=datetime.now(timezone.utc)
        )
    )


async def _enforce_rate(scope: str, ref: str, limit: int, window_seconds: int) -> None:
    if not ref:
        return
    count = await _count_recent(scope, ref, window_seconds)
    if count >= limit:
        logger.warning("rate limit hit scope=%s ref=%s count=%s", scope, _safe_ref(scope, ref), count)
        raise VerificationError(
            error="RATE_LIMITED",
            message="Zbyt wiele prób. Spróbuj ponownie później.",
            http_status=429,
        )


def _safe_ref(scope: str, ref: str) -> str:
    # Mask e-mail refs in logs.
    if scope.endswith("email"):
        return mask_email(ref)
    return ref


# ─────────────────────────── Issue / send ───────────────────────────

async def issue_and_send_code(user_row: Mapping[str, Any], *, enforce_cooldown: bool = True) -> dict:
    """Invalidate previous active codes, store a fresh hashed code and send it.

    Raises ``VerificationError`` (no e-mail / rate limited) or ``EmailDeliveryError``.
    """
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
    code_hash = hash_code(user_id, code)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=cfg.ttl_minutes)

    async with database.transaction():
        # New code invalidates all previous active codes.
        await database.execute(
            update(codes_t)
            .where(and_(codes_t.c.user_id == user_id, codes_t.c.used_at.is_(None)))
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
        "verification_issued user_id=%s email=%s messageId=%s",
        user_id, mask_email(email), message_id,
    )
    return {
        "expires_in_seconds": cfg.ttl_seconds,
        "resend_available_in_seconds": cfg.resend_seconds,
        "message_id": message_id,
    }


# ─────────────────────────── Verify ───────────────────────────

async def verify_email_code(email_input: str, code: str, ip: str) -> dict:
    """Validate a code by e-mail (public flow). Raises ``VerificationError``."""
    await _enforce_rate("verify_ip", ip or "", *_VERIFY_IP_PER_15MIN)
    email_norm = normalize_email(email_input)
    user = await database.fetch_one(
        select(beach_users).where(beach_users.c.email_normalized == email_norm)
    )
    if not user:
        # Do not disclose that the account doesn't exist.
        raise VerificationError(
            error="INVALID_VERIFICATION_CODE",
            message="Kod jest nieprawidłowy.",
            http_status=400,
        )
    return await _verify_with_user(user, code)


async def verify_email_code_for_user(user_id: int, code: str, ip: str) -> dict:
    """Validate a code for the authenticated user (in-app modal flow)."""
    await _enforce_rate("verify_ip", ip or "", *_VERIFY_IP_PER_15MIN)
    user = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not user:
        raise VerificationError(error="USER_NOT_FOUND", message="Nie znaleziono konta.", http_status=404)
    return await _verify_with_user(user, code)


async def _verify_with_user(user: Mapping[str, Any], code: str) -> dict:
    if bool(user["email_verified"]):
        # Idempotent success.
        return {"success": True, "message": "Adres e-mail został potwierdzony."}

    user_id = int(user["id"])
    now = datetime.now(timezone.utc)

    async with database.transaction():
        # Lock the newest active code row so two concurrent requests serialise.
        locked = await database.fetch_one(
            select(codes_t)
            .where(and_(codes_t.c.user_id == user_id, codes_t.c.used_at.is_(None)))
            .order_by(codes_t.c.created_at.desc())
            .limit(1)
            .with_for_update()
        )
        if not locked:
            raise VerificationError(
                error="VERIFICATION_CODE_EXPIRED",
                message="Kod wygasł. Wyślij nowy kod.",
                http_status=400,
            )
        if _aware(locked["expires_at"]) < now:
            await database.execute(
                update(codes_t).where(codes_t.c.id == locked["id"]).values(used_at=now, updated_at=now)
            )
            raise VerificationError(
                error="VERIFICATION_CODE_EXPIRED",
                message="Kod wygasł. Wyślij nowy kod.",
                http_status=400,
            )

        attempts = int(locked["attempts"]) + 1
        await database.execute(
            update(codes_t).where(codes_t.c.id == locked["id"]).values(attempts=attempts, updated_at=now)
        )

        if not verify_code(user_id, code, locked["code_hash"]):
            if attempts >= MAX_CODE_ATTEMPTS:
                await database.execute(
                    update(codes_t).where(codes_t.c.id == locked["id"]).values(used_at=now, updated_at=now)
                )
                logger.info("verify_too_many_attempts user_id=%s", user_id)
                raise VerificationError(
                    error="TOO_MANY_ATTEMPTS",
                    message="Zbyt wiele prób. Wyślij nowy kod.",
                    http_status=400,
                )
            raise VerificationError(
                error="INVALID_VERIFICATION_CODE",
                message="Kod jest nieprawidłowy.",
                http_status=400,
            )

        # Success — atomically mark user verified, consume code, kill siblings.
        await database.execute(
            update(beach_users)
            .where(beach_users.c.id == user_id)
            .values(
                email_verified=True,
                email_verified_at=now,
                email_verification_deadline=None,
                updated_at=now,
            )
        )
        await database.execute(
            update(codes_t).where(codes_t.c.id == locked["id"]).values(used_at=now, updated_at=now)
        )
        await database.execute(
            update(codes_t)
            .where(and_(codes_t.c.user_id == user_id, codes_t.c.used_at.is_(None)))
            .values(used_at=now, updated_at=now)
        )

    logger.info("verification_success user_id=%s email=%s", user_id, mask_email(user["email"]))
    return {"success": True, "message": "Adres e-mail został potwierdzony."}


# ─────────────────────────── Resend ───────────────────────────

NEUTRAL_RESEND_RESPONSE = {
    "success": True,
    "message": "Jeśli konto wymaga weryfikacji, nowy kod został wysłany.",
}


async def resend_verification(email_input: str, ip: str) -> dict:
    """Resend a code. Always returns the same neutral response (no enumeration)."""
    cfg = get_email_config()
    await _enforce_rate("resend_ip", ip or "", *_RESEND_IP_PER_HOUR)

    response = {**NEUTRAL_RESEND_RESPONSE, "resend_available_in_seconds": cfg.resend_seconds}

    email_norm = normalize_email(email_input)
    user = await database.fetch_one(
        select(beach_users).where(beach_users.c.email_normalized == email_norm)
    )
    if not user or bool(user["email_verified"]):
        return response

    try:
        await issue_and_send_code(user, enforce_cooldown=True)
    except VerificationError as exc:
        # Cooldown / missing e-mail — stay neutral, just log.
        logger.info("resend_skipped reason=%s user_id=%s", exc.error, int(user["id"]))
    except EmailDeliveryError as exc:
        # Delivery failed — stay neutral (don't disclose), log server-side.
        logger.error("resend_delivery_failed kind=%s user_id=%s", exc.kind, int(user["id"]))
    return response


# ─────────────────────────── Authenticated set/change e-mail ───────────────────────────

async def set_email_and_issue(user_id: int, raw_email: str) -> dict:
    """Set/replace the current user's e-mail and send a fresh code.

    Used by the mandatory in-app verification modal (user may add or change the
    address). Raises ``VerificationError`` / ``EmailDeliveryError``.
    """
    if not is_valid_email(raw_email):
        raise VerificationError(
            error="INVALID_EMAIL",
            message="Podaj poprawny adres e-mail.",
            http_status=400,
        )
    email_norm = normalize_email(raw_email)

    clash = await database.fetch_one(
        select(beach_users.c.id).where(
            and_(beach_users.c.email_normalized == email_norm, beach_users.c.id != user_id)
        )
    )
    if clash:
        raise VerificationError(
            error="EMAIL_EXISTS",
            message="Ten adres e-mail jest już używany przez inne konto.",
            http_status=409,
        )

    now = datetime.now(timezone.utc)
    await database.execute(
        update(beach_users)
        .where(beach_users.c.id == user_id)
        .values(
            email=raw_email.strip(),
            email_normalized=email_norm,
            email_verified=False,
            email_verified_at=None,
            email_delivery_blocked=False,
            updated_at=now,
        )
    )
    user = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not user:
        raise VerificationError(error="USER_NOT_FOUND", message="Nie znaleziono konta.", http_status=404)

    result = await issue_and_send_code(user, enforce_cooldown=False)
    return {
        "success": True,
        "requires_email_verification": True,
        "email": mask_email(raw_email),
        **result,
    }


# ─────────────────────────── Registration helper ───────────────────────────

async def maybe_issue_on_register(user_id: int, deadline_days: int) -> Optional[dict]:
    """Best-effort: issue a code for a freshly-registered, gated account.

    Returns issue timers on success, ``None`` when no code was sent (e.g. user
    has an approved role, or no e-mail). Swallows delivery failure (the user can
    finish via the resend endpoint) but always keeps DB state consistent.
    """
    user = _as_dict(await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id)))
    if not user:
        return None
    if not requires_email_gate(user):
        return None
    # Set the deletion deadline for the gated account.
    deadline = datetime.now(timezone.utc) + timedelta(days=deadline_days)
    await database.execute(
        update(beach_users)
        .where(and_(beach_users.c.id == user_id, beach_users.c.email_verification_deadline.is_(None)))
        .values(email_verification_deadline=deadline)
    )
    if not (user.get("email") or "").strip():
        return None  # gated but no e-mail yet → handled by in-app modal
    try:
        return await issue_and_send_code(user, enforce_cooldown=False)
    except (VerificationError, EmailDeliveryError) as exc:
        kind = getattr(exc, "kind", getattr(exc, "error", "unknown"))
        logger.error("register_code_send_failed user_id=%s reason=%s", user_id, kind)
        return None


# ─────────────────────────── Migrations / maintenance ───────────────────────────

async def run_email_normalize_backfill() -> None:
    """Backfill ``email_normalized``, set deadlines, create safe partial-unique index.

    Idempotent. The unique index is created only when there are no conflicting
    duplicates (after trim/lower) — otherwise it logs a masked conflict report
    and leaves the constraint out for the operator to resolve.
    """
    # Skip on sqlite (local dev) — uses Postgres-only SQL below.
    try:
        await database.execute(
            "UPDATE beach_users SET email_normalized = lower(btrim(email)) "
            "WHERE email IS NOT NULL AND btrim(email) <> '' AND email_normalized IS NULL"
        )
    except Exception:
        logger.info("email backfill skipped (non-postgres or no rows)")
        return

    cfg = get_email_config()
    deadline = datetime.now(timezone.utc) + timedelta(days=cfg.grace_days)
    await database.execute(
        update(beach_users)
        .where(and_(beach_users.c.email_verified.is_(False), beach_users.c.email_verification_deadline.is_(None)))
        .values(email_verification_deadline=deadline)
    )

    dupes = await database.fetch_all(
        "SELECT email_normalized, count(*) AS c FROM beach_users "
        "WHERE email_normalized IS NOT NULL GROUP BY email_normalized HAVING count(*) > 1"
    )
    if dupes:
        logger.warning(
            "⚠️ email_normalized conflicts: %d adresów z duplikatami — pomijam unikalny indeks. "
            "Przykłady: %s",
            len(dupes),
            ", ".join(f"{mask_email(d['email_normalized'])} x{d['c']}" for d in dupes[:5]),
        )
        return

    await database.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_beach_users_email_normalized "
        "ON beach_users (email_normalized) WHERE email_normalized IS NOT NULL"
    )
    logger.info("✅ email_normalized unique index ensured")


async def run_email_grace_cleanup() -> int:
    """Delete unverified, role-less accounts whose grace deadline has passed."""
    cfg = get_email_config()
    if not cfg.grace_delete_enabled:
        return 0
    now = datetime.now(timezone.utc)
    candidates = await database.fetch_all(
        select(beach_users.c.id, beach_users.c.roles).where(
            and_(
                beach_users.c.email_verified.is_(False),
                beach_users.c.email_verification_deadline.isnot(None),
                beach_users.c.email_verification_deadline < now,
            )
        )
    )
    to_delete = [int(c["id"]) for c in candidates if not has_approved_role(c["roles"])]
    deleted = 0
    for uid in to_delete:
        try:
            await database.execute(delete(beach_users).where(beach_users.c.id == uid))
            deleted += 1
        except Exception:
            logger.exception("grace cleanup: failed to delete user_id=%s", uid)
    if deleted:
        logger.info("🧹 email grace cleanup: usunięto %d niezweryfikowanych kont", deleted)
    return deleted


def _aware(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware (UTC) for safe comparisons."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

"""
Pytest fixtures for the e-mail verification suite.

- Sets required env BEFORE importing app modules (so config validates).
- DB-backed tests run against the configured Postgres ``DATABASE_URL`` and are
  skipped automatically when no Postgres is available (the schema uses
  Postgres-only types: JSONB / UUID).
- Brevo is always mocked — tests never send real e-mail.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest

# ── env must be set before importing app.db / config ──
os.environ.setdefault("BREVO_API_KEY", "test-key")
os.environ.setdefault("BREVO_FROM_EMAIL", "noreply@test.local")
os.environ.setdefault("BREVO_FROM_NAME", "BAZA Beach Test")
os.environ.setdefault("EMAIL_CODE_SECRET", "unit-test-secret")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("EMAIL_VERIFICATION_RESEND_SECONDS", "60")
os.environ.setdefault("EMAIL_VERIFICATION_TTL_MINUTES", "15")

DATABASE_URL = os.getenv("DATABASE_URL", "")
_IS_POSTGRES = DATABASE_URL.startswith("postgres")

requires_db = pytest.mark.skipif(
    not _IS_POSTGRES,
    reason="Wymaga Postgresa (schemat używa JSONB/UUID). Ustaw DATABASE_URL=postgresql://…",
)


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def db():
    """Connect the shared ``databases`` instance and clean email tables around each test."""
    from app.db import database

    if not database.is_connected:
        await database.connect()
    await _truncate(database)
    try:
        yield database
    finally:
        await _truncate(database)


async def _truncate(database):
    for table in (
        "email_rate_events",
        "email_verification_codes",
        "email_delivery_events",
    ):
        try:
            await database.execute(f"DELETE FROM {table}")
        except Exception:
            pass
    try:
        await database.execute("DELETE FROM beach_users WHERE login LIKE 'pytest_%'")
    except Exception:
        pass


async def create_user(
    database,
    *,
    email: str | None = "user@example.com",
    email_verified: bool = False,
    roles: list | None = None,
    full_name: str = "Pytest User",
) -> dict:
    """Insert a beach_users row and return it as a dict."""
    from app.db import beach_users
    from app.beach.email_normalization import normalize_email

    now = datetime.now(timezone.utc)
    login = f"pytest_{uuid.uuid4().hex[:10]}"
    new_id = await database.execute(
        beach_users.insert().values(
            full_name=full_name,
            login=login,
            password_hash="x",
            email=email,
            email_normalized=normalize_email(email) if email else None,
            email_verified=email_verified,
            roles=roles or [],
            badges={},
            device_ids=[],
            is_active=True,
            created_at=now,
            updated_at=now,
        )
    )
    from sqlalchemy import select

    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == int(new_id)))
    return dict(row)


@pytest.fixture
def fake_brevo(monkeypatch):
    """Replace the Brevo sender with an in-memory capture (no HTTP)."""
    sent: list[dict] = []

    async def _fake_send(recipient_email, recipient_name, code, expires_minutes):
        sent.append(
            {
                "email": recipient_email,
                "name": recipient_name,
                "code": code,
                "expires_minutes": expires_minutes,
            }
        )
        return "msg-" + uuid.uuid4().hex[:8]

    # Patch where it's used (imported into the service module).
    monkeypatch.setattr("app.beach.email_verification.send_verification_code", _fake_send)
    return sent


@pytest.fixture
def fake_brevo_failing(monkeypatch):
    """Make the Brevo sender raise a delivery error."""
    from app.beach.brevo_email import EmailDeliveryError

    async def _fail(*args, **kwargs):
        raise EmailDeliveryError("boom", kind="server", status_code=500)

    monkeypatch.setattr("app.beach.email_verification.send_verification_code", _fail)

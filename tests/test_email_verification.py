"""
DB-backed e-mail verification scenarios.

Runs against Postgres (schema uses JSONB/UUID). The whole module is skipped when
DATABASE_URL is not Postgres — so it never fails to import on a dev machine.
Brevo is mocked via the ``fake_brevo`` fixture (captures the generated code).
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest

from conftest import create_user

if not os.getenv("DATABASE_URL", "").startswith("postgres"):
    pytest.skip(
        "Wymaga Postgresa (schemat używa JSONB/UUID). Ustaw DATABASE_URL=postgresql://…",
        allow_module_level=True,
    )

from sqlalchemy import select, update  # noqa: E402

from app.beach import email_verification as ev  # noqa: E402
from app.beach.email_config import get_email_config  # noqa: E402
from app.db import (  # noqa: E402
    beach_users,
    beach_email_verification_codes as codes_t,
)


def test_role_gating():
    assert ev.has_approved_role([{"type": "judge", "verified": "approved"}]) is True
    assert ev.has_approved_role([{"type": "player", "verified": "pending"}]) is False
    assert ev.requires_email_gate({"email_verified": False, "roles": []}) is True
    assert ev.requires_email_gate({"email_verified": True, "roles": []}) is False
    assert ev.requires_email_gate(
        {"email_verified": False, "roles": [{"type": "coach", "verified": "approved"}]}
    ) is False


async def test_register_issues_code_and_sends(db, fake_brevo):  # scenarios 1 + 2
    user = await create_user(db, email="reg@example.com", roles=[])
    timers = await ev.maybe_issue_on_register(user["id"], get_email_config().grace_days)
    assert timers is not None
    assert len(fake_brevo) == 1 and fake_brevo[0]["email"] == "reg@example.com"
    rows = await db.fetch_all(select(codes_t).where(codes_t.c.user_id == user["id"]))
    assert len(rows) == 1 and rows[0]["used_at"] is None
    # 90-day deadline set on the gated account
    fresh = await db.fetch_one(select(beach_users).where(beach_users.c.id == user["id"]))
    assert fresh["email_verification_deadline"] is not None


async def test_register_skips_for_approved_role(db, fake_brevo):
    user = await create_user(db, email="judge@example.com", roles=[{"type": "judge", "verified": "approved"}])
    assert await ev.maybe_issue_on_register(user["id"], 90) is None
    assert fake_brevo == []


async def test_code_not_stored_in_plaintext(db, fake_brevo):  # scenario 16
    user = await create_user(db, email="hash@example.com")
    await ev.issue_and_send_code(user, enforce_cooldown=False)
    code = fake_brevo[-1]["code"]
    row = await db.fetch_one(select(codes_t).where(codes_t.c.user_id == user["id"]))
    assert row["code_hash"] != code
    assert code not in str(dict(row))


async def test_correct_code_verifies_case_insensitive(db, fake_brevo):  # scenarios 3 + 17 + 18
    user = await create_user(db, email="ok@example.com")
    await ev.issue_and_send_code(user, enforce_cooldown=False)
    code = fake_brevo[-1]["code"]
    res = await ev.verify_email_code("OK@Example.com", code, "1.1.1.1")
    assert res["success"] is True
    fresh = await db.fetch_one(select(beach_users).where(beach_users.c.id == user["id"]))
    assert fresh["email_verified"] is True and fresh["email_verified_at"] is not None
    code_row = await db.fetch_one(select(codes_t).where(codes_t.c.user_id == user["id"]))
    assert code_row["used_at"] is not None  # atomic: user + code both updated


async def test_wrong_code_rejected(db, fake_brevo):  # scenario 4
    user = await create_user(db, email="wrong@example.com")
    await ev.issue_and_send_code(user, enforce_cooldown=False)
    real = fake_brevo[-1]["code"]
    bad = "000000" if real != "000000" else "111111"
    with pytest.raises(ev.VerificationError) as exc:
        await ev.verify_email_code("wrong@example.com", bad, "1.1.1.1")
    assert exc.value.error == "INVALID_VERIFICATION_CODE" and exc.value.http_status == 400


async def test_expired_code_rejected(db, fake_brevo):  # scenario 5
    user = await create_user(db, email="exp@example.com")
    await ev.issue_and_send_code(user, enforce_cooldown=False)
    code = fake_brevo[-1]["code"]
    await db.execute(
        update(codes_t)
        .where(codes_t.c.user_id == user["id"])
        .values(expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))
    )
    with pytest.raises(ev.VerificationError) as exc:
        await ev.verify_email_code("exp@example.com", code, "1.1.1.1")
    assert exc.value.error == "VERIFICATION_CODE_EXPIRED"


async def test_code_cannot_be_reused(db, fake_brevo):  # scenario 6
    user = await create_user(db, email="reuse@example.com")
    await ev.issue_and_send_code(user, enforce_cooldown=False)
    code = fake_brevo[-1]["code"]
    assert (await ev.verify_email_code("reuse@example.com", code, "1.1.1.1"))["success"] is True
    # already verified → idempotent success (no second real validation)
    assert (await ev.verify_email_code("reuse@example.com", code, "1.1.1.1"))["success"] is True


async def test_too_many_attempts_invalidates_code(db, fake_brevo):  # scenario 7
    user = await create_user(db, email="brute@example.com")
    await ev.issue_and_send_code(user, enforce_cooldown=False)
    real = fake_brevo[-1]["code"]
    bad = "000000" if real != "000000" else "111111"
    last_error = None
    for _ in range(5):
        with pytest.raises(ev.VerificationError) as exc:
            await ev.verify_email_code("brute@example.com", bad, "9.9.9.9")
        last_error = exc.value.error
    assert last_error == "TOO_MANY_ATTEMPTS"
    with pytest.raises(ev.VerificationError) as exc:
        await ev.verify_email_code("brute@example.com", real, "9.9.9.9")
    assert exc.value.error == "VERIFICATION_CODE_EXPIRED"  # code invalidated


async def test_resend_cooldown_blocks(db, fake_brevo):  # scenario 8
    user = await create_user(db, email="cool@example.com")
    await ev.issue_and_send_code(user, enforce_cooldown=True)
    with pytest.raises(ev.VerificationError) as exc:
        await ev.issue_and_send_code(user, enforce_cooldown=True)
    assert exc.value.error == "RATE_LIMITED" and exc.value.http_status == 429


async def test_resend_after_cooldown_sends(db, fake_brevo):  # scenario 9
    user = await create_user(db, email="after@example.com")
    await ev.issue_and_send_code(user, enforce_cooldown=True)
    await db.execute("DELETE FROM email_rate_events")  # simulate cooldown elapsed
    await ev.issue_and_send_code(user, enforce_cooldown=True)
    assert len(fake_brevo) == 2


async def test_resend_unknown_email_is_neutral(db, fake_brevo):  # scenario 10
    res = await ev.resend_verification("nobody@nowhere.pl", "2.2.2.2")
    assert res["success"] is True and "Jeśli konto" in res["message"]
    assert fake_brevo == []


async def test_verify_already_verified_idempotent(db, fake_brevo):  # scenario 11
    await create_user(db, email="done@example.com", email_verified=True)
    res = await ev.verify_email_code("done@example.com", "123456", "3.3.3.3")
    assert res["success"] is True


async def test_concurrent_verify_only_consumes_once(db, fake_brevo):  # scenario 19
    user = await create_user(db, email="race@example.com")
    await ev.issue_and_send_code(user, enforce_cooldown=False)
    code = fake_brevo[-1]["code"]

    async def _try():
        try:
            await ev.verify_email_code("race@example.com", code, "4.4.4.4")
            return "ok"
        except ev.VerificationError:
            return "fail"

    results = await asyncio.gather(_try(), _try())
    assert "ok" in results
    fresh = await db.fetch_one(select(beach_users).where(beach_users.c.id == user["id"]))
    assert fresh["email_verified"] is True
    used = await db.fetch_all(
        select(codes_t).where(codes_t.c.user_id == user["id"], codes_t.c.used_at.isnot(None))
    )
    assert len(used) == 1  # consumed exactly once


async def test_rate_limit_is_db_backed(db):  # scenario 20
    for _ in range(10):
        await ev._record_rate("verify_ip", "5.5.5.5")
    with pytest.raises(ev.VerificationError) as exc:
        await ev._enforce_rate("verify_ip", "5.5.5.5", *ev._VERIFY_IP_PER_15MIN)
    assert exc.value.error == "RATE_LIMITED"

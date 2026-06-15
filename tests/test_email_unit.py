"""
Pure unit tests — no database, no real network.

These import only leaf modules (security / masking / normalization / brevo) so
they run on any machine, including without Postgres. Brevo HTTP is mocked.
"""
from __future__ import annotations

import os

# Ensure config secrets exist before importing config-dependent modules.
os.environ.setdefault("BREVO_API_KEY", "test-key")
os.environ.setdefault("BREVO_FROM_EMAIL", "noreply@test.local")
os.environ.setdefault("EMAIL_CODE_SECRET", "unit-test-secret")
os.environ.setdefault("ENVIRONMENT", "test")

import httpx
import pytest
import respx

from app.beach import email_security
from app.beach.email_masking import mask_email
from app.beach.email_normalization import normalize_email, is_valid_email
from app.beach.brevo_email import (
    EmailDeliveryError,
    send_verification_code,
    email_delivery_to_http,
    BREVO_URL,
)


def test_generated_code_is_six_digits():
    for _ in range(200):
        code = email_security.generate_code()
        assert len(code) == 6 and code.isdigit()


def test_hash_is_not_plaintext_and_constant_time_match():  # scenario 16 (unit half)
    h = email_security.hash_code(7, "123456")
    assert h != "123456" and len(h) == 64
    assert email_security.verify_code(7, "123456", h) is True
    assert email_security.verify_code(7, "000000", h) is False
    assert email_security.hash_code(8, "123456") != h  # bound to user id


def test_email_normalization_case_insensitive():  # scenario 17 (unit half)
    assert normalize_email("  RaDek@Domena.PL ") == "radek@domena.pl"
    assert is_valid_email("radek@domena.pl") is True
    assert is_valid_email("nope") is False


def test_email_masking():
    assert mask_email("radoslaw@domena.pl") == "ra***@domena.pl"
    assert mask_email("a@b.pl") == "a***@b.pl"
    assert mask_email("") == ""


@respx.mock
async def test_brevo_success_returns_message_id():  # scenarios 1/2 (delivery half)
    route = respx.post(BREVO_URL).mock(return_value=httpx.Response(201, json={"messageId": "abc-123"}))
    msg_id = await send_verification_code("u@example.com", "U", "123456", 15)
    assert msg_id == "abc-123"
    # Recipient name included only when present; tag set.
    body = route.calls.last.request.content.decode()
    assert "email-verification" in body and '"name"' in body


@respx.mock
async def test_brevo_omits_empty_name():
    import json

    route = respx.post(BREVO_URL).mock(return_value=httpx.Response(202, json={"messageId": "x"}))
    await send_verification_code("u@example.com", "", "123456", 15)
    data = json.loads(route.calls.last.request.content.decode())
    assert data["to"] == [{"email": "u@example.com"}]  # no "name" key when empty


@respx.mock
async def test_brevo_timeout_maps_to_timeout():  # scenario 12
    respx.post(BREVO_URL).mock(side_effect=httpx.TimeoutException("t"))
    with pytest.raises(EmailDeliveryError) as exc:
        await send_verification_code("u@example.com", None, "123456", 15)
    assert exc.value.kind == "timeout"


@respx.mock
async def test_brevo_401_maps_to_config():  # scenario 13
    respx.post(BREVO_URL).mock(return_value=httpx.Response(401, json={"message": "bad key"}))
    with pytest.raises(EmailDeliveryError) as exc:
        await send_verification_code("u@example.com", None, "123456", 15)
    assert exc.value.kind == "config"


@respx.mock
async def test_brevo_429_maps_to_rate_limited():  # scenario 14
    respx.post(BREVO_URL).mock(return_value=httpx.Response(429, json={"message": "slow"}))
    with pytest.raises(EmailDeliveryError) as exc:
        await send_verification_code("u@example.com", None, "123456", 15)
    assert exc.value.kind == "rate_limited"


@respx.mock
async def test_brevo_500_maps_to_server():  # scenario 15
    respx.post(BREVO_URL).mock(return_value=httpx.Response(500, text="oops"))
    with pytest.raises(EmailDeliveryError) as exc:
        await send_verification_code("u@example.com", None, "123456", 15)
    assert exc.value.kind == "server"


def test_brevo_error_http_mapping():
    assert email_delivery_to_http(EmailDeliveryError("x", kind="server"))[0] == 503
    assert email_delivery_to_http(EmailDeliveryError("x", kind="rate_limited"))[0] == 503

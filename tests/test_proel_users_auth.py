"""
Konta ProEl — tokeny, generator loginu, transport hasła, kształt profilu.

Najważniejszy test w tym pliku: TOKEN BEACHA NIE PRZECHODZI W PROELU.
Oba światy mogą (fallbackiem) dzielić sekret `SECRET_KEY`, a `uid` to zwykłe
liczby z dwóch różnych tabel — bez twardego `aud` token beachowego użytkownika
#7 uwierzytelniałby proelowego użytkownika #7. To nie jest hipotetyczne:
dokładnie tak wyglądałby pierwszy zgłoszony błąd bezpieczeństwa.
"""
from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import json
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import HTTPException

from app.deps import beach_create_access_token
from app.proel_users import tokens as t
from app.proel_users.users import (
    ProelUserItem,
    _merge_device_ids,
    _merge_device_infos,
    _normalize_province,
    _resolve_password,
    _to_user_item,
    build_login,
)
from app.proel_users.email_flows import signup_key, user_key
from app.proel_users.password_reset_email import _password_strength_error


@pytest.fixture(autouse=True)
def _secrets(monkeypatch):
    monkeypatch.setenv("PROEL_AUTH_SECRET", "proel-test-secret")
    monkeypatch.setenv("BEACH_AUTH_SECRET", "beach-test-secret")
    monkeypatch.setenv("EMAIL_CODE_SECRET", "unit-test-secret")


# ─────────────────────────── tokeny ───────────────────────────

def test_token_roundtrip():
    token = t.create_access_token(42)
    payload = t.verify_access_token(token)
    assert payload["uid"] == 42
    assert payload["aud"] == "proel"


def test_beach_token_is_rejected():
    """Sedno rozdziału światów — patrz nagłówek pliku."""
    beach_token = beach_create_access_token(7)
    with pytest.raises(HTTPException) as e:
        t.verify_access_token(beach_token)
    assert e.value.status_code == 401


def test_beach_token_rejected_even_with_shared_secret(monkeypatch):
    """Wspólny sekret (fallback SECRET_KEY) NIE otwiera drogi między światami:
    beachowy payload nie ma `aud`, więc odpada na publiczności, nie na podpisie."""
    monkeypatch.delenv("PROEL_AUTH_SECRET", raising=False)
    monkeypatch.delenv("BEACH_AUTH_SECRET", raising=False)
    monkeypatch.delenv("AUTH_SECRET", raising=False)
    monkeypatch.setenv("SECRET_KEY", "one-shared-secret")

    beach_token = beach_create_access_token(7)
    with pytest.raises(HTTPException):
        t.verify_access_token(beach_token)
    # a własny token w tej samej konfiguracji działa
    assert t.verify_access_token(t.create_access_token(7))["uid"] == 7


def test_expired_token_is_rejected():
    token = t.create_access_token(1, ttl_seconds=-5)
    with pytest.raises(HTTPException) as e:
        t.verify_access_token(token)
    assert e.value.status_code == 401


def test_tampered_payload_is_rejected():
    token = t.create_access_token(1)
    payload_b64, sig = token.split(".", 1)
    raw = json.loads(t._b64url_decode(payload_b64))
    raw["uid"] = 999
    forged = t._b64url_encode(json.dumps(raw, separators=(",", ":")).encode()) + "." + sig
    with pytest.raises(HTTPException):
        t.verify_access_token(forged)


def test_forged_aud_with_wrong_secret_fails():
    """Token z aud=proel podpisany INNYM sekretem — odpada na podpisie."""
    now = int(time.time())
    payload = {"uid": 5, "iat": now, "exp": now + 3600, "v": 1, "aud": "proel"}
    payload_b64 = t._b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac_mod.new(b"attacker-secret", payload_b64.encode(), hashlib.sha256).digest()
    forged = f"{payload_b64}.{t._b64url_encode(sig)}"
    with pytest.raises(HTTPException):
        t.verify_access_token(forged)


def test_bearer_extraction():
    token = t.create_access_token(3)
    assert t._bearer(f"Bearer {token}") == token
    assert t._bearer("bearer x") == "x"
    assert t._bearer(token) is None
    assert t._bearer(None) is None


# ─────────────────────────── login / profil ───────────────────────────

def test_build_login_matches_beach_style():
    assert build_login("Kowalski", "Jan") == "kowalski_jan"
    # bez diakrytyków (w tym ł→l, które NIE rozkłada się przez NFD)
    assert build_login("Łoś", "Michał") == "los_michal"
    assert build_login("Żółć-Łąka", "Święty") == "zolc-laka_swiety"
    # spacje: w nazwisku → podkreślenia, w imieniu → sklejone
    assert build_login("van der Berg", "Anna Maria") == "van_der_berg_annamaria"


def test_normalize_province():
    assert _normalize_province(" śląskie ") == "ŚLĄSKIE"
    assert _normalize_province("") is None
    assert _normalize_province(None) is None


def test_resolve_password_trims_and_requires():
    assert _resolve_password("  tajne123  ", None) == "tajne123"
    with pytest.raises(HTTPException):
        _resolve_password(None, None)


def test_resolve_password_decrypts_rsa_oaep(monkeypatch):
    """Ta sama ścieżka co Beach: RSA-OAEP(SHA-256) → strip()."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    import app.proel_users.users as users_mod

    monkeypatch.setattr(users_mod, "get_rsa_keys", lambda: (priv, priv.public_key()))
    encrypted = priv.public_key().encrypt(
        "  Hasło123!  ".encode("utf-8"),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    assert _resolve_password(None, base64.b64encode(encrypted).decode()) == "Hasło123!"


def test_user_item_email_verification_flag():
    base = {
        "id": 1, "full_name": "KOWALSKI Jan", "login": "kowalski_jan",
        "email": "a@b.pl", "email_verified": False,
    }
    assert _to_user_item(base).requires_email_verification is True
    assert _to_user_item({**base, "email_verified": True}).requires_email_verification is False
    # Konto bez e-maila nie jest „do zweryfikowania" — nie ma czego.
    assert _to_user_item({**base, "email": None}).requires_email_verification is False


def test_device_merge_helpers():
    assert _merge_device_ids(["a"], "b") == ["a", "b"]
    assert _merge_device_ids(["a"], "a") == ["a"]
    infos = _merge_device_infos({}, "ins_1", "Android", "6.0.0", __import__("datetime").datetime.now(__import__("datetime").timezone.utc))
    assert infos["ins_1"]["platform"] == "android"
    assert infos["ins_1"]["app_version"] == "6.0.0"


# ─────────────────────────── klucze kodów e-mail ───────────────────────────

def test_code_keys_are_world_separated():
    """Kod ProEla i Beacha dla tego samego usera/e-maila hashują się INACZEJ —
    nawet przy wspólnym EMAIL_CODE_SECRET (klucz HMAC niesie prefiks świata)."""
    from app.beach.email_security import hash_code_for_key

    beach_hash = hash_code_for_key("7", "123456")               # klucz beachowy: samo id
    proel_hash = hash_code_for_key(user_key(7), "123456")        # proel:7
    assert beach_hash != proel_hash

    beach_signup = hash_code_for_key("signup:a@b.pl", "123456")
    proel_signup = hash_code_for_key(signup_key("a@b.pl"), "123456")
    assert beach_signup != proel_signup


# ─────────────────────────── polityka haseł (reset) ───────────────────────────

def test_password_strength_rules():
    assert _password_strength_error("Ab1x") is not None            # za krótkie
    assert _password_strength_error("abcdefg1") is not None        # brak wielkiej
    assert _password_strength_error("ABCDEFG1") is not None        # brak małej
    assert _password_strength_error("Abcdefgh") is not None        # brak cyfry
    assert _password_strength_error("Haslo123") is None
    assert _password_strength_error("Żółwik12") is None            # polskie znaki liczą się jak litery

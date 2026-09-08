"""Zależność `get_optional_jwt_payload` - trzy stany, nie dwa.

Bramka okręgowa (`app/province_guard.py`) rozstrzyga na podstawie tego, czy
dostała payload, czy `None`. Ten plik pilnuje, żeby granica leżała tam, gdzie
ją postawiliśmy: token dobry daje payload, a token BRAKUJĄCY, WYGASŁY i
POŁAMANY dają jednakowo `None`.

Dlaczego wygasły nie kończy się 401: BAZA nie odnawia tokenu w tle (`getToken`
oddaje to, co leży w SecureStore, bez patrzenia na datę), więc twarde 401
wywracałoby zapis każdemu, kto od dawna się nie logował - a bramka i tak nie
wpuszcza takiego żądania dalej niż anonimowego.
"""

from __future__ import annotations

import datetime

import pytest
from jose import jwt

SECRET = "sekret-do-testow"
ALGO = "HS256"

REQUIRED_ENV = {
    "SECRET_KEY": SECRET,
    "ALGORITHM": ALGO,
    "ACCESS_TOKEN_EXPIRE_MINUTES": "60",
    "ZPRP_BASE_URL": "https://example.test",
    "ZPRP_BEACH_USERNAME": "u",
    "ZPRP_BEACH_PASSWORD": "p",
    "GOOGLE_CLIENT_ID": "id",
    "GOOGLE_CLIENT_SECRET": "secret",
    "BACKEND_URL": "https://example.test",
    "FRONTEND_DEEP_LINK": "baza://",
    "RSA_PRIVATE_KEY": "brak",
}


@pytest.fixture(autouse=True)
def env(monkeypatch):
    for key, value in REQUIRED_ENV.items():
        monkeypatch.setenv(key, value)


def make_token(minutes: int = 60, **claims) -> str:
    payload = {
        "sub": "login",
        "judge_id": "7",
        "account_type": "judge",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=minutes),
    }
    payload.update(claims)
    return jwt.encode(payload, SECRET, algorithm=ALGO)


async def test_dobry_token_daje_tozsamosc():
    from app.deps import get_optional_jwt_payload

    payload = await get_optional_jwt_payload(make_token())
    assert payload is not None
    assert payload["judge_id"] == "7"


async def test_brak_tokenu_to_none():
    from app.deps import get_optional_jwt_payload

    assert await get_optional_jwt_payload(None) is None
    assert await get_optional_jwt_payload("") is None


async def test_wygasly_token_to_none():
    from app.deps import get_optional_jwt_payload

    assert await get_optional_jwt_payload(make_token(minutes=-5)) is None


async def test_polamany_token_to_none():
    from app.deps import get_optional_jwt_payload

    assert await get_optional_jwt_payload("to-nie-jest-token") is None


async def test_token_bez_loginu_to_none():
    from app.deps import get_optional_jwt_payload

    # Token podpisany naszym sekretem, ale bez `sub` - nie wiemy, kto to.
    token = jwt.encode({"judge_id": "7"}, SECRET, algorithm=ALGO)
    assert await get_optional_jwt_payload(token) is None

"""Token logowania ze strony egzaminu na żywo działa tylko na trasach /exam-live."""

from __future__ import annotations

import datetime

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from jose import jwt

from tests.test_optional_jwt import ALGO, REQUIRED_ENV, SECRET  # noqa: F401


@pytest.fixture(autouse=True)
def env(monkeypatch):
    for k, v in REQUIRED_ENV.items():
        monkeypatch.setenv(k, v)


def _token(scope=None):
    from app.deps import WEB_SCOPE

    exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    payload = {"sub": "u", "judge_id": "123", "exp": exp}
    if scope == "web":
        payload["scope"] = WEB_SCOPE
    elif scope:
        payload["scope"] = scope
    return jwt.encode(payload, SECRET, algorithm=ALGO)


def _client():
    from app.deps import get_current_user, get_jwt_payload, get_optional_jwt_payload

    app = FastAPI()
    live, exams = APIRouter(prefix="/exam-live"), APIRouter(prefix="/exams")

    @live.get("/x")
    async def lx(p: dict = Depends(get_jwt_payload)):
        return {"ok": p["sub"]}

    @exams.get("/mine")
    async def mine(p: dict = Depends(get_jwt_payload)):
        return {"ok": p["sub"]}

    @exams.get("/who")
    async def who(u: str = Depends(get_current_user)):
        return {"ok": u}

    @exams.get("/opt")
    async def opt(p=Depends(get_optional_jwt_payload)):
        return {"anon": p is None}

    app.include_router(live)
    app.include_router(exams)
    return TestClient(app)


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def test_token_www_dziala_na_trasach_na_zywo_i_nie_poza_nimi():
    c = _client()
    web = _token("web")
    assert c.get("/exam-live/x", headers=_h(web)).status_code == 200
    assert c.get("/exams/mine", headers=_h(web)).status_code == 401
    assert c.get("/exams/who", headers=_h(web)).status_code == 401
    assert c.get("/exams/opt", headers=_h(web)).json() == {"anon": True}


def test_zwykly_token_aplikacji_dziala_wszedzie_a_obcy_zakres_nie():
    c = _client()
    plain = _token()
    assert c.get("/exams/mine", headers=_h(plain)).status_code == 200
    assert c.get("/exam-live/x", headers=_h(plain)).status_code == 200
    assert c.get("/exam-live/x", headers=_h(_token("inny"))).status_code == 401


def test_admin_guard_odrzuca_token_z_zakresem():
    from app.admin_guard import REASON_BAD_TOKEN, REASON_OK, decode_token

    assert decode_token(_token())[1] == REASON_OK
    assert decode_token(_token("web")) == (None, REASON_BAD_TOKEN)


def test_login_www_wystawia_token_z_zakresem():
    # app.exam_live importuje żywą bazę, więc sprawdzamy wiązanie ze źródła (jak test_exam_live_wiring).
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[1] / "app" / "exam_live.py").read_text(encoding="utf-8")
    assert '"scope": WEB_SCOPE' in src and "import WEB_SCOPE" in src or "WEB_SCOPE, get_settings" in src

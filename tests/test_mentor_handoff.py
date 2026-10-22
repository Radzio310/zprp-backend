"""Panel „Mentor" - przesiadka z telefonu na komputer: krótki kod i mail z linkiem."""

import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import mentor_handoff_rules as H
from tests.mentor_panel_support import JUDGES, PAIR, Env


def test_reguly_kodu_i_sciezki():
    code = H.new_code()
    assert len(code) == 4 and all(ch in H.ALPHABET for ch in code)
    assert not set("01OIL") & set(H.ALPHABET)
    assert H.normalize_code(" 7k2q ") == "7K2Q"
    assert H.normalize_code("7K-2Q") == "7K2Q"
    assert H.normalize_code("7K0Q") is None and H.normalize_code("7K2") is None
    assert H.clean_path(f"/mentor/{PAIR}/mecz/m1?t=120&klip=c1") == f"/mentor/{PAIR}/mecz/m1?t=120&klip=c1"
    assert H.clean_path("/mentor/") == "/mentor"
    for bad in ("https://x.pl/mentor", "/panel/obsada", "//evil.com", "/mentor/k/tok", "/mentor/zaloguj/AB", "/mentor/a b"):
        with pytest.raises(H.HandoffError):
            H.clean_path(bad)
    assert H.short_label("7K2Q") == "bazapodreka.app/m/7K2Q"
    assert H.mask_email("radoslaw@ovoo.pl") == "r•••••w@ovoo.pl"
    assert H.mask_email("ab@x.pl") == "a•••@x.pl" and H.mask_email("") == ""
    subject, body, text = H.email_content(f"/mentor/{PAIR}", "7K2Q", "Anna Nowak")
    assert "Cześć Anna," in text and "bazapodreka.app/m/7K2Q" in body and f"/mentor/{PAIR}" in body and subject


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


def test_kod_i_mail(env, monkeypatch):
    handoff = importlib.import_module("app.mentor_panel_handoff")
    mails = []

    async def fake_bearer(request, token):
        return {"sub": "x", "judge_id": token}

    async def fake_email(actor):
        return "anna.nowak@example.pl" if actor.judge_id == JUDGES[0] else ""

    async def fake_deliver(address, subject, body, text):
        mails.append((address, subject, text))

    monkeypatch.setattr(env.auth, "_decode_bearer", fake_bearer)
    monkeypatch.setattr(handoff, "account_email", fake_email)
    monkeypatch.setattr(handoff, "deliver", fake_deliver)
    app = FastAPI()
    app.include_router(env.panel.panel_router)

    @app.on_event("startup")
    async def start():
        await env.db.connect()
        await env.seed()

    @app.on_event("shutdown")
    async def stop():
        await env.db.disconnect()

    with TestClient(app) as client:
        path = f"/mentor/{PAIR}/mecz/m1?t=30"
        made = client.post("/mentor-panel/handoff/short", json={"path": path}).json()
        assert made["short"] == f"bazapodreka.app/m/{made['code']}" and made["path"] == path
        # Odświeżenie ekranu nie mnoży kodów.
        assert client.post("/mentor-panel/handoff/short", json={"path": path}).json()["code"] == made["code"]
        assert client.post("/mentor-panel/handoff/short", json={"path": "/mentor/k/tok"}).status_code == 400
        found = client.get(f"/mentor-panel/handoff/short/{made['code'].lower()}").json()
        assert found["path"] == path and found["url"] == f"https://www.bazapodreka.app{path}"
        other = "ZZZZ" if made["code"] != "ZZZZ" else "YYYY"
        missing = client.get(f"/mentor-panel/handoff/short/{other}")
        assert missing.status_code == 404 and missing.json()["detail"]["code"] == "SHORT_UNKNOWN"

        assert client.post("/mentor-panel/handoff/email", json={"path": path}).status_code == 401
        ok = client.post("/mentor-panel/handoff/email", json={"path": path, "code": made["code"]},
                         headers={"authorization": f"Bearer {JUDGES[0]}"})
        assert ok.json() == {"sent": True, "to": "a•••••k@example.pl"}
        assert mails[0][0] == "anna.nowak@example.pl" and made["short"] in mails[0][2]
        none = client.post("/mentor-panel/handoff/email", json={"path": path}, headers={"authorization": f"Bearer {JUDGES[1]}"})
        assert none.status_code == 404 and none.json()["detail"]["code"] == "NO_EMAIL"

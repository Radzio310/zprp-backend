"""Trasy /calendar/setup i /calendar/migrate (FastAPI, atrapa Google)."""

from __future__ import annotations

import pytest

pytest.importorskip("jose")
pytest.importorskip("httpx")

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.calendar_secondary_routes import get_secondary_deps, router  # noqa: E402
from app.deps import get_current_user  # noqa: E402
from tests.calendar_secondary_support import MATCHES_SCOPE, connect, make_deps  # noqa: E402
from tests.test_calendar_secondary_engine import FUTURE, WHISTLE, legacy_account, reconnect_matches  # noqa: E402,F401

U = "judge-1"


def client(env) -> TestClient:
    app = FastAPI()

    @app.exception_handler(HTTPException)
    async def handler(request, exc):  # ta sama koperta co w main.py
        content = {"error": exc.detail}
        if isinstance(exc.detail, dict):
            content.update({k: v for k, v in exc.detail.items() if k != "error"})
        return JSONResponse(status_code=exc.status_code, content=content)

    app.include_router(router)
    app.dependency_overrides[get_current_user] = lambda: U
    app.dependency_overrides[get_secondary_deps] = lambda: env.deps
    return TestClient(app)


def test_get_setup_returns_contract_shape():
    env = connect(make_deps(), U)
    body = client(env).get("/calendar/setup").json()
    assert body["feature_enabled"] is True and body["connected"] is True
    assert body["mode"] == "two" and body["job"] is None
    assert [c["kind"] for c in body["calendars"]] == ["whistle", "stopwatch"]


def test_get_setup_with_flag_off_is_calm():
    env = make_deps(flag=False)
    body = client(env).get("/calendar/setup").json()
    assert body["feature_enabled"] is False and body["calendars"] == [] and body["connected"] is False


def test_put_setup_saves_and_creates_calendars():
    env = connect(make_deps(), U)
    res = client(env).put("/calendar/setup", json={"colors": {"whistle": "#123456"}, "busy": False})
    assert res.status_code == 200
    body = res.json()
    assert body["busy"] is False and body["warnings"] == []
    assert body["calendars"][0]["color"] == "#123456"
    assert len(env.world.calendar_ids()) == 2


def test_put_setup_errors_carry_code_and_message_flat():
    env = connect(make_deps(), U)
    res = client(env).put("/calendar/setup", json={"mode": "trzy"})
    assert res.status_code == 400
    assert res.json()["code"] == "invalid_mode" and "Układ" in res.json()["message"]
    off = make_deps(flag=False)
    assert client(off).put("/calendar/setup", json={}).status_code == 404


def test_put_mode_change_runs_background_job_to_the_end():
    env = connect(make_deps(), U)
    import asyncio

    from tests.test_calendar_secondary_engine import STOPWATCH, post

    asyncio.run(post(env, "1", WHISTLE))
    asyncio.run(post(env, "2", STOPWATCH))
    res = client(env).put("/calendar/setup", json={"mode": "one"})
    assert res.status_code == 200 and res.json()["job"]["kind"] == "mode"
    after = client(env).get("/calendar/setup").json()
    assert after["job"]["state"] == "done" and after["job"]["done"] == 2
    assert [c["kind"] for c in after["calendars"]] == ["shared"]


def test_migrate_starts_runs_and_is_idempotent():
    import asyncio

    env = make_deps()
    legacy_account(env)
    # konto legacy: najpierw trzeba je połączyć ponownie
    res = client(env).post("/calendar/migrate")
    assert res.status_code == 409 and res.json()["code"] == "reconnect_required"
    asyncio.run(reconnect_matches(env))
    env.store.setups[U].update(job_state="failed", job_error="x")
    res = client(env).post("/calendar/migrate")
    assert res.status_code == 200 and res.json()["started"] is True
    status = client(env).get("/calendar/setup").json()
    assert status["job"]["state"] == "done" and status["needs_migration"] is False
    again = client(env).post("/calendar/migrate").json()
    assert again["started"] is False and again["job"]["state"] == "done"


def test_migrate_without_connection_is_a_clear_409():
    res = client(make_deps()).post("/calendar/migrate")
    assert res.status_code == 409 and res.json()["code"] == "calendar_not_connected"
    assert MATCHES_SCOPE  # import używany

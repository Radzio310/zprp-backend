"""Panel „Mentor" - administrator działa okiem mentora (`?act_as=<judge_id mentora>`)."""

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from starlette.requests import Request

from tests.mentor_panel_support import ADMIN, JUDGES, MENTOR, PAIR, STRANGER, Env


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


def request_as(env, monkeypatch, judge_id, act_as, method="GET"):
    async def decode(_request, _token):
        return {"judge_id": judge_id}

    monkeypatch.setattr(env.auth, "_decode_bearer", decode)
    query = f"act_as={act_as}".encode() if act_as else b""
    return Request({"type": "http", "method": method, "headers": [(b"authorization", b"Bearer x")],
                    "query_string": query, "path": "/"})


async def denied(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.status_code, exc.detail.get("code")
    raise AssertionError("oczekiwano odmowy")


def clip_body(env):
    return env.library.ClipBody(match_id="m1", video_id="v1", start_s=100, end_s=120, title="Faul")


def test_admin_dziala_okiem_mentora_i_zostawia_slad(env, monkeypatch):
    async def go():
        actor = await env.auth.mentor_actor(request_as(env, monkeypatch, ADMIN, MENTOR, "POST"))
        clip = await env.library.create_clip(PAIR, clip_body(env), actor)
        thread = await env.library.create_thread(
            PAIR, env.library.ThreadBody(target_kind="clip", target_id=clip["id"], kind="note", body="Uwaga"), actor)
        comp = await env.library.create_compilation(
            PAIR, env.library.CompilationBody(name="Zestaw", mode="free", items=[]), actor)
        dash = await env.panel.dashboard(PAIR, actor)
        audit = [r._mapping for r in await env.db.fetch_all(select(env.T["mentor_audit"]).where(
            env.T["mentor_audit"].c.action == "clip_created"))]
        return actor, clip, thread, comp, dash, audit

    actor, clip, thread, comp, dash, audit = env.run(go)
    assert actor.judge_id == MENTOR and actor.acted_by == ADMIN and actor.is_admin is False
    assert clip["author"]["judge_id"] == MENTOR
    assert clip["acted_by"] == ADMIN and clip["acted_by_name"] == "Ada Admin"
    assert thread["created_by"]["judge_id"] == MENTOR and thread["acted_by"] == ADMIN
    assert thread["comments"][0]["author"]["judge_id"] == MENTOR and thread["comments"][0]["acted_by_name"] == "Ada Admin"
    assert comp["created_by"]["judge_id"] == MENTOR and comp["acted_by"] == ADMIN
    assert dash["role"] == "mentor"
    assert [m["judge_id"] for m in dash["mentors"]] == [MENTOR] and dash["mentors"][0]["full_name"] == "Jan Mentor"
    assert len(audit) == 1 and audit[0]["acted_by"] == ADMIN and audit[0]["actor_id"] == MENTOR


def test_zwykly_zapis_nie_ma_acted_by(env, monkeypatch):
    async def go():
        actor = await env.auth.mentor_actor(request_as(env, monkeypatch, MENTOR, None, "POST"))
        return await env.library.create_clip(PAIR, clip_body(env), actor)

    clip = env.run(go)
    assert clip["acted_by"] is None and clip["acted_by_name"] is None


def test_nie_admin_dostaje_403(env, monkeypatch):
    async def go():
        return await denied(env.auth.mentor_actor(request_as(env, monkeypatch, JUDGES[0], MENTOR)))

    assert env.run(go) == (403, "ACT_AS_FORBIDDEN")


def test_wskazany_nie_jest_mentorem_pary_403(env, monkeypatch):
    async def go():
        out = []
        for target in (STRANGER, JUDGES[1]):
            actor = await env.auth.mentor_actor(request_as(env, monkeypatch, ADMIN, target))
            out.append(await denied(env.panel.dashboard(PAIR, actor)))
        return out

    assert env.run(go) == [(403, "ACT_AS_NOT_MENTOR")] * 2

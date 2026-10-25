"""Oceny mentora - administrator wystawia ocenę okiem mentora (`?act_as=`)."""

import importlib

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from starlette.requests import Request

from tests.mentor_panel_support import ADMIN, JUDGES, MENTOR, STRANGER, Env


class FakeActor:
    def __init__(self, payload, row, admin):
        self.judge_id = str(payload.get("judge_id"))
        self.is_admin = bool(admin)
        self.full_name = (row or {}).get("full_name") or ""
        self.province = (row or {}).get("province") or ""


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    e.ev = importlib.import_module("app.mentor_evaluations")
    monkeypatch.setattr(e.ev, "Actor", FakeActor)

    async def mentors_of(pair, province):
        return {"mentoring": {MENTOR}, "obsada": set()}

    monkeypatch.setattr(e.ev, "mentors_of", mentors_of)
    return e


def request(act_as, judge="m1"):
    return Request({"type": "http", "method": "POST", "headers": [], "path": "/",
                    "query_string": f"act_as={act_as}".encode(), "path_params": {"match_id": judge}})


def request_as_panel(env, act_as):
    async def decode(_request, _token):
        return {"judge_id": ADMIN}

    env.auth._decode_bearer = decode
    return Request({"type": "http", "method": "GET", "headers": [(b"authorization", b"Bearer x")],
                    "query_string": f"act_as={act_as}".encode(), "path": "/"})


def base(judge_id, name, admin):
    return FakeActor({"judge_id": judge_id}, {"full_name": name}, admin)


async def denied(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.status_code, exc.detail.get("code")
    raise AssertionError("oczekiwano odmowy")


def sheet():
    return {"sections": {"I": {"main": "D"}, "II": {"main": "E"}}}


def test_admin_wystawia_ocene_jako_mentor(env):
    async def go():
        actor = await env.ev.evaluation_actor(request(MENTOR), base(ADMIN, "Ada Admin", True))
        out = await env.ev.publish("m1", env.ev.SaveRequest(sheet=sheet()), actor)
        row = (await env.db.fetch_all(select(env.T["mentor_evaluations"])))[0]._mapping
        audit = [r._mapping for r in await env.db.fetch_all(select(env.T["mentor_audit"]))]
        return actor, out, dict(row), audit

    actor, out, row, audit = env.run(go)
    assert actor.judge_id == MENTOR and actor.acted_by == ADMIN and actor.is_admin is False
    assert out["ok"] and out["acted_by"] == ADMIN and out["acted_by_name"] == "Ada Admin"
    assert row["author_id"] == MENTOR and row["acted_by"] == ADMIN and row["status"] == "published"
    assert audit[0]["action"] == "evaluation_published" and audit[0]["actor_id"] == MENTOR and audit[0]["acted_by"] == ADMIN


def test_odmowy(env):
    async def go():
        non_admin = await denied(env.ev.evaluation_actor(request(MENTOR), base(JUDGES[0], "Anna", False)))
        not_mentor = await denied(env.ev.evaluation_actor(request(STRANGER), base(ADMIN, "Ada Admin", True)))
        unknown = await denied(env.ev.evaluation_actor(request("999999"), base(ADMIN, "Ada Admin", True)))
        return non_admin, not_mentor, unknown

    assert env.run(go) == ((403, "ACT_AS_FORBIDDEN"), (403, "ACT_AS_NOT_MENTOR"), (403, "ACT_AS_UNKNOWN"))


def test_trasy_panelu_ocena_z_sesji(env):
    from tests.mentor_panel_support import PAIR

    async def go():
        P = env.panel
        mentor = await env.actor(MENTOR)
        before = await P.match_evaluation(PAIR, "m1", mentor)
        saved = await P.save_match_evaluation(PAIR, "m1", P.EvaluationBody(sheet=sheet()), mentor)
        published = await P.publish_match_evaluation(PAIR, "m1", P.EvaluationBody(sheet=sheet()), mentor)
        wrong = await denied(P.match_evaluation(PAIR, "m5", mentor))
        admin = await env.actor(ADMIN)
        admin.acted_by, admin.acted_by_name = None, None
        as_mentor = await env.auth.mentor_actor(request_as_panel(env, MENTOR))
        by_admin = await P.match_evaluation(PAIR, "m1", as_mentor)
        return before, saved, published, wrong, by_admin

    before, saved, published, wrong, by_admin = env.run(go)
    assert before["can_rate"] is True and before["mine"] is None
    assert saved["status"] == "draft" and published["status"] == "published" and published["acted_by"] is None
    assert wrong == (404, "MATCH_NOT_FOUND")
    assert by_admin["mine"]["author"]["judge_id"] == MENTOR

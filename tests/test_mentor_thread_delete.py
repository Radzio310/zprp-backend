"""Panel „Mentor" - usuwanie wątku (autor albo administrator, razem z odpowiedziami)."""

import pytest
from fastapi import HTTPException

from tests.mentor_panel_support import ADMIN, JUDGES, MENTOR, PAIR, Env


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


async def raises(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.status_code
    raise AssertionError("oczekiwano odmowy")


def test_usuwanie_watku(env):
    async def go():
        L = env.library
        pair, mentor, admin = await env.actor(JUDGES[0]), await env.actor(MENTOR), await env.actor(ADMIN)
        first = await L.create_thread(PAIR, L.ThreadBody(target_kind="match", target_id="m1", kind="question", body="Pytanie"), pair)
        await L.add_comment(first["id"], L.CommentBody(body="Odpowiedź"), mentor)
        not_owner = await raises(L.delete_thread(first["id"], mentor))
        await L.delete_thread(first["id"], pair)
        gone = await raises(L.delete_thread(first["id"], pair))
        second = await L.create_thread(PAIR, L.ThreadBody(target_kind="match", target_id="m1", kind="note", body="Do omówienia"), pair)
        await L.delete_thread(second["id"], admin)
        left = await L.list_threads(PAIR, "", "", "", mentor)
        return not_owner, gone, left

    not_owner, gone, left = env.run(go)
    assert not_owner == 403
    assert gone == 404
    assert left["threads"] == []

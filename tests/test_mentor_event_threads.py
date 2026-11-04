"""Panel „Mentor" - wątek przy zdarzeniu ProEla (04.11.2026): klucz z osi meczu, migawka, start akcji."""

import pytest
from fastapi import HTTPException

from app import mentor_panel_rules as R
from tests.mentor_panel_support import JUDGES, MENTOR, PAIR, Env

A, B = JUDGES
KEY = "penalty1:guest:7:754000"


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


async def raises(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.status_code, exc.detail.get("code") if isinstance(exc.detail, dict) else exc.detail
    raise AssertionError("oczekiwano odmowy")


async def event_thread(env, author, body, key=KEY, **over):
    L = env.library
    data = {"target_kind": "event", "target_id": key, "match_id": "m1", "kind": "question", "body": body,
            "event": {"type": "penalty1", "label": "Kara 2 min - nr 7 Nowak (Goście)", "half": 1, "score": "6:5"},
            "video_id": "v1", "video_s": 1180.0, **over}
    return await L.create_thread(PAIR, L.ThreadBody(**data), await env.actor(author))


def test_migawka_zdarzenia_z_klucza():
    snap = R.event_snapshot(KEY, {"type": "penalty1", "label": "Kara — nr 7", "half": "1", "team": "host", "score": "6:5"})
    assert snap["type"] == "penalty1" and snap["kind"] == "penalty" and snap["clock"] == "12:34"
    assert snap["team"] == "guest" and snap["player"] == "7" and snap["match_ms"] == 754000
    assert snap["label"] == "Kara - nr 7" and snap["half"] == 1 and snap["score"] == "6:5"
    bare = R.event_snapshot("teamTime:host::60000")
    assert bare["label"] == "Czas dla drużyny" and bare["player"] is None and bare["clock"] == "01:00"
    for bad in ("", "nieznany:host:7:1000", "goal:host:7", "goal:host:7:12a", "goal:host:7:1:2"):
        with pytest.raises(R.RuleError):
            R.event_snapshot(bad)
    with pytest.raises(R.RuleError):
        R.event_snapshot(KEY, {"type": "goal"})


def test_watek_zdarzenia_w_pokoju_i_push(env):
    async def go():
        thread = await event_thread(env, A, "Czy ta kara była za wcześnie?\nDruga linia")
        sent = list(env.sent)
        no_match = await raises(event_thread(env, A, "Bez meczu", match_id=None))
        bad_key = await raises(event_thread(env, A, "Zły klucz", key="cokolwiek"))
        room = await env.panel.match_room(PAIR, "m1", await env.actor(B))
        listed = (await env.library.list_threads(PAIR, target_kind="event", target_id=KEY, status="", actor=await env.actor(MENTOR)))["threads"]
        return thread, sent, no_match, bad_key, room, listed

    thread, sent, no_match, bad_key, room, listed = env.run(go)
    assert thread["target_kind"] == "event" and thread["target_id"] == KEY and thread["match_id"] == "m1"
    assert thread["title"] == "Czy ta kara była za wcześnie?"
    assert thread["event"]["label"] == "Kara 2 min - nr 7 Nowak (Goście)" and thread["event"]["clock"] == "12:34"
    assert thread["anchor"] == {"comment_id": thread["comments"][0]["id"], "video_id": "v1", "video_s": 1180.0}
    assert no_match == (422, "THREAD_TARGET") and bad_key == (422, "EVENT_KEY")
    in_room = {t["id"]: t for t in room["threads"]}[thread["id"]]
    assert in_room["event"]["kind"] == "penalty" and in_room["unread"] is True
    assert [t["id"] for t in listed] == [thread["id"]]
    assert sent and f"/mecz/m1?zakladka=watki&watek={thread['id']}" in sent[0]["link"]
    assert sent[0]["extra"] == {"eventKey": KEY, "videoS": "1180.00"}

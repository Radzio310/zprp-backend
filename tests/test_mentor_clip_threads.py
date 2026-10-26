"""Panel „Mentor" - wątki przy klipie (26.10.2026): wiele wątków, kotwica w czasie oryginału."""

from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text

from app import mentor_panel_rules as R
from app.mentor_panel_tables import MIGRATIONS
from tests.mentor_panel_support import JUDGES, MENTOR, PAIR, Env

A, B = JUDGES


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


async def raises(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.status_code, exc.detail.get("code") if isinstance(exc.detail, dict) else exc.detail
    raise AssertionError("oczekiwano odmowy")


async def new_clip(env, author=A, start=100, end=120):
    body = env.library.ClipBody(match_id="m1", video_id="v1", start_s=start, end_s=end, title="Faul")
    return await env.library.create_clip(PAIR, body, await env.actor(author))


async def clip_thread(env, clip_id, author, body, **over):
    L = env.library
    return await L.create_thread(PAIR, L.ThreadBody(target_kind="clip", target_id=clip_id, kind="question", body=body, **over),
                                 await env.actor(author))


# ─── Reguły (czyste funkcje) ────────────────────────────────────────────────


def test_przeliczenie_kotwicy_oryginal_klip():
    clip = {"video_id": "v1", "start_s": 100.0, "end_s": 120.0}
    assert R.clip_anchor_video_s(clip, clip_s=3.5) == 103.5
    assert R.clip_anchor_video_s(clip, video_s=110) == 110
    assert R.clip_anchor_video_s(clip, clip_s=-4) == 96  # poszerzenie 5 s w kinie
    with pytest.raises(R.RuleError):
        R.clip_anchor_video_s(clip, clip_s=40)
    assert R.clip_local_s(clip, "v1", 103.5) == 3.5
    assert R.clip_local_s(clip, "inne", 103.5) is None
    assert R.clip_anchor_inside(clip, 120) and not R.clip_anchor_inside(clip, 99)
    assert R.initials("Anna Maria Nowak") == "AM" and R.initials("") == "?"
    assert R.auto_thread_title("pierwszy", 0) == "Rozmowa"
    assert R.auto_thread_title("x" * 80 + "\ndruga linia", 2).endswith("...")


# ─── Trasy ──────────────────────────────────────────────────────────────────


def test_wiele_watkow_kotwice_i_przyciecie(env):
    async def go():
        clip = await new_clip(env)
        first = await clip_thread(env, clip["id"], A, "Bez kotwicy")
        pinned = await clip_thread(env, clip["id"], MENTOR, "Tu ręka w kole", clip_s=3.5)
        web = await clip_thread(env, clip["id"], A, "Z weba", video_id="v1", video_s=110)
        bad = await raises(clip_thread(env, clip["id"], A, "Za daleko", clip_s=60))
        reply = await env.library.add_comment(pinned["id"], env.library.CommentBody(body="Odpowiedź", clip_s=4), await env.actor(B))
        # Przycięcie klipu: kotwice zostają w oryginale, czas lokalny się przesuwa.
        await env.library.update_clip(clip["id"], env.library.ClipPatch(start_s=105, end_s=120), await env.actor(A))
        listed = (await env.library.list_threads(PAIR, target_kind="clip", target_id=clip["id"], status="", actor=await env.actor(B)))["threads"]
        clips = (await env.library.list_clips(PAIR, category="", match_id="", author="", q="", actor=await env.actor(B)))["clips"]
        room = await env.panel.match_room(PAIR, "m1", await env.actor(B))
        return clip, first, pinned, web, bad, reply, listed, clips, room

    clip, first, pinned, web, bad, reply, listed, clips, room = env.run(go)
    assert first["title"] == "Rozmowa" and first["anchor"] is None
    assert pinned["title"] == "Tu ręka w kole"
    assert pinned["anchor"]["video_s"] == 103.5 and pinned["anchor"]["clip_s"] == 3.5 and pinned["anchor"]["in_range"]
    assert pinned["comments"][0]["video_id"] == "v1"
    assert web["anchor"]["clip_s"] == 10
    assert bad == (422, "ANCHOR_RANGE")
    assert reply["video_s"] == 104 and reply["clip_s"] == 4
    after = {t["id"]: t for t in listed}[pinned["id"]]
    assert after["anchor"]["video_s"] == 103.5 and after["anchor"]["clip_s"] == -1.5 and not after["anchor"]["in_range"]
    assert after["clip"]["start_s"] == 105 and after["clip"]["id"] == clip["id"]
    summary = clips[0]["threads"]
    assert (summary["total"], summary["open"], summary["comments"]) == (3, 3, 4)
    assert [p["thread_id"] for p in summary["pins"]] == [pinned["id"], web["id"]]
    assert summary["pins"][0]["author"]["initials"] == "JM"
    # B odpisał tylko w wątku z kotwicą - pozostałe dwa są dla niego nowe.
    assert summary["unread"] == 2 and [p["unread"] for p in summary["pins"]] == [False, True]
    assert clips[0]["thread"]["id"] == first["id"] and clips[0]["thread"]["comments"] == 4
    in_room = {t["id"]: t for t in room["threads"]}
    assert in_room[pinned["id"]]["clip"]["id"] == clip["id"] and in_room[pinned["id"]]["anchor"]["video_s"] == 103.5


def test_push_watku_klipu_niesie_sekunde_i_link_kina(env):
    async def go():
        clip = await new_clip(env)
        thread = await clip_thread(env, clip["id"], MENTOR, "Spójrz", clip_s=2)
        sent = list(env.sent)
        env.sent.clear()
        await env.library.add_comment(thread["id"], env.library.CommentBody(body="Widzę", clip_s=6), await env.actor(A))
        return clip, thread, sent, list(env.sent)

    clip, thread, created, replied = env.run(go)
    assert created and all(s["clip_id"] == clip["id"] for s in created)
    assert created[0]["extra"] == {"clipS": "2.00", "videoS": "102.00"}
    assert f"/klipy?klip={clip['id']}&watek={thread['id']}" in created[0]["link"]
    assert replied[0]["extra"]["clipS"] == "6.00" and replied[0]["tag"] == f"mentor-thread-{thread['id']}"


def test_push_data_dodatki_jako_napisy():
    from app.mentor_panel_notify import push_data

    data = push_data("p1", clip_id="c1", extra={"clipS": "2.00", "pairId": "nie-nadpisuj"})
    assert data["clipS"] == "2.00" and data["pairId"] == "p1"


def test_migracja_stary_watek_to_rozmowa(env):
    async def go():
        clip = await new_clip(env)
        now = datetime.now(timezone.utc)
        await env.ins("mentor_threads", id="old", pair_id=PAIR, target_kind="clip", target_id=clip["id"], match_id="m1",
                      title=None, kind="question", status="open", created_by=A, created_at=now, updated_at=now)
        await env.ins("mentor_threads", id="mecz", pair_id=PAIR, target_kind="match", target_id="m1", match_id="m1",
                      title=None, kind="question", status="open", created_by=A, created_at=now, updated_at=now)
        stmt = next(m for m in MIGRATIONS if m.startswith("UPDATE mentor_threads"))
        await env.db.execute(text(stmt))
        T = env.T["mentor_threads"]
        return {r["id"]: r["title"] for r in await env.db.fetch_all(select(T.c.id, T.c.title))}

    titles = env.run(go)
    assert titles == {"old": "Rozmowa", "mecz": None}

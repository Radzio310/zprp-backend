"""Panel „Mentor" - powiadomienia wątków (obserwuj/wycisz, sklejanie) i kropki nowości."""

import pytest

from tests.mentor_panel_support import ADMIN, JUDGES, MENTOR, PAIR, Env

A, B = JUDGES


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


async def new_thread(env, author, body="Pytanie o akcję"):
    actor = await env.actor(author)
    return await env.library.create_thread(
        PAIR, env.library.ThreadBody(target_kind="pair", target_id=PAIR, kind="question", title="Akcja", body=body), actor)


async def reply(env, thread_id, author, body, mentions=()):
    actor = await env.actor(author)
    return await env.library.add_comment(thread_id, env.library.CommentBody(body=body, mentions=list(mentions)), actor)


def test_nowy_watek_idzie_do_wszystkich_poza_autorem(env):
    async def go():
        thread = await new_thread(env, MENTOR)
        return thread, env.sent[-1], sorted(r for s in env.sent for r in s["recipients"])

    thread, sent, everyone = env.run(go)
    assert everyone == sorted(JUDGES)
    assert sent["tag"] == f"mentor-thread-{thread['id']}" and sent["target"] == "thread"
    assert sent["thread_id"] == thread["id"] and sent["message_id"]


def test_odpowiedz_tylko_do_zaangazowanych_follow_i_mute(env):
    async def go():
        thread = await new_thread(env, MENTOR)
        tid = thread["id"]
        env.sent.clear()
        await reply(env, tid, A, "Moja odpowiedź")
        first = [(s["recipients"], s["tag"], s["target"]) for s in env.sent]
        env.sent.clear()
        # B nie pisał - dostaje dopiero po kliknięciu Obserwuj; mentor wycisza.
        await env.library.set_follow(tid, env.library.FollowBody(mode="follow"), await env.actor(B))
        await env.library.set_follow(tid, env.library.FollowBody(mode="mute"), await env.actor(MENTOR))
        await reply(env, tid, A, "Druga odpowiedź")
        second = [s["recipients"] for s in env.sent]
        mine = (await env.library.list_threads(PAIR, target_kind="", target_id="", status="", actor=await env.actor(B)))["threads"][0]["my_follow"]
        auto = (await env.library.list_threads(PAIR, target_kind="", target_id="", status="", actor=await env.actor(A)))["threads"][0]["my_follow"]
        bad = await env.library.set_follow(tid, env.library.FollowBody(mode="auto"), await env.actor(B))
        return first, second, mine, auto, bad

    first, second, mine, auto, bad = env.run(go)
    assert first[0][0] == [MENTOR] and first[0][2] == "message"
    assert second == [[B]]
    assert (mine, auto, bad["my_follow"]) == ("follow", "auto", "auto")


def test_tresc_zbiorcza_od_ostatniego_przeczytania(env):
    async def go():
        thread = await new_thread(env, MENTOR)
        tid = thread["id"]
        await reply(env, tid, A, "pierwsza")
        await reply(env, tid, B, "druga")
        env.sent.clear()
        await reply(env, tid, A, "trzecia")
        return env.sent[0]

    sent = env.run(go)
    assert sent["recipients"] == [MENTOR] or sent["recipients"] == [B]
    bodies = {s for s in [sent["body"]]}
    assert any(b.endswith(": trzecia") for b in bodies)
    assert any(" i 1 inna: trzecia" in b or b.startswith("Nowak: ") for b in bodies)


def test_kropki_watki_i_oceny(env):
    async def go():
        thread = await new_thread(env, MENTOR)
        tid = thread["id"]
        await reply(env, tid, MENTOR, "odpowiedź mentora")
        dash = await env.panel.dashboard(PAIR, await env.actor(A))
        cards = (await env.panel.list_pairs(await env.actor(A)))["pairs"]
        await env.library.thread_seen(tid, await env.actor(A))
        after = await env.panel.dashboard(PAIR, await env.actor(A))
        # Wysłana ocena mentora: kropka u sędziego pary, nie u autora; POST seen gasi.
        await env.ins("mentor_evaluations", id="ev1", match_id="m1", province="ŚLĄSKIE", pair_key="|".join(sorted(JUDGES)),
                      author_id=MENTOR, co_author_ids="[]", source="mentoring", status="published", sheet_json="{}",
                      published_json="{}", points=4.5, letter="B")
        room = await env.panel.match_room(PAIR, "m1", await env.actor(A))
        before_seen = (dash2 := await env.panel.dashboard(PAIR, await env.actor(A)))["new_sheets"]
        author_view = (await env.panel.dashboard(PAIR, await env.actor(MENTOR)))["new_sheets"]
        marked = await env.panel.sheet_seen(PAIR, "m1", await env.actor(A))
        gone = (await env.panel.dashboard(PAIR, await env.actor(A)))["new_sheets"]
        return dash, cards, after, room, before_seen, author_view, marked, gone

    dash, cards, after, room, before_seen, author_view, marked, gone = env.run(go)
    assert dash["unread_threads"] == 1 and cards[0]["unread_threads"] == 1 and cards[0]["new_sheets"] == 0
    assert after["unread_threads"] == 0
    assert room["match"]["unseen"]["sheet"] is True
    assert (before_seen, author_view, marked["marked"], gone) == (1, 0, 1, 0)


def test_push_data_kontrakt():
    from app.mentor_panel_notify import push_data

    data = push_data("p1", target="sheet", match_id="m1", sheet_id="ev1", tag="mentor-sheet-m1", quiet=True)
    assert data["kind"] == "mentor_panel" and data["pairId"] == "p1" and data["target"] == "sheet"
    assert data["tag"] == data["notificationTag"] == "mentor-sheet-m1"
    assert data["notificationColor"] == "#FF7A59" and data["notificationSilent"] == "1" and data["notificationPriority"] == "normal"


def test_fcm_tag_kolor_i_priorytet():
    from app.push.fcm import fcm_message_payload
    from app.mentor_panel_notify import push_data

    msg = fcm_message_payload("tok", "T", "B", push_data("p1", tag="mentor-thread-x", quiet=True, image="https://x/y.png"))["message"]
    android = msg["android"]
    assert android["collapse_key"] == "mentor-thread-x" and android["priority"] == "normal"
    assert android["notification"]["tag"] == "mentor-thread-x" and android["notification"]["color"] == "#FF7A59"
    assert android["notification"]["image"] == "https://x/y.png"
    assert msg["apns"]["headers"]["apns-collapse-id"] == "mentor-thread-x"

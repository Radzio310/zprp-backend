"""Panel „Mentor”: pokój meczu podpowiada transmisje z portalu (`suggested_streams`)."""

from datetime import datetime, timezone

import pytest

from tests.mentor_panel_support import MENTOR, PAIR, Env


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


def test_pokoj_meczu_podpowiada_transmisje(env):
    async def go():
        now = datetime.now(timezone.utc)
        base = {"match_id": "m1", "platform": "youtube", "state": "vod", "source": "rss", "first_seen_at": now,
                "last_seen_at": now, "hidden": False}
        rows = (
            ("abcdefghijk", "official", False),   # już dodany przez parę (v1) - pomijamy
            ("zyxwvutsrqp", "confirmed", False),  # podpowiedź
            ("possible000", "possible", False),   # za słaby
            ("hiddenvid00", "official", True),    # ukryty przez admina
        )
        for vid, level, hidden in rows:
            await env.ins("match_streams", **{**base, "url": f"https://www.youtube.com/watch?v={vid}", "video_id": vid,
                                              "confidence": level, "hidden": hidden, "title": f"Film {vid}"})
        return await env.panel.match_room(PAIR, "m1", await env.actor(MENTOR))

    room = env.run(go)
    assert [s["video_id"] for s in room["suggested_streams"]] == ["zyxwvutsrqp"]
    assert room["suggested_streams"][0]["embed_url"] == "https://www.youtube-nocookie.com/embed/zyxwvutsrqp"


def test_pokoj_meczu_bez_transmisji(env):
    async def go():
        return await env.panel.match_room(PAIR, "m1", await env.actor(MENTOR))

    assert env.run(go)["suggested_streams"] == []

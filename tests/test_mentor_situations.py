"""Sytuacje z arkuszy - wspólnie poprawiony czas w nagraniu (23.11.2026, sekcja 17)."""

import pytest

from tests.mentor_panel_support import JUDGES, MENTOR, PAIR, Env


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


def test_klucz_stabilny_i_unikalny(env):
    from app import mentor_panel_rules as R
    a = {"source": "delegate", "time": "12:30", "category": "Błędna", "description": "Faul w ataku", "author": "X"}
    b = dict(a, author="X + Y")
    assert R.situation_key(a) == R.situation_key(b)  # autor nie zmienia klucza
    rows = R.unique_situation_keys([dict(a, key=R.situation_key(a)), dict(a, key=R.situation_key(a))])
    assert rows[0]["key"] != rows[1]["key"] and rows[1]["key"].endswith("-2")


def test_poprawka_widoczna_w_pokoju_dla_wszystkich_i_cofniecie(env):
    async def go():
        a, m = await env.actor(JUDGES[0]), await env.actor(MENTOR)
        room = await env.panel.match_room(PAIR, "m1", a)
        sit = room["sheet_situations"][0]
        assert sit["key"].startswith("s_") and room["situation_times"] == []
        saved = await env.situations.set_time(PAIR, "m1", sit["key"], env.situations.TimeBody(video_id="v1", start_s=741.04, end_s=752.3), a)
        seen = await env.panel.match_room(PAIR, "m1", m)
        await env.situations.clear_time(PAIR, "m1", sit["key"], "v1", m)
        after = await env.panel.match_room(PAIR, "m1", a)
        return saved, seen, after

    saved, seen, after = env.run(go)
    assert saved["start_s"] == 741.0 and saved["end_s"] == 752.3 and saved["video_id"] == "v1"
    assert saved["updated_by"]["judge_id"] == JUDGES[0]
    assert seen["situation_times"][0]["key"] == saved["key"]
    assert after["situation_times"] == []


def test_zly_zakres_i_obca_para(env):
    async def go():
        a = await env.actor(JUDGES[0])
        key = (await env.panel.match_room(PAIR, "m1", a))["sheet_situations"][0]["key"]
        errs = []
        for body in (dict(start_s=50, end_s=40), dict(start_s=0, end_s=900)):
            try:
                await env.situations.set_time(PAIR, "m1", key, env.situations.TimeBody(video_id="v1", **body), a)
            except Exception as e:  # noqa: BLE001
                errs.append(getattr(e, "status_code", None))
        try:
            await env.situations.set_time(PAIR, "m1", "s_zzzz", env.situations.TimeBody(video_id="v1", start_s=1, end_s=2), a)
        except Exception as e:  # noqa: BLE001
            errs.append(getattr(e, "status_code", None))
        try:
            await env.situations.set_time(PAIR, "m1", key, env.situations.TimeBody(video_id="v1", start_s=1, end_s=2), await env.actor("999"))
        except Exception as e:  # noqa: BLE001
            errs.append(getattr(e, "status_code", None))
        return errs

    assert env.run(go)[:3] == [422, 422, 404]

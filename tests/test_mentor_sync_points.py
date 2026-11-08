"""Punkty kontrolne synchronizacji (08.11.2026): kształt, limit, podmiana po kluczu i zapis przez PATCH nagrania."""

import json
from datetime import datetime, timezone

from sqlalchemy import select
from starlette.requests import Request

from app.mentor_video_rules import MAX_SYNC_POINTS, clean_points, clean_sync
from tests.mentor_panel_support import JUDGES, PAIR, Env

A, _B = JUDGES
PAIR_KEY = "|".join(sorted(JUDGES))


def test_punkty_kontrolne_ksztalt_i_porzadek():
    raw = [
        {"key": "g2", "match_ms": 600000, "half": 1, "video_s": 712.34},
        {"key": "g9", "match_ms": 2100000, "half": 2, "video_s": 3000},
        {"key": "g1", "match_ms": 180000.4, "half": 1, "video_s": 290},
        {"key": "g2", "match_ms": 600000, "half": 1, "video_s": 715},  # ten sam klucz - ostatni wygrywa
        {"key": "", "match_ms": 1, "half": 1, "video_s": 1},
        {"key": "zla", "match_ms": 1, "half": 3, "video_s": 1},
        {"key": "ujemna", "match_ms": 1, "half": 1, "video_s": -1},
        "śmieć",
    ]
    assert clean_points(raw) == [
        {"key": "g1", "match_ms": 180000, "half": 1, "video_s": 290.0},
        {"key": "g2", "match_ms": 600000, "half": 1, "video_s": 715.0},
        {"key": "g9", "match_ms": 2100000, "half": 2, "video_s": 3000.0},
    ]
    assert clean_points(None) == [] and clean_points("x") == []
    many = [{"key": f"e{i}", "match_ms": i * 1000, "half": 1, "video_s": i} for i in range(MAX_SYNC_POINTS + 5)]
    assert len(clean_points(many)) == MAX_SYNC_POINTS
    assert clean_sync({"match_start_s": 10})["points"] == []


def test_zapis_punktow_przez_patch_nagrania_podmienia_liste(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)

    async def decode(_request, _token):
        return {"judge_id": A}

    monkeypatch.setattr(e.auth, "_decode_bearer", decode)

    async def go():
        now = datetime.now(timezone.utc)
        await e.ins("mentor_match_videos", id="yt", match_id="m1", pair_key=PAIR_KEY, url="https://youtu.be/abcdefghijk",
                    normalized_url="yt:abc", provider="youtube", added_by=A, created_at=now, kind="link",
                    sync_json=json.dumps({"match_start_s": 100, "second_half_s": 2000}))
        actor = await e.auth.mentor_actor(Request({"type": "http", "method": "PATCH", "headers": [(b"authorization", b"Bearer x")],
                                                    "query_string": b"", "path": "/"}))
        one = {"key": "g1", "match_ms": 180000, "half": 1, "video_s": 290}
        await e.media.update_video(PAIR, "m1", "yt", e.media.VideoPatch(sync={"points": [one]}), actor)
        two = [one, {"key": "g2", "match_ms": 600000, "half": 1, "video_s": 715}]
        out = await e.media.update_video(PAIR, "m1", "yt", e.media.VideoPatch(sync={"points": two}), actor)
        removed = await e.media.update_video(PAIR, "m1", "yt", e.media.VideoPatch(sync={"points": [two[1]]}), actor)
        T = e.T["mentor_match_videos"]
        row = await e.core.one(select(T).where(T.c.id == "yt"))
        return out, removed, json.loads(row["sync_json"])

    out, removed, stored = e.run(go)
    sync = out["sync"] if isinstance(out, dict) and "sync" in out else None
    if sync is not None:
        assert [p["key"] for p in sync["points"]] == ["g1", "g2"]
    assert [p["key"] for p in stored["points"]] == ["g2"]  # cała lista podmieniona, nie dopisana
    assert stored["match_start_s"] == 100 and stored["second_half_s"] == 2000  # gwizdki nietknięte

"""Panel „Mentor": nagrania meczu z YouTube - gotowe trafienia, „Poszukaj nagrania", „Nie ten".

Sieć to atrapa `net.fetch_text` (YouTube Data API odpowiada z pamięci), baza to SQLite z `mentor_panel_support`.
"""

import importlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from tests.mentor_panel_support import COMMITTEE, JUDGES, MENTOR, PAIR, Env

GOOD = "matchvid001"
TALK = "othervid002"


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    e.streams = importlib.import_module("app.mentor_panel_streams")
    e.store = importlib.import_module("app.streams.store")
    e.net = importlib.import_module("app.streams.net")
    e.calls = []
    e.search_items = [GOOD, TALK]
    monkeypatch.setenv("YOUTUBE_API_KEY", "test-key")

    async def fake_fetch(url, **kwargs):
        e.calls.append(url)
        if "/search?" in url:
            return json.dumps({"items": [{"id": {"kind": "youtube#video", "videoId": v}} for v in e.search_items]})
        if "/videos?" in url:
            published = (datetime.now(timezone.utc) - timedelta(days=3) + timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
            items = [
                {"id": GOOD, "snippet": {"title": "SPR Gliwice - KS Opole | I liga", "channelId": "UCnieznany0000000000000",
                                         "channelTitle": "Kibice Gliwice", "publishedAt": published, "liveBroadcastContent": "none",
                                         "thumbnails": {}}, "contentDetails": {"duration": "PT1H32M"}},
                {"id": TALK, "snippet": {"title": "Wywiad po meczu SPR Gliwice - KS Opole", "channelId": "UCnieznany0000000000000",
                                         "publishedAt": published, "liveBroadcastContent": "none", "thumbnails": {}},
                 "contentDetails": {"duration": "PT4M"}},
            ]
            return json.dumps({"items": items})
        return None

    monkeypatch.setattr(e.net, "fetch_text", fake_fetch)
    return e


def searches(env):
    return [c for c in env.calls if "/search?" in c]


async def search(env, judge_id, match_id="m1"):
    return await env.streams.search_streams(PAIR, match_id, await env.actor(judge_id))


def test_szukanie_znajduje_wspolny_wynik_bez_drugiego_wyszukiwania(env):
    async def go():
        first = await search(env, JUDGES[0])
        second = await search(env, MENTOR)  # mentor widzi ten sam wynik, limit nie spada
        room = await env.panel.match_room(PAIR, "m1", await env.actor(JUDGES[1]))
        return first, second, room

    first, second, room = env.run(go)
    assert [s["video_id"] for s in first["streams"]] == [GOOD]  # wywiad odrzucony regułami
    assert first["streams"][0]["confidence"] == "possible"
    assert first["cached"] is False and first["search"]["left"] == 2
    assert second["cached"] is True and [s["video_id"] for s in second["streams"]] == [GOOD]
    assert len(searches(env)) == 1
    assert "eventType" not in searches(env)[0] and "publishedAfter" in searches(env)[0]  # po meczu: zwykłe filmy
    assert [s["video_id"] for s in room["suggested_streams"]] == [GOOD]
    assert room["stream_search"]["reason"] == "FOUND"


def test_gotowe_trafienie_portalu_nie_zuzywa_limitu(env):
    async def go():
        now = datetime.now(timezone.utc)
        await env.ins("match_streams", match_id="m1", url="https://www.youtube.com/watch?v=portalvid01", platform="youtube",
                      video_id="portalvid01", state="vod", source="rss", confidence="official", hidden=False,
                      first_seen_at=now, last_seen_at=now, title="SPR Gliwice - KS Opole")
        return await search(env, JUDGES[0])

    out = env.run(go)
    assert out["cached"] is True and [s["video_id"] for s in out["streams"]] == ["portalvid01"]
    assert env.calls == []


def test_trzy_wyszukiwania_na_dobe_potem_jasny_komunikat(env):
    env.search_items = []

    async def go():
        for _ in range(3):
            out = await search(env, JUDGES[0])
            assert out["streams"] == [] and out["search"]["last_found"] == 0
        with pytest.raises(HTTPException) as exc:
            await search(env, MENTOR)
        room = await env.panel.match_room(PAIR, "m1", await env.actor(JUDGES[0]))
        return exc.value, room

    exc, room = env.run(go)
    assert exc.status_code == 429 and exc.detail["code"] == "STREAM_SEARCH_LIMIT"
    assert "Spróbuj jutro albo wklej link" in exc.detail["message"]
    assert room["stream_search"]["left"] == 0 and room["stream_search"]["allowed"] is False
    assert len(searches(env)) == 3


def test_wyczerpana_pula_mowi_wprost(env, monkeypatch):
    async def go():
        monkeypatch.setattr(env.store, "DAILY_SEARCHES", 0)
        with pytest.raises(HTTPException) as exc:
            await search(env, JUDGES[0])
        room = await env.panel.match_room(PAIR, "m1", await env.actor(JUDGES[0]))
        return exc.value, room

    exc, room = env.run(go)
    assert exc.status_code == 429 and exc.detail["code"] == "STREAM_SEARCH_QUOTA"
    assert "Spróbuj jutro albo wklej link" in exc.detail["message"]
    assert room["stream_search"]["reason"] == "QUOTA"
    assert env.calls == []


def test_przed_dniem_meczu_nie_szukamy(env):
    async def go():
        with pytest.raises(HTTPException) as exc:
            await search(env, JUDGES[0], "m2")
        return exc.value

    exc = env.run(go)
    assert exc.status_code == 409 and exc.detail["code"] == "STREAM_SEARCH_EARLY"


def test_komisja_nie_szuka_a_bez_klucza_jasna_odmowa(env, monkeypatch):
    async def go():
        with pytest.raises(HTTPException) as committee:
            await search(env, COMMITTEE)
        monkeypatch.delenv("YOUTUBE_API_KEY")
        with pytest.raises(HTTPException) as off:
            await search(env, JUDGES[0])
        return committee.value, off.value

    committee, off = env.run(go)
    assert committee.status_code == 403
    assert off.status_code == 503 and off.detail["code"] == "STREAM_SEARCH_OFF"


def test_nie_ten_chowa_film_tylko_w_parze(env):
    async def go():
        await search(env, JUDGES[0])
        after = await env.streams.reject_stream(PAIR, "m1", env.streams.RejectBody(video_id=GOOD), await env.actor(MENTOR))
        room = await env.panel.match_room(PAIR, "m1", await env.actor(JUDGES[0]))
        public = await env.store.streams_for(["m1"])
        return after, room, public

    after, room, public = env.run(go)
    assert after["streams"] == [] and after["search"]["allowed"] is True and after["search"]["left"] == 2
    assert room["suggested_streams"] == []
    assert [r["video_id"] for r in public] == [GOOD]  # portal dalej ma nagranie


def test_okno_wyszukiwania():
    from app import mentor_panel_streams as S

    kickoff = datetime(2026, 10, 24, 16, 0, tzinfo=timezone.utc)  # 18:00 w Warszawie
    assert S.search_window(kickoff, True, kickoff - timedelta(days=1)) is None
    assert S.search_window(kickoff, True, kickoff - timedelta(hours=3))["event"] == "upcoming"
    assert S.search_window(kickoff, True, kickoff + timedelta(minutes=40))["event"] == "live"
    late = S.search_window(kickoff, True, kickoff + timedelta(hours=5))
    assert late["event"] is None and late["published_after"] == "2026-10-24T14:00:00Z"
    assert S.search_window(kickoff, False, kickoff)["event"] is None  # bez godziny: zwykłe filmy


def test_mecz_z_filmem_pokazuje_go_jako_juz_w_meczu_bez_zuzycia_puli(env):
    async def go():
        now = datetime.now(timezone.utc)
        await search(env, JUDGES[0])  # pierwsze szukanie znajduje GOOD (jedno wyszukiwanie)
        env.calls.clear()
        await env.ins("mentor_match_videos", id="vy", match_id="m1", pair_key="|".join(sorted(JUDGES)),
                      url=f"https://www.youtube.com/watch?v={GOOD}", normalized_url=f"https://www.youtube.com/watch?v={GOOD}",
                      provider="youtube", added_by=JUDGES[0], created_at=now, kind="link", title="LCM: AZS AGH - Gwardia")
        return await search(env, JUDGES[0])

    out = env.run(go)
    assert out["streams"] == [] and out["cached"] is True
    assert GOOD in [v["video_id"] for v in out["in_match"]]
    assert env.calls == []  # pula YouTube nietknięta
    assert out["search"]["left"] == 2

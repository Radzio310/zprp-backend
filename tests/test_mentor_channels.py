"""Kanał YouTube pary (18.11.2026): przegląd, propozycje, „Dodaj”, połówki sklejane na serwerze, odrzucenie, ponowny przegląd."""

import os
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from tests.mentor_panel_support import JUDGES, PAIR, Env


@pytest.fixture
def d(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    day = (datetime.now() - timedelta(days=3)).strftime("%d.%m.%Y")
    videos = [
        {"video_id": "aaaaaaaaaa1", "title": f"{day} - SPR Gliwice vs KS Opole (I połowa)", "duration_s": 1900},
        {"video_id": "aaaaaaaaaa2", "title": f"{day} - SPR Gliwice vs KS Opole (II połowa)", "duration_s": 1950},
        {"video_id": "aaaaaaaaaa3", "title": "UKS Mali - MKS Młodzi", "duration_s": 3600},
        {"video_id": "aaaaaaaaaa4", "title": "Jak sędziować faule w ataku", "duration_s": 600},
        {"video_id": "aaaaaaaaaa5", "title": f"{day} A vs B", "duration_s": 3500},  # mecz innej pary (m5) - nie nasz
    ]
    e.yt_videos = videos

    async def fake_read(ref):
        return {"channel_id": "UCkyXYml9ku9IGnFmiScUIKw", "title": "Referee", "handle": "@referee1710", "thumbnail_url": None,
                "videos": list(e.yt_videos), "source": "page", "complete": True}

    monkeypatch.setattr(e.channels, "read_channel", fake_read)
    monkeypatch.setattr(e.media, "storage_config", lambda: {"endpoint": "x", "region": "auto", "bucket": "b", "access_key": "k",
                                                            "secret_key": "s", "prefix": "mentor"})
    return e


async def _actor(d):
    return await d.actor(JUDGES[0])


def test_przeglad_kanalu_proponuje_mecze_pary(d):
    async def go():
        actor = await _actor(d)
        out = await d.channels.add_channel(PAIR, d.channels.ChannelBody(url="https://www.youtube.com/@referee1710"), actor)
        return out

    out = d.run(go)
    by = {v["video_id"]: v for v in out["videos"]}
    assert by["aaaaaaaaaa1"]["match_id"] == "m1" and by["aaaaaaaaaa1"]["confidence"] == "sure"
    assert by["aaaaaaaaaa1"]["half_of"] == "m1" and by["aaaaaaaaaa2"]["half_of"] == "m1"
    assert by["aaaaaaaaaa3"]["match_id"] == "m2" and by["aaaaaaaaaa3"]["confidence"] == "likely"
    assert by["aaaaaaaaaa4"]["match_id"] is None
    assert by["aaaaaaaaaa5"]["match_id"] is None  # tylko mecze pary
    assert out["channel"]["title"] == "Referee" and out["channel"]["counts"]["sure"] == 2
    assert by["aaaaaaaaaa1"]["match"]["home"]["name"] == "SPR Gliwice"


def test_dodaj_polowki_to_jedno_nagranie_sklejane_a_pojedynczy_film_to_link(d, monkeypatch):
    async def go():
        actor = await _actor(d)
        out = await d.channels.add_channel(PAIR, d.channels.ChannelBody(url="@referee1710"), actor)
        cid = out["channel"]["id"]
        out = await d.channels.accept(cid, d.channels.AcceptBody(video_ids=["aaaaaaaaaa1", "aaaaaaaaaa2", "aaaaaaaaaa3"]), actor)
        uploads = await d.core.rows(select(d.T["mentor_uploads"]).where(d.T["mentor_uploads"].c.origin == "youtube_part"))
        links = await d.core.rows(select(d.T["mentor_match_videos"]).where(d.T["mentor_match_videos"].c.match_id == "m2"))
        # Worker: obie połówki „pobrane” i położone w magazynie -> jedno nagranie w kolejce sklejania.
        from app import mentor_youtube_copy as YC

        def fake_download(upload_id, url, folder, proxy, cookiefile):
            path = os.path.join(folder, "source.mp4")
            open(path, "wb").write(b"x" * 10)
            return {"path": path, "info": {"title": "t"}}

        monkeypatch.setattr(YC, "_download", fake_download)
        monkeypatch.setattr(d.media, "put_file", lambda path, key, ct: 10)
        while await d.channels.process_next():
            pass
        after = await d.core.rows(select(d.T["mentor_uploads"]).where(d.T["mentor_uploads"].c.origin == "youtube_part"))
        videos = await d.core.rows(select(d.T["mentor_match_videos"]).where(d.T["mentor_match_videos"].c.match_id == "m1"))
        again = await d.channels.rescan(cid, actor)
        return out, uploads, links, after, videos, again

    out, uploads, links, after, videos, again = d.run(go)
    by = {v["video_id"]: v for v in out["videos"]}
    assert by["aaaaaaaaaa1"]["state"] == "added" and by["aaaaaaaaaa1"]["group_id"] == by["aaaaaaaaaa2"]["group_id"]
    assert sorted((u["group_index"], u["status"]) for u in uploads) == [(0, "downloading"), (1, "downloading")]
    assert uploads[0]["source_url"].startswith("https://www.youtube.com/watch?v=")
    assert len(links) == 1 and "aaaaaaaaaa3" in links[0]["normalized_url"]
    assert {u["status"] for u in after} == {"processing"}
    assert len([v for v in videos if v["kind"] == "upload"]) == 1
    assert "(obie połowy)" in [v for v in videos if v["kind"] == "upload"][0]["title"]
    # Ponowny przegląd nie cofa decyzji.
    assert {v["video_id"]: v["state"] for v in again["videos"]}["aaaaaaaaaa3"] == "added"


def test_odrzucenie_i_przywrocenie(d):
    async def go():
        actor = await _actor(d)
        out = await d.channels.add_channel(PAIR, d.channels.ChannelBody(url="@referee1710"), actor)
        cid = out["channel"]["id"]
        gone = await d.channels.dismiss(cid, d.channels.DismissBody(video_ids=["aaaaaaaaaa3"]), actor)
        back = await d.channels.dismiss(cid, d.channels.DismissBody(video_ids=["aaaaaaaaaa3"], undo=True), actor)
        listed = await d.channels.list_channels(PAIR, actor)
        await d.channels.remove_channel(cid, actor)
        empty = await d.channels.list_channels(PAIR, actor)
        return gone, back, listed, empty

    gone, back, listed, empty = d.run(go)
    assert {v["video_id"]: v["state"] for v in gone["videos"]}["aaaaaaaaaa3"] == "dismissed"
    assert {v["video_id"]: v["state"] for v in back["videos"]}["aaaaaaaaaa3"] == "new"
    assert listed["channels"][0]["counts"]["total"] == 5
    assert empty["channels"] == []


def test_zly_link_i_strona_kanalu(d):
    from fastapi import HTTPException

    async def go():
        actor = await _actor(d)
        with pytest.raises(HTTPException):
            await d.channels.add_channel(PAIR, d.channels.ChannelBody(url="https://example.com/x"), actor)

    d.run(go)
    html = open(os.path.join(os.path.dirname(__file__), "fixtures", "yt_channel_page.html"), encoding="utf-8").read() \
        if os.path.exists(os.path.join(os.path.dirname(__file__), "fixtures", "yt_channel_page.html")) else None
    if html:
        page = d.channels.parse_channel_page(html)
        assert page["channel_id"] == "UCkyXYml9ku9IGnFmiScUIKw" and page["handle"] == "@referee1710" and page["title"] == "Referee"
        assert [v["title"][:10] for v in page["videos"]] == ["28.02.2026", "28.02.2026", "22.11.2025"] and page["more"] is False

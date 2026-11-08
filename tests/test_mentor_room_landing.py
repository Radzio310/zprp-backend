"""Pokój meczu (08.11.2026): nagranie w odpowiedzi stanu wgrywania (pokój wkłada je sam, bez odświeżania strony),
gwizdek przed początkiem nagrania (ujemna kotwica) i podpowiedzi transmisji bez filmów, których YouTube już nie podaje."""

import importlib
from datetime import datetime, timezone

import pytest
from starlette.requests import Request

from app.mentor_video_rules import MAX_LEAD_SECONDS, clean_sync
from tests.mentor_panel_support import JUDGES, PAIR, Env

A, B = JUDGES
PAIR_KEY = "|".join(sorted(JUDGES))


def test_gwizdek_przed_poczatkiem_nagrania():
    assert clean_sync({"match_start_s": -9, "second_half_s": 1990})["match_start_s"] == -9
    assert clean_sync({"match_start_s": -9.4})["match_start_s"] == -9
    assert clean_sync({"second_half_s": -120})["second_half_s"] == -120  # nagranie zaczęte w II połowie
    assert clean_sync({"match_start_s": -(MAX_LEAD_SECONDS + 1)})["match_start_s"] is None
    assert clean_sync({"match_start_s": 0})["match_start_s"] == 0


@pytest.fixture
def d(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    e.mp = monkeypatch
    monkeypatch.setattr(e.media, "storage_ready", lambda: True)
    monkeypatch.setattr(e.media, "presign_get", lambda key, expires=0, filename=None: f"https://r2/{key}" if key else None)
    return e


async def actor_for(e, judge=A):
    async def decode(_request, _token):
        return {"judge_id": judge}

    e.mp.setattr(e.auth, "_decode_bearer", decode)
    r = Request({"type": "http", "method": "GET", "headers": [(b"authorization", b"Bearer x")], "query_string": b"", "path": "/"})
    return await e.auth.mentor_actor(r)


async def seed_upload(e, status, video=True):
    now = datetime.now(timezone.utc)
    await e.ins("mentor_uploads", id="u1", pair_id=PAIR, match_id="m1", video_id="vf" if video else None, uploader_id=A,
                filename="mecz.mp4", size=10, r2_key="mentor/orig.mp4", status=status,
                play_key="mentor/play.mp4" if status == "ready" else None, created_at=now)
    if video:
        await e.ins("mentor_match_videos", id="vf", match_id="m1", pair_key=PAIR_KEY, url="upload:u1", normalized_url="upload:u1",
                    provider="upload", added_by=A, created_at=now, kind="upload", upload_id="u1", title="mecz.mp4")


@pytest.mark.parametrize("status,playable", [("processing", False), ("ready", True)])
def test_stan_wgrywania_niesie_nagranie(d, status, playable):
    async def go():
        await seed_upload(d, status)
        return await d.media.upload_status(PAIR, "m1", "u1", await actor_for(d))

    out = d.run(go)
    assert out["video_id"] == "vf" and out["video"]["id"] == "vf"
    assert out["video"]["upload_status"] == status and out["video"]["playable"] is playable
    if playable:
        assert out["video"]["play_url"] == "https://r2/mentor/play.mp4"


def test_stan_wgrywania_bez_nagrania_albo_w_trakcie_wysylki(d):
    async def go():
        await seed_upload(d, "uploading", video=False)
        return await d.media.upload_status(PAIR, "m1", "u1", await actor_for(d))

    out = d.run(go)
    assert out["video"] is None and out["status"] == "uploading"


def test_dostepnosc_filmu_z_kodu_oembed():
    streams = importlib.import_module("app.mentor_panel_streams")
    assert streams.availability_from_status(200) is True
    for code in (401, 403, 404):
        assert streams.availability_from_status(code) is False
    assert streams.availability_from_status(500) is None and streams.availability_from_status(429) is None


def test_niedostepny_film_znika_z_podpowiedzi_a_wynik_jest_pamietany(d):
    calls = []

    async def probe(video_id):
        calls.append(video_id)
        return {"prywatny01a": False, "publiczny1a": True}.get(video_id)

    d.mp.setattr(d.panel_streams, "_probe", probe)
    d.mp.setattr(d.panel_streams, "_availability", {})
    rows = [{"video_id": "prywatny01a"}, {"video_id": "publiczny1a"}, {"video_id": "niewiadomo1"}]

    async def go():
        first = await d.panel_streams.available_rows(rows)
        again = await d.panel_streams.available_rows(rows)
        return first, again

    first, again = d.run(go, seed=False)
    assert [r["video_id"] for r in first] == ["publiczny1a", "niewiadomo1"]  # awaria/nie wiadomo = zostaje
    assert [r["video_id"] for r in again] == ["publiczny1a", "niewiadomo1"]
    assert calls.count("prywatny01a") == 1 and calls.count("publiczny1a") == 1 and calls.count("niewiadomo1") == 2

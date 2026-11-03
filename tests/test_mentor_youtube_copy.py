"""Kopia filmu YouTube na serwerze: reguły (format, postęp, błędy, proxy) i przebieg (zamówienie, worker, zapas przez
proxy, błąd i ponowienie, usunięcie, MP4 klipu z kopii, kosz). Atrapy yt-dlp, ffmpeg i R2 - bez sieci."""

import json
import os
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from starlette.requests import Request

from app import mentor_youtube_copy_rules as Y
from tests.mentor_panel_support import JUDGES, PAIR, Env

A, B = JUDGES
PAIR_KEY = "|".join(sorted(JUDGES))
YT_URL = "https://www.youtube.com/watch?v=abcdefghijk"


# ─── Reguły ─────────────────────────────────────────────────────────────────


def test_klasyfikacja_bledow_yt_dlp():
    assert Y.classify("ERROR: [youtube] x: Sign in to confirm you’re not a bot.")[0] == "BLOCKED"
    assert Y.classify("HTTP Error 429: Too Many Requests", via_proxy=True)[0] == "BLOCKED_PROXY"
    assert Y.classify("Sign in to confirm your age. This video may be inappropriate for some users.")[0] == "AGE"
    assert Y.classify("ERROR: Private video. Sign in if you've been granted access")[0] == "PRIVATE"
    assert Y.classify("Video unavailable. This video has been removed by the uploader")[0] == "GONE"
    assert Y.classify("Join this channel to get access to members-only content")[0] == "MEMBERS"
    assert Y.classify("This live event will begin in 3 hours.")[0] == "UPCOMING"
    code, message = Y.classify("cos zupelnie innego")
    assert code == "FAILED" and message == Y.MESSAGES["FAILED"]
    assert Y.retry_through_proxy("BLOCKED") and not Y.retry_through_proxy("PRIVATE")


def test_sprawdzenie_przed_pobraniem():
    for info, code in (({"is_live": True}, "LIVE"), ({"live_status": "is_upcoming"}, "UPCOMING"),
                       ({"live_status": "post_live"}, "POST_LIVE"), ({"duration": 6 * 3600}, "TOO_LONG"),
                       ({"duration": 5400, "requested_formats": [{"format_id": "137", "filesize": 13 * 1024 ** 3}]}, "TOO_BIG")):
        with pytest.raises(Y.CopyError) as caught:
            Y.check_info(info)
        assert caught.value.code == code
    ok = {"duration": 5400, "live_status": "was_live", "requested_formats": [{"format_id": "137", "filesize": 2_000_000_000, "height": 1080},
                                                                              {"format_id": "140", "filesize_approx": 90_000_000}]}
    Y.check_info(ok)
    assert Y.expected_bytes(ok) == 2_090_000_000 and Y.chosen_height(ok) == 1080


def test_postep_dwoch_strumieni_nie_cofa_paska():
    expected = [("137", 900.0), ("140", 100.0)]
    assert Y.download_fraction({"137": (450, 900)}, expected) == 0.45
    # Obraz skończony, dźwięk się zaczyna: pasek idzie dalej, nie wraca do zera.
    assert Y.download_fraction({"137": (900, 900), "140": (10, 100)}, expected) == pytest.approx(0.91)
    assert Y.download_fraction({}, []) is None
    assert Y.overall("downloading", 0.5) == pytest.approx(0.44)
    assert Y.overall("uploading", 1.0) == 1.0 and Y.overall("queued", None) == 0.0


def test_proxy_dopiero_po_blokadzie_ciasteczka_i_adres(monkeypatch):
    monkeypatch.delenv("MENTOR_YT_PROXY", raising=False)
    assert Y.attempts() == (None,)
    monkeypatch.setenv("MENTOR_YT_PROXY", "http://u:p@proxy:8000")
    assert Y.attempts() == (None, "http://u:p@proxy:8000")
    monkeypatch.setenv("MENTOR_YT_PROXY_ALWAYS", "1")
    assert Y.attempts() == ("http://u:p@proxy:8000",)
    netscape = "# Netscape HTTP Cookie File\n.youtube.com\tTRUE\t/\tTRUE\t0\tSID\tx"
    import base64

    assert Y.cookies_text(netscape).startswith("# Netscape")
    assert "\tSID\t" in Y.cookies_text(base64.b64encode(netscape.encode()).decode())
    assert Y.cookies_text("nie-base64!!") is None and Y.cookies_text("") is None
    assert Y.watch_url("https://youtu.be/abcdefghijk?t=30") == YT_URL
    assert Y.watch_url("https://www.youtube.com/live/abcdefghijk") == YT_URL
    assert Y.watch_url("https://vimeo.com/1") is None
    assert Y.safe_filename('Mecz: A / B "finał"') == "Mecz A B finał.mp4"


def test_ksztalt_pola_mirror():
    base = {"id": "u", "uploader_id": A, "size": 0, "created_at": None}
    working = Y.mirror_shape({**base, "status": "downloading"}, {"phase": "downloading", "progress": 0.4, "speed_bps": 5_000_000}, None, None)
    assert working["status"] == "working" and working["phase"] == "downloading" and working["progress"] == 0.4
    queued = Y.mirror_shape({**base, "status": "downloading"}, None, None, None)
    assert queued["phase"] == "queued" and queued["progress"] is None
    ready = Y.mirror_shape({**base, "status": "ready", "size": 2048, "height": 1080}, None, "https://r2/play", "https://r2/poster")
    assert ready["status"] == "ready" and ready["play_url"] == "https://r2/play" and ready["progress"] == 1.0 and ready["phase"] is None
    failed = Y.mirror_shape({**base, "status": "failed", "error": "Ten film jest prywatny"}, None, None, None)
    assert failed["status"] == "failed" and failed["error"] and failed["play_url"] is None
    assert Y.mirror_shape(None, None, None, None) is None


# ─── Przebieg ───────────────────────────────────────────────────────────────


@pytest.fixture
def d(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    import importlib

    e.copy = importlib.import_module("app.mentor_youtube_copy")
    e.mp = monkeypatch
    e.calls = []
    e.forgotten = []
    e.uploaded = []
    monkeypatch.delenv("MENTOR_YT_PROXY", raising=False)
    monkeypatch.delenv("MENTOR_YT_COPY", raising=False)
    monkeypatch.setenv("MENTOR_MEDIA_TMP", str(tmp_path / "work"))
    monkeypatch.setattr(e.media, "storage_ready", lambda: True)
    monkeypatch.setattr(e.media, "storage_config", lambda: {"endpoint": "x", "region": "auto", "bucket": "b", "access_key": "k",
                                                            "secret_key": "s", "prefix": "mentor"})
    monkeypatch.setattr(e.media, "presign_get", lambda key, expires=0, filename=None: f"https://r2/{key}" if key else None)
    monkeypatch.setattr(e.media, "forget_object", lambda *keys: e.forgotten.extend(k for k in keys if k))
    monkeypatch.setattr(e.copy, "_tool", True)

    def fake_download(upload_id, url, folder, proxy, cookiefile):
        e.calls.append({"url": url, "proxy": proxy})
        if e.download_errors:
            raise e.download_errors.pop(0)
        path = os.path.join(folder, "source.mp4")
        with open(path, "wb") as handle:
            handle.write(b"x" * 64)
        return {"path": path, "info": {"title": "LCM/32 Zagłębie - Śląsk", "duration": 5400}}

    def fake_put(upload_id, path, key):
        e.uploaded.append(key)
        return 2_000_000_000

    def fake_run_put(path, key, content_type):
        e.uploaded.append(key)
        return 10

    def fake_remux(source, target):
        with open(target, "wb") as handle:
            handle.write(b"mp4")

    e.download_errors = []
    monkeypatch.setattr(e.copy, "_download", fake_download)
    monkeypatch.setattr(e.copy, "_codecs", lambda path: {"video": "h264", "audio": "aac", "height": 1080, "width": 1920, "duration_s": 5400.0})
    monkeypatch.setattr(e.copy, "_remux", fake_remux)
    monkeypatch.setattr(e.copy, "_put", fake_put)
    monkeypatch.setattr(e.media, "put_file", fake_run_put)
    monkeypatch.setattr(e.media, "poster", lambda source, target, duration: open(target, "wb").close() or True)
    return e


async def actor_for(e, judge=A):
    async def decode(_request, _token):
        return {"judge_id": judge}

    e.mp.setattr(e.auth, "_decode_bearer", decode)
    r = Request({"type": "http", "method": "POST", "headers": [(b"authorization", b"Bearer x")], "query_string": b"", "path": "/"})
    return await e.auth.mentor_actor(r)


async def seed(e, url=YT_URL, provider="youtube", video_id="yt"):
    now = datetime.now(timezone.utc)
    await e.ins("mentor_match_videos", id=video_id, match_id="m1", pair_key=PAIR_KEY, url=url, normalized_url=url,
                provider=provider, added_by=A, created_at=now, kind="link", title="Transmisja",
                sync_json=json.dumps({"match_start_s": 100, "second_half_s": 2000}))


async def video_row(e, video_id="yt"):
    T = e.T["mentor_match_videos"]
    return await e.core.one(select(T).where(T.c.id == video_id))


async def upload_row(e, upload_id):
    T = e.T["mentor_uploads"]
    return await e.core.one(select(T).where(T.c.id == upload_id))


async def failure(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.status_code, exc.detail
    return None


def test_kopia_od_zamowienia_do_gotowej_drugiej_opcji_odtwarzania(d):
    async def go():
        await seed(d)
        actor = await actor_for(d)
        started = await d.copy.start_copy(PAIR, "m1", "yt", actor)
        again = await d.copy.start_copy(PAIR, "m1", "yt", actor)
        row = await video_row(d)
        polled = await d.copy.copy_status(PAIR, "m1", "yt", actor)
        worked = await d.copy.process_next()
        idle = await d.copy.process_next()
        up = await upload_row(d, row["mirror_upload_id"])
        ctx = await d.core.pair_context(PAIR, actor)
        listed, _ = await d.media.video_list(ctx, "m1")
        return started, again, row, polled, worked, idle, up, listed

    started, again, row, polled, worked, idle, up, listed = d.run(go)
    assert started["can_copy"] is True and started["mirror"]["status"] == "working" and started["mirror"]["phase"] == "queued"
    assert again["mirror"]["id"] == started["mirror"]["id"]  # drugie kliknięcie nie zakłada drugiej kopii
    assert polled["mirror"]["status"] == "working"
    assert worked is True and idle is False
    assert d.calls == [{"url": YT_URL, "proxy": None}]
    assert up["status"] == "ready" and up["origin"] == "youtube" and up["source_url"] == YT_URL and up["height"] == 1080
    assert up["play_key"].endswith("/play.mp4") and up["play_key"] in d.uploaded and up["filename"] == "LCM 32 Zagłębie - Śląsk.mp4"
    video = next(v for v in listed if v["id"] == "yt")
    assert video["provider"] == "youtube" and "abcdefghijk" in video["url"]  # YouTube zostaje
    assert video["mirror"]["status"] == "ready" and video["mirror"]["play_url"] == f"https://r2/{up['play_key']}"
    assert video["mirror"]["poster_url"] and video["mirror"]["size"] == 2_000_000_000
    # 03.11: gotowa kopia to osobne nagranie meczu, z synchronizacją filmu i nazwą „... · kopia 1080p”.
    copy = next(v for v in listed if v.get("copy_of") == "yt")
    assert video["mirror"]["video_id"] == copy["id"] == up["video_id"]
    assert copy["kind"] == "upload" and copy["copy_of"] == "yt" and copy["playable"] is True
    assert copy["title"] == "Transmisja · kopia 1080p" and copy["sync"]["match_start_s"] == 100
    assert copy["can_delete"] is True and copy["mirror"] is None and sum(1 for v in listed if v.get("copy_of")) == 1


def test_blokada_prosto_z_serwera_druga_proba_przez_proxy(d):
    d.mp.setenv("MENTOR_YT_PROXY", "http://u:p@proxy:8000")
    d.download_errors.append(Y.CopyError("BLOCKED", Y.MESSAGES["BLOCKED"]))

    async def go():
        await seed(d)
        actor = await actor_for(d)
        await d.copy.start_copy(PAIR, "m1", "yt", actor)
        await d.copy.process_next()
        row = await video_row(d)
        return await upload_row(d, row["mirror_upload_id"])

    up = d.run(go)
    assert [c["proxy"] for c in d.calls] == [None, "http://u:p@proxy:8000"]
    assert up["status"] == "ready"


def test_blad_bez_proxy_czytelny_komunikat_i_ponowienie(d):
    d.download_errors.append(Y.CopyError("PRIVATE", Y.MESSAGES["PRIVATE"]))

    async def go():
        await seed(d)
        actor = await actor_for(d)
        await d.copy.start_copy(PAIR, "m1", "yt", actor)
        await d.copy.process_next()
        failed = await d.copy.copy_status(PAIR, "m1", "yt", actor)
        retried = await d.copy.start_copy(PAIR, "m1", "yt", actor)
        await d.copy.process_next()
        done = await d.copy.copy_status(PAIR, "m1", "yt", actor)
        return failed, retried, done

    failed, retried, done = d.run(go)
    assert len(d.calls) == 2 and d.calls[0]["proxy"] is None
    assert failed["mirror"]["status"] == "failed" and failed["mirror"]["error"] == Y.MESSAGES["PRIVATE"]
    assert retried["mirror"]["status"] == "working" and retried["mirror"]["id"] == failed["mirror"]["id"]
    assert done["mirror"]["status"] == "ready"


def test_anulowanie_kopii_w_toku_sprzata(d):
    async def go():
        await seed(d)
        actor = await actor_for(d)
        await d.copy.start_copy(PAIR, "m1", "yt", actor)
        before = await video_row(d)
        removed = await d.copy.remove_copy(PAIR, "m1", "yt", actor)
        up = await upload_row(d, before["mirror_upload_id"])
        worked = await d.copy.process_next()
        return removed, up, await video_row(d), worked

    removed, up, after, worked = d.run(go)
    assert removed["removed"] is True and removed["trashed"] is False and removed["video"]["mirror"] is None
    assert after["mirror_upload_id"] is None and up["status"] == "removed" and worked is False


async def _copy_id(d, actor):
    ctx = await d.core.pair_context(PAIR, actor)
    listed, _ = await d.media.video_list(ctx, "m1")
    return next(v["id"] for v in listed if v.get("copy_of") == "yt")


def test_kopia_jak_kazde_nagranie_kosz_przywrocenie_nazwa_bez_dublowania(d):
    async def go():
        await seed(d)
        actor = await actor_for(d)
        await d.copy.start_copy(PAIR, "m1", "yt", actor)
        await d.copy.process_next()
        ctx = await d.core.pair_context(PAIR, actor)
        copy_id = await _copy_id(d, actor)
        renamed = await d.media.update_video(PAIR, "m1", copy_id, d.media.VideoPatch(title="Mecz z Zabrza (serwer)"), actor)
        impact = await d.media.video_delete_impact(PAIR, "m1", copy_id, actor)
        trashed = await d.media.delete_video(PAIR, "m1", copy_id, actor)
        in_trash, _ = await d.media.video_list(ctx, "m1")
        again = await d.copy.start_copy(PAIR, "m1", "yt", actor)  # kopia w koszu: wraca z kosza, nie powstaje druga
        back, _ = await d.media.video_list(ctx, "m1")
        await d.media.delete_video(PAIR, "m1", copy_id, actor)
        restored = await d.media.restore_video(PAIR, "m1", copy_id, actor)
        # Usunięcie filmu YouTube (kosz, potem na zawsze) nie rusza kopii.
        await d.media.delete_video(PAIR, "m1", "yt", actor)
        await d.media.purge_video(PAIR, "m1", "yt", actor)
        alone, _ = await d.media.video_list(ctx, "m1")
        up = await upload_row(d, (await video_row(d, copy_id))["upload_id"])
        return copy_id, renamed, impact, trashed, in_trash, again, back, restored, alone, up

    copy_id, renamed, impact, trashed, in_trash, again, back, restored, alone, up = d.run(go)
    assert renamed["title"] == "Mecz z Zabrza (serwer)"
    assert impact["restorable"] is True and trashed["trashed"] is True
    assert copy_id not in [v["id"] for v in in_trash] and "yt" in [v["id"] for v in in_trash]
    assert again["mirror"]["video_id"] == copy_id and {"yt", copy_id} <= {v["id"] for v in back} and sum(1 for v in back if v.get("copy_of")) == 1
    assert restored["video"]["id"] == copy_id and len(d.calls) == 1
    mine = [v for v in alone if v["id"] in (copy_id, "yt")]
    assert [v["id"] for v in mine] == [copy_id] and mine[0]["playable"] is True
    assert up["status"] == "ready" and not any(k.endswith("/play.mp4") for k in d.forgotten)


def test_usuniecie_kopii_na_zawsze_kasuje_pliki_i_pozwala_na_nowa(d):
    async def go():
        await seed(d)
        actor = await actor_for(d)
        await d.copy.start_copy(PAIR, "m1", "yt", actor)
        await d.copy.process_next()
        up_id = (await video_row(d))["mirror_upload_id"]
        copy_id = (await upload_row(d, up_id))["video_id"]
        trashed = await d.copy.remove_copy(PAIR, "m1", "yt", actor)  # stara trasa: gotowa kopia idzie do kosza
        await d.media.purge_video(PAIR, "m1", copy_id, actor)
        up = await upload_row(d, up_id)
        yt = await video_row(d)
        fresh = await d.copy.start_copy(PAIR, "m1", "yt", actor)
        return trashed, up, yt, fresh

    trashed, up, yt, fresh = d.run(go)
    assert trashed["trashed"] is True and trashed["copy_video_id"]
    assert up["status"] == "removed" and up["play_key"] is None and any(k.endswith("/play.mp4") for k in d.forgotten)
    assert yt["mirror_upload_id"] is None and fresh["mirror"]["status"] == "working"


def test_stara_kopia_dostaje_wlasne_nagranie_przy_odczycie(d):
    async def go():
        await seed(d)
        now = datetime.now(timezone.utc)
        await d.ins("mentor_uploads", id="old", pair_id=PAIR, match_id="m1", uploader_id=A, filename="Stary mecz.mp4", size=10,
                    content_type="video/mp4", status="ready", created_at=now, origin="youtube", source_url=YT_URL,
                    play_key="mentor/p/m1/old/play.mp4", height=720, duration_s=5400.0)
        T = d.T["mentor_match_videos"]
        await d.db.execute(T.update().where(T.c.id == "yt").values(mirror_upload_id="old"))
        actor = await actor_for(d)
        ctx = await d.core.pair_context(PAIR, actor)
        first, _ = await d.media.video_list(ctx, "m1")
        second, _ = await d.media.video_list(ctx, "m1")
        orphans = await d.copy.adopt_orphans()
        again = await d.copy.start_copy(PAIR, "m1", "yt", actor)
        return first, second, orphans, again, await upload_row(d, "old")

    first, second, orphans, again, up = d.run(go)
    copy = next(v for v in first if v.get("copy_of") == "yt")
    assert copy["title"] == "Transmisja · kopia 720p" and copy["copy_of"] == "yt" and up["video_id"] == copy["id"]
    assert [v["id"] for v in second] == [v["id"] for v in first] and orphans == 0 and sum(1 for v in first if v.get("copy_of")) == 1
    assert again["mirror"]["video_id"] == copy["id"] and d.calls == []


def test_stare_kopie_przy_starcie_workera(d):
    async def go():
        await seed(d)
        now = datetime.now(timezone.utc)
        await d.ins("mentor_uploads", id="old", pair_id=PAIR, match_id="m1", uploader_id=A, filename="Stary mecz.mp4", size=10,
                    content_type="video/mp4", status="ready", created_at=now, origin="youtube", source_url=YT_URL,
                    play_key="mentor/p/m1/old/play.mp4")
        T = d.T["mentor_match_videos"]
        await d.db.execute(T.update().where(T.c.id == "yt").values(mirror_upload_id="old"))
        return await d.copy.adopt_orphans(), await d.copy.adopt_orphans(), await upload_row(d, "old")

    first, second, up = d.run(go)
    assert first == 1 and second == 0 and up["video_id"] and up["play_key"]


def test_odmowy_nie_youtube_i_wylacznik(d):
    async def go():
        await seed(d, url="https://vimeo.com/123", provider="vimeo", video_id="vm")
        await seed(d)
        actor = await actor_for(d)
        vimeo = await failure(d.copy.start_copy(PAIR, "m1", "vm", actor))
        d.mp.setenv("MENTOR_YT_COPY", "0")
        off = await failure(d.copy.start_copy(PAIR, "m1", "yt", actor))
        ctx = await d.core.pair_context(PAIR, actor)
        listed, _ = await d.media.video_list(ctx, "m1")
        return vimeo, off, listed

    vimeo, off, listed = d.run(go)
    assert vimeo[0] == 422 and vimeo[1]["code"] == "NOT_YOUTUBE"
    assert off[0] == 404 and off[1]["code"] == "COPY_DISABLED"
    assert all(v["can_copy"] is False for v in listed)
    assert next(v for v in listed if v["id"] == "vm")["mirror"] is None


def test_mp4_klipu_z_filmu_youtube_tnie_wprost_z_kopii(d):
    import subprocess

    runs = []

    def fake_run(args, timeout=None):
        runs.append(list(args))
        with open(args[-1], "wb") as handle:
            handle.write(b"mp4")
        return subprocess.CompletedProcess(args, 0, "", "")

    d.mp.setattr(d.media, "_run", fake_run)
    d.mp.setattr(d.media, "put_file", lambda path, key, content_type: 3)

    async def go():
        await seed(d)
        now = datetime.now(timezone.utc)
        await d.ins("mentor_clips", id="c1", pair_id=PAIR, match_id="m1", video_id="yt", start_s=1500.0, end_s=1520.0, title="Kara",
                    author_id=A, category_ids="[]", source="manual", created_at=now, updated_at=now, mp4_status="none", media_rev=1)
        actor = await actor_for(d)
        before = await failure(d.media.request_mp4("c1", actor))
        await d.copy.start_copy(PAIR, "m1", "yt", actor)
        await d.copy.process_next()
        ordered = await d.media.request_mp4("c1", actor)
        await d.media.process_next()
        T = d.T["mentor_clips"]
        return before, ordered, await d.core.one(select(T).where(T.c.id == "c1"))

    before, ordered, clip = d.run(go)
    assert before[0] == 409 and before[1]["code"] == "NO_SOURCE"  # bez kopii sam YouTube nie daje MP4
    assert ordered == {"mp4_status": "queued"} and clip["mp4_status"] == "ready"
    cut = runs[-1]
    assert cut[cut.index("-ss") + 1] == "1500.00" and any("play.mp4" in a for a in cut)  # te same sekundy, plik kopii


def test_usuniecie_na_zawsze_filmu_w_trakcie_kopii_przerywa_ja(d):
    async def go():
        await seed(d)
        actor = await actor_for(d)
        await d.copy.start_copy(PAIR, "m1", "yt", actor)
        before = await video_row(d)
        await d.media.delete_video(PAIR, "m1", "yt", actor)
        await d.media.purge_video(PAIR, "m1", "yt", actor)
        return await upload_row(d, before["mirror_upload_id"]), await d.copy.process_next()

    up, worked = d.run(go)
    assert up["status"] == "removed" and worked is False

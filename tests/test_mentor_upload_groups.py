"""Nagranie meczu z kilku plików (07.11.2026) - trasy i worker na małej bazie SQLite (R2 i ffmpeg podmienione)."""

import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from tests.mentor_panel_support import COMMITTEE, JUDGES, MENTOR, PAIR, Env
from tests.test_mentor_panel_routes import FakeS3

GB = 1024 ** 3


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


async def raises(coro):
    try:
        await coro
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {"code": exc.detail, "message": ""}
        return exc.status_code, detail.get("code"), detail.get("message")
    raise AssertionError("oczekiwano odmowy")


def storage(monkeypatch, env):
    s3 = FakeS3()
    counter = iter(range(1, 1000))
    s3.create_multipart_upload = lambda **kw: (s3.calls.append(("create", kw)), {"UploadId": f"UP-{next(counter)}"})[1]
    monkeypatch.setattr(env.media, "storage_config", lambda: {"endpoint": "e", "region": "auto", "bucket": "b",
                                                              "access_key": "a", "secret_key": "s", "prefix": "mentor"})
    monkeypatch.setattr(env.media, "s3_client", lambda config=None: s3)
    return s3


def probe_data(vcodec="h264", width=1920, height=1080, fps="25/1", duration=1800.0, acodec="aac"):
    streams = [{"codec_type": "video", "codec_name": vcodec, "width": width, "height": height, "avg_frame_rate": fps,
                "pix_fmt": "yuv420p", "profile": "High", "level": 40}]
    if acodec:
        streams.append({"codec_type": "audio", "codec_name": acodec, "sample_rate": "48000", "channels": 2})
    return {"format": {"duration": str(duration)}, "streams": streams}


def fake_media(monkeypatch, env, by_name):
    """ffprobe po nazwie pliku w kluczu R2 (`original.mp4` w katalogu wgrywania) albo części po wyrównaniu (`partN.mp4`)."""
    UG, M = env.groups, env.media
    calls = []
    keys = {}

    def fake_probe(source):
        calls.append(("probe", source))
        if os.path.basename(source).startswith("part"):
            index = int(os.path.basename(source)[4:-4])
            return probe_data(duration=by_name[index][1] + 0.04)  # rzeczywisty czas po wyrównaniu
        for name, data in keys.items():
            if name in source:
                return data
        raise AssertionError(f"nieznane źródło {source}")

    def fake_ffmpeg(args, on_seconds, cancelled):
        calls.append(("ffmpeg", list(args)))
        on_seconds(10.0)
        with open(args[-1], "wb") as handle:
            handle.write(b"mp4")

    def fake_poster(source, target, duration):
        with open(target, "wb") as handle:
            handle.write(b"jpg")
        return True

    monkeypatch.setattr(UG, "probe_raw", fake_probe)
    monkeypatch.setattr(UG, "run_ffmpeg", fake_ffmpeg)
    monkeypatch.setattr(M, "poster", fake_poster)
    return calls, keys


def bodies(env, names, size=GB):
    return env.groups.GroupBody(files=[{"filename": n, "size": size, "content_type": "video/mp4",
                                        "recorded_at": f"2026-11-0{i + 1}T18:00:00Z", "duration_s": 1800}
                                       for i, n in enumerate(names)], order_source="recorded")


def env_parts(total):
    return [{"n": n, "etag": f"e{n}"} for n in range(1, total + 1)]


async def complete(env, actor, uid, size=GB):
    M = env.media
    return await M.complete_upload(PAIR, "m1", uid, M.CompleteBody(parts=env_parts(M.R.upload_parts(size))), actor)


NAMES = ["GX010123.MP4", "GX020123.MP4", "GX030123.MP4"]


def test_zalozenie_grupy_i_walidacja(env, monkeypatch):
    s3 = storage(monkeypatch, env)

    async def go():
        UG = env.groups
        pair, committee = await env.actor(JUDGES[0]), await env.actor(COMMITTEE)
        one = await raises(UG.start_group(PAIR, "m1", bodies(env, NAMES[:1]), pair))
        many = await raises(UG.start_group(PAIR, "m1", bodies(env, [f"f{i}.mp4" for i in range(13)]), pair))
        too_big = await raises(UG.start_group(PAIR, "m1", bodies(env, NAMES, size=7 * GB), pair))
        bad_type = UG.GroupBody(files=[{"filename": "a.mp4", "size": 10, "content_type": "video/mp4"},
                                       {"filename": "zdjecie.png", "size": 10, "content_type": "image/png"}])
        wrong = await raises(UG.start_group(PAIR, "m1", bad_type, pair))
        denied = await raises(UG.start_group(PAIR, "m1", bodies(env, NAMES), committee))
        started = await UG.start_group(PAIR, "m1", bodies(env, NAMES, size=GB + 5), pair)
        rows = [dict(r) for r in await env.db.fetch_all(select(env.T["mentor_uploads"]).order_by(env.T["mentor_uploads"].c.group_index))]
        return one, many, too_big, wrong, denied, started, rows

    one, many, too_big, wrong, denied, started, rows = env.run(go)
    assert one[:2] == (422, "UPLOAD_GROUP_COUNT") and many[:2] == (422, "UPLOAD_GROUP_COUNT")
    assert too_big[:2] == (422, "UPLOAD_TOO_BIG") and "20 GB" in too_big[2]
    assert wrong[:2] == (422, "UPLOAD_TYPE") and wrong[2].startswith("Plik 2 (zdjecie.png)")
    assert denied[0] == 403
    assert started["count"] == 3 and started["order_source"] == "recorded"
    assert [u["index"] for u in started["uploads"]] == [0, 1, 2]
    first = started["uploads"][0]
    assert first["total_parts"] == 17 and first["part_size"] == 64 * 1024 * 1024 and first["expires_at"]
    assert [p["n"] for p in first["parts"]] == list(range(1, 18)) and all(set(p) == {"n", "url"} and p["url"] for p in first["parts"])
    assert len({u["upload_id"] for u in started["uploads"]}) == 3
    assert [r["group_index"] for r in rows] == [0, 1, 2] and {r["group_id"] for r in rows} == {started["group_id"]}
    assert all(r["group_count"] == 3 and r["status"] == "uploading" for r in rows)
    assert rows[1]["recorded_at"].replace(tzinfo=timezone.utc) == datetime(2026, 11, 2, 18, 0, tzinfo=timezone.utc)
    assert rows[0]["duration_s"] == 1800.0 and rows[0]["upload_id"] == "UP-1" and rows[2]["upload_id"] == "UP-3"
    created = [c[1]["Key"] for c in s3.calls if c[0] == "create"]
    assert len(created) == 3 and all(k.endswith("/original.mp4") for k in created) and len(set(created)) == 3


def test_domkniecie_w_dowolnej_kolejnosci_i_jedno_nagranie(env, monkeypatch):
    s3 = storage(monkeypatch, env)

    async def go():
        UG, M = env.groups, env.media
        pair, mentor = await env.actor(JUDGES[0]), await env.actor(MENTOR)
        started = await UG.start_group(PAIR, "m1", bodies(env, NAMES), pair)
        gid, ids = started["group_id"], [u["upload_id"] for u in started["uploads"]]
        out = {"stranger": await raises(complete(env, mentor, ids[2]))}
        out["third"] = await complete(env, pair, ids[2])
        out["third_again"] = await complete(env, pair, ids[2])
        out["first"] = await complete(env, pair, ids[0])
        out["status_mid"] = await UG.group_status(PAIR, "m1", gid, mentor)
        out["last"] = await complete(env, pair, ids[1])
        out["last_again"] = await complete(env, pair, ids[0])
        out["status"] = await UG.group_status(PAIR, "m1", gid, mentor)
        out["member_status"] = await M.upload_status(PAIR, "m1", ids[1], mentor)
        out["job"] = await M.next_job()
        out["videos"] = [dict(v) for v in await env.db.fetch_all(
            select(env.T["mentor_match_videos"]).where(env.T["mentor_match_videos"].c.kind == "upload"))]
        out["room"] = await env.panel.match_room(PAIR, "m1", mentor)
        out["missing"] = await raises(UG.group_status(PAIR, "m1", "nie-ma", mentor))
        out["ids"], out["gid"] = ids, gid
        return out

    out = env.run(go)
    ids, gid = out["ids"], out["gid"]
    assert out["stranger"][:2] == (403, "NOT_OWNER")
    assert out["third"] == {"status": "waiting_group", "group_id": gid, "done": 1, "count": 3}
    assert out["third_again"] == out["third"]
    assert out["first"] == {"status": "waiting_group", "group_id": gid, "done": 2, "count": 3}
    assert out["status_mid"]["status"] == "uploading" and out["status_mid"]["done"] == 2 and out["status_mid"]["video_id"] is None
    assert [f["status"] for f in out["status_mid"]["files"]] == ["uploaded", "uploading", "uploaded"]
    assert out["last"]["status"] == "processing" and out["last"]["group_id"] == gid and out["last"]["video_id"]
    assert out["last_again"] == {"status": "processing", "video_id": out["last"]["video_id"], "group_id": gid, "error": None}
    assert len([c for c in s3.calls if c[0] == "complete"]) == 3  # powtórki nie składają pliku drugi raz
    status = out["status"]
    assert status["status"] == "processing" and status["video_id"] == out["last"]["video_id"] and status["progress"] is None
    assert [f["index"] for f in status["files"]] == [0, 1, 2] and [f["filename"] for f in status["files"]] == NAMES
    assert all(f["status"] == "processing" for f in status["files"]) and status["count"] == 3
    assert out["member_status"]["status"] == "processing"
    assert out["job"][0] == "upload" and out["job"][1]["id"] == ids[0]
    assert len(out["videos"]) == 1
    video = out["videos"][0]
    assert video["upload_id"] == ids[0] and video["title"] == "GX010123 (3 części)" and video["id"] == out["last"]["video_id"]
    shaped = next(v for v in out["room"]["videos"] if v["kind"] == "upload")
    assert shaped["upload_status"] == "processing" and shaped["parts"] is None and shaped["playable"] is False
    assert out["missing"][:2] == (404, "UPLOAD_GROUP_NOT_FOUND")


def _upload_all(env, names, sizes=None):
    async def run():
        UG = env.groups
        pair = await env.actor(JUDGES[0])
        started = await UG.start_group(PAIR, "m1", bodies(env, names), pair)
        ids = [u["upload_id"] for u in started["uploads"]]
        for uid in ids:
            last = await complete(env, pair, uid)
        return started["group_id"], ids, last["video_id"]

    return run


def _keys_for(keys, ids, datas):
    for uid, data in zip(ids, datas):
        keys[uid] = data


def test_worker_skleja_bez_przekodowania(env, monkeypatch):
    s3 = storage(monkeypatch, env)
    calls, keys = fake_media(monkeypatch, env, {})

    async def go():
        M, UG = env.media, env.groups
        mentor = await env.actor(MENTOR)
        gid, ids, video_id = await _upload_all(env, NAMES)()
        _keys_for(keys, ids, [probe_data(duration=1872.04), probe_data(duration=1800.0), probe_data(duration=95.5)])
        worked = await M.process_next()
        status = await UG.group_status(PAIR, "m1", gid, mentor)
        room = await env.panel.match_room(PAIR, "m1", mentor)
        rows = [dict(r) for r in await env.db.fetch_all(select(env.T["mentor_uploads"]).order_by(env.T["mentor_uploads"].c.group_index))]
        idle = await M.process_next()
        counts = await M.retention_once(datetime.now(timezone.utc))
        after = [dict(r) for r in await env.db.fetch_all(select(env.T["mentor_uploads"]).order_by(env.T["mentor_uploads"].c.group_index))]
        return worked, status, room, rows, idle, counts, after, video_id

    worked, status, room, rows, idle, counts, after, video_id = env.run(go)
    ffmpeg = [c[1] for c in calls if c[0] == "ffmpeg"]
    assert worked is True and idle is False
    assert len(ffmpeg) == 1 and ffmpeg[0][ffmpeg[0].index("-c") + 1] == "copy" and "-protocol_whitelist" in ffmpeg[0]
    assert ffmpeg[0][-1].endswith("play.mp4") and "+faststart" in ffmpeg[0]
    assert status["status"] == "ready" and status["progress"] == 1.0 and status["video_id"] == video_id and status["error"] is None
    video = next(v for v in room["videos"] if v["kind"] == "upload")
    # Stan grupy niesie gotowe nagranie - pokój wkłada je sam, bez odświeżania strony (08.11.2026).
    assert status["video"]["id"] == video_id and status["video"]["playable"] and status["video"]["parts"] == video["parts"]
    assert video["playable"] and video["play_url"].endswith("/play.mp4?part=None") and video["poster_url"]
    assert video["parts"] == [{"index": 0, "filename": NAMES[0], "start_s": 0.0, "duration_s": 1872.04},
                              {"index": 1, "filename": NAMES[1], "start_s": 1872.04, "duration_s": 1800.0},
                              {"index": 2, "filename": NAMES[2], "start_s": 3672.04, "duration_s": 95.5}]
    assert video["duration_s"] == 3767.54
    assert other_videos_have_no_parts(room)
    assert [r["status"] for r in rows] == ["ready", "ready", "ready"]
    assert rows[0]["play_key"].endswith("/play.mp4") and rows[1]["play_key"] is None and rows[1]["duration_s"] == 1800.0
    assert ("upload", rows[0]["play_key"]) in s3.calls
    assert counts["originals"] == 3 and all(r["r2_key"] is None for r in after) and after[0]["play_key"]


def other_videos_have_no_parts(room):
    return all(v["parts"] is None for v in room["videos"] if v["kind"] != "upload")


def test_worker_wyrownuje_rozne_formaty(env, monkeypatch):
    storage(monkeypatch, env)
    durations = {0: ("a", 1500.0), 1: ("b", 1600.0), 2: ("c", 300.0)}
    calls, keys = fake_media(monkeypatch, env, durations)
    progress = []

    async def go():
        M, UG = env.media, env.groups
        mentor = await env.actor(MENTOR)
        gid, ids, video_id = await _upload_all(env, NAMES)()
        _keys_for(keys, ids, [probe_data(duration=1500.0), probe_data(vcodec="hevc", width=3840, height=2160, fps="50/1", duration=1600.0),
                                   probe_data(duration=300.0, acodec=None)])
        original = UG.G.group_progress

        def spy(*args, **kwargs):
            value = original(*args, **kwargs)
            progress.append(value)
            return value

        monkeypatch.setattr(UG.G, "group_progress", spy)
        await M.process_next()
        room = await env.panel.match_room(PAIR, "m1", mentor)
        rows = [dict(r) for r in await env.db.fetch_all(select(env.T["mentor_uploads"]).order_by(env.T["mentor_uploads"].c.group_index))]
        return room, rows

    room, rows = env.run(go)
    ffmpeg = [c[1] for c in calls if c[0] == "ffmpeg"]
    assert len(ffmpeg) == 4  # trzy wyrównania + sklejenie
    for args in ffmpeg[:3]:
        vf = args[args.index("-vf") + 1]
        assert "pad=1920:1080" in vf and "fps=25" in vf and args[args.index("-c:v") + 1] == "libx264"
    assert "anullsrc=channel_layout=stereo:sample_rate=48000" in ffmpeg[2] and "anullsrc" not in " ".join(ffmpeg[0])
    concat = ffmpeg[3]
    assert concat[concat.index("-c") + 1] == "copy" and "-protocol_whitelist" not in concat
    video = next(v for v in room["videos"] if v["kind"] == "upload")
    assert [p["duration_s"] for p in video["parts"]] == [1500.04, 1600.04, 300.04]  # czasy rzeczywiste po wyrównaniu
    assert [p["start_s"] for p in video["parts"]] == [0.0, 1500.04, 3100.08]
    assert rows[0]["width"] == 1920 and rows[0]["height"] == 1080 and rows[0]["status"] == "ready"
    assert progress and all(0.0 <= p <= 0.99 for p in progress) and max(progress) >= 0.95


def test_zla_czesc_to_cala_grupa_nieudana(env, monkeypatch):
    storage(monkeypatch, env)
    calls, keys = fake_media(monkeypatch, env, {})

    async def go():
        M, UG = env.media, env.groups
        mentor = await env.actor(MENTOR)
        gid, ids, video_id = await _upload_all(env, NAMES)()
        _keys_for(keys, ids, [probe_data(), probe_data(), probe_data()])
        monkeypatch.setattr(UG, "probe_raw", lambda source: (_ for _ in ()).throw(RuntimeError("moov atom not found"))
                            if ids[1] in source else keys[ids[0]])
        worked = await M.process_next()
        status = await UG.group_status(PAIR, "m1", gid, mentor)
        room = await env.panel.match_room(PAIR, "m1", mentor)
        again = await M.process_next()
        return worked, status, room, again

    worked, status, room, again = env.run(go)
    assert worked is True and again is False
    assert status["status"] == "failed" and status["error"] == "Część 2 (GX020123.MP4) nie daje się odczytać."
    assert all(f["status"] == "failed" for f in status["files"]) and status["progress"] is None
    video = next(v for v in room["videos"] if v["kind"] == "upload")
    assert video["upload_status"] == "failed" and video["parts"] is None


def test_usuniecie_grupy(env, monkeypatch):
    s3 = storage(monkeypatch, env)
    calls, keys = fake_media(monkeypatch, env, {})

    async def go():
        M, UG = env.media, env.groups
        pair, mentor = await env.actor(JUDGES[0]), await env.actor(MENTOR)
        # 1) w trakcie wysyłki: jeden plik gotowy, dwa w toku
        started = await UG.start_group(PAIR, "m1", bodies(env, NAMES), pair)
        gid, ids = started["group_id"], [u["upload_id"] for u in started["uploads"]]
        await complete(env, pair, ids[0])
        not_owner = await raises(UG.abort_group(PAIR, "m1", gid, mentor))
        removed = await UG.abort_group(PAIR, "m1", gid, pair)
        aborted = [c[1]["UploadId"] for c in s3.calls if c[0] == "abort"]
        dropped = [c[1] for c in s3.calls if c[0] == "delete"]
        removed_again = await UG.abort_group(PAIR, "m1", gid, pair)
        status = await UG.group_status(PAIR, "m1", gid, mentor)
        late = await complete(env, pair, ids[1])
        # 2) w trakcie sklejania: nagranie znika; DELETE pliku grupy przerywa całą grupę
        gid2, ids2, video2 = await _upload_all(env, NAMES)()
        member_abort = await M.abort_upload(PAIR, "m1", ids2[2], pair)
        video_gone = await env.db.fetch_one(select(env.T["mentor_match_videos"]).where(env.T["mentor_match_videos"].c.id == video2))
        status2 = await UG.group_status(PAIR, "m1", gid2, mentor)
        # 3) gotowe: DELETE grupy odmawia, usunięcie nagrania kasuje oryginały wszystkich części
        gid3, ids3, video3 = await _upload_all(env, NAMES[:2])()
        _keys_for(keys, ids3, [probe_data(), probe_data()])
        await M.process_next()
        ready = await raises(UG.abort_group(PAIR, "m1", gid3, pair))
        rows3 = [dict(r) for r in await env.db.fetch_all(select(env.T["mentor_uploads"]).where(env.T["mentor_uploads"].c.group_id == gid3))]
        s3.calls.clear()
        deleted = await M.delete_video(PAIR, "m1", video3, pair)
        after3 = [dict(r) for r in await env.db.fetch_all(select(env.T["mentor_uploads"]).where(env.T["mentor_uploads"].c.group_id == gid3))]
        return (not_owner, removed, removed_again, status, late, member_abort, video_gone, status2, ready, rows3, deleted, after3,
                aborted, dropped, gid2)

    (not_owner, removed, removed_again, status, late, member_abort, video_gone, status2, ready, rows3, deleted, after3,
     aborted, dropped, gid2) = env.run(go)
    assert not_owner[:2] == (403, "NOT_OWNER")
    assert removed["ok"] and removed["status"] == "removed" and removed_again == removed
    assert aborted == ["UP-2", "UP-3"]  # multiparty w toku przerwane, gotowy plik skasowany
    assert len(dropped) == 1 and dropped[0].endswith("/original.mp4")
    assert status["status"] == "removed" and all(f["status"] == "removed" for f in status["files"])
    assert late == {"status": "removed", "video_id": None, "group_id": removed["group_id"], "error": "Wgrywanie przerwane."}
    assert member_abort == {"ok": True, "status": "removed", "group_id": gid2}
    assert video_gone is None and status2["status"] == "removed" and status2["video_id"] is None
    assert ready[:2] == (409, "UPLOAD_GROUP_READY")
    originals = {r["r2_key"] for r in rows3 if r["r2_key"]}
    assert len(originals) == 2 and deleted["ok"] and deleted["trashed"] is False
    gone = {c[1] for c in s3.calls if c[0] == "delete"}
    assert originals <= gone and all(r["status"] == "expired" and r["r2_key"] is None for r in after3)


def test_porzucona_grupa_retencja(env, monkeypatch):
    s3 = storage(monkeypatch, env)

    async def go():
        UG, M = env.groups, env.media
        pair = await env.actor(JUDGES[0])
        started = await UG.start_group(PAIR, "m1", bodies(env, NAMES[:2]), pair)
        ids = [u["upload_id"] for u in started["uploads"]]
        await complete(env, pair, ids[0])
        later = datetime.now(timezone.utc) + timedelta(days=2)
        counts = await M.retention_once(later)
        status = await UG.group_status(PAIR, "m1", started["group_id"], pair)
        return counts, status

    counts, status = env.run(go)
    assert counts["aborted"] == 2
    assert status["status"] == "failed" and "porzucone" in status["error"]
    assert any(c[0] == "delete" and c[1].endswith("/original.mp4") for c in s3.calls)
    assert any(c[0] == "abort" for c in s3.calls)

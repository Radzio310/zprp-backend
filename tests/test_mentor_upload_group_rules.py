"""Nagranie z kilku plików (07.11.2026) - czysta logika `app/mentor_upload_group_rules.py` i retencja części."""

from datetime import datetime, timedelta, timezone

import pytest

from app import mentor_panel_rules as R
from app import mentor_upload_group_rules as G

GB = 1024 ** 3
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)


def probe(vcodec="h264", width=1920, height=1080, fps="25/1", acodec="aac", rate="48000", channels=2, duration="1800.5",
          profile="High", level=40, pix="yuv420p", rotation=None):
    video = {"codec_type": "video", "codec_name": vcodec, "width": width, "height": height, "avg_frame_rate": fps,
             "r_frame_rate": fps, "pix_fmt": pix, "profile": profile, "level": level}
    if rotation is not None:
        video["side_data_list"] = [{"side_data_type": "Display Matrix", "rotation": rotation}]
    streams = [video]
    if acodec:
        streams.append({"codec_type": "audio", "codec_name": acodec, "sample_rate": rate, "channels": channels})
    streams.append({"codec_type": "data", "codec_tag_string": "gpmd"})
    return {"format": {"duration": duration}, "streams": streams}


def files(n, size=GB, **over):
    return [{"filename": f"GX0{i + 1}0123.MP4", "size": size, "content_type": "video/mp4", **over} for i in range(n)]


# ─── Walidacja grupy ────────────────────────────────────────────────────────


def test_walidacja_grupy_liczba_suma_i_pliki():
    for n in (0, 1, 13):
        with pytest.raises(R.RuleError) as exc:
            G.validate_group(files(n))
        assert exc.value.code == "UPLOAD_GROUP_COUNT" and exc.value.status == 422
    with pytest.raises(R.RuleError) as exc:
        G.validate_group(files(3, size=7 * GB))
    assert exc.value.code == "UPLOAD_TOO_BIG" and "razem" in exc.value.message
    bad = files(3)
    bad[1]["content_type"] = "image/png"
    with pytest.raises(R.RuleError) as exc:
        G.validate_group(bad)
    assert exc.value.code == "UPLOAD_TYPE" and exc.value.message.startswith("Plik 2 (GX020123.MP4):")
    with pytest.raises(R.RuleError):
        G.validate_group("nie lista")

    cleaned, source = G.validate_group(
        [{"filename": "a.mp4", "size": 10 * GB, "content_type": "video/mp4", "recorded_at": "2026-11-07T10:00:00.5Z", "duration_s": 1800},
         {"filename": "b.mp4", "size": 10 * GB, "content_type": "", "recorded_at": "zły", "duration_s": -3}], "RECORDED")
    assert source == "recorded"
    assert [c["index"] for c in cleaned] == [0, 1] and cleaned[1]["content_type"] == "application/octet-stream"
    assert cleaned[0]["recorded_at"] == datetime(2026, 11, 7, 10, 0, 0, 500000, tzinfo=timezone.utc)
    assert cleaned[1]["recorded_at"] is None and cleaned[0]["duration_s"] == 1800.0 and cleaned[1]["duration_s"] is None
    assert G.validate_group(files(12))[1] == "manual"
    assert G.validate_group(files(2), "cokolwiek")[1] == "manual"


def test_czas_nagrania_i_nazwa():
    assert G.parse_recorded_at("2026-11-07T10:00:00+01:00") == datetime(2026, 11, 7, 9, 0, tzinfo=timezone.utc)
    assert G.parse_recorded_at("2026-11-07T10:00:00") == datetime(2026, 11, 7, 10, 0, tzinfo=timezone.utc)
    assert G.parse_recorded_at("2026-11-07T10:00:00.1234567Z").microsecond == 123456
    assert G.parse_recorded_at(None) is None and G.parse_recorded_at("") is None and G.parse_recorded_at("wczoraj") is None
    assert G.group_title("GX010123.MP4", 3) == "GX010123 (3 części)"
    assert G.group_title("mecz.kopia1", 2) == "mecz.kopia1 (2 części)"
    assert G.group_title("", 12) == "Nagranie (12 części)"


# ─── Stan grupy ─────────────────────────────────────────────────────────────


def rows(*statuses, video_id=None, error=None):
    return [{"id": f"u{i}", "group_index": i, "group_count": len(statuses), "status": st,
             "video_id": video_id if i == 0 else None, "error": error if st == "failed" else None}
            for i, st in enumerate(statuses)]


def test_stan_grupy():
    assert G.group_state(rows("uploading", "uploaded", "uploading")) == {
        "status": "uploading", "error": None, "video_id": None, "done": 1, "count": 3}
    assert G.all_uploaded(rows("uploaded", "uploaded")) and not G.all_uploaded(rows("uploaded", "uploading"))
    assert not G.all_uploaded(rows("uploaded", "uploaded")[:1] + [])  # brakuje wiersza względem group_count
    assert G.group_state(rows("processing", "processing", video_id="v"))["status"] == "processing"
    assert G.group_state(rows("ready", "ready", video_id="v")) == {"status": "ready", "error": None, "video_id": "v", "done": 2, "count": 2}
    failed = G.group_state(rows("failed", "failed", error="Część 2 (b.mp4) nie daje się odczytać."))
    assert failed["status"] == "failed" and failed["error"].startswith("Część 2")
    assert G.group_state(rows("uploaded", "failed"))["error"] == "Wgrywanie przerwane."
    assert G.group_state(rows("removed", "removed"))["status"] == "removed"
    assert G.lead_of(list(reversed(rows("uploaded", "uploading"))))["id"] == "u0"
    assert [r["id"] for r in G.ordered(list(reversed(rows("a", "b", "c"))))] == ["u0", "u1", "u2"]


# ─── ffprobe i wspólny format ───────────────────────────────────────────────


def test_odczyt_ffprobe():
    info = G.probe_info(probe())
    assert info == {"width": 1920, "height": 1080, "rotation": 0, "fps": 25.0, "vcodec": "h264", "pix_fmt": "yuv420p",
                    "profile": "High", "level": 40, "acodec": "aac", "sample_rate": 48000, "channels": 2, "duration_s": 1800.5}
    portrait = G.probe_info(probe(rotation=-90, fps="30000/1001", acodec=None))
    assert (portrait["width"], portrait["height"], portrait["rotation"]) == (1080, 1920, 270)
    assert portrait["fps"] == 29.97 and portrait["acodec"] is None and portrait["sample_rate"] is None
    with pytest.raises(ValueError):
        G.probe_info({"streams": [{"codec_type": "audio"}]})
    with pytest.raises(ValueError):
        G.probe_info({"streams": [{"codec_type": "video", "width": 0, "height": 0}]})
    assert G.parse_rate("0/0") is None and G.parse_rate("x") is None and G.parse_rate("50") == 50.0


def test_wybor_formatu_copy_albo_wyrownanie():
    same = [G.probe_info(probe()) for _ in range(3)]
    assert G.copy_compatible(same) and G.group_plan(same) == {"mode": "copy", "width": 1920, "height": 1080, "fps": 25.0}
    for change in ({"vcodec": "hevc"}, {"acodec": None}, {"fps": "50/1"}, {"rate": "44100"}, {"channels": 1},
                   {"width": 1280, "height": 720}, {"profile": "Main"}):
        other = G.probe_info(probe(**change))
        assert not G.copy_compatible([same[0], other]), change
        assert G.group_plan([same[0], other])["mode"] == "normalize"
    four_k = [G.probe_info(probe(width=3840, height=2160)) for _ in range(2)]
    assert not G.copy_compatible(four_k)  # te same parametry, ale ponad 1080p: wyrównanie do 1080p
    assert G.group_plan(four_k) == {"mode": "normalize", "width": 1920, "height": 1080, "fps": 25}
    mixed = [G.probe_info(probe(width=1280, height=720, fps="50/1")), G.probe_info(probe(fps="25/1")),
             G.probe_info(probe(fps="24000/1001")), G.probe_info(probe(fps="50/1"))]
    plan = G.group_plan(mixed)
    assert plan == {"mode": "normalize", "width": 1920, "height": 1080, "fps": 50}  # 50 dwa razy, remis -> wcześniejszy
    assert G.common_fps([G.probe_info(probe(fps="120/1"))]) == 60 and G.common_fps([]) == 25
    # Pion i poziom: kadr najszerszych proporcji, pion wpisany z pasami.
    portrait = G.probe_info(probe(width=720, height=1280))
    landscape = G.probe_info(probe(width=1280, height=720))
    plan = G.group_plan([portrait, landscape])
    assert (plan["width"], plan["height"]) == (1920, 1080)
    assert G.fit_size(portrait, plan) == (608, 1080) and G.fit_size(landscape, plan) == (1920, 1080)


def test_argumenty_ffmpeg():
    plan = {"mode": "normalize", "width": 1920, "height": 1080, "fps": 25}
    args = G.normalize_args("https://r2/a.mp4", "/tmp/p0.mp4", G.probe_info(probe(width=1280, height=720)), plan)
    vf = args[args.index("-vf") + 1]
    assert vf == "scale=1920:1080,pad=1920:1080:(ow-iw)/2:(oh-ih)/2,setsar=1,fps=25,format=yuv420p"
    assert args[args.index("-c:v") + 1] == "libx264" and args[args.index("-ar") + 1] == "48000" and args[args.index("-ac") + 1] == "2"
    assert ["-map", "0:a:0"] == args[args.index("0:v:0") + 1:args.index("0:v:0") + 3] and "anullsrc" not in " ".join(args)
    assert args[-1] == "/tmp/p0.mp4" and "-progress" in args
    silent = G.normalize_args("src", "dst", G.probe_info(probe(acodec=None)), plan)
    assert "anullsrc=channel_layout=stereo:sample_rate=48000" in silent and "1:a:0" in silent and "-shortest" in silent
    assert G.concat_list(["/tmp/a.mp4", "https://r2/x?sig=a'b"]) == "file '/tmp/a.mp4'\nfile 'https://r2/x?sig=a'\\''b'\n"
    remote = G.concat_args("/tmp/l.txt", "/tmp/out.mp4", True)
    assert remote[remote.index("-c") + 1] == "copy" and "-protocol_whitelist" in remote and ["-f", "concat"] == remote[4:6]
    assert remote[remote.index("-movflags") + 1] == "+faststart" and remote[-1] == "/tmp/out.mp4"
    assert "-protocol_whitelist" not in G.concat_args("/tmp/l.txt", "/tmp/out.mp4", False)


def test_postep_i_os_czesci():
    assert G.out_seconds("out_time_us=1500000") == 1.5 and G.out_seconds("frame=1") is None
    assert G.group_progress(0, 0, 100) == 0.0 and G.group_progress(50, 25, 100) == 0.742
    assert G.group_progress(100, 50, 100) == 0.99 and G.group_progress(0, 10, 0, low=0.95) == 0.95
    assert G.group_progress(0, 50, 100, low=0.95, high=0.99) == 0.97
    timeline = G.parts_timeline(["a.mp4", "b.mp4", "c.mp4"], [1872.04, 1800.0, 95.5])
    assert timeline == [{"index": 0, "filename": "a.mp4", "start_s": 0.0, "duration_s": 1872.04},
                        {"index": 1, "filename": "b.mp4", "start_s": 1872.04, "duration_s": 1800.0},
                        {"index": 2, "filename": "c.mp4", "start_s": 3672.04, "duration_s": 95.5}]
    assert G.clean_timeline(timeline) == timeline and G.clean_timeline(list(reversed(timeline))) == timeline
    assert G.clean_timeline(None) is None and G.clean_timeline(timeline[:1]) is None and G.clean_timeline([1, 2]) is None
    assert G.total_duration([1.5, None, 2]) == 3.5
    assert G.part_error(2, "GX030123.MP4") == "Część 3 (GX030123.MP4) nie daje się odczytać."
    assert G.part_error(0, "") == "Część 1 nie daje się odczytać."


def test_retencja_czesci_grupy():
    base = {"created_at": NOW - timedelta(days=2), "expires_at": NOW + timedelta(days=300), "group_id": "g1"}
    member = {**base, "status": "ready", "r2_key": "o2", "play_key": None}
    assert R.retention_actions(member, NOW)["delete_original"] is True
    assert R.retention_actions({**member, "group_id": None}, NOW)["delete_original"] is False  # pojedynczy bez play_key
    waiting = {**base, "status": "uploaded", "r2_key": "o3"}
    assert R.retention_actions(waiting, NOW)["abort"] is True
    assert R.retention_actions({**waiting, "created_at": NOW}, NOW)["abort"] is False
    assert R.retention_actions({**waiting, "group_id": None}, NOW)["abort"] is False
    assert R.retention_actions({**base, "status": "processing", "r2_key": "o4"}, NOW) == {
        "expire": False, "delete_original": False, "abort": False}

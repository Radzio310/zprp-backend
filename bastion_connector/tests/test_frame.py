from connector import frame as F

M = "https://vz-abc.b-cdn.net/guid/playlist.m3u8?token=SEKRET&expires=1"
V = "https://vz-abc.b-cdn.net/guid/720p/video.m3u8?token=SEKRET&expires=1"


def test_is_media_request():
    assert F.is_media_request(M) and F.is_media_request("https://x.net/a/b.MP4")
    assert not F.is_media_request("https://x.net/a/player.js?x=.m3u8")


def test_pick_prefers_variant_then_master_then_mp4():
    assert F.pick_media_url([M, V]) == V
    assert F.pick_media_url([M]) == M
    assert F.pick_media_url(["https://x.net/a.mp4", "https://x.net/s.js"]) == "https://x.net/a.mp4"
    assert F.pick_media_url([]) is None


def test_ffmpeg_cmd_has_referer_seek_before_input_and_no_shell():
    cmd = F.build_ffmpeg_cmd(V, 300.456, "/tmp/o.jpg", user_agent="UA/1")
    assert cmd[0] == "ffmpeg" and isinstance(cmd, list)
    assert cmd[cmd.index("-headers") + 1] == "Referer: https://iframe.mediadelivery.net/\r\n"
    assert cmd[cmd.index("-ss") + 1] == "300.46" and cmd.index("-ss") < cmd.index("-i")
    assert cmd[cmd.index("-user_agent") + 1] == "UA/1"
    assert cmd[cmd.index("-i") + 1] == V and cmd[-1] == "/tmp/o.jpg" and "-frames:v" in cmd


def test_ffprobe_cmd_without_ua():
    cmd = F.build_ffprobe_cmd(V)
    assert "-user_agent" not in cmd and cmd[-1] == V


def test_urls_never_leak_into_errors():
    assert "SEKRET" not in F.redact(f"Server returned 403 for {V} end")
    assert "SEKRET" not in F.describe("ffmpeg", f"boom {V}")
    assert F.describe("goto", TimeoutError()) == "goto:TimeoutError"

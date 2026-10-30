"""Klatka miniatury bez dekodowania w przegladarce: adres playlisty HLS z ruchu odtwarzacza Bunny + ffmpeg.

Chromium z Playwrighta nie ma kodekow H264/AAC, wiec <video> nie podaje czasu trwania. ffmpeg w obrazie je ma.
Adresy podpisane sa sekretem: nie trafiaja do logow ani do tekstow bledow (`redact`)."""
from __future__ import annotations

import asyncio
import os
import re
import tempfile
from urllib.parse import urlsplit

FFMPEG_TIMEOUT_S = 30
EMBED_REFERER = "https://iframe.mediadelivery.net/"
_URL_RE = re.compile(r"https?://\S+")


class FrameError(Exception):
    """Blad z nazwanym etapem (ffprobe, ffmpeg)."""

    def __init__(self, stage: str, detail: str) -> None:
        super().__init__(f"{stage}: {detail}")
        self.stage, self.detail = stage, detail


def redact(text: str) -> str:
    return _URL_RE.sub("<url>", text or "")


def describe(stage: str, exc) -> str:
    """'etap:NazwaWyjatku' albo 'etap:tekst' - bez adresow, krotko (kolumna error ma 200 znakow)."""
    what = exc if isinstance(exc, str) else type(exc).__name__
    return f"{stage}:{redact(what)}"[:120]


def _path(url: str) -> str:
    return (urlsplit(url).path or "").lower()


def is_media_request(url: str) -> bool:
    return _path(url).endswith((".m3u8", ".mp4"))


def pick_media_url(urls) -> str | None:
    """Z zebranych zapytan: playlista wariantu (np. video.m3u8) przed glowna (playlist.m3u8), potem plik mp4."""
    hls = [u for u in urls if _path(u).endswith(".m3u8")]
    variants = [u for u in hls if not _path(u).endswith("/playlist.m3u8")]
    if variants:
        return variants[0]
    if hls:
        return hls[0]
    mp4 = [u for u in urls if _path(u).endswith(".mp4")]
    return mp4[0] if mp4 else None


def _header_args(referer: str, user_agent: str | None) -> list:
    args = ["-headers", f"Referer: {referer}\r\n"]
    if user_agent:
        args += ["-user_agent", user_agent]
    return args


def build_ffmpeg_cmd(url: str, at_s: float, out_path: str, referer: str = EMBED_REFERER,
                     user_agent: str | None = None) -> list:
    """Jedna klatka JPEG: -ss przed -i (szybkie przewiniecie po segmentach HLS)."""
    return ["ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin", "-y",
            *_header_args(referer, user_agent), "-ss", f"{max(at_s, 0):.2f}", "-i", url,
            "-frames:v", "1", "-vf", "scale='min(1280,iw)':-2", "-q:v", "4", out_path]


def build_ffprobe_cmd(url: str, referer: str = EMBED_REFERER, user_agent: str | None = None) -> list:
    return ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=nw=1:nk=1",
            *_header_args(referer, user_agent), url]


async def _run(cmd: list, stage: str, timeout: float = FFMPEG_TIMEOUT_S) -> bytes:
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError as e:
        raise FrameError(stage, "FileNotFoundError") from e
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError as e:
        proc.kill()
        await proc.wait()
        raise FrameError(stage, f"timeout {int(timeout)}s") from e
    if proc.returncode != 0:
        lines = (err or b"").decode("utf-8", "replace").strip().splitlines()
        raise FrameError(stage, redact(f"rc={proc.returncode} {lines[-1] if lines else ''}")[:100])
    return out


async def probe_duration(url: str, user_agent: str | None = None) -> float:
    out = await _run(build_ffprobe_cmd(url, user_agent=user_agent), "ffprobe")
    try:
        dur = float(out.decode().strip().splitlines()[0])
    except (ValueError, IndexError) as e:
        raise FrameError("ffprobe", "brak czasu trwania") from e
    if not 0 < dur < 86400 * 2:
        raise FrameError("ffprobe", "czas trwania poza zakresem")
    return dur


async def grab_jpeg(url: str, at_s: float, user_agent: str | None = None) -> bytes:
    fd, path = tempfile.mkstemp(suffix=".jpg", prefix="frame-")
    os.close(fd)
    try:
        await _run(build_ffmpeg_cmd(url, at_s, path, user_agent=user_agent), "ffmpeg")
        with open(path, "rb") as fh:
            return fh.read()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

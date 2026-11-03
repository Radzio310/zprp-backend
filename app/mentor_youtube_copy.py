"""Kopia filmu YouTube na serwerze (02.11.2026) - trasy i worker. Reguły: `mentor_youtube_copy_rules`.

  - `POST /mentor-panel/pairs/{p}/matches/{m}/videos/{v}/copy` - „Zrób kopię na serwer” (akcja `video`); ponowienie po
    błędzie tym samym wywołaniem. Odpowiedź = nagranie (`Video` z polem `mirror`).
  - `GET .../videos/{v}/copy` - lekki stan kopii do odpytywania co 2-3 s (`{mirror}`).
  - `DELETE .../videos/{v}/copy` - anuluj kopię w toku albo usuń gotową (pliki w R2 znikają, YouTube zostaje).

Worker: jedna kopia naraz, osobno od kolejki ffmpeg klipów (wielominutowe pobieranie nie blokuje MP4 klipów).
yt-dlp i ffmpeg pracują w wątku; stan na żywo (etap, postęp, prędkość) trzyma pamięć procesu, trwały stan
`mentor_uploads` (`origin = 'youtube'`, `status`: downloading -> ready | failed | removed | expired).
Po restarcie kopia w toku zaczyna się od nowa (pliki robocze są tymczasowe).

Zmienne: `MENTOR_YT_COPY=0` (wyłącznik), `MENTOR_YT_PROXY` (np. `http://user:haslo@host:port`, używane dopiero po
blokadzie), `MENTOR_YT_PROXY_ALWAYS=1`, `MENTOR_YT_COOKIES` (ciasteczka Netscape, wprost albo base64),
`MENTOR_MEDIA_TMP` (katalog roboczy - kopia 1080p to do ~2x rozmiar filmu na dysku na czas składania).
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from sqlalchemy import select, update

from app import mentor_panel_core as C
from app import mentor_panel_media as M
from app import mentor_panel_rules as R
from app import mentor_youtube_copy_rules as Y
from app.db import database, mentor_match_videos, mentor_uploads
from app.mentor_panel_auth import mentor_actor

logger = logging.getLogger("app.mentor_youtube_copy")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor"])
Actor = C.MentorActor

ORIGIN = "youtube"
#: Stan na żywo kopii w toku: {upload_id: {phase, progress, speed_bps, eta_s, downloaded_bytes, total_bytes, via_proxy}}.
_live: Dict[str, Dict[str, Any]] = {}
_cancelled: set = set()
_failed_here: set = set()
_wake_event: Optional[asyncio.Event] = None
_tool: Optional[bool] = None


def tool_ready() -> bool:
    global _tool
    if _tool is None:
        _tool = importlib.util.find_spec("yt_dlp") is not None
    return _tool


def available() -> bool:
    """Czy serwer w ogóle umie zrobić kopię (wyłącznik, magazyn R2, yt-dlp)."""
    return Y.enabled() and tool_ready() and M.storage_ready()


def can_copy(row: Dict[str, Any], provider: str) -> bool:
    return provider == "youtube" and (row.get("kind") or "link") != "upload" and available()


def live_state(upload_id: Any) -> Optional[Dict[str, Any]]:
    return _live.get(R.s(upload_id)) if upload_id else None


def mirror_of(upload: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Pole `mirror` nagrania z wiersza `mentor_uploads` kopii (adresy podpisane tylko dla gotowej)."""
    if not upload:
        return None
    ready = upload.get("status") == "ready" and upload.get("play_key")
    play = M.presign_get(upload.get("play_key")) if ready else None
    poster = M.presign_get(upload.get("poster_key")) if ready and upload.get("poster_key") else None
    return Y.mirror_shape(upload, live_state(upload.get("id")), play, poster)


def wake_worker() -> None:
    if _wake_event is not None:
        _wake_event.set()


def _set_live(upload_id: str, phase: str, fraction: Optional[float] = None, **extra: Any) -> None:
    state = dict(_live.get(upload_id) or {})
    state.update(extra)
    state["phase"] = phase
    state["progress"] = Y.overall(phase, fraction)
    _live[upload_id] = state


# ─── Trasy ──────────────────────────────────────────────────────────────────


async def _youtube_video(ctx: Dict[str, Any], match_id: str, video_id: str) -> Dict[str, Any]:
    row = await M._pair_video(ctx, match_id, video_id)
    from app.mentor_evaluation_request_rules import video_provider

    provider = row.get("provider") or video_provider(R.s(row.get("url")))
    if (row.get("kind") or "link") == "upload" or provider != "youtube" or not Y.watch_url(row.get("url")):
        raise C.err(422, "NOT_YOUTUBE", Y.MESSAGES["NOT_YOUTUBE"])
    return row


async def _mirror_row(video: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not video.get("mirror_upload_id"):
        return None
    return await C.one(select(mentor_uploads).where(mentor_uploads.c.id == video["mirror_upload_id"]))


@router.post("/pairs/{pair_id}/matches/{match_id}/videos/{video_id}/copy")
async def start_copy(pair_id: str, match_id: str, video_id: str, actor: Actor = Depends(mentor_actor)):
    """Zakłada kopię (albo zwraca trwającą/gotową; po błędzie zaczyna od nowa). Idempotentne."""
    ctx = await C.pair_context(pair_id, actor, action="video")
    video = await _youtube_video(ctx, match_id, video_id)
    if not Y.enabled():
        raise C.err(404, "COPY_DISABLED", "Kopie filmów YouTube są wyłączone na serwerze.")
    if not tool_ready():
        raise C.err(503, "COPY_NO_TOOL", Y.MESSAGES["NO_TOOL"])
    M._storage_or_503()
    current = await _mirror_row(video)
    if current and current.get("status") in ("downloading", "ready"):
        return await M._video_payload(ctx, video_id)
    stamp = C.now()
    if current and current.get("status") in ("failed", "expired", "removed"):
        _failed_here.discard(current["id"])
        _cancelled.discard(current["id"])
        await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == current["id"]).values(
            status="downloading", error=None, uploader_id=actor.judge_id, created_at=stamp, play_key=None, poster_key=None))
        upload_id = current["id"]
    else:
        card = await C.match_card(ctx, match_id)
        upload_id = R.new_id()
        await database.execute(mentor_uploads.insert().values(
            id=upload_id, pair_id=ctx["pair_id"], match_id=video["match_id"], video_id=None, uploader_id=actor.judge_id,
            filename=Y.safe_filename(video.get("title")), size=0, content_type="video/mp4", r2_key=None,
            status="downloading", created_at=stamp, expires_at=R.upload_expires_at(card.get("scheduled_at"), stamp),
            origin=ORIGIN, source_url=Y.watch_url(video.get("url"))))
        # Dwa równoległe kliknięcia: wygrywa ostatni zapis, a osieroconą kopię worker zamyka sam (`process_copy`: brak nagrania).
        await database.execute(update(mentor_match_videos).where(mentor_match_videos.c.id == video_id)
                               .values(mirror_upload_id=upload_id, updated_at=stamp))
    _set_live(upload_id, "queued")
    await C.touch(ctx, actor.judge_id, "copy_started", "videos", video["match_id"], {"id": video_id})
    wake_worker()
    return await M._video_payload(ctx, video_id)


@router.get("/pairs/{pair_id}/matches/{match_id}/videos/{video_id}/copy")
async def copy_status(pair_id: str, match_id: str, video_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    video = await M._pair_video(ctx, match_id, video_id)
    return {"video_id": video_id, "mirror": mirror_of(await _mirror_row(video))}


@router.delete("/pairs/{pair_id}/matches/{match_id}/videos/{video_id}/copy")
async def remove_copy(pair_id: str, match_id: str, video_id: str, actor: Actor = Depends(mentor_actor)):
    """Anuluje kopię w toku albo usuwa gotową. Nagranie YouTube, klipy i gotowe MP4 klipów zostają."""
    ctx = await C.pair_context(pair_id, actor, action="video")
    video = await M._pair_video(ctx, match_id, video_id)
    current = await _mirror_row(video)
    if current is None:
        return {"ok": True, "removed": False, "video": await M._video_payload(ctx, video_id)}
    await drop_mirror(video, current, reason="Kopię usunięto.")
    await C.touch(ctx, actor.judge_id, "copy_removed", "videos", video["match_id"], {"id": video_id})
    return {"ok": True, "removed": True, "video": await M._video_payload(ctx, video_id)}


async def drop_mirror(video: Dict[str, Any], upload: Optional[Dict[str, Any]] = None, reason: str = "Kopię usunięto.") -> None:
    """Zdejmuje kopię z nagrania: przerywa pracę, kasuje pliki w R2, wiersz kopii dostaje `removed`. Bezpieczne wielokrotnie."""
    upload = upload or await _mirror_row(video)
    await database.execute(update(mentor_match_videos).where(mentor_match_videos.c.id == video["id"])
                           .values(mirror_upload_id=None, updated_at=C.now()))
    if not upload:
        return
    _cancelled.add(upload["id"])
    _live.pop(upload["id"], None)
    M.forget_object(upload.get("r2_key"), upload.get("play_key"), upload.get("poster_key"))
    await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == upload["id"]).values(
        status="removed", error=reason, r2_key=None, play_key=None, poster_key=None))


# ─── Worker ─────────────────────────────────────────────────────────────────


def _js_runtimes() -> Optional[Dict[str, Dict[str, str]]]:
    """yt-dlp potrzebuje silnika JS do podpisów YouTube: deno z paczki PyPI (`yt-dlp[deno]`), inaczej domyślne szukanie w PATH."""
    try:
        import deno  # type: ignore

        path = deno.find_deno_bin()
        if path and os.path.exists(path):
            return {"deno": {"path": path}}
    except Exception:  # noqa: BLE001
        pass
    return None


def _download(upload_id: str, url: str, folder: str, proxy: Optional[str], cookiefile: Optional[str]) -> Dict[str, Any]:
    """Pobiera film (1080p) do `folder`, w wątku. Zwraca {path, info}. Błędy jako `Y.CopyError`."""
    import yt_dlp  # type: ignore
    from yt_dlp.utils import DownloadCancelled, DownloadError  # type: ignore

    parts: Dict[str, Any] = {}
    expected: List[Any] = []
    via = bool(proxy)

    def hook(d: Dict[str, Any]) -> None:
        if upload_id in _cancelled:
            raise DownloadCancelled("cancelled")
        fid = R.s((d.get("info_dict") or {}).get("format_id")) or R.s(d.get("filename"))
        got = float(d.get("downloaded_bytes") or 0)
        total = float(d.get("total_bytes") or d.get("total_bytes_estimate") or 0)
        parts[fid] = (got, total)
        fraction = Y.download_fraction(parts, expected)
        whole = sum(size for _fid, size in expected) or sum(t for _g, t in parts.values()) or None
        done = sum(g for g, _t in parts.values())
        speed = d.get("speed")
        eta = d.get("eta")
        if fraction is not None and speed and whole:
            eta = max(0, int((whole - done) / max(1.0, float(speed))))
        _set_live(upload_id, "downloading", fraction, speed_bps=int(speed) if speed else None, eta_s=int(eta) if eta is not None else None,
                  downloaded_bytes=int(done), total_bytes=int(whole) if whole else None, via_proxy=via)

    def post_hook(d: Dict[str, Any]) -> None:
        if d.get("status") == "started" and d.get("postprocessor") in ("Merger", "FFmpegMerger", "MoveFiles"):
            _set_live(upload_id, "finishing", 0.0, speed_bps=None, eta_s=None, via_proxy=via)

    opts: Dict[str, Any] = {
        "format": Y.FORMAT, "merge_output_format": "mp4", "outtmpl": os.path.join(folder, "source.%(ext)s"),
        "noplaylist": True, "quiet": True, "no_warnings": True, "noprogress": True, "logger": _YtLogger(),
        "progress_hooks": [hook], "postprocessor_hooks": [post_hook], "concurrent_fragment_downloads": 4,
        "retries": 5, "fragment_retries": 10, "socket_timeout": 30, "continuedl": False, "overwrites": True,
        "cachedir": os.path.join(folder, ".cache"),
    }
    if proxy:
        opts["proxy"] = proxy
    if cookiefile:
        opts["cookiefile"] = cookiefile
    runtimes = _js_runtimes()
    if runtimes:
        opts["js_runtimes"] = runtimes
    _set_live(upload_id, "connecting", 0.0, via_proxy=via)
    with yt_dlp.YoutubeDL(opts) as ydl:
        try:
            info = ydl.extract_info(url, download=False)
        except DownloadCancelled as exc:
            raise Y.CopyError("CANCELLED", Y.MESSAGES["CANCELLED"]) from exc
        except DownloadError as exc:
            raise Y.CopyError(*Y.classify(exc, via_proxy=via)) from exc
        if upload_id in _cancelled:
            raise Y.CopyError("CANCELLED", Y.MESSAGES["CANCELLED"])
        Y.check_info(info)
        expected.extend((R.s(f.get("format_id")), float(f.get("filesize") or f.get("filesize_approx") or 0))
                        for f in Y.chosen_formats(info))
        _set_live(upload_id, "downloading", 0.0, total_bytes=Y.expected_bytes(info) or None, via_proxy=via)
        try:
            done = ydl.process_ie_result(info, download=True)
        except DownloadCancelled as exc:
            raise Y.CopyError("CANCELLED", Y.MESSAGES["CANCELLED"]) from exc
        except DownloadError as exc:
            if upload_id in _cancelled:
                raise Y.CopyError("CANCELLED", Y.MESSAGES["CANCELLED"]) from exc
            raise Y.CopyError(*Y.classify(exc, via_proxy=via)) from exc
    path = _result_path(done or info, folder)
    if not path:
        raise Y.CopyError("FAILED", Y.MESSAGES["FAILED"])
    return {"path": path, "info": info}


class _YtLogger:
    """yt-dlp pisze do naszego logu (ostrzeżenia i błędy), bez wypluwania postępu na stdout."""

    def debug(self, msg: str) -> None:
        pass

    def info(self, msg: str) -> None:
        pass

    def warning(self, msg: str) -> None:
        logger.info("yt-dlp: %s", msg)

    def error(self, msg: str) -> None:
        logger.warning("yt-dlp: %s", msg)


def _result_path(info: Dict[str, Any], folder: str) -> Optional[str]:
    for item in info.get("requested_downloads") or []:
        path = item.get("filepath") or item.get("_filename")
        if path and os.path.exists(path):
            return path
    found = [os.path.join(folder, n) for n in os.listdir(folder) if n.startswith("source.") and not n.endswith((".part", ".ytdl"))]
    found = [p for p in found if os.path.isfile(p)]
    return max(found, key=os.path.getsize) if found else None


def _codecs(path: str) -> Dict[str, Any]:
    done = subprocess.run(["ffprobe", "-v", "error", "-print_format", "json", "-show_format", "-show_streams", path],
                          capture_output=True, text=True, timeout=300, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"ffprobe: {done.stderr[-400:]}")
    data = json.loads(done.stdout or "{}")
    streams = data.get("streams") or []
    video = next((s for s in streams if s.get("codec_type") == "video"), None) or {}
    audio = next((s for s in streams if s.get("codec_type") == "audio"), None) or {}
    duration = float((data.get("format") or {}).get("duration") or video.get("duration") or 0) or None
    return {"video": video.get("codec_name"), "audio": audio.get("codec_name"), "height": int(video.get("height") or 0) or None,
            "width": int(video.get("width") or 0) or None, "duration_s": duration}


def _remux(source: str, target: str) -> None:
    """H.264/AAC: przepakowanie bez kodowania, `faststart` (odtwarzanie i przewijanie od razu, zanim dojdzie cały plik)."""
    done = subprocess.run(["ffmpeg", "-hide_banner", "-nostdin", "-y", "-i", source, "-map", "0:v:0", "-map", "0:a:0?",
                           "-c", "copy", "-movflags", "+faststart", target], capture_output=True, text=True, timeout=3600, check=False)
    if done.returncode != 0 or not os.path.exists(target):
        raise RuntimeError(f"ffmpeg remux: {done.stderr[-400:]}")


def _put(upload_id: str, path: str, key: str) -> int:
    from boto3.s3.transfer import TransferConfig

    config = M.storage_config()
    total = max(1, os.path.getsize(path))
    sent = {"n": 0, "at": time.monotonic(), "last": 0, "speed": 0.0}

    def progress(chunk: int) -> None:
        sent["n"] += chunk
        now = time.monotonic()
        if now - sent["at"] >= 0.7:
            inst = (sent["n"] - sent["last"]) / (now - sent["at"])
            sent["speed"] = inst if not sent["speed"] else sent["speed"] * 0.7 + inst * 0.3
            sent["at"], sent["last"] = now, sent["n"]
        speed = sent["speed"] or None
        eta = int((total - sent["n"]) / speed) if speed else None
        _set_live(upload_id, "uploading", sent["n"] / total, speed_bps=int(speed) if speed else None, eta_s=eta,
                  downloaded_bytes=sent["n"], total_bytes=total)

    transfer = TransferConfig(multipart_threshold=64 * 1024 ** 2, multipart_chunksize=64 * 1024 ** 2, max_concurrency=4)
    M.s3_client(config).upload_file(path, config["bucket"], key, ExtraArgs={"ContentType": "video/mp4"}, Callback=progress,
                                    Config=transfer)
    return os.path.getsize(path)


def _cookie_file(folder: str) -> Optional[str]:
    text = Y.cookies_text()
    if not text:
        return None
    path = os.path.join(folder, "cookies.txt")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


async def _still_wanted(upload_id: str) -> bool:
    row = await C.one(select(mentor_uploads.c.status).where(mentor_uploads.c.id == upload_id))
    return bool(row and row.get("status") == "downloading") and upload_id not in _cancelled


async def process_copy(row: Dict[str, Any]) -> None:
    upload_id = row["id"]
    video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.mirror_upload_id == upload_id))
    if not video:
        await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == upload_id)
                               .values(status="removed", error="Nagranie usunięto."))
        return
    url = Y.watch_url(row.get("source_url") or video.get("url"))
    if not url:
        raise Y.CopyError("NOT_YOUTUBE", Y.MESSAGES["NOT_YOUTUBE"])
    folder = await asyncio.to_thread(M.make_tmpdir, "mentor-yt-")
    try:
        cookiefile = await asyncio.to_thread(_cookie_file, folder)
        tries = Y.attempts()
        result: Optional[Dict[str, Any]] = None
        for n, proxy in enumerate(tries):
            try:
                result = await asyncio.to_thread(_download, upload_id, url, folder, proxy, cookiefile)
                break
            except Y.CopyError as exc:
                if exc.code == "CANCELLED" or n + 1 >= len(tries) or not Y.retry_through_proxy(exc.code):
                    raise
                logger.info("mentor: kopia %s - YouTube odmówił prosto z serwera (%s), próba przez proxy", upload_id, exc.code)
                for name in os.listdir(folder):
                    if name.startswith("source."):
                        os.remove(os.path.join(folder, name))
        assert result is not None
        if not await _still_wanted(upload_id):
            return
        source = result["path"]
        meta = await asyncio.to_thread(_codecs, source)
        target = os.path.join(folder, "play.mp4")
        if meta["video"] == "h264" and meta["audio"] in ("aac", None):
            _set_live(upload_id, "finishing", 0.5, speed_bps=None, eta_s=None)
            await asyncio.to_thread(_remux, source, target)
        else:
            _set_live(upload_id, "converting", 0.0, speed_bps=None, eta_s=None)
            await asyncio.to_thread(M.transcode, source, target, meta.get("height"), meta.get("duration_s"),
                                    lambda value: _set_live(upload_id, "converting", value), lambda: upload_id in _cancelled)
            if upload_id in _cancelled:
                return
        await asyncio.to_thread(os.remove, source)
        poster_path = os.path.join(folder, "poster.jpg")
        has_poster = await asyncio.to_thread(M.poster, target, poster_path, meta.get("duration_s"))
        base = M.object_key(row["pair_id"], R.s(row["match_id"]).replace(":", "_"), upload_id)
        play_key, poster_key = f"{base}/play.mp4", f"{base}/poster.jpg"
        _set_live(upload_id, "uploading", 0.0)
        size = await asyncio.to_thread(_put, upload_id, target, play_key)
        if has_poster:
            await asyncio.to_thread(M.put_file, poster_path, poster_key, "image/jpeg")
        if not await _still_wanted(upload_id):  # usunięto w trakcie wysyłki: nie zostawiamy sierot w R2
            M.forget_object(play_key, poster_key if has_poster else None)
            return
        info = result["info"]
        await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == upload_id).values(
            status="ready", play_key=play_key, poster_key=poster_key if has_poster else None, error=None, size=size,
            duration_s=meta.get("duration_s"), width=meta.get("width"), height=meta.get("height"),
            filename=Y.safe_filename(info.get("title") or video.get("title"))))
        if not video.get("duration_s") and meta.get("duration_s"):
            await database.execute(update(mentor_match_videos).where(mentor_match_videos.c.id == video["id"])
                                   .values(duration_s=int(meta["duration_s"]), updated_at=C.now()))
        await C.touch(row["pair_id"], row["uploader_id"], "copy_ready", "videos", row["match_id"], {"id": video["id"]})
        logger.info("mentor: kopia YouTube %s gotowa (%s MB, %sp)", upload_id, size // (1024 * 1024), meta.get("height"))
    finally:
        _live.pop(upload_id, None)
        await asyncio.to_thread(shutil.rmtree, folder, True)


async def next_copy() -> Optional[Dict[str, Any]]:
    return await C.one(select(mentor_uploads).where(mentor_uploads.c.origin == ORIGIN)
                       .where(mentor_uploads.c.status == "downloading")
                       .where(mentor_uploads.c.id.notin_(list(_failed_here) or [""]))
                       .order_by(mentor_uploads.c.created_at.asc()).limit(1))


async def _fail(row: Dict[str, Any], message: str) -> None:
    _failed_here.add(row["id"])
    await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == row["id"])
                           .where(mentor_uploads.c.status == "downloading").values(status="failed", error=message[:300]))
    video = await C.one(select(mentor_match_videos.c.id).where(mentor_match_videos.c.mirror_upload_id == row["id"]))
    await C.touch(row["pair_id"], row["uploader_id"], "copy_failed", "videos", row["match_id"], {"id": (video or {}).get("id")})


async def process_next() -> bool:
    row = await next_copy()
    if not row:
        return False
    try:
        await process_copy(row)
    except Y.CopyError as exc:
        if exc.code != "CANCELLED":
            logger.info("mentor: kopia YouTube %s nieudana: %s", row["id"], exc.code)
            await _fail(row, exc.message)
        else:
            _failed_here.add(row["id"])
    except Exception:  # noqa: BLE001 - jedna zła kopia nie zatrzymuje kolejki
        logger.warning("mentor: kopia YouTube %s nieudana", row["id"], exc_info=True)
        await _fail(row, Y.MESSAGES["FAILED"])
    return True


async def run_copy_worker() -> None:
    """Pętla w tle: jedna kopia naraz; budzi ją „Zrób kopię”, inaczej sprawdza co 60 s."""
    global _wake_event
    _wake_event = asyncio.Event()
    await asyncio.sleep(25)
    while True:
        try:
            busy = await process_next()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("mentor: przebieg kolejki kopii nieudany")
            busy = False
        if busy:
            continue
        _wake_event.clear()
        try:
            await asyncio.wait_for(_wake_event.wait(), timeout=60)
        except asyncio.TimeoutError:
            pass

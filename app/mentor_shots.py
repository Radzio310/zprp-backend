"""Panel „Mentor" - zrzuty klatek (02.11.2026). Kontrakt: `docs/mentor-panel.md`, sekcja 13.

Zrzut to moment nagrania meczu pary (`at_s` z ułamkiem) z rysunkiem (kształty 0..1 względem kadru), opcjonalnym obrazem
w magazynie nagrań i opcjonalnym powiązaniem z klipem. Obraz pochodzi z przeglądarki (wgranie JPEG/WebP) albo z serwera
(ffmpeg na pliku/Veo, connector Bastionu); YouTube i zwykłe linki obrazu nie mają (`image_status = none` z powodem).
Uprawnienia i błędy jak przy klipach (`C.pair_context`, `C.check`), adresy podpisane nigdy nie trafiają do logów.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update

from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app import mentor_shot_render as SH
from app import mentor_shot_rules as SR
from app.db import database, mentor_clips, mentor_comments, mentor_match_videos, mentor_shots, mentor_threads, mentor_uploads
from app.mentor_panel_auth import mentor_actor

logger = logging.getLogger("app.mentor_panel")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor Zrzuty"])
Actor = C.MentorActor

FRAME_TIMEOUT_S = 90
BASTION_FRAME_TIMEOUT_S = 80.0
#: Testy ustawiają `True`, żeby zadanie obrazu wykonało się w tym samym żądaniu (zamiast w tle).
INLINE = False
_tasks: set = set()


# ─── Magazyn (cienka warstwa, podmieniana w testach) ────────────────────────


def store_put(key: str, data: bytes, content_type: str) -> None:
    from app import mentor_panel_media as M

    config = M.storage_config()
    M.s3_client(config).put_object(Bucket=config["bucket"], Key=key, Body=data, ContentType=content_type)


def store_get(key: str) -> bytes:
    from app import mentor_panel_media as M

    config = M.storage_config()
    return M.s3_client(config).get_object(Bucket=config["bucket"], Key=key)["Body"].read()


def store_forget(*keys: Optional[str]) -> None:
    from app import mentor_panel_media as M

    M.forget_object(*keys)


def store_ready() -> bool:
    from app import mentor_panel_media as M

    return M.storage_ready()


def store_url(key: Optional[str]) -> Optional[str]:
    from app import mentor_panel_media as M

    return M.presign_get(key, M.PLAY_URL_TTL) if key else None


def _storage_or_503() -> None:
    if not store_ready():
        raise C.err(503, "STORAGE_OFF", SR.REASONS["STORAGE_OFF"])


# ─── Kształt odpowiedzi ─────────────────────────────────────────────────────


async def _thread_summaries(pair_id: str, shot_ids: List[str]) -> Dict[str, Dict[str, int]]:
    out = {i: {"total": 0, "open": 0, "comments": 0} for i in shot_ids}
    if not shot_ids:
        return out
    found = await C.rows(select(mentor_threads.c.id, mentor_threads.c.target_id, mentor_threads.c.status)
                         .where(mentor_threads.c.pair_id == pair_id).where(mentor_threads.c.target_kind == "shot")
                         .where(mentor_threads.c.target_id.in_(shot_ids)))
    owner = {t["id"]: R.s(t["target_id"]) for t in found}
    for t in found:
        entry = out[R.s(t["target_id"])]
        entry["total"] += 1
        entry["open"] += 1 if t.get("status") == "open" else 0
    if owner:
        for c in await C.rows(select(mentor_comments.c.thread_id, func.count().label("n")).where(mentor_comments.c.thread_id.in_(list(owner)))
                              .where(mentor_comments.c.deleted_at.is_(None)).group_by(mentor_comments.c.thread_id)):
            out[owner[c["thread_id"]]]["comments"] += int(c["n"] or 0)
    return out


def shot_shape(ctx: Dict[str, Any], row: Dict[str, Any], names: Dict[str, Dict[str, Any]], threads: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    status = R.s(row.get("image_status")) or "none"
    reason = R.s(row.get("image_reason")) or None
    if status == "processing" and SR.stale_processing(row.get("updated_at"), C.now()):
        status, reason = "failed", "FRAME_TIMEOUT"  # zadanie przerwane (restart serwera): użytkownik może ponowić
    ready = status == "ready"
    owner = R.s(row.get("author_id")) == ctx["actor"].judge_id
    return {
        "id": row["id"], "pair_id": row.get("pair_id"), "match_id": row.get("match_id"), "video_id": row.get("video_id"),
        "at_s": row.get("at_s"), "title": row.get("title"), "note": row.get("note"),
        "category_ids": R.json_value(row.get("category_ids"), []), "shapes": R.json_value(row.get("shapes_json"), []),
        "view": SR.view_of(row), "clip_id": row.get("clip_id"), "attach_mode": R.s(row.get("attach_mode")) or "auto",
        "image_status": status, "image_reason": reason, "image_message": SR.reason_text(reason),
        "image_source": row.get("image_source") if ready else None,
        "image_url": store_url(row.get("image_key")) if ready else None,
        "thumb_url": store_url(row.get("thumb_key")) if ready else None,
        "width": row.get("width") if ready else None, "height": row.get("height") if ready else None,
        "author": C.person(names, row.get("author_id")), **C.acted_fields(names, row),
        "created_at": row.get("created_at"), "updated_at": row.get("updated_at"), "can_edit": C.may(ctx, "edit", owner=owner),
        "threads": threads or {"total": 0, "open": 0, "comments": 0},
    }


async def shots_payload(ctx: Dict[str, Any], rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    names = await C.people({r.get("author_id") for r in rows} | {r.get("acted_by") for r in rows})
    threads = await _thread_summaries(ctx["pair_id"], [r["id"] for r in rows])
    return [shot_shape(ctx, r, names, threads.get(r["id"])) for r in rows]


async def shot_payload(ctx: Dict[str, Any], shot_id: str) -> Dict[str, Any]:
    row = await C.one(select(mentor_shots).where(mentor_shots.c.id == shot_id))
    return (await shots_payload(ctx, [row]))[0]


async def room_shots(ctx: Dict[str, Any], match_id: str) -> List[Dict[str, Any]]:
    """Lista zrzutów meczu do `GET /matches/{id}` (pokój). Błąd zrzutów nigdy nie psuje pokoju."""
    try:
        found = await C.rows(select(mentor_shots).where(mentor_shots.c.pair_id == ctx["pair_id"]).where(mentor_shots.c.match_id == match_id)
                             .where(mentor_shots.c.deleted_at.is_(None)).order_by(mentor_shots.c.at_s.asc()))
        return await shots_payload(ctx, found)
    except Exception:  # noqa: BLE001
        logger.warning("mentor: zrzuty pokoju nieodczytane", exc_info=True)
        return []


async def shot_counts(clip_ids: List[str]) -> Dict[str, int]:
    """Liczba żywych zrzutów przy klipach (pole `shots_count` klipu)."""
    if not clip_ids:
        return {}
    found = await C.rows(select(mentor_shots.c.clip_id, func.count().label("n")).where(mentor_shots.c.clip_id.in_(clip_ids))
                         .where(mentor_shots.c.deleted_at.is_(None)).group_by(mentor_shots.c.clip_id))
    return {R.s(r["clip_id"]): int(r["n"] or 0) for r in found}


async def shot_slims(shot_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Skrót zrzutu przy wątku (`thread.shot`): miniatura, czas i klip. Usunięty zrzut ma `deleted: true`."""
    ids = sorted({i for i in shot_ids if i})
    if not ids:
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for r in await C.rows(select(mentor_shots).where(mentor_shots.c.id.in_(ids))):
        ready = r.get("image_status") == "ready"
        out[r["id"]] = {"id": r["id"], "match_id": r.get("match_id"), "video_id": r.get("video_id"), "at_s": r.get("at_s"),
                        "title": r.get("title"), "clip_id": r.get("clip_id"), "image_status": r.get("image_status") or "none",
                        "thumb_url": store_url(r.get("thumb_key")) if ready else None, "deleted": r.get("deleted_at") is not None}
    return out


# ─── Nagranie, kategorie, dołączanie ────────────────────────────────────────


async def _video_of(ctx: Dict[str, Any], match_id: str, video_id: str) -> Dict[str, Any]:
    video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == video_id))
    if (not video or video.get("deleted_at") is not None or R.s(video.get("match_id")) != R.s(match_id)
            or R.s(video.get("pair_key")) != ctx["pair_key"]):
        raise C.err(404, "VIDEO_NOT_FOUND", "Nie ma takiego nagrania przy tym meczu.")
    return video


async def _video_duration(video: Dict[str, Any]) -> Optional[float]:
    if video.get("kind") == "upload" and video.get("upload_id"):
        upload = await C.one(select(mentor_uploads.c.duration_s).where(mentor_uploads.c.id == video["upload_id"]))
        if upload and upload.get("duration_s"):
            return float(upload["duration_s"])
    return float(video["duration_s"]) if video.get("duration_s") else None


async def _allowed_categories(ctx: Dict[str, Any]) -> List[str]:
    return [r["id"] for r in await C.categories(ctx) if not r.get("archived")]


async def _live_clips(pair_id: str, match_id: str) -> List[Dict[str, Any]]:
    return await C.rows(select(mentor_clips).where(mentor_clips.c.pair_id == pair_id).where(mentor_clips.c.match_id == match_id)
                        .where(mentor_clips.c.deleted_at.is_(None)))


async def _clip_for_attach(ctx: Dict[str, Any], clip_id: str, match_id: str) -> Dict[str, Any]:
    clip = await C.one(select(mentor_clips).where(mentor_clips.c.id == clip_id))
    if not clip or clip["pair_id"] != ctx["pair_id"] or clip.get("deleted_at") is not None:
        raise C.err(404, "NOT_FOUND", "Nie ma takiego klipu.")
    if R.s(clip["match_id"]) != R.s(match_id):
        raise C.err(422, "SHOT_CLIP_MATCH", "Zrzut można dołączyć tylko do klipu z tego samego meczu.")
    return clip


async def _touch_shots(pair_id: str, actor_id: str, action: str, match_id: Optional[str], data: Dict[str, Any]) -> None:
    try:
        await C.touch(pair_id, actor_id, action, "shots", match_id, data)
    except Exception:  # noqa: BLE001 - ślad nie cofa zapisu
        logger.warning("mentor: rewizja po zrzucie nieudana", exc_info=True)


async def on_clip_saved(clip: Dict[str, Any]) -> int:
    """Po utworzeniu albo zmianie zakresu klipu (wołane z `mentor_panel_library`). Zwraca liczbę zmienionych zrzutów.

    Klip zgarnia zrzuty `auto` bez klipu, które w nim mieszczą się czasowo; `manual` i `detached` zostają. Zrzut `auto`, który wypadł
    z zakresu tego klipu, szuka innego klipu (najkrótszy w zakresie) albo zostaje samodzielny."""
    try:
        shots = await C.rows(select(mentor_shots).where(mentor_shots.c.pair_id == clip["pair_id"]).where(mentor_shots.c.video_id == clip["video_id"])
                             .where(mentor_shots.c.deleted_at.is_(None)).where(mentor_shots.c.attach_mode == "auto"))
        changes = SR.reattach_after_clip_change(shots, clip)
        if not changes:
            return 0
        clips = await _live_clips(clip["pair_id"], clip["match_id"])
        by_id = {s["id"]: s for s in shots}
        for change in changes:
            shot = by_id[change["id"]]
            # Przy kilku klipach w zakresie wygrywa najkrótszy.
            target = SR.pick_clip(clips, shot.get("video_id"), float(shot["at_s"]))
            await database.execute(update(mentor_shots).where(mentor_shots.c.id == change["id"])
                                   .values(clip_id=target, updated_at=C.now()))
        await _touch_shots(clip["pair_id"], R.s(clip.get("author_id")), "shots_attached", clip["match_id"], {"clip_id": clip["id"], "count": len(changes)})
        return len(changes)
    except Exception:  # noqa: BLE001 - dołączanie zrzutów nigdy nie psuje zapisu klipu
        logger.warning("mentor: dołączanie zrzutów do klipu nieudane", exc_info=True)
        return 0


async def on_clip_deleted(clip: Dict[str, Any]) -> int:
    """Usunięcie klipu zostawia zrzuty samodzielne: `auto` może zostać zgarnięty przez inny klip, `manual` staje się `detached`."""
    try:
        shots = await C.rows(select(mentor_shots).where(mentor_shots.c.clip_id == clip["id"]).where(mentor_shots.c.deleted_at.is_(None)))
        if not shots:
            return 0
        clips = [c for c in await _live_clips(clip["pair_id"], clip["match_id"]) if c["id"] != clip["id"]]
        for shot in shots:
            mode = R.s(shot.get("attach_mode")) or "auto"
            if mode == "manual":
                values = {"clip_id": None, "attach_mode": "detached"}
            elif mode == "auto":
                values = {"clip_id": SR.pick_clip(clips, shot.get("video_id"), float(shot["at_s"]))}
            else:
                values = {"clip_id": None}
            await database.execute(update(mentor_shots).where(mentor_shots.c.id == shot["id"]).values(updated_at=C.now(), **values))
        await _touch_shots(clip["pair_id"], R.s(clip.get("author_id")), "shots_detached", clip["match_id"], {"clip_id": clip["id"], "count": len(shots)})
        return len(shots)
    except Exception:  # noqa: BLE001
        logger.warning("mentor: odłączanie zrzutów usuniętego klipu nieudane", exc_info=True)
        return 0


# ─── Źródło obrazu ──────────────────────────────────────────────────────────


class FrameError(Exception):
    """`code` z `SR.REASONS`."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


async def source_kind(video: Dict[str, Any]) -> str:
    """`file` | `veo` | `bastion` | `youtube` | `link`."""
    from app import mentor_bastion_jobs as J
    from app import mentor_veo_rules as VR

    if video.get("kind") == "upload" and video.get("upload_id"):
        return "file"
    if video.get("provider") == "veo" or VR.is_veo_url(video.get("url")):
        return "veo"
    if J.bastion_item_of(video):
        return "bastion"
    if R.s(video.get("provider")) == "youtube" and video.get("mirror_upload_id"):
        # Gotowa kopia filmu na serwerze (02.11.2026) = te same sekundy w pliku R2: klatka jak z własnego nagrania.
        mirror = await C.one(select(mentor_uploads.c.status, mentor_uploads.c.play_key)
                             .where(mentor_uploads.c.id == video["mirror_upload_id"]))
        if mirror and mirror.get("status") == "ready" and mirror.get("play_key"):
            return "file"
    return "youtube" if R.s(video.get("provider")) == "youtube" else "link"


def _run(args: List[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, timeout=timeout, check=False)


def frame_args(source: str, at_s: float, target: str, *, remote: bool) -> List[str]:
    """Jedna klatka co do klatki: `-ss` PRZED `-i` (skok po indeksie/Range), a potem dekodowanie do dokładnej klatki."""
    pre: List[str] = []
    if remote:
        from app import mentor_veo_rules as VR

        pre = VR.input_args(source)
    return ["ffmpeg", "-hide_banner", "-nostdin", "-y", *pre, "-ss", f"{at_s:.3f}", "-i", source, "-frames:v", "1", "-an",
            "-vf", "scale='min(1920,iw)':-2", "-q:v", "2", target]


def extract_frame(source: str, at_s: float, *, remote: bool) -> bytes:
    """Synchronicznie (wołać w wątku). Adres źródła jest sekretem: nie trafia do logów ani do komunikatów."""
    folder = tempfile.mkdtemp(prefix="shot-")
    target = os.path.join(folder, "frame.jpg")
    try:
        try:
            done = _run(frame_args(source, at_s, target, remote=remote), FRAME_TIMEOUT_S)
        except FileNotFoundError as exc:
            raise FrameError("FFMPEG_MISSING") from exc
        except subprocess.TimeoutExpired as exc:
            raise FrameError("FRAME_TIMEOUT") from exc
        if done.returncode != 0 or not os.path.exists(target) or os.path.getsize(target) < 500:
            raise FrameError("FRAME_FAILED")
        with open(target, "rb") as handle:
            return handle.read()
    finally:
        for name in os.listdir(folder):
            try:
                os.unlink(os.path.join(folder, name))
            except OSError:
                pass
        try:
            os.rmdir(folder)
        except OSError:
            pass


async def bastion_frame(video: Dict[str, Any], at_s: float, real_judge_id: str) -> bytes:
    """Klatka z Bastionu przez istniejący connector (`POST /frame` z `at_s`, JPEG w base64), w zakresie domyślnym, potem osobistym."""
    from app import mentor_bastion_client as CL
    from app import mentor_bastion_jobs as J
    from app import mentor_bastion_rules as BR

    flags = BR.load_flags()
    if not flags.enabled or not flags.configured:
        raise FrameError("BASTION_OFF")
    item = J.bastion_item_of(video)
    try:
        client = CL.get_client()
    except CL.ConnectorUnavailable as exc:
        raise FrameError("BASTION_UNAVAILABLE") from exc
    error: Optional[str] = None
    for scope in BR.candidate_scopes(flags):
        if scope == "personal" and not real_judge_id:
            continue
        try:
            reply = await client.request("POST", "/frame", timeout=BASTION_FRAME_TIMEOUT_S,
                                         json={"scope": scope, "judge_id": real_judge_id if scope == "personal" else None,
                                               "bunny_item_id": int(item), "at_s": float(at_s)})
        except CL.ConnectorUnavailable:
            raise FrameError("BASTION_UNAVAILABLE") from None
        body = reply.body if isinstance(reply.body, dict) else {}
        if reply.status == 200 and isinstance(body.get("jpeg_b64"), str):
            try:
                return base64.b64decode(body["jpeg_b64"])
            except ValueError as exc:
                raise FrameError("BASTION_FRAME_FAILED") from exc
        code = R.s(body.get("code") or body.get("error"))
        if code == "BASTION_AUTH_REQUIRED" or reply.status == 401:
            error = error or "BASTION_AUTH_REQUIRED"
        elif code == "BASTION_NOT_CONNECTED" or reply.status == 409:
            error = error or "BASTION_NOT_CONNECTED"
        else:
            error = "BASTION_FRAME_FAILED"
    raise FrameError(error or "BASTION_NOT_CONNECTED")


async def server_frame_bytes(video: Dict[str, Any], kind: str, at_s: float, real_judge_id: str) -> bytes:
    """Surowy obraz klatki z serwera. Rzuca `FrameError`."""
    if kind == "file":
        from app.mentor_panel_media import file_upload_id

        upload = await C.one(select(mentor_uploads).where(mentor_uploads.c.id == file_upload_id(video)))
        if not upload or upload.get("status") != "ready" or not upload.get("play_key"):
            raise FrameError("VIDEO_NOT_READY")
        from app import mentor_panel_media as M

        if not M.storage_ready():
            raise FrameError("STORAGE_OFF")
        source = M.presign_get(upload["play_key"], M.SOURCE_URL_TTL)
        if not source:
            raise FrameError("STORAGE_OFF")
        return await asyncio.to_thread(extract_frame, source, at_s, remote=True)
    if kind == "veo":
        from app import mentor_veo

        try:
            source = await mentor_veo.resolve_media(video)
        except mentor_veo.VeoError as exc:
            raise FrameError({"private": "VEO_PRIVATE", "gone": "VEO_GONE", "processing": "VEO_PROCESSING"}.get(exc.status, "VEO_UNAVAILABLE")) from exc
        return await asyncio.to_thread(extract_frame, source, at_s, remote=True)
    if kind == "bastion":
        return await bastion_frame(video, at_s, real_judge_id)
    raise FrameError("YOUTUBE_NO_IMAGE" if kind == "youtube" else "LINK_NO_IMAGE")


async def _save_image(row: Dict[str, Any], jpeg: bytes, thumb: bytes, width: int, height: int, source: str) -> None:
    """Zapis obrazu do magazynu i bazy; poprzednie obiekty są kasowane dopiero po udanym zapisie."""
    from app import mentor_panel_media as M

    stamp = C.now()
    base = f"{row['id']}-{int(stamp.timestamp() * 1000)}"
    key = M.object_key(row["pair_id"], "shots", f"{base}.jpg")
    thumb_key = M.object_key(row["pair_id"], "shots", f"{base}-thumb.jpg")
    await asyncio.to_thread(store_put, key, jpeg, "image/jpeg")
    await asyncio.to_thread(store_put, thumb_key, thumb, "image/jpeg")
    old = (row.get("image_key"), row.get("thumb_key"))
    await database.execute(update(mentor_shots).where(mentor_shots.c.id == row["id"]).values(
        image_status="ready", image_reason=None, image_source=source, image_key=key, thumb_key=thumb_key, image_size=len(jpeg),
        width=width, height=height, image_updated_at=stamp, updated_at=stamp))
    store_forget(*old)


async def run_frame(shot_id: str, real_judge_id: str) -> None:
    """Zadanie obrazu z serwera. Kończy się zawsze stanem `ready` albo `failed` (z kodem powodu)."""
    row = await C.one(select(mentor_shots).where(mentor_shots.c.id == shot_id))
    if not row or row.get("deleted_at") is not None or row.get("image_status") != "processing":
        return
    code: Optional[str] = None
    try:
        video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == row["video_id"]))
        if not video or video.get("deleted_at") is not None:
            raise FrameError("FRAME_FAILED")
        raw = await server_frame_bytes(video, await source_kind(video), float(row["at_s"]), real_judge_id)
        prepared = await asyncio.to_thread(SH.prepare_stored, raw)
        await _save_image(row, prepared["jpeg"], prepared["thumb"], prepared["width"], prepared["height"], "server")
    except FrameError as exc:
        code = exc.code
    except R.RuleError:
        code = "FRAME_FAILED"
    except Exception:  # noqa: BLE001 - treść wyjątku może zawierać adres źródła, więc nie logujemy jej
        logger.warning("mentor: klatka zrzutu %s nieudana", shot_id)
        code = "FRAME_FAILED"
    if code:
        await database.execute(update(mentor_shots).where(mentor_shots.c.id == shot_id).values(
            image_status="failed", image_reason=code, updated_at=C.now()))
    await _touch_shots(row["pair_id"], R.s(row.get("author_id")), "shot_image", row["match_id"], {"id": shot_id, "status": "failed" if code else "ready"})


async def request_frame(row: Dict[str, Any], real_judge_id: str) -> None:
    """Ustawia `processing` (albo `none`/`failed` z powodem dla źródeł bez obrazu) i uruchamia zadanie."""
    video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == row["video_id"]))
    if not video:
        raise C.err(404, "VIDEO_NOT_FOUND", "Nie ma takiego nagrania przy tym meczu.")
    kind = await source_kind(video)
    if kind in ("youtube", "link"):
        await database.execute(update(mentor_shots).where(mentor_shots.c.id == row["id"]).values(
            image_status="none", image_reason="YOUTUBE_NO_IMAGE" if kind == "youtube" else "LINK_NO_IMAGE", updated_at=C.now()))
        return
    if row.get("image_status") == "processing" and not SR.stale_processing(row.get("updated_at"), C.now()):
        return
    if kind in ("file", "veo", "bastion") and not store_ready():
        raise C.err(503, "STORAGE_OFF", SR.REASONS["STORAGE_OFF"])
    await database.execute(update(mentor_shots).where(mentor_shots.c.id == row["id"]).values(
        image_status="processing", image_reason=None, updated_at=C.now()))
    if INLINE:
        await run_frame(row["id"], real_judge_id)
        return
    task = asyncio.get_running_loop().create_task(run_frame(row["id"], real_judge_id))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


# ─── Trasy ──────────────────────────────────────────────────────────────────


async def _shot_ctx(shot_id: str, actor: Actor, *, action: str = "view") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    row = await C.one(select(mentor_shots).where(mentor_shots.c.id == shot_id))
    if not row or row.get("deleted_at") is not None:
        raise C.err(404, "NOT_FOUND", "Nie ma takiego zrzutu.")
    return await C.pair_context(row["pair_id"], actor, action=action), row


def _edit_check(ctx: Dict[str, Any], row: Dict[str, Any], actor: Actor) -> None:
    C.check(ctx, "edit", owner=R.s(row.get("author_id")) == actor.judge_id)


def _rule(exc: R.RuleError):
    return C.rule_error(exc)


class ShotBody(BaseModel):
    match_id: str = Field(min_length=1, max_length=80)
    video_id: str = Field(min_length=1, max_length=80)
    at_s: float
    title: Optional[str] = Field(default=None, max_length=400)
    note: Optional[str] = Field(default=None, max_length=5000)
    category_ids: List[str] = Field(default_factory=list, max_length=20)
    shapes: Optional[List[Any]] = Field(default=None, max_length=200)
    #: Kadr zrzutu zrobionego w zoomie `{cx, cy, zoom}` (zoom 1..6); null = cała klatka.
    view: Optional[Any] = None
    #: Podane `clip_id` = dołączenie ręczne (`manual`); pominięte = automat (`auto`); `attach_mode: "detached"` = bez klipu.
    clip_id: Optional[str] = Field(default=None, max_length=80)
    attach_mode: Optional[str] = Field(default=None, max_length=20)
    #: true = od razu zamów obraz z serwera (plik, Veo, Bastion).
    server_frame: bool = False


class ShotPatch(BaseModel):
    title: Optional[str] = Field(default=None, max_length=400)
    note: Optional[str] = Field(default=None, max_length=5000)
    category_ids: Optional[List[str]] = Field(default=None, max_length=20)
    shapes: Optional[List[Any]] = Field(default=None, max_length=200)
    #: Kadr (jak przy tworzeniu); null = cała klatka.
    view: Optional[Any] = None
    #: Napis = dołącz ręcznie; null = odłącz (`detached`).
    clip_id: Optional[str] = Field(default=None, max_length=80)
    #: `auto` = wróć do automatu (serwer sam wybierze najkrótszy klip w zakresie).
    attach_mode: Optional[str] = Field(default=None, max_length=20)


@router.get("/pairs/{pair_id}/shots")
async def list_shots(pair_id: str, match_id: str = Query("", max_length=80), clip_id: str = Query("", max_length=80),
                     video_id: str = Query("", max_length=80), category: str = Query("", max_length=80),
                     author: str = Query("", max_length=40), q: str = Query("", max_length=80),
                     standalone: bool = Query(False), actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    query = select(mentor_shots).where(mentor_shots.c.pair_id == ctx["pair_id"]).where(mentor_shots.c.deleted_at.is_(None))
    for column, value in ((mentor_shots.c.match_id, match_id), (mentor_shots.c.clip_id, clip_id), (mentor_shots.c.video_id, video_id),
                          (mentor_shots.c.author_id, author)):
        if value:
            query = query.where(column == value)
    if standalone:
        query = query.where(mentor_shots.c.clip_id.is_(None))
    found = await C.rows(query.order_by(mentor_shots.c.created_at.desc()).limit(1000))
    if category:
        found = [r for r in found if category in R.json_value(r.get("category_ids"), [])]
    needle = q.strip().casefold()
    if needle:
        found = [r for r in found if needle in f"{R.s(r.get('title'))} {R.s(r.get('note'))}".casefold()]
    return {"shots": await shots_payload(ctx, found), "rev": ctx["rev"]}


@router.get("/shots/{shot_id}")
async def get_shot(shot_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _shot_ctx(shot_id, actor)
    return (await shots_payload(ctx, [row]))[0]


@router.post("/pairs/{pair_id}/shots")
async def create_shot(pair_id: str, body: ShotBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="create")
    card = await C.match_card(ctx, body.match_id)
    video = await _video_of(ctx, card["match_id"], body.video_id)
    try:
        at_s = SR.validate_at(body.at_s, await _video_duration(video))
        shapes = SR.clean_shapes(body.shapes)
        view = SR.clean_view(body.view)
    except R.RuleError as exc:
        raise _rule(exc) from exc
    live = await C.one(select(func.count().label("n")).select_from(mentor_shots).where(mentor_shots.c.pair_id == ctx["pair_id"])
                       .where(mentor_shots.c.match_id == card["match_id"]).where(mentor_shots.c.deleted_at.is_(None)))
    if int((live or {}).get("n") or 0) >= SR.MAX_SHOTS_PER_MATCH:
        raise C.err(409, "SHOT_LIMIT", f"Na jednym meczu może być najwyżej {SR.MAX_SHOTS_PER_MATCH} zrzutów.")
    if body.attach_mode is not None and body.attach_mode not in ("auto", "detached"):
        raise C.err(422, "SHOT_ATTACH_MODE", "Przy tworzeniu zrzutu attach_mode to auto albo detached.")
    clip_id, mode = None, "auto"
    if body.clip_id:
        clip_id, mode = (await _clip_for_attach(ctx, body.clip_id, card["match_id"]))["id"], "manual"
    elif body.attach_mode == "detached":
        mode = "detached"
    else:
        clip_id = SR.pick_clip(await _live_clips(ctx["pair_id"], card["match_id"]), video["id"], at_s)
    stamp = C.now()
    row = {
        "id": R.new_id(), "pair_id": ctx["pair_id"], "match_id": card["match_id"], "video_id": video["id"], "at_s": at_s,
        "title": R.plain(body.title, SR.MAX_TITLE) or None, "note": R.plain(body.note, SR.MAX_NOTE) or None,
        "category_ids": C.dumps(R.clean_category_ids(body.category_ids, await _allowed_categories(ctx))),
        "shapes_json": C.dumps(shapes), "view_json": C.dumps(view) if view else None, "clip_id": clip_id, "attach_mode": mode, "image_status": "none", "author_id": actor.judge_id,
        "acted_by": actor.acted_by, "created_at": stamp, "updated_at": stamp,
    }
    kind = await source_kind(video)
    if kind in ("youtube", "link"):
        row["image_reason"] = "YOUTUBE_NO_IMAGE" if kind == "youtube" else "LINK_NO_IMAGE"
    await database.execute(mentor_shots.insert().values(**row))
    await C.touch(ctx, actor.judge_id, "shot_created", "shots", card["match_id"], {"id": row["id"]})
    if body.server_frame:
        from app import mentor_bastion_jobs as J

        await request_frame(row, J.real_judge_of(actor))
    return await shot_payload(ctx, row["id"])


@router.patch("/shots/{shot_id}")
async def update_shot(shot_id: str, body: ShotPatch, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _shot_ctx(shot_id, actor)
    _edit_check(ctx, row, actor)
    patch = body.model_dump(exclude_unset=True)
    values: Dict[str, Any] = {"updated_at": C.now()}
    if "title" in patch:
        values["title"] = R.plain(patch["title"], SR.MAX_TITLE) or None
    if "note" in patch:
        values["note"] = R.plain(patch["note"], SR.MAX_NOTE) or None
    if patch.get("category_ids") is not None:
        values["category_ids"] = C.dumps(R.clean_category_ids(patch["category_ids"], await _allowed_categories(ctx)))
    if "shapes" in patch:
        try:
            values["shapes_json"] = C.dumps(SR.clean_shapes(patch["shapes"]))
        except R.RuleError as exc:
            raise _rule(exc) from exc
    if "view" in patch:
        try:
            view = SR.clean_view(patch["view"])
        except R.RuleError as exc:
            raise _rule(exc) from exc
        values["view_json"] = C.dumps(view) if view else None
    mode = patch.get("attach_mode")
    if mode is not None and mode not in SR.ATTACH_MODES:
        raise C.err(422, "SHOT_ATTACH_MODE", "attach_mode to auto, manual albo detached.")
    if "clip_id" in patch:
        if patch["clip_id"]:
            if mode not in (None, "manual"):
                raise C.err(422, "SHOT_ATTACH_MODE", "Z podanym clip_id attach_mode to manual.")
            values.update(clip_id=(await _clip_for_attach(ctx, patch["clip_id"], row["match_id"]))["id"], attach_mode="manual")
        else:
            if mode not in (None, "detached"):
                raise C.err(422, "SHOT_ATTACH_MODE", "Odłączenie (clip_id null) ustawia attach_mode detached.")
            values.update(clip_id=None, attach_mode="detached")
    elif mode == "auto":
        picked = SR.pick_clip(await _live_clips(ctx["pair_id"], row["match_id"]), row["video_id"], float(row["at_s"]))
        values.update(clip_id=picked, attach_mode="auto")
    elif mode == "detached":
        values.update(clip_id=None, attach_mode="detached")
    elif mode == "manual":
        if not row.get("clip_id"):
            raise C.err(422, "SHOT_ATTACH_MODE", "Dołączenie ręczne wymaga clip_id.")
        values["attach_mode"] = "manual"
    await database.execute(update(mentor_shots).where(mentor_shots.c.id == shot_id).values(**values))
    await C.touch(ctx, actor.judge_id, "shot_updated", "shots", row["match_id"], {"id": shot_id})
    return await shot_payload(ctx, shot_id)


@router.delete("/shots/{shot_id}")
async def delete_shot(shot_id: str, actor: Actor = Depends(mentor_actor)):
    """Do kosza jak klip (`deleted_at`); obraz w magazynie jest kasowany, wątki zostają."""
    ctx, row = await _shot_ctx(shot_id, actor)
    _edit_check(ctx, row, actor)
    await database.execute(update(mentor_shots).where(mentor_shots.c.id == shot_id).values(
        deleted_at=C.now(), image_key=None, thumb_key=None, image_status="none", image_reason=None))
    store_forget(row.get("image_key"), row.get("thumb_key"))
    await C.touch(ctx, actor.judge_id, "shot_deleted", "shots", row["match_id"], {"id": shot_id})
    return {"ok": True}


async def _read_limited(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > SR.MAX_IMAGE_BYTES:
        raise C.err(413, "SHOT_IMAGE_TOO_LARGE", f"Obraz jest za duży (najwyżej {SR.MAX_IMAGE_BYTES // (1024 * 1024)} MB).")
    data = bytearray()
    async for chunk in request.stream():
        data += chunk
        if len(data) > SR.MAX_IMAGE_BYTES:
            raise C.err(413, "SHOT_IMAGE_TOO_LARGE", f"Obraz jest za duży (najwyżej {SR.MAX_IMAGE_BYTES // (1024 * 1024)} MB).")
    return bytes(data)


@router.post("/shots/{shot_id}/image")
async def upload_image(shot_id: str, request: Request, actor: Actor = Depends(mentor_actor)):
    """Klatka złapana w przeglądarce (canvas): surowe ciało żądania, `Content-Type: image/jpeg` albo `image/webp`."""
    ctx, row = await _shot_ctx(shot_id, actor)
    _edit_check(ctx, row, actor)
    data = await _read_limited(request)
    try:
        SR.check_upload(data, request.headers.get("content-type"))
        prepared = await asyncio.to_thread(SH.prepare_stored, data)
    except R.RuleError as exc:
        raise _rule(exc) from exc
    _storage_or_503()
    await _save_image(row, prepared["jpeg"], prepared["thumb"], prepared["width"], prepared["height"], "browser")
    await C.touch(ctx, actor.judge_id, "shot_image", "shots", row["match_id"], {"id": shot_id, "status": "ready"})
    return await shot_payload(ctx, shot_id)


@router.post("/shots/{shot_id}/frame")
async def request_server_frame(shot_id: str, actor: Actor = Depends(mentor_actor)):
    """Obraz z serwera (ffmpeg na pliku/Veo, connector Bastionu). Odpowiedź od razu: `processing`; gotowość po `GET /shots/{id}`."""
    from app import mentor_bastion_jobs as J

    ctx, row = await _shot_ctx(shot_id, actor)
    _edit_check(ctx, row, actor)
    await request_frame(row, J.real_judge_of(actor))
    await C.touch(ctx, actor.judge_id, "shot_image", "shots", row["match_id"], {"id": shot_id, "status": "requested"})
    return await shot_payload(ctx, shot_id)


def _ready_or_error(row: Dict[str, Any]) -> None:
    """Pobranie i Teczka wymagają gotowego obrazu; w innym stanie czytelny kod po polsku."""
    status = R.s(row.get("image_status")) or "none"
    if status == "processing" and SR.stale_processing(row.get("updated_at"), C.now()):
        status = "failed"
    if status == "ready" and row.get("image_key"):
        return
    reason = R.s(row.get("image_reason"))
    if status == "processing":
        raise C.err(409, "SHOT_IMAGE_PROCESSING", SR.PROCESSING_MESSAGE)
    if status == "failed":
        raise C.err(409, "SHOT_IMAGE_FAILED", SR.reason_text(reason) or SR.REASONS["FRAME_FAILED"])
    raise C.err(409, "SHOT_NO_IMAGE", SR.reason_text(reason) or SR.NO_IMAGE_MESSAGE)


async def render_from_row(row: Dict[str, Any], *, shapes: bool = True, lines: Optional[List[str]] = None, view: bool = True) -> bytes:
    """Obraz z magazynu + zaznaczenia (+ pasek) -> PNG. Bez kontekstu pary: używa też worker Teczki."""
    raw = await asyncio.to_thread(store_get, row["image_key"])
    frame = SR.view_of(row) if view else None
    return await asyncio.to_thread(SH.render_png, raw, R.json_value(row.get("shapes_json"), []) if shapes else [], lines, frame)


async def render_shot_png(ctx: Dict[str, Any], row: Dict[str, Any], *, banner: bool = False, shapes: bool = True,
                         view: bool = True) -> Tuple[bytes, str]:
    """PNG z wypalonymi zaznaczeniami i (opcjonalnie) paskiem: mecz, minuta nagrania, kategoria. Wynik: (bajty, nazwa pliku)."""
    _ready_or_error(row)
    info = await match_info(ctx, row)
    lines = SR.banner_lines(info["label"], float(row["at_s"]), info["category"]) if banner else None
    try:
        data = await render_from_row(row, shapes=shapes, lines=lines, view=view)
    except Exception as exc:  # noqa: BLE001 - brak obiektu w magazynie
        raise C.err(503, "STORAGE_OFF", SR.REASONS["STORAGE_OFF"]) from exc
    return data, SR.png_filename(row.get("title"), info["code"], float(row["at_s"]))


async def match_info(ctx: Dict[str, Any], row: Dict[str, Any]) -> Dict[str, str]:
    """Podpis meczu (drużyny i numer), numer i nazwa pierwszej kategorii zrzutu."""
    from app import mentor_clip_download as D

    shared = D.Context(ctx)
    card = await shared.card(row["match_id"])
    names = await shared.category_names()
    category = next((names[R.s(c)] for c in R.json_value(row.get("category_ids"), []) if names.get(R.s(c))), "Bez kategorii")
    teams = " - ".join(p for p in (R.s(card.get("home")), R.s(card.get("away"))) if p)
    code = R.s(card.get("code"))
    label = " ".join(p for p in (teams, f"({code})" if code else "") if p)
    return {"label": label, "code": code, "category": category, "card": card}


@router.get("/shots/{shot_id}/png")
async def download_png(shot_id: str, banner: bool = Query(False), shapes: bool = Query(True), actor: Actor = Depends(mentor_actor),
                       view: bool = Query(True)):
    """Pobranie PNG: obraz z wypalonymi zaznaczeniami (`shapes=false` = sama klatka), `banner=true` dokleja pasek pod kadrem.
    `view=true` (domyślnie) tnie do kadru zrzutu i skaluje do rozmiaru klatki, `view=false` daje całą klatkę (też przy `shapes=false`).
    Odpowiedź to sam plik (`Content-Disposition: attachment`), bez adresu podpisanego."""
    from app import mentor_panel_media as M

    ctx, row = await _shot_ctx(shot_id, actor)
    data, filename = await render_shot_png(ctx, row, banner=banner, shapes=shapes, view=view)
    return Response(content=data, media_type="image/png",
                    headers={"Content-Disposition": M._disposition(filename), "Cache-Control": "private, no-store"})

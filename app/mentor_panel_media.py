"""
Panel „Mentor" - nagrania meczu (`docs/mentor-panel.md`, 4.4, 4.5, MP4 klipów z 4.6).

  - linki YouTube/Vimeo/inne: wspólna logika z galerią aplikacji
    (`mentor_evaluations.insert_link_video` - podgląd linku, start transmisji),
  - własne nagrania: wgrywanie wieloczęściowe prosto do Cloudflare R2
    (podpisane adresy części po 64 MB), potem kolejka w procesie: ffprobe ->
    H.264/AAC MP4 faststart (do 1080p, CRF 23, veryfast) + plakat JPG,
  - MP4 klipu tylko z własnego nagrania (cięcie ffmpeg), pobieranie przez
    podpisany adres z `Content-Disposition: attachment`,
  - retencja (zadanie dzienne): oryginał znika po udanym transkodowaniu, całe
    nagranie 12 miesięcy po meczu; porzucone wgrywanie jest przerywane.

R2: zmienne `MENTOR_S3_*` (ENDPOINT, REGION, BUCKET, ACCESS_KEY_ID,
SECRET_ACCESS_KEY, PREFIX), a bez nich `BACKUP_S3_*` - obiekty pod własnym
prefiksem (domyślnie `mentor/`). ffmpeg i ffprobe są w obrazie (Dockerfile).
Kolejka: najwyżej jedno ffmpeg naraz, praca w wątku (pętla zdarzeń wolna).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app.db import database, mentor_clips, mentor_match_videos, mentor_uploads
from app.mentor_panel_auth import mentor_actor

logger = logging.getLogger("app.mentor_panel")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor"])
Actor = C.MentorActor

PLAY_URL_TTL = 6 * 3600
SOURCE_URL_TTL = 12 * 3600
DOWNLOAD_TTL = 3600
PART_URL_TTL = 6 * 3600

# ─── R2 ─────────────────────────────────────────────────────────────────────


def storage_config() -> Dict[str, str]:
    def env(name: str, default: str = "") -> str:
        return os.getenv(f"MENTOR_S3_{name}") or os.getenv(f"BACKUP_S3_{name}", default)

    config = {
        "endpoint": env("ENDPOINT"), "region": env("REGION", "auto") or "auto", "bucket": env("BUCKET"),
        "access_key": env("ACCESS_KEY_ID"), "secret_key": env("SECRET_ACCESS_KEY"),
        "prefix": (os.getenv("MENTOR_S3_PREFIX", "mentor").strip("/") or "mentor"),
    }
    if any(not config[k] for k in ("endpoint", "bucket", "access_key", "secret_key")):
        raise R.RuleError(503, "STORAGE_OFF", "Magazyn nagrań (Cloudflare R2) nie jest skonfigurowany.")
    return config


def storage_ready() -> bool:
    try:
        storage_config()
        return True
    except R.RuleError:
        return False


_clients: Dict[Tuple[str, ...], Any] = {}


def s3_client(config: Optional[Dict[str, str]] = None):
    config = config or storage_config()
    key = (config["endpoint"], config["region"], config["access_key"])
    if key not in _clients:
        import boto3
        from botocore.config import Config

        _clients[key] = boto3.client(
            "s3", endpoint_url=config["endpoint"], region_name=config["region"],
            aws_access_key_id=config["access_key"], aws_secret_access_key=config["secret_key"],
            config=Config(signature_version="s3v4", retries={"max_attempts": 3}),
        )
    return _clients[key]


def object_key(*parts: str) -> str:
    return "/".join([storage_config()["prefix"], *[str(p).strip("/") for p in parts]])


def _disposition(filename: str) -> str:
    """Nagłówek pobrania; nazwa z polskimi literami idzie też w formie RFC 5987 (`filename*`)."""
    from urllib.parse import quote

    try:
        filename.encode("ascii")
        return f'attachment; filename="{filename}"'
    except UnicodeEncodeError:
        import unicodedata

        ascii_name = unicodedata.normalize("NFKD", filename.replace("ł", "l").replace("Ł", "L")).encode("ascii", "ignore").decode() or "klip.mp4"
        return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename)}"


def presign_get(key: Optional[str], expires: int = PLAY_URL_TTL, filename: Optional[str] = None) -> Optional[str]:
    if not key:
        return None
    try:
        config = storage_config()
        params: Dict[str, Any] = {"Bucket": config["bucket"], "Key": key}
        if filename:
            params["ResponseContentDisposition"] = _disposition(filename)
            params["ResponseContentType"] = "video/mp4"
        return s3_client(config).generate_presigned_url("get_object", Params=params, ExpiresIn=expires)
    except Exception:  # noqa: BLE001 - brak magazynu = brak odtwarzania, nie błąd ekranu
        logger.warning("mentor: podpisanie adresu nieudane", exc_info=True)
        return None


def delete_objects(keys: List[Optional[str]]) -> None:
    wanted = [k for k in keys if k]
    if not wanted:
        return
    try:
        config = storage_config()
        client = s3_client(config)
        for key in wanted:
            client.delete_object(Bucket=config["bucket"], Key=key)
    except Exception:  # noqa: BLE001 - osierocone obiekty posprząta prefiks
        logger.warning("mentor: usuwanie obiektów R2 nieudane", exc_info=True)


def forget_object(*keys: Optional[str]) -> None:
    """Skasuj obiekty w tle (wątek) - zapis w bazie nie czeka na R2."""
    wanted = [k for k in keys if k]
    if not wanted:
        return
    try:
        asyncio.get_running_loop().create_task(asyncio.to_thread(delete_objects, wanted))
    except RuntimeError:
        delete_objects(wanted)


def _storage_or_503() -> Dict[str, str]:
    try:
        return storage_config()
    except R.RuleError as exc:
        raise C.rule_error(exc) from exc


# ─── Kształt nagrania ───────────────────────────────────────────────────────


async def _uploads_by_id(ids: List[str]) -> Dict[str, Dict[str, Any]]:
    ids = [i for i in ids if i]
    if not ids:
        return {}
    return {r["id"]: r for r in await C.rows(select(mentor_uploads).where(mentor_uploads.c.id.in_(ids)))}


def _auto_added(raw: Any) -> Optional[Dict[str, Any]]:
    found = R.json_value(raw, {})
    if not found.get("at"):
        return None
    return {"at": found.get("at"), "source": found.get("source")}


def video_shape(row: Dict[str, Any], names: Dict[str, Dict[str, Any]], upload: Optional[Dict[str, Any]] = None,
                ctx: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from app.mentor_evaluation_request_rules import video_provider, youtube_thumbnail
    from app import mentor_bastion_rules as bastion
    from app.mentor_video_rules import clean_sync

    kind = row.get("kind") or "link"
    sync_raw = R.json_value(row.get("sync_json"), {})
    provider = row.get("provider") or video_provider(R.s(row.get("url")))
    if provider == bastion.PROVIDER and not bastion.enabled():
        provider = "video"  # flaga wyłączona: nagranie zostaje zwykłym linkiem, stare źródła działają bez zmian
    out = {
        "id": row["id"], "kind": kind, "provider": provider,
        "url": row.get("url"), "title": row.get("title") or "", "thumbnail_url": row.get("thumbnail_url") or youtube_thumbnail(R.s(row.get("url"))),
        "duration_s": row.get("duration_s"), "sync": clean_sync(sync_raw) if sync_raw else None,
        "added_by": C.person(names, row.get("added_by")), "created_at": row.get("created_at"),
        "playable": provider in ("youtube", "vimeo", bastion.PROVIDER),
        #: Bastion: adres odtwarzania daje dopiero `POST .../videos/{id}/playback` (czasowy, wrażliwy, nie leży w nagraniu).
        "external_id": row.get("external_id") if provider == bastion.PROVIDER else None,
        "play_url": None, "poster_url": None, "upload_status": None,
        #: Automat nagrań (30.10.2026): {at, source}, gdy nagranie dodał serwer sam; null przy dodanym ręcznie.
        "auto_added": _auto_added(row.get("auto_added_json")),
    }
    if kind == "upload":
        upload = upload or {}
        status = upload.get("status") or "failed"
        ready = status == "ready" and upload.get("play_key")
        play = presign_get(upload.get("play_key")) if ready else None
        poster = presign_get(upload.get("poster_key")) if upload.get("poster_key") and status == "ready" else None
        out.update(provider="upload", url=play, play_url=play, poster_url=poster, thumbnail_url=poster,
                   playable=bool(play), upload_status=status, title=row.get("title") or upload.get("filename") or "",
                   duration_s=upload.get("duration_s") or row.get("duration_s"))
    if ctx is not None:
        out["can_edit"] = C.may(ctx, "edit", owner=R.s(row.get("added_by")) == ctx["actor"].judge_id)
        out["can_delete"] = C.may(ctx, "video")  # kto może dodać nagranie, ten może je usunąć
    return out


async def video_list(ctx: Dict[str, Any], match_id: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    found = await C.rows(select(mentor_match_videos).where(mentor_match_videos.c.match_id == R.s(match_id))
                         .where(mentor_match_videos.c.pair_key == ctx["pair_key"]).where(mentor_match_videos.c.deleted_at.is_(None))
                         .order_by(mentor_match_videos.c.created_at.asc()))
    names = await C.people({r.get("added_by") for r in found})
    uploads = await _uploads_by_id([r.get("upload_id") for r in found])
    return [video_shape(r, names, uploads.get(r.get("upload_id")), ctx) for r in found], found


async def public_video(row: Dict[str, Any]) -> Dict[str, Any]:
    uploads = await _uploads_by_id([row.get("upload_id")])
    shaped = video_shape(row, {}, uploads.get(row.get("upload_id")))
    shaped.pop("added_by", None)
    return shaped


async def _video_payload(ctx: Dict[str, Any], video_id: str) -> Dict[str, Any]:
    row = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == video_id))
    names = await C.people([row.get("added_by")])
    uploads = await _uploads_by_id([row.get("upload_id")])
    return video_shape(row, names, uploads.get(row.get("upload_id")), ctx)


async def _pair_video(ctx: Dict[str, Any], match_id: str, video_id: str, include_trashed: bool = False) -> Dict[str, Any]:
    row = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == video_id))
    if not row or R.s(row.get("match_id")) != R.s(match_id) or R.s(row.get("pair_key")) != ctx["pair_key"]             or (row.get("deleted_at") is not None and not include_trashed):
        raise C.err(404, "VIDEO_NOT_FOUND", "Nie znaleziono tego nagrania - mogło zostać usunięte.")
    return row


# ─── Wideo: linki ───────────────────────────────────────────────────────────


class VideoBody(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


class VideoPatch(BaseModel):
    sync: Optional[Dict[str, Any]] = None
    title: Optional[str] = Field(default=None, max_length=200)


def idempotency_key(value: Optional[str]) -> Optional[str]:
    """Nagłówek `Idempotency-Key` (uuid z klienta): 8-80 znaków [A-Za-z0-9._:-]; pusty = bez idempotencji."""
    if not isinstance(value, str):
        return None
    key = value.strip()
    if not key:
        return None
    if not 8 <= len(key) <= 80 or not all(ch.isalnum() or ch in "._:-" for ch in key):
        raise C.err(422, "BAD_IDEMPOTENCY_KEY", "Nagłówek Idempotency-Key ma 8-80 znaków: litery, cyfry oraz . _ : -")
    return key


@router.post("/pairs/{pair_id}/matches/{match_id}/videos")
async def add_video(pair_id: str, match_id: str, body: VideoBody, actor: Actor = Depends(mentor_actor),
                    idempotency_header: Optional[str] = Header(default=None, alias="Idempotency-Key")):
    """Dodaje nagranie-link. `Idempotency-Key: <uuid>` (jeden na próbę dodania, ten sam przy ponowieniu): powtórka zwraca
    to samo nagranie bez duplikatu; ten sam klucz z innym adresem = 409 `IDEMPOTENCY_KEY_REUSED`."""
    ctx = await C.pair_context(pair_id, actor, action="video")
    card = await C.match_card(ctx, match_id)
    key = idempotency_key(idempotency_header)
    from app.mentor_evaluation_request_rules import normalized_video_url
    from app.mentor_evaluations import insert_link_video

    try:
        url = normalized_video_url(body.url)
    except ValueError as exc:
        raise C.err(422, "VIDEO_URL", str(exc)) from exc
    if not url:
        raise C.err(422, "VIDEO_URL", "Podaj link do nagrania.")
    row, created = await insert_link_video(card["match_id"], ctx["pair_key"], url, actor.judge_id, key)
    if key and row.get("idempotency_key") == key and R.s(row.get("normalized_url")) != url:
        raise C.err(409, "IDEMPOTENCY_KEY_REUSED", "Ten klucz idempotencji był już użyty z innym adresem nagrania.")
    if created:
        await C.touch(ctx, actor.judge_id, "video_added", "videos", card["match_id"], {"id": row["id"]})
    return await _video_payload(ctx, row["id"])


@router.patch("/pairs/{pair_id}/matches/{match_id}/videos/{video_id}")
async def update_video(pair_id: str, match_id: str, video_id: str, body: VideoPatch, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="video")
    row = await _pair_video(ctx, match_id, video_id)
    from app.mentor_video_rules import clean_sync

    values: Dict[str, Any] = {"updated_at": C.now()}
    if body.sync is not None:
        merged = {**R.json_value(row.get("sync_json"), {}), **body.sync}
        values["sync_json"] = json.dumps(clean_sync(merged))
    if body.title is not None:
        values["title"] = R.plain(body.title, 200) or None
    await database.execute(update(mentor_match_videos).where(mentor_match_videos.c.id == video_id).values(**values))
    await C.touch(ctx, actor.judge_id, "video_updated", "videos", row["match_id"], {"id": video_id})
    return await _video_payload(ctx, video_id)


@router.get("/pairs/{pair_id}/matches/{match_id}/videos/{video_id}/delete-impact")
async def video_delete_impact(pair_id: str, match_id: str, video_id: str, actor: Actor = Depends(mentor_actor)):
    """Co zniknie razem z nagraniem - do arkusza z ostrzeżeniem (bez zapisu)."""
    from app import mentor_video_trash as T

    ctx = await C.pair_context(pair_id, actor)
    row = await _pair_video(ctx, match_id, video_id)
    return await T.impact(ctx, row)


@router.delete("/pairs/{pair_id}/matches/{match_id}/videos/{video_id}")
async def delete_video(pair_id: str, match_id: str, video_id: str, actor: Actor = Depends(mentor_actor)):
    """Link: do kosza na 30 dni (`POST .../restore`). Wgrany plik: kasowany od razu (bez kosza)."""
    from app import mentor_video_trash as T

    ctx = await C.pair_context(pair_id, actor, action="video")
    row = await _pair_video(ctx, match_id, video_id)
    if row.get("kind") == "upload" and row.get("upload_id"):
        impact = await T.impact(ctx, row)  # przed skasowaniem: ile klipów zostanie bez źródła (bez kosza, bez cofania)
        upload = await C.one(select(mentor_uploads).where(mentor_uploads.c.id == row["upload_id"]))
        if upload:
            forget_object(upload.get("r2_key"), upload.get("play_key"), upload.get("poster_key"))
            await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == upload["id"])
                                   .values(status="expired", error="Nagranie usunięte.", r2_key=None, play_key=None, poster_key=None))
        await database.execute(mentor_match_videos.delete().where(mentor_match_videos.c.id == video_id))
        await C.touch(ctx, actor.judge_id, "video_deleted", "videos", row["match_id"], {"id": video_id})
        return {"ok": True, "trashed": False, "orphan_clips": impact["orphan_clips"], "kept_clips": impact["kept_clips"]}
    moved = await T.move_to_trash(ctx, row, actor.judge_id)
    await C.touch(ctx, actor.judge_id, "video_trashed", "videos", row["match_id"], {"id": video_id})
    return {"ok": True, "trashed": True, **moved}


@router.post("/pairs/{pair_id}/matches/{match_id}/videos/{video_id}/restore")
async def restore_video(pair_id: str, match_id: str, video_id: str, actor: Actor = Depends(mentor_actor)):
    from app import mentor_video_trash as T

    ctx = await C.pair_context(pair_id, actor, action="video")
    row = await _pair_video(ctx, match_id, video_id, include_trashed=True)
    if not T.in_trash(row):
        raise C.err(409, "VIDEO_NOT_IN_TRASH", "To nagranie nie leży w koszu - nie ma czego przywracać.")
    back = await T.restore(row)
    await C.touch(ctx, actor.judge_id, "video_restored", "videos", row["match_id"], {"id": video_id})
    return {"ok": True, **back, "video": await _video_payload(ctx, video_id)}


@router.delete("/pairs/{pair_id}/matches/{match_id}/videos/{video_id}/permanent")
async def purge_video(pair_id: str, match_id: str, video_id: str, actor: Actor = Depends(mentor_actor)):
    """„Usuń na zawsze” z kosza: to samo, co sprzątanie po 30 dniach (nagrobek, gdy są klipy z MP4). Bez cofania."""
    from app import mentor_video_trash as T

    ctx = await C.pair_context(pair_id, actor, action="video")
    row = await _pair_video(ctx, match_id, video_id, include_trashed=True)
    if not T.in_trash(row):
        raise C.err(409, "VIDEO_NOT_IN_TRASH", "To nagranie nie leży w koszu - nie ma czego usuwać na zawsze.")
    gone = T.trash_shape(row, {})
    result = await T.purge_row(row)
    await C.touch(ctx, actor.judge_id, "video_purged", "videos", row["match_id"], {"id": video_id})
    return {"ok": True, "purged": True, "tombstone": result == "tombstone", "virtual_clips": gone["virtual_clips"],
            "kept_clips": gone["kept_clips"], "threads": gone["threads"], "comments": gone["comments"]}


# ─── Wgrywanie (R2, wieloczęściowe) ─────────────────────────────────────────


class UploadBody(BaseModel):
    filename: str = Field(min_length=1, max_length=400)
    size: int = Field(gt=0)
    content_type: Optional[str] = Field(default="", max_length=120)


class CompleteBody(BaseModel):
    parts: List[Dict[str, Any]] = Field(default_factory=list, max_length=10000)


def _part_urls(config: Dict[str, str], upload: Dict[str, Any], numbers: List[int]) -> List[Dict[str, Any]]:
    client = s3_client(config)
    return [{"n": n, "url": client.generate_presigned_url(
        "upload_part", Params={"Bucket": config["bucket"], "Key": upload["r2_key"], "UploadId": upload["upload_id"], "PartNumber": n},
        ExpiresIn=PART_URL_TTL)} for n in numbers]


def _ext(filename: str) -> str:
    base, dot, ext = filename.rpartition(".")
    ext = ext.lower() if dot and base else ""
    return f".{ext}" if ext and ext.isalnum() and len(ext) <= 5 else ""


@router.post("/pairs/{pair_id}/matches/{match_id}/uploads")
async def start_upload(pair_id: str, match_id: str, body: UploadBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="video")
    card = await C.match_card(ctx, match_id)
    try:
        filename, size, content_type = R.validate_upload(body.filename, body.size, body.content_type)
    except R.RuleError as exc:
        raise C.rule_error(exc) from exc
    config = _storage_or_503()
    upload_id = R.new_id()
    key = object_key(ctx["pair_id"], card["match_id"], upload_id, f"original{_ext(filename)}")
    try:
        created = await asyncio.to_thread(
            s3_client(config).create_multipart_upload, Bucket=config["bucket"], Key=key, ContentType=content_type)
    except Exception as exc:  # noqa: BLE001
        logger.warning("mentor: start wgrywania nieudany", exc_info=True)
        raise C.err(502, "STORAGE_ERROR", "Magazyn nagrań nie odpowiada. Spróbuj za chwilę.") from exc
    stamp = C.now()
    row = {
        "id": upload_id, "pair_id": ctx["pair_id"], "match_id": card["match_id"], "uploader_id": actor.judge_id,
        "filename": filename, "size": size, "content_type": content_type, "r2_key": key, "upload_id": created["UploadId"],
        "status": "uploading", "created_at": stamp, "expires_at": R.upload_expires_at(card.get("scheduled_at"), stamp),
    }
    await database.execute(mentor_uploads.insert().values(**row))
    total = R.upload_parts(size)
    return {"upload_id": upload_id, "part_size": R.PART_SIZE, "total_parts": total,
            "parts": _part_urls(config, row, R.part_batch(total, 1)), "expires_at": row["expires_at"]}


async def _own_upload(ctx: Dict[str, Any], match_id: str, upload_id: str, actor: Actor) -> Dict[str, Any]:
    row = await C.one(select(mentor_uploads).where(mentor_uploads.c.id == upload_id))
    if not row or row["pair_id"] != ctx["pair_id"] or R.s(row["match_id"]) != R.s(match_id):
        raise C.err(404, "UPLOAD_NOT_FOUND", "Nie ma takiego wgrywania.")
    if row["uploader_id"] != actor.judge_id and not actor.is_admin:
        raise C.err(403, "NOT_OWNER", "To wgrywanie należy do innej osoby.")
    return row


@router.post("/pairs/{pair_id}/matches/{match_id}/uploads/{upload_id}/parts")
async def more_parts(pair_id: str, match_id: str, upload_id: str, from_: int = Query(1, alias="from", ge=1),
                     actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="video")
    row = await _own_upload(ctx, match_id, upload_id, actor)
    if row["status"] != "uploading":
        raise C.err(409, "UPLOAD_CLOSED", "To wgrywanie jest już zakończone.")
    config = _storage_or_503()
    total = R.upload_parts(row["size"])
    return {"upload_id": upload_id, "part_size": R.PART_SIZE, "total_parts": total,
            "parts": _part_urls(config, row, R.part_batch(total, from_))}


@router.post("/pairs/{pair_id}/matches/{match_id}/uploads/{upload_id}/complete")
async def complete_upload(pair_id: str, match_id: str, upload_id: str, body: CompleteBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="video")
    row = await _own_upload(ctx, match_id, upload_id, actor)
    if row["status"] != "uploading":
        return {"status": row["status"], "video_id": row.get("video_id")}
    try:
        parts = R.clean_parts(body.parts, R.upload_parts(row["size"]))
    except R.RuleError as exc:
        raise C.rule_error(exc) from exc
    config = _storage_or_503()
    try:
        await asyncio.to_thread(s3_client(config).complete_multipart_upload, Bucket=config["bucket"], Key=row["r2_key"],
                                UploadId=row["upload_id"], MultipartUpload={"Parts": parts})
    except Exception as exc:  # noqa: BLE001
        logger.warning("mentor: domknięcie wgrywania nieudane", exc_info=True)
        raise C.err(502, "STORAGE_ERROR", "Nie udało się złożyć pliku w magazynie. Wyślij części jeszcze raz.") from exc
    video_id = R.new_id()
    marker = f"upload:{upload_id}"
    await database.execute(mentor_match_videos.insert().values(
        id=video_id, match_id=row["match_id"], pair_key=ctx["pair_key"], url=marker, normalized_url=marker, provider="upload",
        added_by=row["uploader_id"], created_at=C.now(), title=row["filename"], kind="upload", upload_id=upload_id))
    await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == upload_id)
                           .values(status="processing", video_id=video_id))
    await C.touch(ctx, actor.judge_id, "upload_completed", "videos", row["match_id"], {"id": upload_id})
    wake_worker()
    return {"status": "processing", "video_id": video_id}


@router.get("/pairs/{pair_id}/matches/{match_id}/uploads/{upload_id}")
async def upload_status(pair_id: str, match_id: str, upload_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    row = await C.one(select(mentor_uploads).where(mentor_uploads.c.id == upload_id))
    if not row or row["pair_id"] != ctx["pair_id"] or R.s(row["match_id"]) != R.s(match_id):
        raise C.err(404, "UPLOAD_NOT_FOUND", "Nie ma takiego wgrywania.")
    progress = 1.0 if row["status"] == "ready" else _progress.get(upload_id) if row["status"] == "processing" else None
    return {"status": row["status"], "progress": progress, "error": row.get("error"), "video_id": row.get("video_id")}


@router.delete("/pairs/{pair_id}/matches/{match_id}/uploads/{upload_id}")
async def abort_upload(pair_id: str, match_id: str, upload_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="video")
    row = await _own_upload(ctx, match_id, upload_id, actor)
    if row["status"] == "uploading" and row.get("upload_id") and storage_ready():
        config = storage_config()
        try:
            await asyncio.to_thread(s3_client(config).abort_multipart_upload, Bucket=config["bucket"], Key=row["r2_key"],
                                    UploadId=row["upload_id"])
        except Exception:  # noqa: BLE001
            logger.warning("mentor: przerwanie wgrywania w R2 nieudane", exc_info=True)
    elif row["status"] in ("processing", "ready", "failed"):
        forget_object(row.get("r2_key"), row.get("play_key"), row.get("poster_key"))
    _cancelled.add(upload_id)
    await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == upload_id)
                           .values(status="failed", error="Wgrywanie przerwane.", r2_key=None, play_key=None, poster_key=None))
    if row.get("video_id"):
        await database.execute(mentor_match_videos.delete().where(mentor_match_videos.c.id == row["video_id"]))
    await C.touch(ctx, actor.judge_id, "upload_aborted", "videos", row["match_id"], {"id": upload_id})
    return {"ok": True, "status": "failed"}


# ─── MP4 klipu ──────────────────────────────────────────────────────────────


async def _clip_upload(clip: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == clip["video_id"]))
    if not video or video.get("kind") != "upload" or not video.get("upload_id"):
        return None
    return await C.one(select(mentor_uploads).where(mentor_uploads.c.id == video["upload_id"]))


class Mp4Request(BaseModel):
    title_card: bool = False


async def queue_clip_file(ctx: Dict[str, Any], clip: Dict[str, Any], actor: Actor, source: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """MP4 z własnego pliku do kolejki ffmpeg. `source` = {video_id, start_s, end_s} przy klipie przeliczonym z innego nagrania
    (wideo-link); None = klip leży na tym pliku. Zmiana źródła unieważnia gotowy plik i wariant z planszą."""
    if source:
        video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == source["video_id"]))
        upload = await C.one(select(mentor_uploads).where(mentor_uploads.c.id == video["upload_id"])) if video and video.get("upload_id") else None
    else:
        upload = await _clip_upload(clip)
    if not upload or upload.get("status") != "ready" or not upload.get("play_key"):
        raise C.err(409, "MP4_NOT_READY", "Nagranie jeszcze się przetwarza - spróbuj za chwilę.")
    _storage_or_503()
    same = (R.json_value(clip.get("mp4_source_json"), {}) or None) == source
    if clip.get("mp4_status") in ("queued", "working", "ready") and same:
        return {"mp4_status": clip["mp4_status"]}
    values: Dict[str, Any] = {"mp4_status": "queued", "mp4_source_json": json.dumps(source) if source else None}
    if not same:
        values.update(card_status="none", card_sig=None)
    await database.execute(update(mentor_clips).where(mentor_clips.c.id == clip["id"]).values(**values))
    await C.touch(ctx, actor.judge_id, "clip_mp4", "clips", clip["match_id"], {"id": clip["id"]})
    wake_worker()
    return {"mp4_status": "queued"}


@router.post("/clips/{clip_id}/mp4")
async def request_mp4(clip_id: str, actor: Actor = Depends(mentor_actor), body: Optional[Mp4Request] = None):
    """Zamów MP4. Źródło rozstrzyga `mentor_clip_download`: własny plik, Bastion albo (dla klipu z wideo-linku) przeliczony
    zakres z synchronizacji nagrań. Brak synchronizacji = 409 NEED_SYNC z `missing`, sam link = 409 NO_SOURCE.
    `title_card: true` dokłada osobny wariant z planszą (2 s)."""
    clip = await C.one(select(mentor_clips).where(mentor_clips.c.id == clip_id))
    if not clip or clip.get("deleted_at") is not None:
        raise C.err(404, "NOT_FOUND", "Nie ma takiego klipu.")
    ctx = await C.pair_context(clip["pair_id"], actor, action="create")
    from app import mentor_clip_download as D

    return await D.order(ctx, clip, actor, bool(body and body.title_card))


@router.get("/clips/{clip_id}/mp4")
async def download_mp4(clip_id: str, actor: Actor = Depends(mentor_actor), title_card: bool = Query(False),
                       full_name: bool = Query(False)):
    clip = await C.one(select(mentor_clips).where(mentor_clips.c.id == clip_id))
    if not clip or clip.get("deleted_at") is not None:
        raise C.err(404, "NOT_FOUND", "Nie ma takiego klipu.")
    ctx = await C.pair_context(clip["pair_id"], actor)
    if clip.get("mp4_status") != "ready" or not clip.get("mp4_key"):
        raise C.err(409, "MP4_NOT_READY", "Plik MP4 tego klipu nie jest gotowy.")
    key, size = clip["mp4_key"], clip.get("mp4_size")
    if title_card:
        if clip.get("card_status") != "ready" or not clip.get("card_key"):
            raise C.err(409, "MP4_NOT_READY", "Wariant z planszą nie jest jeszcze gotowy.")
        key, size = clip["card_key"], clip.get("card_size")
    from app import mentor_clip_download as D
    from app import mentor_clip_download_rules as DR

    try:
        shared = D.Context(ctx)
        plan = await D.build_plan(shared, clip, actor, title_card=title_card)
        filename = plan["filename"]
        if full_name:
            # Zwykłe pobranie nie ma folderów: mecz i kategoria jadą w samej nazwie.
            filename = DR.full_filename(await shared.card(clip["match_id"]), plan["folder"]["category"], filename)
    except Exception:  # noqa: BLE001 - nazwa to wygoda, nie warunek pobrania
        filename = R.clip_filename(clip.get("title"), None, float(clip["start_s"]))
    url = presign_get(key, DOWNLOAD_TTL, filename)
    if not url:
        raise C.err(503, "STORAGE_OFF", "Magazyn nagrań jest chwilowo niedostępny.")
    return {"url": url, "filename": filename, "size": size}


# ─── Kolejka ffmpeg (1 naraz) ───────────────────────────────────────────────

_wake_event: Optional[asyncio.Event] = None
_progress: Dict[str, float] = {}
_cancelled: set = set()
_failed_here: set = set()


def wake_worker() -> None:
    if _wake_event is not None:
        _wake_event.set()


def _run(args: List[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def probe(source: str) -> Dict[str, Any]:
    done = _run(["ffprobe", "-v", "error", "-print_format", "json", "-show_format", "-show_streams", source], timeout=300)
    if done.returncode != 0:
        raise RuntimeError(f"ffprobe: {done.stderr[-400:]}")
    data = json.loads(done.stdout or "{}")
    video = next((s for s in data.get("streams") or [] if s.get("codec_type") == "video"), None)
    if not video:
        raise UserFacingError("Plik nie zawiera obrazu wideo.")
    duration = float((data.get("format") or {}).get("duration") or video.get("duration") or 0) or None
    return {"duration_s": duration, "width": int(video.get("width") or 0) or None, "height": int(video.get("height") or 0) or None}


def transcode(source: str, target: str, height: Optional[int], duration: Optional[float],
              on_progress: Callable[[float], None], cancelled: Callable[[], bool]) -> None:
    err_path = target + ".log"
    with open(err_path, "w", encoding="utf-8") as err_file:
        proc = subprocess.Popen(R.transcode_args(source, target, height), stdout=subprocess.PIPE, stderr=err_file, text=True)
        assert proc.stdout is not None
        for line in proc.stdout:
            value = R.ffmpeg_progress(line.strip(), duration)
            if value is not None:
                on_progress(value)
            if cancelled():
                proc.kill()
                break
        code = proc.wait()
    if code != 0:
        with open(err_path, encoding="utf-8", errors="replace") as handle:
            raise RuntimeError(f"ffmpeg {code}: {handle.read()[-600:]}")


def poster(source: str, target: str, duration: Optional[float]) -> bool:
    at = max(1.0, min(60.0, (duration or 30) / 3))
    done = _run(["ffmpeg", "-hide_banner", "-nostdin", "-y", "-ss", f"{at:.1f}", "-i", source, "-frames:v", "1",
                 "-vf", "scale=-2:360", "-q:v", "4", target], timeout=120)
    return done.returncode == 0 and os.path.exists(target)


def put_file(path: str, key: str, content_type: str) -> int:
    config = storage_config()
    s3_client(config).upload_file(path, config["bucket"], key, ExtraArgs={"ContentType": content_type})
    return os.path.getsize(path)


def _tmpdir() -> str:
    base = os.getenv("MENTOR_MEDIA_TMP") or None
    return tempfile.mkdtemp(prefix="mentor-", dir=base)


async def process_upload(row: Dict[str, Any]) -> None:
    upload_id = row["id"]
    source = presign_get(row["r2_key"], SOURCE_URL_TTL)
    if not source:
        raise RuntimeError("brak adresu źródła")
    folder = await asyncio.to_thread(_tmpdir)
    try:
        info = await asyncio.to_thread(probe, source)
        _progress[upload_id] = 0.0
        target = os.path.join(folder, "play.mp4")

        def progress(value: float) -> None:
            _progress[upload_id] = value

        await asyncio.to_thread(transcode, source, target, info.get("height"), info.get("duration_s"), progress,
                                lambda: upload_id in _cancelled)
        if upload_id in _cancelled:
            return
        base = row["r2_key"].rsplit("/", 1)[0]
        play_key, poster_key = f"{base}/play.mp4", f"{base}/poster.jpg"
        await asyncio.to_thread(put_file, target, play_key, "video/mp4")
        poster_path = os.path.join(folder, "poster.jpg")
        has_poster = await asyncio.to_thread(poster, target, poster_path, info.get("duration_s"))
        if has_poster:
            await asyncio.to_thread(put_file, poster_path, poster_key, "image/jpeg")
        await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == upload_id).values(
            status="ready", play_key=play_key, poster_key=poster_key if has_poster else None, error=None,
            duration_s=info.get("duration_s"), width=info.get("width"), height=info.get("height")))
        if row.get("video_id"):
            duration = info.get("duration_s")
            await database.execute(update(mentor_match_videos).where(mentor_match_videos.c.id == row["video_id"])
                                   .values(duration_s=int(duration) if duration else None, updated_at=C.now()))
        await C.touch(row["pair_id"], row["uploader_id"], "upload_ready", "videos", row["match_id"], {"id": upload_id})
    finally:
        _progress.pop(upload_id, None)
        await asyncio.to_thread(shutil.rmtree, folder, True)


class UserFacingError(ValueError):
    """Komunikat po polsku, który wolno pokazać użytkownikowi (reszta wyjątków dostaje ogólny)."""


async def process_clip(clip: Dict[str, Any]) -> None:
    start_s, end_s = float(clip["start_s"]), float(clip["end_s"])
    override = R.json_value(clip.get("mp4_source_json"), {})
    if override.get("video_id"):  # klip z wideo-linku, przeliczony na własny plik
        video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == override["video_id"]))
        upload = await C.one(select(mentor_uploads).where(mentor_uploads.c.id == video["upload_id"])) if video and video.get("upload_id") else None
        start_s, end_s = float(override["start_s"]), float(override["end_s"])
    else:
        upload = await _clip_upload(clip)
    if not upload or upload.get("status") != "ready" or not upload.get("play_key"):
        raise ValueError("Nagranie klipu nie jest jeszcze gotowe.")
    await database.execute(update(mentor_clips).where(mentor_clips.c.id == clip["id"]).values(mp4_status="working"))
    source = presign_get(upload["play_key"], SOURCE_URL_TTL)
    folder = await asyncio.to_thread(_tmpdir)
    try:
        target = os.path.join(folder, "clip.mp4")
        done = await asyncio.to_thread(_run, R.cut_args(source, target, start_s, end_s), 1800)
        if done.returncode != 0 or not os.path.exists(target):
            raise RuntimeError(f"ffmpeg: {done.stderr[-400:]}")
        key = object_key(clip["pair_id"], "clips", f"{clip['id']}.mp4")
        size = await asyncio.to_thread(put_file, target, key, "video/mp4")
        await database.execute(update(mentor_clips).where(mentor_clips.c.id == clip["id"])
                               .values(mp4_status="ready", mp4_key=key, mp4_size=size))
        await C.touch(clip["pair_id"], clip["author_id"], "clip_mp4_ready", "clips", clip["match_id"], {"id": clip["id"]})
    finally:
        await asyncio.to_thread(shutil.rmtree, folder, True)


async def next_job() -> Optional[Tuple[str, Dict[str, Any]]]:
    clip = await C.one(select(mentor_clips).where(mentor_clips.c.mp4_status.in_(("queued", "working")))
                       .where(mentor_clips.c.deleted_at.is_(None)).where(mentor_clips.c.id.notin_(list(_failed_here) or [""]))
                       .order_by(mentor_clips.c.updated_at.asc()).limit(1))
    if clip:
        return "clip", clip
    from app import mentor_clip_download as D

    card = await D.next_card()
    if card and card["id"] not in _failed_here:
        return "card", card
    upload = await C.one(select(mentor_uploads).where(mentor_uploads.c.status == "processing")
                         .where(mentor_uploads.c.id.notin_(list(_failed_here) or [""]))
                         .order_by(mentor_uploads.c.created_at.asc()).limit(1))
    return ("upload", upload) if upload else None


async def process_next() -> bool:
    job = await next_job()
    if not job:
        return False
    kind, row = job
    try:
        if kind == "clip":
            await process_clip(row)
        elif kind == "card":
            from app import mentor_clip_download as D

            await D.process_card(row)
        else:
            await process_upload(row)
    except Exception as exc:  # noqa: BLE001 - jedna zła praca nie zatrzymuje kolejki
        logger.warning("mentor: praca %s %s nieudana: %s", kind, row["id"], exc, exc_info=True)
        _failed_here.add(row["id"])
        if kind == "card":
            await database.execute(update(mentor_clips).where(mentor_clips.c.id == row["id"]).values(card_status="failed"))
        elif kind == "clip":
            await database.execute(update(mentor_clips).where(mentor_clips.c.id == row["id"]).values(mp4_status="failed"))
            await C.touch(row["pair_id"], row["author_id"], "clip_mp4_failed", "clips", row["match_id"], {"id": row["id"]})
        else:
            message = str(exc) if isinstance(exc, UserFacingError) else "Nie udało się przetworzyć nagrania. Sprawdź plik i wgraj go ponownie."
            await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == row["id"]).values(status="failed", error=message[:300]))
            await C.touch(row["pair_id"], row["uploader_id"], "upload_failed", "videos", row["match_id"], {"id": row["id"]})
    return True


async def run_media_worker() -> None:
    """Pętla w tle: jedna praca ffmpeg naraz; budzi ją zapis, inaczej sprawdza co 30 s."""
    global _wake_event
    _wake_event = asyncio.Event()
    await asyncio.sleep(20)
    while True:
        try:
            busy = await process_next()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("mentor: przebieg kolejki nieudany")
            busy = False
        if busy:
            continue
        _wake_event.clear()
        try:
            await asyncio.wait_for(_wake_event.wait(), timeout=30)
        except asyncio.TimeoutError:
            pass


# ─── Retencja ───────────────────────────────────────────────────────────────


async def retention_once(now: Optional[datetime] = None) -> Dict[str, int]:
    stamp = now or datetime.now(timezone.utc)
    counts = {"originals": 0, "expired": 0, "aborted": 0}
    candidates = await C.rows(select(mentor_uploads).where(mentor_uploads.c.status.in_(("ready", "uploading", "processing", "failed"))))
    for row in candidates:
        actions = R.retention_actions(row, stamp)
        if actions["expire"]:
            await asyncio.to_thread(delete_objects, [row.get("r2_key"), row.get("play_key"), row.get("poster_key")])
            await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == row["id"]).values(
                status="expired", r2_key=None, play_key=None, poster_key=None, error="Nagranie wygasło (12 miesięcy od meczu)."))
            await C.touch(row["pair_id"], "system", "upload_expired", "videos", row["match_id"], {"id": row["id"]})
            counts["expired"] += 1
        elif actions["delete_original"]:
            await asyncio.to_thread(delete_objects, [row.get("r2_key")])
            await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == row["id"]).values(r2_key=None))
            counts["originals"] += 1
        elif actions["abort"]:
            if row.get("upload_id") and row.get("r2_key") and storage_ready():
                config = storage_config()
                try:
                    await asyncio.to_thread(s3_client(config).abort_multipart_upload, Bucket=config["bucket"],
                                            Key=row["r2_key"], UploadId=row["upload_id"])
                except Exception:  # noqa: BLE001
                    logger.warning("mentor: przerwanie porzuconego wgrywania nieudane", exc_info=True)
            await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == row["id"]).values(
                status="failed", r2_key=None, error="Wgrywanie porzucone - nie dokończono go w ciągu doby."))
            counts["aborted"] += 1
    try:
        from app import mentor_video_trash as T

        purged = await T.purge_expired(stamp)
        if purged:
            counts["trash"] = purged
    except Exception:  # noqa: BLE001
        logger.warning("mentor: sprzątanie kosza nagrań nieudane", exc_info=True)
    try:
        from app.mentor_panel_auth import cleanup_auth

        await cleanup_auth(stamp)
    except Exception:  # noqa: BLE001
        logger.warning("mentor: sprzątanie sesji nieudane", exc_info=True)
    return counts


async def run_retention() -> None:
    """Zadanie dzienne (pierwsze 10 minut po starcie)."""
    await asyncio.sleep(600)
    while True:
        try:
            counts = await retention_once()
            logger.info("mentor: retencja nagrań %s", counts)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("mentor: retencja nieudana")
        await asyncio.sleep(24 * 3600)

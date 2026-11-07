"""
Panel „Mentor" - nagranie meczu z kilku plików, sklejane na serwerze (07.11.2026, `docs/mentor-panel.md` 4.5).

  - `POST .../upload-groups` zakłada N wierszy `mentor_uploads` (wspólne `group_id`, `group_index` = kolejność
    sklejania ustalona przez klienta), każdy z własnym multipart w R2 - dalej działają zwykłe `.../uploads/{id}/parts`
    i `.../complete` (domknięcie członka grupy trafia tutaj przez `complete_member`),
  - komplet plików = JEDNO nagranie (`kind = 'upload'`, `upload_id` = część 0) i praca dla kolejki ffmpeg,
  - worker: ffprobe każdej części -> sklejenie bez przekodowania (concat + remux), gdy parametry są te same, albo
    wyrównanie części do wspólnego formatu i dopiero sklejenie; oś części (`parts_json`) z czasów rzeczywistych.

Czysta logika (walidacja, stan grupy, wybór formatu, argumenty ffmpeg, oś części): `app/mentor_upload_group_rules.py`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
from typing import Any, Callable, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app import mentor_panel_core as C
from app import mentor_panel_media as M
from app import mentor_panel_rules as R
from app import mentor_upload_group_rules as G
from app.db import database, mentor_match_videos, mentor_uploads
from app.mentor_panel_auth import mentor_actor

logger = logging.getLogger("app.mentor_panel")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor"])
Actor = C.MentorActor

MISSING_PART = "Brakuje części nagrania - wgraj pliki jeszcze raz."


class GroupFile(BaseModel):
    filename: str = Field(min_length=1, max_length=400)
    size: int = Field(gt=0)
    content_type: Optional[str] = Field(default="", max_length=120)
    recorded_at: Optional[str] = Field(default=None, max_length=64)
    duration_s: Optional[float] = None


class GroupBody(BaseModel):
    files: List[GroupFile] = Field(default_factory=list, max_length=50)
    order_source: Optional[str] = Field(default=None, max_length=20)


# ─── Odczyt grupy ───────────────────────────────────────────────────────────


async def group_rows(group_id: str, *, lock: bool = False) -> List[Dict[str, Any]]:
    query = select(mentor_uploads).where(mentor_uploads.c.group_id == R.s(group_id))
    return G.ordered(await C.rows(query.with_for_update() if lock else query))  # type: ignore[return-value]


async def _pair_group(ctx: Dict[str, Any], match_id: str, group_id: str) -> List[Dict[str, Any]]:
    rows = await group_rows(group_id) if R.s(group_id) else []
    if not rows or any(r["pair_id"] != ctx["pair_id"] or R.s(r["match_id"]) != R.s(match_id) for r in rows):
        raise C.err(404, "UPLOAD_GROUP_NOT_FOUND", "Nie ma takiego nagrania z kilku plików.")
    return rows


def _owner_or_403(row: Dict[str, Any], actor: Actor) -> None:
    if row["uploader_id"] != actor.judge_id and not actor.is_admin:
        raise C.err(403, "NOT_OWNER", "To wgrywanie należy do innej osoby.")


def lead_progress(lead_id: Optional[str]) -> Optional[float]:
    return M._progress.get(lead_id) if lead_id else None


# ─── Trasy ──────────────────────────────────────────────────────────────────


@router.post("/pairs/{pair_id}/matches/{match_id}/upload-groups")
async def start_group(pair_id: str, match_id: str, body: GroupBody, actor: Actor = Depends(mentor_actor)):
    """Nagranie z 2-12 plików (razem do 20 GB). Kolejność w `files` = kolejność sklejania (ustala ją klient)."""
    ctx = await C.pair_context(pair_id, actor, action="video")
    card = await C.match_card(ctx, match_id)
    try:
        files, order_source = G.validate_group([f.model_dump() for f in body.files], body.order_source)
    except R.RuleError as exc:
        raise C.rule_error(exc) from exc
    config = M._storage_or_503()
    client = M.s3_client(config)
    group_id, stamp = R.new_id(), C.now()
    expires = R.upload_expires_at(card.get("scheduled_at"), stamp)
    rows: List[Dict[str, Any]] = []
    try:
        for item in files:
            upload_id = R.new_id()
            key = M.object_key(ctx["pair_id"], R.s(card["match_id"]).replace(":", "_"), upload_id, f"original{M._ext(item['filename'])}")
            created = await asyncio.to_thread(client.create_multipart_upload, Bucket=config["bucket"], Key=key,
                                              ContentType=item["content_type"])
            rows.append({
                "id": upload_id, "pair_id": ctx["pair_id"], "match_id": card["match_id"], "uploader_id": actor.judge_id,
                "filename": item["filename"], "size": item["size"], "content_type": item["content_type"], "r2_key": key,
                "upload_id": created["UploadId"], "status": "uploading", "created_at": stamp, "expires_at": expires,
                "group_id": group_id, "group_index": item["index"], "group_count": len(files),
                "recorded_at": item["recorded_at"], "duration_s": item["duration_s"],
            })
    except Exception as exc:  # noqa: BLE001
        logger.warning("mentor: start wgrywania z kilku plików nieudany", exc_info=True)
        for row in rows:
            await asyncio.to_thread(_abort_quietly, config, row)
        raise C.err(502, "STORAGE_ERROR", "Magazyn nagrań nie odpowiada. Spróbuj za chwilę.") from exc
    async with database.transaction():
        for row in rows:
            await database.execute(mentor_uploads.insert().values(**row))
    await C.touch(ctx, actor.judge_id, "upload_group_started", "videos", card["match_id"],
                  {"id": group_id, "count": len(rows), "order": order_source})
    uploads = []
    for row in rows:
        total = R.upload_parts(row["size"])
        # Ten sam kształt co `start_upload` pojedynczego pliku: `parts: [{n, url}]` (klienci liczą na niego).
        uploads.append({"index": row["group_index"], "upload_id": row["id"], "part_size": R.PART_SIZE, "total_parts": total,
                        "parts": M._part_urls(config, row, R.part_batch(total, 1)), "expires_at": row["expires_at"]})
    return {"group_id": group_id, "count": len(rows), "order_source": order_source, "uploads": uploads}


@router.get("/pairs/{pair_id}/matches/{match_id}/upload-groups/{group_id}")
async def group_status(pair_id: str, match_id: str, group_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    rows = await _pair_group(ctx, match_id, group_id)
    state = G.group_state(rows)
    lead = G.lead_of(rows) or {}
    progress = 1.0 if state["status"] == "ready" else lead_progress(lead.get("id")) if state["status"] == "processing" else None
    return {
        "group_id": group_id, "status": state["status"], "progress": progress, "error": state["error"],
        "video_id": state["video_id"], "done": state["done"], "count": state["count"],
        "files": [{"index": r.get("group_index"), "upload_id": r["id"], "filename": r["filename"], "size": r["size"],
                   "status": r["status"]} for r in rows],
    }


@router.delete("/pairs/{pair_id}/matches/{match_id}/upload-groups/{group_id}")
async def abort_group(pair_id: str, match_id: str, group_id: str, actor: Actor = Depends(mentor_actor)):
    """Przerywa wszystkie pliki grupy; nagranie (jeśli powstało i nie jest gotowe) znika jak przy przerwaniu wgrywania."""
    ctx = await C.pair_context(pair_id, actor, action="video")
    rows = await _pair_group(ctx, match_id, group_id)
    return await _abort(ctx, rows, actor)


async def _abort(ctx: Dict[str, Any], rows: List[Dict[str, Any]], actor: Actor) -> Dict[str, Any]:
    lead = G.lead_of(rows) or rows[0]
    _owner_or_403(lead, actor)
    state = G.group_state(rows)
    group_id = lead["group_id"]
    if state["status"] == "removed":
        return {"ok": True, "status": "removed", "group_id": group_id}
    if state["status"] == "ready":
        raise C.err(409, "UPLOAD_GROUP_READY", "To nagranie jest już gotowe - usuń je z listy nagrań meczu.")
    await remove_group(rows, "Wgrywanie przerwane.")
    await C.touch(ctx, actor.judge_id, "upload_group_aborted", "videos", lead["match_id"], {"id": group_id})
    return {"ok": True, "status": "removed", "group_id": group_id}


async def abort_member(ctx: Dict[str, Any], row: Dict[str, Any], actor: Actor) -> Dict[str, Any]:
    """`DELETE .../uploads/{id}` członka grupy: nagranie bez jednej części nie ma sensu - przerywa całą grupę."""
    return await _abort(ctx, await group_rows(row["group_id"]), actor)


def _abort_quietly(config: Dict[str, str], row: Dict[str, Any]) -> None:
    try:
        M.s3_client(config).abort_multipart_upload(Bucket=config["bucket"], Key=row["r2_key"], UploadId=row["upload_id"])
    except Exception:  # noqa: BLE001 - porzucony multipart sprzątnie reguła cyklu życia R2
        logger.warning("mentor: przerwanie wgrywania części w R2 nieudane", exc_info=True)


async def remove_group(rows: List[Dict[str, Any]], reason: str) -> None:
    """Pliki grupy znikają z R2 (multipart w toku przerwany), wiersze dostają `removed`, nagranie w toku znika."""
    lead = G.lead_of(rows) or rows[0]
    M._cancelled.add(lead["id"])
    config = M.storage_config() if M.storage_ready() else None
    for row in rows:
        if row["status"] == "uploading" and row.get("upload_id") and row.get("r2_key") and config:
            await asyncio.to_thread(_abort_quietly, config, row)
        else:
            M.forget_object(row.get("r2_key"), row.get("play_key"), row.get("poster_key"))
    await database.execute(update(mentor_uploads).where(mentor_uploads.c.group_id == lead["group_id"])
                           .values(status="removed", error=reason, r2_key=None, play_key=None, poster_key=None))
    if lead.get("video_id"):
        await database.execute(mentor_match_videos.delete().where(mentor_match_videos.c.id == lead["video_id"]))
        await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == lead["id"]).values(video_id=None))


async def drop_members(lead: Dict[str, Any], reason: str) -> None:
    """Usunięcie gotowego nagrania z kilku plików: oryginały pozostałych części też znikają (część 0 robi `delete_video`)."""
    others = [r for r in await group_rows(lead["group_id"]) if r["id"] != lead["id"]]
    for row in others:
        M.forget_object(row.get("r2_key"), row.get("play_key"), row.get("poster_key"))
    if others:
        await database.execute(update(mentor_uploads).where(mentor_uploads.c.group_id == lead["group_id"])
                               .where(mentor_uploads.c.id != lead["id"])
                               .values(status="expired", error=reason, r2_key=None, play_key=None, poster_key=None))


# ─── Domknięcie pliku grupy ─────────────────────────────────────────────────


async def complete_member(ctx: Dict[str, Any], row: Dict[str, Any], raw_parts: Any, actor: Actor) -> Dict[str, Any]:
    """`POST .../uploads/{id}/complete` członka grupy. Nie ostatni: `waiting_group`; ostatni brakujący: JEDNO nagranie
    i praca dla kolejki (`processing`). Kolejność dowolna, powtórka idempotentna."""
    if row["status"] == "uploading":
        await M.finish_multipart(row, raw_parts)
        await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == row["id"])
                               .where(mentor_uploads.c.status == "uploading").values(status=G.WAITING))
        await C.touch(ctx, actor.judge_id, "upload_completed", "videos", row["match_id"], {"id": row["id"], "group_id": row["group_id"]})
    group_id = row["group_id"]
    video_id: Optional[str] = None
    state: Dict[str, Any] = {}
    async with database.transaction():
        rows = await group_rows(group_id, lock=True)
        if G.all_uploaded(rows):
            lead = G.lead_of(rows)
            assert lead is not None
            video_id = R.new_id()
            marker = f"upload:{lead['id']}"
            await database.execute(mentor_match_videos.insert().values(
                id=video_id, match_id=lead["match_id"], pair_key=ctx["pair_key"], url=marker, normalized_url=marker,
                provider="upload", added_by=lead["uploader_id"], created_at=C.now(), kind="upload", upload_id=lead["id"],
                title=G.group_title(lead["filename"], len(rows))))
            await database.execute(update(mentor_uploads).where(mentor_uploads.c.group_id == group_id).values(status="processing"))
            await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == lead["id"]).values(video_id=video_id))
        else:
            state = G.group_state(rows)
    if video_id:
        await C.touch(ctx, actor.judge_id, "upload_group_completed", "videos", row["match_id"], {"id": group_id, "video": video_id})
        M.wake_worker()
        return {"status": "processing", "video_id": video_id, "group_id": group_id}
    if state["status"] == "uploading":
        return {"status": "waiting_group", "group_id": group_id, "done": state["done"], "count": state["count"]}
    return {"status": state["status"], "video_id": state["video_id"], "group_id": group_id, "error": state["error"]}


# ─── Worker ─────────────────────────────────────────────────────────────────


def probe_raw(source: str) -> Dict[str, Any]:
    done = M._run(["ffprobe", "-v", "error", "-print_format", "json", "-show_format", "-show_streams", source], timeout=300)
    if done.returncode != 0:
        raise RuntimeError(f"ffprobe: {done.stderr[-400:]}")
    return json.loads(done.stdout or "{}")


def run_ffmpeg(args: List[str], on_seconds: Callable[[float], None], cancelled: Callable[[], bool]) -> None:
    """ffmpeg z `-progress pipe:1`: sekundy wyjścia do `on_seconds`, przerywalny przez `cancelled`."""
    err_path = args[-1] + ".log"
    with open(err_path, "w", encoding="utf-8") as err_file:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=err_file, text=True)
        assert proc.stdout is not None
        for line in proc.stdout:
            seconds = G.out_seconds(line.strip())
            if seconds is not None:
                on_seconds(seconds)
            if cancelled():
                proc.kill()
                break
        code = proc.wait()
    if code != 0 and not cancelled():
        with open(err_path, encoding="utf-8", errors="replace") as handle:
            raise RuntimeError(f"ffmpeg {code}: {handle.read()[-600:]}")


async def _probe_part(index: int, row: Dict[str, Any], source: str) -> Dict[str, Any]:
    try:
        return G.probe_info(await asyncio.to_thread(probe_raw, source))
    except Exception as exc:  # noqa: BLE001 - zły plik = czytelny powód ze wskazaniem części
        logger.warning("mentor: część %s grupy %s nieczytelna: %s", index, row.get("group_id"), exc)
        raise M.UserFacingError(G.part_error(index, row.get("filename"))) from exc


async def process_group(lead: Dict[str, Any]) -> None:
    """Praca kolejki dla części 0: ffprobe części -> (wyrównanie) -> concat copy + faststart -> plakat -> gotowe."""
    lead_id, group_id = lead["id"], lead["group_id"]
    rows = await group_rows(group_id)
    count = int(lead.get("group_count") or len(rows))
    if len(rows) != count or any(r["status"] != "processing" or not r.get("r2_key") for r in rows):
        raise M.UserFacingError(MISSING_PART)
    sources = [M.presign_get(r["r2_key"], M.SOURCE_URL_TTL) for r in rows]
    if not all(sources):
        raise RuntimeError("brak adresu źródła części")
    cancelled = lambda: lead_id in M._cancelled  # noqa: E731
    folder = await asyncio.to_thread(M._tmpdir)
    M._progress[lead_id] = 0.0
    try:
        infos = [await _probe_part(i, row, src) for i, (row, src) in enumerate(zip(rows, sources))]
        plan = G.group_plan(infos)
        total = G.total_duration([i.get("duration_s") for i in infos])

        def report(low: float, high: float, base: float, span: float) -> Callable[[float], None]:
            return lambda seconds: M._progress.__setitem__(lead_id, G.group_progress(base, seconds, span, low, high))

        inputs: List[str] = list(sources)  # type: ignore[arg-type]
        durations = [i.get("duration_s") for i in infos]
        low = 0.0
        if plan["mode"] == "normalize":
            inputs, durations, done_s = [], [], 0.0
            for index, (row, src, info) in enumerate(zip(rows, sources, infos)):
                target = os.path.join(folder, f"part{index}.mp4")
                try:
                    await asyncio.to_thread(run_ffmpeg, G.normalize_args(src, target, info, plan),
                                            report(0.0, G.NORMALIZE_SHARE, done_s, total), cancelled)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("mentor: wyrównanie części %s grupy %s nieudane: %s", index, group_id, exc)
                    raise M.UserFacingError(G.part_error(index, row.get("filename"))) from exc
                if cancelled():
                    return
                real = await _probe_part(index, row, target)
                durations.append(real.get("duration_s") or info.get("duration_s"))
                inputs.append(target)
                done_s += float(info.get("duration_s") or 0)
            low = G.NORMALIZE_SHARE
        list_path = os.path.join(folder, "parts.txt")
        with open(list_path, "w", encoding="utf-8") as handle:
            handle.write(G.concat_list(inputs))
        target = os.path.join(folder, "play.mp4")
        joined = G.total_duration(durations)
        await asyncio.to_thread(run_ffmpeg, G.concat_args(list_path, target, plan["mode"] == "copy"),
                                report(low, 0.99, 0.0, joined), cancelled)
        if cancelled():
            return
        await _publish(lead, rows, plan, durations, joined, folder, target)
    finally:
        M._progress.pop(lead_id, None)
        await asyncio.to_thread(shutil.rmtree, folder, True)


async def _publish(lead: Dict[str, Any], rows: List[Dict[str, Any]], plan: Dict[str, Any], durations: List[Any],
                   joined: float, folder: str, target: str) -> None:
    base = lead["r2_key"].rsplit("/", 1)[0]
    play_key, poster_key = f"{base}/play.mp4", f"{base}/poster.jpg"
    await asyncio.to_thread(M.put_file, target, play_key, "video/mp4")
    poster_path = os.path.join(folder, "poster.jpg")
    has_poster = await asyncio.to_thread(M.poster, target, poster_path, joined)
    if has_poster:
        await asyncio.to_thread(M.put_file, poster_path, poster_key, "image/jpeg")
    timeline = G.parts_timeline([r["filename"] for r in rows], durations)
    async with database.transaction():
        for row, part in zip(rows, timeline):
            values: Dict[str, Any] = {"status": "ready", "error": None, "width": plan["width"], "height": plan["height"],
                                      "duration_s": part["duration_s"]}
            if row["id"] == lead["id"]:
                values.update(play_key=play_key, poster_key=poster_key if has_poster else None, duration_s=joined)
            await database.execute(update(mentor_uploads).where(mentor_uploads.c.id == row["id"])
                                   .where(mentor_uploads.c.status == "processing").values(**values))
        if lead.get("video_id"):
            await database.execute(update(mentor_match_videos).where(mentor_match_videos.c.id == lead["video_id"]).values(
                duration_s=int(joined) if joined else None, parts_json=json.dumps(timeline, ensure_ascii=False), updated_at=C.now()))
    await C.touch(lead["pair_id"], lead["uploader_id"], "upload_ready", "videos", lead["match_id"],
                  {"id": lead["id"], "group_id": lead["group_id"], "mode": plan["mode"]})


async def fail_group(lead: Dict[str, Any], message: str) -> None:
    """Błąd jednej części = cała grupa `failed` z polskim powodem (nagranie zostaje na liście z `upload_status`)."""
    await database.execute(update(mentor_uploads).where(mentor_uploads.c.group_id == lead["group_id"])
                           .where(mentor_uploads.c.status.in_(("processing", G.WAITING, "uploading")))
                           .values(status="failed", error=message[:300]))
    await C.touch(lead["pair_id"], lead["uploader_id"], "upload_failed", "videos", lead["match_id"],
                  {"id": lead["id"], "group_id": lead["group_id"]})

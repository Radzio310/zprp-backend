"""Pobieranie klipów Mentora jako MP4 (30.10.2026): plan, zamówienie z przeliczeniem czasu, plansza, paczka.

Rozwija istniejący przepływ MP4 („Ciemnia”), nie buduje drugiego:
  - klip na własnym pliku -> kolejka ffmpeg (`mentor_panel_media`), klip na Bastionie -> zadanie connectora,
  - klip na wideo-linku (YouTube/Vimeo) -> czas przeliczamy z synchronizacji nagrań meczu (`mentor_clip_download_rules`)
    na własny plik, a gdy go nie ma, na nagranie Bastionu; potem ta sama kolejka co wyżej,
  - plansza tytułowa to OSOBNY wariant pliku (`card_*` w `mentor_clips`), robiony z gotowego zwykłego MP4 (Pillow + ffmpeg
    w backendzie; zwykły plik zostaje nietknięty).
Importy bazy na górze jak w reszcie panelu (`app.db` łączy się przy imporcie).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app import mentor_bastion_rules as BR
from app import mentor_clip_download_rules as D
from app import mentor_panel_core as C
from app import mentor_panel_media as M
from app import mentor_panel_rules as R
from app.db import database, mentor_categories, mentor_clips, mentor_match_videos, mentor_uploads
from app.mentor_panel_auth import mentor_actor

logger = logging.getLogger("app.mentor_clip_download")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor"])
Actor = C.MentorActor
FONT_PATH = os.path.join(os.path.dirname(__file__), "fonts", "NotoSans-Regular.ttf")


def derr(status: int, code: str, message: str, **extra: Any):
    from app.mentor_bastion import berr

    return berr(status, code, message, **extra)


# ─── Odczyt: nagrania meczu i źródło ────────────────────────────────────────


def _kind(video: Dict[str, Any]) -> str:
    from app import mentor_bastion_jobs as J

    if video.get("kind") == "upload" and video.get("upload_id"):
        return "file"
    if J.bastion_item_of(video):
        return "bastion"
    return "link"


def _label(video: Dict[str, Any], kind: str) -> str:
    if kind == "bastion":
        return "Handball Bastion"
    title = R.s(video.get("title"))
    if title:
        return title[:60]
    return R.s(video.get("site_name")) or R.s(video.get("provider")).capitalize() or "Nagranie"


def _video_view(video: Dict[str, Any], uploads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    kind = _kind(video)
    up = uploads.get(R.s(video.get("upload_id"))) if kind == "file" else None
    ready = bool(up and up.get("status") == "ready" and up.get("play_key")) if kind == "file" else True
    from app.mentor_video_rules import clean_sync

    return {"id": video["id"], "kind": kind, "label": _label(video, kind), "ready": ready,
            "sync": clean_sync(R.json_value(video.get("sync_json"), {})), "row": video}


class Context:
    """Dane wspólne dla planów jednej paczki: nagrania meczów, karty meczów, kategorie (ładowane raz)."""

    def __init__(self, ctx: Dict[str, Any]):
        self.ctx = ctx
        self._videos: Dict[str, List[Dict[str, Any]]] = {}
        self._uploads: Optional[Dict[str, Dict[str, Any]]] = None
        self._cards: Optional[Dict[str, Dict[str, Any]]] = None
        self._cats: Optional[Dict[str, str]] = None

    async def videos(self, match_id: str) -> List[Dict[str, Any]]:
        if match_id not in self._videos:
            rows = await C.rows(select(mentor_match_videos).where(mentor_match_videos.c.match_id == match_id)
                                .where(mentor_match_videos.c.pair_key == self.ctx["pair_key"]))
            self._videos[match_id] = rows
        return self._videos[match_id]

    async def uploads(self) -> Dict[str, Dict[str, Any]]:
        if self._uploads is None:
            rows = await C.rows(select(mentor_uploads).where(mentor_uploads.c.pair_id == self.ctx["pair_id"]))
            self._uploads = {r["id"]: r for r in rows}
        return self._uploads

    async def card(self, match_id: str) -> Dict[str, Any]:
        if self._cards is None:
            try:
                cards = await C.pair_match_cards(self.ctx["judge_ids"])
            except Exception:  # noqa: BLE001 - brak karty meczu nie blokuje pobrania
                cards = []
            self._cards = {c["match_id"]: c for c in cards}
        card = self._cards.get(match_id) or {}
        return {"date": R.s(card.get("scheduled_at"))[:10], "home": (card.get("home") or {}).get("name"),
                "away": (card.get("away") or {}).get("name"), "code": card.get("match_code")}

    async def category_names(self) -> Dict[str, str]:
        if self._cats is None:
            self._cats = {r["id"]: R.s(r.get("name")) for r in await C.categories(self.ctx, seed=False)}
        return self._cats


def _category_of(clip: Dict[str, Any], names: Dict[str, str]) -> str:
    for cid in R.json_value(clip.get("category_ids"), []) or []:
        if names.get(R.s(cid)):
            return names[R.s(cid)]
    if clip.get("to_discuss"):
        return "Do dyskusji"
    if clip.get("important"):
        return "Istotne"
    return "Bez kategorii"


def _stored_source(clip: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = R.json_value(clip.get("mp4_source_json"), {})
    return raw if raw.get("video_id") else None


# ─── Plan ───────────────────────────────────────────────────────────────────


async def build_plan(shared: Context, clip: Dict[str, Any], actor: Any, *, title_card: bool = False) -> Dict[str, Any]:
    """Plan pobrania klipu (kształt odpowiedzi `GET /clips/{id}/download-plan`) + pole `_target` do zamówienia."""
    from app import mentor_bastion_jobs as J

    uploads = await shared.uploads()
    rows = await shared.videos(clip["match_id"])
    views = {v["id"]: _video_view(v, uploads) for v in rows}
    own_row = next((v for v in rows if v["id"] == clip["video_id"]), None) or await C.one(
        select(mentor_match_videos).where(mentor_match_videos.c.id == clip["video_id"]))
    own = views.get(clip["video_id"]) or (_video_view(own_row, uploads) if own_row else
                                           {"id": clip["video_id"], "kind": "link", "label": "Nagranie", "ready": False, "sync": {}})
    flags_on = BR.load_flags().enabled
    options = [v for v in views.values() if v["id"] != own["id"] and not v["row"].get("deleted_at")
               and (v["kind"] == "file" or (v["kind"] == "bastion" and flags_on))]
    decision = D.choose_source(own, options)
    option = decision["option"]
    reason, missing = decision["reason"], decision["missing"]
    start_s, end_s = float(clip["start_s"]), float(clip["end_s"])
    source = option["kind"] if option else None
    target: Optional[Dict[str, Any]] = None
    if decision["mode"] == "direct" and option and option["kind"] == "bastion" and not flags_on:
        reason, source = "NO_SOURCE", None
    if reason is None and option:
        if decision["mode"] == "convert":
            try:
                start_s, end_s = D.convert_range(own["sync"], option["sync"], start_s, end_s)
            except ValueError:
                reason = "BAD_RANGE"
        if reason is None and source == "bastion":
            try:
                BR.bastion_clip_range(start_s, end_s)
            except BR.ClipRangeError:
                reason = "BAD_RANGE"
        if reason is None:
            target = {"mode": decision["mode"], "video_id": option["id"], "kind": source, "row": option["row"],
                      "start_s": start_s, "end_s": end_s}
    if reason == "NEED_SYNC" or reason == "NO_SOURCE" or reason == "BAD_RANGE":
        source = None if reason != "NEED_SYNC" else source
    can = reason is None and target is not None
    # Nazwa pliku i folder.
    cats = await shared.category_names()
    category = _category_of(clip, cats)
    seconds = D.match_time_s(clip.get("match_ms"), float(clip["start_s"]), own["sync"])
    folder = D.folder_names(await shared.card(clip["match_id"]), category)
    filename = D.download_filename(clip.get("title"), seconds)
    lines = [folder["match"], D.match_clock(seconds), R.s(clip.get("title")) or "Klip", category]
    sig = D.card_signature(lines)
    status = await _mp4_status(clip, target, own)
    job_info = _job_info(await _plan_job(clip, target, own))
    card_ready = clip.get("card_status") == "ready" and clip.get("card_key") and clip.get("card_sig") == sig
    effective = status
    if title_card and status == "ready":
        effective = "ready" if card_ready else (clip.get("card_status") if clip.get("card_sig") == sig and
                                                clip.get("card_status") in ("queued", "working", "failed") else "none")
    url = None
    if effective == "ready" and can:
        key = clip.get("card_key") if title_card else clip.get("mp4_key")
        url = M.presign_get(key, M.DOWNLOAD_TTL, filename)
    plan = {
        "clip_id": clip["id"], "can_download": bool(can), "source": source if can else None,
        "reason": reason, "missing": missing if reason == "NEED_SYNC" else [],
        "hint": D.hint_for(reason, missing, option) if reason else D.hint_for(None, option=option),
        "mp4_status": effective, "url": url, "estimated_s": D.estimate_s(source, title_card) if can else None,
        "filename": filename, "folder": folder, "title_card_available": bool(M.storage_ready()),
        "title_card": bool(title_card), "card_signature": sig, "card_lines": lines,
        "source_range": {"video_id": option["id"], "start_s": start_s, "end_s": end_s} if can and option else None,
        **job_info,
    }
    plan["_target"] = target
    return plan


async def _mp4_status(clip: Dict[str, Any], target: Optional[Dict[str, Any]], own: Dict[str, Any]) -> str:
    """none | queued | working | ready | failed - dla klipu na własnym nagraniu i dla klipu przeliczonego."""
    from app import mentor_bastion_jobs as J

    stored = clip.get("mp4_status") or "none"
    if target and target["mode"] == "convert":
        src = _stored_source(clip)
        same = bool(src and src["video_id"] == target["video_id"] and abs(float(src["start_s"]) - target["start_s"]) < 0.01
                    and abs(float(src["end_s"]) - target["end_s"]) < 0.01)
        if target["kind"] == "bastion":
            job = await J.current_job(clip)
            if job and job["state"] != "cancelled" and job.get("source_video_id") == target["video_id"] and \
                    (float(job["start_s"]), float(job["end_s"])) == _bastion_pair(target):
                if job["state"] == "ready":
                    return "ready" if stored == "ready" and clip.get("mp4_key") else "working"
                return "failed" if job["state"] == "failed" else "working"
            return "none"
        return stored if same else "none"
    if own["kind"] == "bastion":
        media = (await J.media_for_clips([clip])).get(clip["id"])
        return J.mp4_status_of(media, stored)
    return stored


async def _plan_job(clip: Dict[str, Any], target: Optional[Dict[str, Any]], own: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Zadanie Bastionu, które obsługuje ten plan (własne nagranie z Bastionu albo klip przeliczony na Bastion)."""
    from app import mentor_bastion_jobs as J

    if target and target["mode"] == "convert":
        if target["kind"] != "bastion":
            return None
        job = await J.current_job(clip)
        if job and job["state"] != "cancelled" and job.get("source_video_id") == target["video_id"] and                 (float(job["start_s"]), float(job["end_s"])) == _bastion_pair(target):
            return job
        return None
    if own["kind"] == "bastion":
        job = await J.current_job(clip)
        return job if job and job["state"] != "cancelled" else None
    return None


def _job_info(job: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Pola planu o zadaniu: etap, kod i polski komunikat błędu, liczba prób. Bez szczegółów technicznych i adresów."""
    state = (job or {}).get("state")
    stage = BR.plan_job_stage(state)
    code = (job or {}).get("last_error_code") if state in ("failed", "retryable_failed", "needs_reconciliation") else None
    message = BR.job_message(state, code, None) if code else None
    return {"job_stage": stage, "error_code": code, "error_message": message,
            "attempts": int((job or {}).get("attempts") or 0) if job else 0}


def _bastion_pair(target: Dict[str, Any]) -> tuple:
    rng = BR.bastion_clip_range(target["start_s"], target["end_s"])
    return float(rng["start_s"]), float(rng["end_s"])


def public_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in plan.items() if not k.startswith("_") and k not in ("card_lines",)}


# ─── Zamówienie ─────────────────────────────────────────────────────────────


def fail_for(plan: Dict[str, Any]):
    """Odrzucenie zamówienia: kod z powodu planu (NEED_SYNC z `missing`, NO_SOURCE), nie ogólne MP4_LINK_VIDEO."""
    reason = plan["reason"] or "NO_SOURCE"
    if reason == "NEED_SYNC":
        return derr(409, "NEED_SYNC", plan["hint"], missing=plan["missing"])
    if reason == "NOT_READY":
        return derr(409, "MP4_NOT_READY", plan["hint"])
    if reason == "BAD_RANGE":
        return derr(422, "CLIP_RANGE", plan["hint"])
    return derr(409, "NO_SOURCE", plan["hint"])


async def place_order(ctx: Dict[str, Any], clip: Dict[str, Any], actor: Any, plan: Dict[str, Any]) -> Dict[str, Any]:
    """Zakłada zwykły MP4 (bez planszy) według planu. Zwraca odpowiedź w kształcie dotychczasowego `/mp4`."""
    from app import mentor_bastion_jobs as J

    target = plan["_target"]
    video = target["row"]
    if target["mode"] == "direct":
        if target["kind"] == "bastion":
            from app.mentor_bastion import order_mp4

            return await order_mp4(ctx, clip, video, actor)
        return await M.queue_clip_file(ctx, clip, actor, None)
    source = {"video_id": target["video_id"], "start_s": target["start_s"], "end_s": target["end_s"]}
    if target["kind"] == "file":
        return await M.queue_clip_file(ctx, clip, actor, source)
    # Bastion z przeliczonego zakresu: zmiana źródła = nowa rewizja pliku (stary wynik nie nadpisze nowego).
    existing = await J.current_job(clip)
    stored = _stored_source(clip)
    pair = _bastion_pair(target)
    changed = (existing and existing["state"] != "cancelled" and
               (existing.get("source_video_id") != target["video_id"] or (float(existing["start_s"]), float(existing["end_s"])) != pair))
    if changed or (stored and stored["video_id"] != target["video_id"]):
        await database.execute(update(mentor_clips).where(mentor_clips.c.id == clip["id"]).values(
            media_rev=int(clip.get("media_rev") or 1) + 1, mp4_status="none", card_status="none", card_sig=None))
    await database.execute(update(mentor_clips).where(mentor_clips.c.id == clip["id"]).values(mp4_source_json=json.dumps(source)))
    fresh = await C.one(select(mentor_clips).where(mentor_clips.c.id == clip["id"])) or clip
    virtual = {**fresh, "start_s": target["start_s"], "end_s": target["end_s"], "video_id": target["video_id"]}
    if existing and existing["state"] == "failed" and not changed:
        job = await J.resume_clip_media(fresh, video, actor)  # ponowienie po niepowodzeniu: zadanie od początku
    else:
        job = await J.after_clip_saved(virtual, video, actor, want_mp4=True)
    if job is None:
        from app.mentor_bastion import _unavailable

        raise _unavailable()
    await C.touch(ctx, actor.judge_id, "clip_mp4", "clips", clip["match_id"], {"id": clip["id"], "source": "bastion_synced"})
    return {"mp4_status": "queued" if job.get("state") == "queued" else "working"}


async def order(ctx: Dict[str, Any], clip: Dict[str, Any], actor: Any, title_card: bool, shared: Optional[Context] = None) -> Dict[str, Any]:
    shared = shared or Context(ctx)
    plan = await build_plan(shared, clip, actor, title_card=title_card)
    if not plan["can_download"]:
        raise fail_for(plan)
    result = await place_order(ctx, clip, actor, plan)
    if title_card:
        result = {**result, **(await queue_card(clip, plan))}
    return result


async def _refresh(shared: Context, clip: Dict[str, Any], actor: Any, title_card: bool) -> Dict[str, Any]:
    fresh = await C.one(select(mentor_clips).where(mentor_clips.c.id == clip["id"])) or clip
    return await build_plan(shared, fresh, actor, title_card=title_card)


async def queue_card(clip: Dict[str, Any], plan: Dict[str, Any]) -> Dict[str, Any]:
    """Wariant z planszą: kolejkowany, gdy jeszcze nie ma aktualnego. Robi go worker po gotowym zwykłym MP4."""
    fresh = await C.one(select(mentor_clips).where(mentor_clips.c.id == clip["id"])) or clip
    sig = plan["card_signature"]
    if fresh.get("card_sig") == sig and fresh.get("card_status") in ("queued", "working", "ready"):
        return {"card_status": fresh["card_status"]}
    if not M.storage_ready():
        return {"card_status": "none"}
    await database.execute(update(mentor_clips).where(mentor_clips.c.id == clip["id"]).values(card_status="queued", card_sig=sig))
    await database.execute(update(mentor_clips).where(mentor_clips.c.id == clip["id"]).values(
        card_key=None, card_size=None))
    M.wake_worker()
    return {"card_status": "queued"}


# ─── Plansza (worker) ───────────────────────────────────────────────────────


def _wrap(draw, text: str, font, width: int, max_lines: int) -> List[str]:
    words, lines, line = text.split(), [], ""
    for word in words:
        trial = f"{line} {word}".strip()
        if draw.textlength(trial, font=font) <= width or not line:
            line = trial
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = lines[-1].rstrip(" .") + "..."
    return lines


def render_card_png(lines: List[str], width: int, height: int, target: str) -> None:
    """Plansza 2 s: mecz u góry, duża minuta, tytuł, kategoria. Ciemne tło i koralowy akcent Mentora."""
    from PIL import Image, ImageDraw, ImageFont

    match, clock, title, category = (list(lines) + ["", "", "", ""])[:4]
    img = Image.new("RGB", (width, height), (14, 17, 22))
    draw = ImageDraw.Draw(img)
    unit = height / 720.0
    big, mid, small = (ImageFont.truetype(FONT_PATH, max(12, int(size * unit))) for size in (120, 52, 32))
    margin = int(width * 0.08)
    inner = width - 2 * margin
    draw.rectangle([margin, int(height * 0.2), margin + int(10 * unit), int(height * 0.82)], fill=(255, 122, 89))
    left = margin + int(40 * unit)
    y = int(height * 0.2)
    for row in _wrap(draw, match, small, inner - int(40 * unit), 2):
        draw.text((left, y), row, font=small, fill=(150, 160, 175))
        y += int(42 * unit)
    y += int(14 * unit)
    draw.text((left, y), clock, font=big, fill=(255, 122, 89))
    y += int(150 * unit)
    for row in _wrap(draw, title, mid, inner - int(40 * unit), 2):
        draw.text((left, y), row, font=mid, fill=(240, 243, 247))
        y += int(64 * unit)
    y += int(14 * unit)
    draw.text((left, y), category, font=small, fill=(255, 122, 89))
    img.save(target, "PNG")


def card_ffmpeg_args(card_png: str, source: str, target: str, width: int, height: int, has_audio: bool) -> List[str]:
    """ffmpeg: plansza (obraz w pętli + cisza) i klip sklejone filtrem concat; ten sam rozmiar i klatkaż."""
    seconds = D.CARD_SECONDS
    scale = f"scale={width}:{height}:force_original_aspect_ratio=decrease,pad={width}:{height}:(ow-iw)/2:(oh-ih)/2,setsar=1,fps=30,format=yuv420p"
    args = ["ffmpeg", "-hide_banner", "-nostdin", "-y", "-loop", "1", "-framerate", "30", "-t", str(seconds), "-i", card_png]
    if has_audio:
        args += ["-f", "lavfi", "-t", str(seconds), "-i", "anullsrc=r=48000:cl=stereo", "-i", source]
        graph = (f"[0:v]{scale}[v0];[2:v]{scale}[v1];[1:a]aformat=sample_rates=48000:channel_layouts=stereo[a0];"
                 f"[2:a]aformat=sample_rates=48000:channel_layouts=stereo[a1];[v0][a0][v1][a1]concat=n=2:v=1:a=1[v][a]")
        maps = ["-map", "[v]", "-map", "[a]", "-c:a", "aac", "-b:a", "128k"]
    else:
        args += ["-i", source]
        graph = f"[0:v]{scale}[v0];[1:v]{scale}[v1];[v0][v1]concat=n=2:v=1:a=0[v]"
        maps = ["-map", "[v]", "-an"]
    return [*args, "-filter_complex", graph, *maps, "-c:v", "libx264", "-preset", "veryfast", "-crf", "21",
            "-pix_fmt", "yuv420p", "-movflags", "+faststart", target]


async def next_card() -> Optional[Dict[str, Any]]:
    return await C.one(select(mentor_clips).where(mentor_clips.c.card_status.in_(("queued", "working")))
                       .where(mentor_clips.c.mp4_status == "ready").where(mentor_clips.c.mp4_key.isnot(None))
                       .where(mentor_clips.c.deleted_at.is_(None)).order_by(mentor_clips.c.updated_at.asc()).limit(1))


async def process_card(clip: Dict[str, Any]) -> None:
    from app import mentor_bastion_media as BM

    await database.execute(update(mentor_clips).where(mentor_clips.c.id == clip["id"]).values(card_status="working"))
    source = M.presign_get(clip["mp4_key"], M.SOURCE_URL_TTL)
    if not source:
        raise RuntimeError("brak adresu zwykłego MP4")
    info = await asyncio.to_thread(BM.ffprobe_file, source)
    width = int(info.get("width") or 1280) // 2 * 2
    height = int(info.get("height") or 720) // 2 * 2
    folder = await asyncio.to_thread(M._tmpdir)
    try:
        png, target = os.path.join(folder, "card.png"), os.path.join(folder, "card.mp4")
        lines = await _card_lines(clip)
        await asyncio.to_thread(render_card_png, lines, width, height, png)
        done = await asyncio.to_thread(M._run, card_ffmpeg_args(png, source, target, width, height, bool(info.get("has_audio"))), 1800)
        if done.returncode != 0 or not os.path.exists(target):
            raise RuntimeError(f"ffmpeg: {done.stderr[-400:]}")
        key = M.object_key(clip["pair_id"], "clips", f"{clip['id']}-plansza.mp4")
        size = await asyncio.to_thread(M.put_file, target, key, "video/mp4")
        await database.execute(update(mentor_clips).where(mentor_clips.c.id == clip["id"])
                               .values(card_status="ready", card_key=key, card_size=size, card_sig=D.card_signature(lines)))
    finally:
        await asyncio.to_thread(shutil.rmtree, folder, True)


async def _card_lines(clip: Dict[str, Any]) -> List[str]:
    """Treść planszy z AKTUALNYCH danych klipu (tytuł mógł się zmienić od zamówienia); odcisk idzie do wiersza."""
    fresh = await C.one(select(mentor_clips).where(mentor_clips.c.id == clip["id"])) or clip
    from app.db import mentoring_pairs

    pair = await C.one(select(mentoring_pairs).where(mentoring_pairs.c.id == fresh["pair_id"])) or {}
    judge_ids = [R.s(j) for j in R.json_value(pair.get("judge_ids"), [])]
    shared = Context({"pair_id": fresh["pair_id"], "pair_key": "|".join(sorted(judge_ids)), "judge_ids": judge_ids})
    video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == fresh["video_id"])) or {}
    from app.mentor_video_rules import clean_sync

    sync = clean_sync(R.json_value(video.get("sync_json"), {}))
    names = {r["id"]: R.s(r.get("name")) for r in await C.rows(select(mentor_categories).where(
        (mentor_categories.c.pair_id == fresh["pair_id"]) | mentor_categories.c.pair_id.is_(None)))}
    folder = D.folder_names(await shared.card(fresh["match_id"]), _category_of(fresh, names))
    seconds = D.match_time_s(fresh.get("match_ms"), float(fresh["start_s"]), sync)
    return [folder["match"], D.match_clock(seconds), R.s(fresh.get("title")) or "Klip", _category_of(fresh, names)]


# ─── Trasy ──────────────────────────────────────────────────────────────────


async def _clip(clip_id: str) -> Dict[str, Any]:
    clip = await C.one(select(mentor_clips).where(mentor_clips.c.id == clip_id))
    if not clip or clip.get("deleted_at") is not None:
        raise C.err(404, "NOT_FOUND", "Nie ma takiego klipu.")
    return clip


@router.get("/clips/{clip_id}/download-plan")
async def download_plan(clip_id: str, title_card: bool = Query(False), actor: Actor = Depends(mentor_actor)):
    clip = await _clip(clip_id)
    ctx = await C.pair_context(clip["pair_id"], actor)
    return public_plan(await build_plan(Context(ctx), clip, actor, title_card=title_card))


class BatchBody(BaseModel):
    clip_ids: List[str] = Field(default_factory=list)
    #: Zamiast `clip_ids`: wszystkie nieusunięte klipy tego meczu w parze („Pobierz wszystkie klipy meczu”).
    match_id: Optional[str] = None
    title_card: bool = False


@router.post("/pairs/{pair_id}/clips/download-batch")
async def download_batch(pair_id: str, body: BatchBody, actor: Actor = Depends(mentor_actor)):
    """Zamawia każdy klip, który się da; reszta wraca z powodem. Zamówienia Bastionu mieszczą się w limicie kolejki."""
    from sqlalchemy import func

    from app.db import mentor_bastion_clip_jobs as JOBS
    from app import mentor_bastion_jobs as J

    ctx = await C.pair_context(pair_id, actor, action="create")
    if body.match_id and R.s(body.match_id):
        in_match = await C.rows(select(mentor_clips.c.id).where(mentor_clips.c.pair_id == ctx["pair_id"])
                                .where(mentor_clips.c.match_id == R.s(body.match_id)).where(mentor_clips.c.deleted_at.is_(None))
                                .order_by(mentor_clips.c.start_s.asc()))
        ids = [r["id"] for r in in_match][: D.BATCH_MAX]
    else:
        ids = list(dict.fromkeys(R.s(i) for i in body.clip_ids if R.s(i)))[: D.BATCH_MAX]
    if not ids:
        raise C.err(422, "NO_CLIPS", "Brak klipów do pobrania. Podaj clip_ids albo match_id meczu z klipami.")
    found = {r["id"]: r for r in await C.rows(select(mentor_clips).where(mentor_clips.c.id.in_(ids))
                                              .where(mentor_clips.c.pair_id == ctx["pair_id"]).where(mentor_clips.c.deleted_at.is_(None)))}
    shared = Context(ctx)
    real = J.real_judge_of(actor)
    active = await database.fetch_val(select(func.count()).select_from(JOBS).where(JOBS.c.requested_by_real_judge_id == real)
                                      .where(JOBS.c.state.in_(BR.JOB_ACTIVE))) or 0
    plans: List[Dict[str, Any]] = []
    for cid in ids:
        clip = found.get(cid)
        if not clip:
            plans.append({"clip_id": cid, "can_download": False, "reason": "NOT_FOUND", "source": None, "missing": [], "mp4_status": "none",
                          "hint": "Nie ma takiego klipu w tej parze.", "url": None, "_target": None})
            continue
        plans.append(await build_plan(shared, clip, actor, title_card=body.title_card))
    allowed = D.allocate_batch(plans, int(active))
    items: List[Dict[str, Any]] = []
    for cid, plan, ok in zip(ids, plans, allowed):
        item = public_plan(plan)
        item["ordered"] = False
        if plan["can_download"] and not ok:
            item.update(can_download=False, reason="QUEUE_LIMIT",
                        hint="Kolejka Bastionu jest pełna. Poczekaj na gotowe klipy i pobierz resztę ponownie.")
        elif plan["can_download"]:
            try:
                clip = found[cid]
                await place_order(ctx, clip, actor, plan)
                if body.title_card:
                    await queue_card(clip, plan)
                refreshed = await _refresh(shared, clip, actor, body.title_card)
                item = {**public_plan(refreshed), "ordered": True}
            except Exception as exc:  # noqa: BLE001 - jeden zły klip nie wstrzymuje paczki
                detail = getattr(exc, "detail", None)
                code = detail.get("code") if isinstance(detail, dict) else "ORDER_FAILED"
                item.update(can_download=False, reason=code or "ORDER_FAILED",
                            hint=(detail.get("message") if isinstance(detail, dict) else None) or "Nie udało się zamówić pliku.")
                logger.warning("mentor: zamówienie klipu %s w paczce nieudane", cid, exc_info=not isinstance(detail, dict))
        items.append(item)
    return {"items": items}

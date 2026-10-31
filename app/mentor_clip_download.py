"""Pobieranie klipów Mentora jako MP4 (30.10.2026): plan, zamówienie z przeliczeniem czasu, plansza, paczka.

Rozwija istniejący przepływ MP4 („Ciemnia”), nie buduje drugiego:
  - klip na własnym pliku -> kolejka ffmpeg (`mentor_panel_media`), klip na Bastionie -> zadanie connectora,
  - klip na wideo-linku (YouTube/Vimeo) -> czas przeliczamy z synchronizacji nagrań meczu (`mentor_clip_download_rules`)
    na własny plik, a gdy go nie ma, na nagranie Bastionu; potem ta sama kolejka co wyżej,
  - plansza tytułowa to OSOBNY wariant pliku (`card_*` w `mentor_clips`), robiony z gotowego zwykłego MP4 (wygląd i ruch:
    `mentor_clip_card`; zwykły plik zostaje nietknięty).
Importy bazy na górze jak w reszcie panelu (`app.db` łączy się przy imporcie).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app import mentor_bastion_rules as BR
from app import mentor_clip_card as CARD
from app import mentor_clip_download_rules as D
from app import mentor_panel_core as C
from app import mentor_panel_media as M
from app import mentor_panel_rules as R
from app import mentor_veo_rules as VR
from app.db import database, mentor_clips, mentor_match_videos, mentor_uploads
from app.mentor_panel_auth import mentor_actor

logger = logging.getLogger("app.mentor_clip_download")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor"])
Actor = C.MentorActor

#: Herb na planszę: limity pobierania i pamięć wyników (herb + barwa). Błąd pamiętamy krócej, ale paczka nie czeka na każdy klip.
CREST_MAX_BYTES = 1_500_000
CREST_DEADLINE_S = 5.0
CREST_CACHE_MAX = 48
CREST_TTL_S = 6 * 3600.0
CREST_FAIL_TTL_S = 600.0
_crest_cache: "OrderedDict[str, Tuple[float, Optional[bytes], Optional[str]]]" = OrderedDict()


def derr(status: int, code: str, message: str, **extra: Any):
    from app.mentor_bastion import berr

    return berr(status, code, message, **extra)


# ─── Odczyt: nagrania meczu i źródło ────────────────────────────────────────


def _kind(video: Dict[str, Any]) -> str:
    from app import mentor_bastion_jobs as J

    if video.get("kind") == "upload" and video.get("upload_id"):
        return "file"
    if video.get("provider") == "veo" or VR.is_veo_url(video.get("url")):
        return "veo"
    if J.bastion_item_of(video):
        return "bastion"
    return "link"


def _label(video: Dict[str, Any], kind: str) -> str:
    if kind == "bastion":
        return "Handball Bastion"
    title = R.s(video.get("title"))
    if title:
        return title[:60]
    if kind == "veo":
        return "Veo"
    return R.s(video.get("site_name")) or R.s(video.get("provider")).capitalize() or "Nagranie"


def _video_view(video: Dict[str, Any], uploads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    kind = _kind(video)
    up = uploads.get(R.s(video.get("upload_id"))) if kind == "file" else None
    ready = bool(up and up.get("status") == "ready" and up.get("play_key")) if kind == "file" else True
    veo_status = None
    if kind == "veo":
        veo_status = VR.public_fields(R.json_value(video.get("veo_json"), {}))["veo_status"]
        ready = veo_status == "ok"
    from app.mentor_video_rules import clean_sync

    return {"id": video["id"], "kind": kind, "label": _label(video, kind), "ready": ready, "veo_status": veo_status,
            "sync": clean_sync(R.json_value(video.get("sync_json"), {})), "row": video}


class Context:
    """Dane wspólne dla planów jednej paczki: nagrania meczów, karty meczów, kategorie (ładowane raz)."""

    def __init__(self, ctx: Dict[str, Any]):
        self.ctx = ctx
        self._videos: Dict[str, List[Dict[str, Any]]] = {}
        self._uploads: Optional[Dict[str, Dict[str, Any]]] = None
        self._cards: Optional[Dict[str, Dict[str, Any]]] = None
        self._cats: Optional[Dict[str, str]] = None
        self._category_rows: Optional[List[Dict[str, Any]]] = None
        self._watched: Dict[str, Dict[str, Any]] = {}

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

    async def _raw_card(self, match_id: str) -> Dict[str, Any]:
        """Karta meczu pary albo (przedrostek `tr_`) migawka meczu z Trybuny. Brak karty = puste pola, pobrania nie blokuje."""
        if R.s(match_id).startswith("tr_"):
            if match_id not in self._watched:
                from app.mentor_trybuna import lookup_cards

                try:
                    self._watched.update(await lookup_cards(self.ctx["pair_id"], [match_id]))
                except Exception:  # noqa: BLE001
                    logger.warning("mentor: karta meczu z Trybuny %s nieczytelna", match_id, exc_info=True)
                self._watched.setdefault(match_id, {})
            return self._watched[match_id]
        if self._cards is None:
            try:
                cards = await C.pair_match_cards(self.ctx["judge_ids"])
            except Exception:  # noqa: BLE001 - brak karty meczu nie blokuje pobrania
                cards = []
            self._cards = {c["match_id"]: c for c in cards}
        return self._cards.get(match_id) or {}

    async def card(self, match_id: str) -> Dict[str, Any]:
        card = await self._raw_card(match_id)
        home, away = card.get("home") or {}, card.get("away") or {}
        return {"date": R.s(card.get("scheduled_at"))[:10], "home": home.get("name"), "away": away.get("name"), "code": card.get("match_code"),
                "competition": card.get("competition_name") or card.get("category"), "home_logo": home.get("logo_url"), "away_logo": away.get("logo_url")}

    async def category_rows(self) -> List[Dict[str, Any]]:
        if self._category_rows is None:
            self._category_rows = await C.categories(self.ctx, seed=False)
        return self._category_rows

    async def category_names(self) -> Dict[str, str]:
        if self._cats is None:
            self._cats = {r["id"]: R.s(r.get("name")) for r in await self.category_rows()}
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


def _category_color(clip: Dict[str, Any], rows: List[Dict[str, Any]]) -> str:
    """Kolor kategorii z `_category_of`: ta sama kolejność, nazwa koloru z palety Mentora."""
    named = {r["id"]: r for r in rows if R.s(r.get("name"))}
    for cid in R.json_value(clip.get("category_ids"), []) or []:
        if R.s(cid) in named:
            return R.s(named[R.s(cid)].get("color")) or "slate"
    if clip.get("to_discuss"):
        return "amber"
    return "orange" if clip.get("important") else "slate"


async def _card_content(shared: Context, clip: Dict[str, Any], sync: Any) -> Tuple[List[str], Dict[str, str], Dict[str, Any]]:
    """Treść planszy, wspólna dla planu i workera, żeby ich podpisy były równe: `card_lines`, pola dodatkowe, karta meczu."""
    match = await shared.card(clip["match_id"])
    rows = await shared.category_rows()
    category = _category_of(clip, {r["id"]: R.s(r.get("name")) for r in rows})
    video_s = float(clip["start_s"])
    seconds = D.match_time_s(clip.get("match_ms"), video_s, sync)
    lines = [D.folder_names(match, category)["match"], D.match_clock(seconds), R.s(clip.get("title")) or "Klip", category]
    details = D.card_details(match, category_color=_category_color(clip, rows), time_label=D.card_time_label(clip.get("match_ms"), video_s, sync))
    return lines, details, match


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
               and (v["kind"] in ("file", "veo") or (v["kind"] == "bastion" and flags_on))]
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
    if reason == "NOT_READY" and option and option["kind"] == "veo":
        reason = D.VEO_REASONS.get(option.get("veo_status") or "unavailable", "VEO_UNAVAILABLE")
    if reason == "NEED_SYNC" or reason == "NO_SOURCE" or reason == "BAD_RANGE":
        source = None if reason != "NEED_SYNC" else source
    can = reason is None and target is not None
    # Nazwa pliku i folder.
    category = _category_of(clip, await shared.category_names())
    seconds = D.match_time_s(clip.get("match_ms"), float(clip["start_s"]), own["sync"])
    folder = D.folder_names(await shared.card(clip["match_id"]), category)
    filename = D.download_filename(clip.get("title"), seconds)
    lines, details, _match = await _card_content(shared, clip, own["sync"])
    sig = D.card_signature(lines, details)
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
        "title_card": bool(title_card), "card_signature": sig, "card_lines": lines, "card_details": details,
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
    return {k: v for k, v in plan.items() if not k.startswith("_") and k not in ("card_lines", "card_details")}


# ─── Zamówienie ─────────────────────────────────────────────────────────────


def fail_for(plan: Dict[str, Any]):
    """Odrzucenie zamówienia: kod z powodu planu (NEED_SYNC z `missing`, NO_SOURCE), nie ogólne MP4_LINK_VIDEO."""
    reason = plan["reason"] or "NO_SOURCE"
    if reason == "NEED_SYNC":
        return derr(409, "NEED_SYNC", plan["hint"], missing=plan["missing"])
    if reason == "NOT_READY":
        return derr(409, "MP4_NOT_READY", plan["hint"])
    if reason in D.VEO_REASONS.values():
        return derr(409, reason, plan["hint"])
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
        if target["kind"] == "veo":
            return await M.queue_clip_veo(ctx, clip, actor, None, video)
        return await M.queue_clip_file(ctx, clip, actor, None)
    source = {"video_id": target["video_id"], "start_s": target["start_s"], "end_s": target["end_s"]}
    if target["kind"] == "veo":
        return await M.queue_clip_veo(ctx, clip, actor, source, video)
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


def render_card_png(lines: List[str], width: int, height: int, target: str, details: Optional[Dict[str, Any]] = None) -> None:
    """Plansza po ustaniu ruchu jako jeden PNG (podgląd i testy; do pliku idą osobne warstwy z `CARD.write_layers`)."""
    CARD.flatten(CARD.compose(CARD.card_data(lines, details), width, height)).save(target, "PNG")


async def _fetch_crest(url: str) -> Tuple[Optional[bytes], Optional[str]]:
    """(PNG herbu, barwa) albo (None, None). Tylko hosty z `zprp_public_clubs.logo_url` (SSRF), bez przekierowań, z limitem
    czasu i rozmiaru strumienia."""
    import httpx

    from app.zprp_public import crest as Z

    host = Z._host_ok(url)
    if not host or host not in await Z.allowed_hosts():
        return None, None
    body = bytearray()
    async with httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(3.0, connect=1.5)) as client:
        async with client.stream("GET", url, headers={"Accept": "image/*"}) as response:
            kind = response.headers.get("content-type", "").split(";")[0].strip().lower()
            if response.status_code != 200 or not kind.startswith("image/"):
                return None, None
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > CREST_MAX_BYTES:
                    return None, None
    raw = bytes(body)
    image = await asyncio.to_thread(CARD.normalize_crest, raw)
    if not image:
        return None, None
    return image, await asyncio.to_thread(CARD.dominant_color, raw)


async def crest_asset(url: Optional[str]) -> Tuple[Optional[bytes], Optional[str]]:
    """Herb i jego dominująca barwa z pamięcią wyników. Nigdy nie rzuca: bez herbu plansza dostaje zastępczą tarczę."""
    target = R.s(url)
    if not target:
        return None, None
    now = time.monotonic()
    hit = _crest_cache.get(target)
    if hit and hit[0] > now:
        _crest_cache.move_to_end(target)
        return hit[1], hit[2]
    try:
        image, color = await asyncio.wait_for(_fetch_crest(target), CREST_DEADLINE_S)
    except Exception:  # noqa: BLE001 - sieć, limit czasu, zły obraz
        logger.info("mentor: herb %s niedostępny na planszę", target, exc_info=True)
        image, color = None, None
    _crest_cache[target] = (now + (CREST_TTL_S if image else CREST_FAIL_TTL_S), image, color)
    while len(_crest_cache) > CREST_CACHE_MAX:
        _crest_cache.popitem(last=False)
    return image, color


async def _crest_url(logo: Any, name: Any) -> Optional[str]:
    """Adres herbu: z karty meczu, inaczej po nazwie drużyny (monitor okręgu i archiwum kart nie mają `logo_url`)."""
    if R.s(logo):
        return R.s(logo)
    try:
        from app.mentor_bastion_search import crest_for

        return await crest_for(name)
    except Exception:  # noqa: BLE001
        logger.info("mentor: indeks herbów niedostępny na planszę", exc_info=True)
        return None


async def card_assets(match: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Herby i barwy obu drużyn: (crests, colors). Braki to None."""
    urls = [await _crest_url(match.get("home_logo"), match.get("home")), await _crest_url(match.get("away_logo"), match.get("away"))]
    (home, home_color), (away, away_color) = await asyncio.gather(crest_asset(urls[0]), crest_asset(urls[1]))
    return {"home": home, "away": away}, {"home": home_color, "away": away_color}


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
        target = os.path.join(folder, "card.mp4")
        lines, details, match = await _card_lines(clip)
        crests, colors = await card_assets(match)
        layers = await asyncio.to_thread(CARD.write_layers, CARD.card_data(lines, details, crests, colors), width, height, folder)
        done = await asyncio.to_thread(M._run, CARD.ffmpeg_args(layers, source, target, width, height, bool(info.get("has_audio"))), 1800)
        if done.returncode != 0 or not os.path.exists(target):
            raise RuntimeError(f"ffmpeg: {done.stderr[-400:]}")
        key = M.object_key(clip["pair_id"], "clips", f"{clip['id']}-plansza.mp4")
        size = await asyncio.to_thread(M.put_file, target, key, "video/mp4")
        await database.execute(update(mentor_clips).where(mentor_clips.c.id == clip["id"])
                               .values(card_status="ready", card_key=key, card_size=size, card_sig=D.card_signature(lines, details)))
    finally:
        await asyncio.to_thread(shutil.rmtree, folder, True)


async def _card_lines(clip: Dict[str, Any]) -> Tuple[List[str], Dict[str, str], Dict[str, Any]]:
    """Treść planszy z AKTUALNYCH danych klipu (tytuł mógł się zmienić od zamówienia); odcisk idzie do wiersza."""
    fresh = await C.one(select(mentor_clips).where(mentor_clips.c.id == clip["id"])) or clip
    from app.db import mentoring_pairs

    pair = await C.one(select(mentoring_pairs).where(mentoring_pairs.c.id == fresh["pair_id"])) or {}
    judge_ids = [R.s(j) for j in R.json_value(pair.get("judge_ids"), [])]
    shared = Context({"pair_id": fresh["pair_id"], "pair_key": "|".join(sorted(judge_ids)), "judge_ids": judge_ids})
    video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == fresh["video_id"])) or {}
    from app.mentor_video_rules import clean_sync

    return await _card_content(shared, fresh, clean_sync(R.json_value(video.get("sync_json"), {})))


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

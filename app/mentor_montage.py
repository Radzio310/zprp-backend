"""Montaż zestawienia w jeden film (12.11.2026) - trasy, przegląd gotowości i worker. Kontrakt: `docs/mentor-panel.md` sekcja 15.

  - `POST /mentor-panel/pairs/{p}/montages/preflight` - gotowość pozycji bez zamawiania (podgląd przed „Zrób film”),
  - `POST /mentor-panel/pairs/{p}/montages` - zamówienie filmu z zestawienia (całość albo wybrane N w podanej kolejności)
    albo z zaznaczenia; zamawia zwykłe MP4 klipów tą samą drogą co pobieranie (`mentor_clip_download.place_order`),
  - `GET /mentor-panel/pairs/{p}/montages?compilation_id=` - lista, `GET /mentor-panel/montages/{id}` - stan do odpytywania,
  - `POST /mentor-panel/montages/{id}/retry` - ponowienie (po błędzie albo po wygaśnięciu), `DELETE` - anuluj i usuń.

Przygotowanie czeka na pliki klipów (Bastion, Veo, cięcie z pliku) i na akcję użytkownika: mecz tylko z YouTube po kopii
na serwer odblokowuje się sam (kopia ma te same sekundy), brakujące gwizdki po synchronizacji też. Worker: jeden film naraz,
osobno od kolejki ffmpeg klipów (klipy dalej się tną w trakcie renderu filmu). Odcinki filmu trafiają do księgi
`mentor_montage_assets` po odcisku treści - przestawienie dwóch klipów renderuje tylko odcinki, które się zmieniły.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import time
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, update

from app import mentor_clip_download as D
from app import mentor_clip_download_rules as DR
from app import mentor_montage_cards as MC
from app import mentor_montage_render as MV
from app import mentor_montage_rules as MR
from app import mentor_panel_core as C
from app import mentor_panel_media as M
from app import mentor_panel_rules as R
from app.db import (database, mentor_clips, mentor_compilation_items, mentor_compilations, mentor_match_videos, mentor_montage_assets,
                    mentor_montages, mentor_uploads)
from app.mentor_panel_auth import mentor_actor

logger = logging.getLogger("app.mentor_montage")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor"])
Actor = C.MentorActor

#: Najwyżej tyle filmów w drodze naraz na parę (przygotowanie, kolejka, render).
PAIR_ACTIVE_CAP = 3
TICK_S = 8.0
RENDER_TIMEOUT_S = 1800
_wake: Optional[asyncio.Event] = None
#: Postęp renderu z pamięci workera: {id: {stage, progress}} (po restarcie wraca z bazy).
_live: Dict[str, Dict[str, Any]] = {}
_woken: Dict[str, float] = {}
#: Tyle prób renderu jednego filmu; dalej błąd zamiast kręcenia się w kółko.
MAX_ATTEMPTS = 3


def merr(exc: MR.MontageError):
    return C.err(exc.status, exc.code, exc.message)


def wake_worker() -> None:
    if _wake is not None:
        _wake.set()


# ─── Ładowanie ──────────────────────────────────────────────────────────────


async def _clips(pair_id: str, ids: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    if not ids:
        return {}
    rows = await C.rows(select(mentor_clips).where(mentor_clips.c.pair_id == pair_id).where(mentor_clips.c.id.in_(list(ids)))
                        .where(mentor_clips.c.deleted_at.is_(None)))
    return {r["id"]: r for r in rows}


async def _compilation_items(ctx: Dict[str, Any], compilation_id: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    comp = await C.one(select(mentor_compilations).where(mentor_compilations.c.id == compilation_id))
    if not comp or comp["pair_id"] != ctx["pair_id"]:
        raise C.err(404, "NOT_FOUND", "Nie ma takiego zestawienia.")
    rows = await C.rows(select(mentor_compilation_items).where(mentor_compilation_items.c.compilation_id == compilation_id)
                        .order_by(mentor_compilation_items.c.position.asc()))
    mode = comp.get("mode") or "free"
    ordered = R.playlist_items(rows, mode) if mode == "contrast" else rows
    items = [{"clip_id": r["clip_id"], "label": R.legacy_label(r, mode), "note": r.get("note")} for r in ordered]
    return comp, items


class MontageBody(BaseModel):
    #: Zestawienie; bez niego szybki montaż z `clip_ids` (Biblioteka, pokój meczu).
    compilation_id: Optional[str] = None
    #: Wybrane klipy w kolejności filmu (z zestawienia: podzbiór i przestawienie przed montażem).
    clip_ids: Optional[List[str]] = None
    name: Optional[str] = Field(None, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    #: Nie czekaj na klipy, które wymagają akcji (kopia, gwizdki) albo się nie udały.
    skip_missing: bool = False


async def _request(ctx: Dict[str, Any], body: MontageBody) -> Dict[str, Any]:
    """Pozycje, nazwa i opis zamówienia; walidacja liczby i przynależności klipów."""
    try:
        if body.compilation_id:
            comp, base = await _compilation_items(ctx, R.s(body.compilation_id))
            items = MR.pick_items(base, body.clip_ids)
            name = MR.clean_text(body.name, MR.MAX_NAME) or MR.clean_text(comp.get("name"), MR.MAX_NAME)
            description = MR.clean_text(body.description, MR.MAX_DESCRIPTION) if body.description is not None else \
                MR.clean_text(comp.get("description"), MR.MAX_DESCRIPTION)
            compilation_id = comp["id"]
        else:
            items = MR.clean_items({"clip_id": c} for c in (body.clip_ids or []))
            name = MR.clean_text(body.name, MR.MAX_NAME)
            description = MR.clean_text(body.description, MR.MAX_DESCRIPTION)
            compilation_id = None
        MR.check_count(items)
    except MR.MontageError as exc:
        raise merr(exc) from exc
    clips = await _clips(ctx["pair_id"], [i["clip_id"] for i in items])
    missing = [i["clip_id"] for i in items if i["clip_id"] not in clips]
    if missing:
        if compilation_id:
            items = [i for i in items if i["clip_id"] in clips]  # klip usunięty z Biblioteki po prostu wypada
            if not items:
                raise C.err(422, "MONTAGE_EMPTY", "W tym zestawieniu nie ma już żadnego klipu.")
        else:
            raise C.err(422, "CLIP_NOT_FOUND", "Część klipów nie należy do tej pary albo została usunięta.")
    shared = D.Context(ctx)
    if not name:
        matches = []
        for mid in dict.fromkeys(clips[i["clip_id"]]["match_id"] for i in items):
            matches.append(await shared.card(mid))
        name = MR.default_name(matches)
    durations = [float(clips[i["clip_id"]]["end_s"]) - float(clips[i["clip_id"]]["start_s"]) for i in items]
    flags = MR.chapter_flags([clips[i["clip_id"]]["match_id"] for i in items])
    film_s = MR.estimate_film_s(durations, sum(flags), len(items))
    if film_s > MR.MAX_FILM_S:
        raise C.err(422, "MONTAGE_TOO_LONG", f"Film miałby {MR.duration_label(film_s)}, a najdłuższy to "
                    f"{MR.duration_label(MR.MAX_FILM_S)}. Wybierz mniej klipów albo krótsze fragmenty.")
    return {"items": items, "clips": clips, "name": name, "description": description, "compilation_id": compilation_id,
            "film_s": film_s, "shared": shared, "matches": len(set(c["match_id"] for c in clips.values()))}


# ─── Gotowość pozycji ───────────────────────────────────────────────────────


async def _copy_status(video: Optional[Dict[str, Any]]) -> Tuple[Optional[str], Optional[float]]:
    """Stan kopii filmu YouTube na serwerze: (status wiersza, postęp 0..1 z pamięci workera kopii)."""
    upload_id = R.s((video or {}).get("mirror_upload_id"))
    if not upload_id:
        return None, None
    upload = await C.one(select(mentor_uploads).where(mentor_uploads.c.id == upload_id))
    if not upload:
        return None, None
    try:
        from app.mentor_youtube_copy import live_state

        live = live_state(upload_id) or {}
    except Exception:  # noqa: BLE001
        live = {}
    return R.s(upload.get("status")) or None, live.get("progress")


async def assess(ctx: Dict[str, Any], items: Sequence[Dict[str, Any]], clips: Dict[str, Dict[str, Any]], actor: Any, *,
                 order: bool, shared: Optional[D.Context] = None) -> Dict[str, Dict[str, Any]]:
    """Stan każdej pozycji z planu pobrania klipu. `order=True` zamawia brakujące zwykłe MP4 (z limitem kolejki Bastionu)."""
    from app import mentor_bastion_jobs as J
    from app import mentor_bastion_rules as BR
    from app import mentor_youtube_copy as Y
    from app.db import mentor_bastion_clip_jobs as JOBS

    shared = shared or D.Context(ctx)
    plans: List[Dict[str, Any]] = []
    for item in items:
        clip = clips.get(item["clip_id"])
        if not clip:
            plans.append({"clip_id": item["clip_id"], "can_download": False, "reason": "NOT_FOUND", "mp4_status": "none",
                          "hint": "Tego klipu już nie ma w Bibliotece.", "_target": None})
            continue
        plans.append(await D.build_plan(shared, clip, actor))
    allowed = [True] * len(plans)
    if order:
        active = await database.fetch_val(select(func.count()).select_from(JOBS).where(JOBS.c.requested_by_real_judge_id == J.real_judge_of(actor))
                                          .where(JOBS.c.state.in_(BR.JOB_ACTIVE))) or 0
        # Limit kolejki liczymy tylko dla klipów, które naprawdę zamówimy teraz (nowe albo ponawiane): nieudany klip bez
        # ponowienia nie zajmuje miejsca i nie udaje „czekania w kolejce”.
        orderable = [dict(p, can_download=bool(p.get("can_download")) and (p.get("mp4_status") == "none" or bool(i.get("_retry"))))
                     for p, i in zip(plans, items)]
        allowed = DR.allocate_batch(orderable, int(active))
    out: Dict[str, Dict[str, Any]] = {}
    videos: Dict[str, Optional[Dict[str, Any]]] = {}
    for item, plan, ok in zip(items, plans, allowed):
        cid = item["clip_id"]
        clip = clips.get(cid)
        wants = plan.get("mp4_status") == "none" or (plan.get("mp4_status") == "failed" and item.get("_retry"))
        if order and plan.get("can_download") and wants and clip is not None:
            if not ok:
                plan = {**plan, "can_download": False, "reason": "QUEUE_LIMIT",
                        "hint": "Kolejka Bastionu jest pełna. Zamówimy ten klip, gdy zwolni się miejsce."}
            else:
                try:
                    await D.place_order(ctx, clip, actor, plan)
                    fresh = await C.one(select(mentor_clips).where(mentor_clips.c.id == cid)) or clip
                    clips[cid] = fresh
                    plan = await D.build_plan(shared, fresh, actor)
                except Exception as exc:  # noqa: BLE001 - jeden zły klip nie wstrzymuje filmu
                    detail = getattr(exc, "detail", None)
                    plan = {**plan, "can_download": False, "reason": (detail or {}).get("code") if isinstance(detail, dict) else "ORDER_FAILED",
                            "hint": (detail or {}).get("message") if isinstance(detail, dict) else "Nie udało się zamówić pliku klipu."}
                    logger.warning("montaż: zamówienie klipu %s nieudane", cid, exc_info=not isinstance(detail, dict))
        own_provider, can_copy, copy_status, copy_progress, video_id = "", False, None, None, None
        if clip is not None:
            video_id = clip.get("video_id")
            if video_id not in videos:
                videos[video_id] = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == video_id))
            video = videos[video_id] or {}
            own_provider = R.s(video.get("provider")).lower()
            if plan.get("reason") == "NO_SOURCE" and own_provider == "youtube":
                copy_status, copy_progress = await _copy_status(video)
                try:
                    can_copy = Y.can_copy(video, own_provider) and C.may(ctx, "video")
                except Exception:  # noqa: BLE001
                    can_copy = False
        state = MR.item_state(plan, own_provider=own_provider, can_copy=can_copy, copy_status=copy_status)
        state.update({"clip_id": cid, "match_id": (clip or {}).get("match_id"), "video_id": video_id, "source": plan.get("source"),
                      "range": plan.get("source_range"),
                      "copy_progress": copy_progress if state["state"] == "copying" else None,
                      "missing": plan.get("missing") or [] if state["reason"] == "NEED_SYNC" else []})
        out[cid] = state
    return out


# ─── Kształt odpowiedzi ─────────────────────────────────────────────────────


def _j(raw: Any, default: Any) -> Any:
    return R.json_value(raw, default)


async def shape(ctx: Dict[str, Any], row: Dict[str, Any], *, with_items: bool = True) -> Dict[str, Any]:
    items = _j(row.get("items_json"), [])
    states = _j(row.get("states_json"), {})
    status = row.get("status") or "preparing"
    live = _live.get(row["id"]) or {}
    ready = status == "ready" and row.get("film_key")
    filename = MR.film_filename(row.get("name"))
    names = await C.people([row.get("created_by"), row.get("acted_by")])
    out: Dict[str, Any] = {
        "id": row["id"], "pair_id": row["pair_id"], "compilation_id": row.get("compilation_id"), "name": row.get("name"),
        "description": row.get("description"), "status": status, "stage": live.get("stage") or row.get("stage"),
        "progress": round(float(live.get("progress") if live.get("progress") is not None else row.get("progress") or 0.0), 4),
        "message": row.get("message"), "skip_missing": bool(row.get("skip_missing")),
        "counts": MR.counts(states.get(i["clip_id"], {}).get("state") or "waiting" for i in items),
        "items_count": len(items), "duration_s": row.get("duration_s"), "width": row.get("width"), "height": row.get("height"),
        "size": row.get("size"), "estimate_s": row.get("estimate_s"), "filename": filename,
        "chapters": _j(row.get("chapters_json"), []) if ready else [],
        "play_url": M.presign_get(row.get("film_key")) if ready else None,
        "download_url": M.presign_get(row.get("film_key"), M.DOWNLOAD_TTL, filename) if ready else None,
        "poster_url": M.presign_get(row.get("poster_key")) if row.get("poster_key") and status in ("ready", "expired") else None,
        "created_by": C.person(names, row.get("created_by")), **C.acted_fields(names, row),
        "created_at": row.get("created_at"), "updated_at": row.get("updated_at"), "ready_at": row.get("ready_at"),
        "expires_at": row.get("expires_at"),
        "can_delete": C.may(ctx, "edit", owner=R.s(row.get("created_by")) == ctx["actor"].judge_id),
    }
    if with_items:
        clips = await _clips(row["pair_id"], [i["clip_id"] for i in items])
        rendered = set(_j(row.get("rendered_json"), []) or [])
        shaped = []
        for n, item in enumerate(items, start=1):
            clip = clips.get(item["clip_id"]) or {}
            st = states.get(item["clip_id"]) or {"state": "waiting", "reason": None, "hint": "", "action": None}
            if status == "ready" and rendered and item["clip_id"] not in rendered:
                st = {**st, "state": "skipped"}
            shaped.append({"clip_id": item["clip_id"], "position": n, "label": item.get("label") or "", "note": item.get("note") or "",
                           "title": clip.get("title") or "", "match_id": clip.get("match_id") or st.get("match_id"),
                           "video_id": clip.get("video_id") or st.get("video_id"), "start_s": clip.get("start_s"), "end_s": clip.get("end_s"),
                           "state": st.get("state"), "reason": st.get("reason"), "hint": st.get("hint") or "", "action": st.get("action"),
                           "copy_progress": st.get("copy_progress"), "missing": st.get("missing") or []})
        out["items"] = shaped
    return out


def _summary(row: Dict[str, Any]) -> Dict[str, Any]:
    """Lekki skrót do list i do zestawień (`film` w `compilation_summaries`)."""
    status = row.get("status")
    live = _live.get(row["id"]) or {}
    return {"id": row["id"], "status": status, "name": row.get("name"), "duration_s": row.get("duration_s"),
            "progress": round(float(live.get("progress") if live.get("progress") is not None else row.get("progress") or 0.0), 4),
            "items_count": len(_j(row.get("items_json"), [])), "updated_at": row.get("updated_at"), "ready_at": row.get("ready_at"),
            "poster_url": M.presign_get(row.get("poster_key")) if row.get("poster_key") and status == "ready" else None}


async def films_for(compilation_ids: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    """Ostatni film każdego zestawienia (gotowy ma pierwszeństwo przed starszym w drodze). Do kafli i nagłówka zestawienia."""
    ids = [R.s(i) for i in compilation_ids if R.s(i)]
    if not ids:
        return {}
    rows = await C.rows(select(mentor_montages).where(mentor_montages.c.compilation_id.in_(ids))
                        .where(mentor_montages.c.status.notin_(("cancelled",))).order_by(mentor_montages.c.updated_at.desc()))
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        cid = row["compilation_id"]
        if cid not in out:
            out[cid] = _summary(row)
    return out


# ─── Trasy ──────────────────────────────────────────────────────────────────


@router.post("/pairs/{pair_id}/montages/preflight")
async def preflight(pair_id: str, body: MontageBody, actor: Actor = Depends(mentor_actor)):
    """Gotowość bez zamawiania: co jest gotowe, co się tnie, co wymaga kopii z YouTube albo gwizdków; szacunek długości."""
    ctx = await C.pair_context(pair_id, actor)
    req = await _request(ctx, body)
    states = await assess(ctx, req["items"], req["clips"], actor, order=False, shared=req["shared"])
    clips = req["clips"]
    out_items = []
    for n, item in enumerate(req["items"], start=1):
        clip = clips.get(item["clip_id"]) or {}
        st = states.get(item["clip_id"]) or {}
        out_items.append({"clip_id": item["clip_id"], "position": n, "label": item["label"], "note": item["note"], "title": clip.get("title") or "",
                          "match_id": clip.get("match_id"), "video_id": clip.get("video_id"), "start_s": clip.get("start_s"),
                          "end_s": clip.get("end_s"), "state": st.get("state"), "reason": st.get("reason"), "hint": st.get("hint") or "",
                          "action": st.get("action"), "copy_progress": st.get("copy_progress"), "missing": st.get("missing") or []})
    heights = [720]  # przed cięciem nie znamy plików: szacunek dla 720p, render dobierze 1080p sam
    flags = MR.chapter_flags([i["match_id"] for i in out_items])
    return {"name": req["name"], "description": req["description"], "compilation_id": req["compilation_id"], "items": out_items,
            "counts": MR.counts(i["state"] for i in out_items), "film_s": req["film_s"], "matches": sum(1 for f in flags if f),
            "estimate_s": MR.estimate_render_s(req["film_s"], min(heights), len(out_items) + 2),
            "can_create": C.may(ctx, "create"), "limits": {"items": MR.MAX_ITEMS, "film_s": MR.MAX_FILM_S}}


@router.post("/pairs/{pair_id}/montages")
async def create_montage(pair_id: str, body: MontageBody, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor, action="create")
    req = await _request(ctx, body)
    planned = await assess(ctx, req["items"], req["clips"], actor, order=False, shared=req["shared"])
    rsig = MR.request_sig(req["name"], req["description"], req["items"], req["clips"], body.skip_missing,
                          ranges={cid: st.get("range") for cid, st in planned.items()})
    same = await C.one(select(mentor_montages).where(mentor_montages.c.pair_id == ctx["pair_id"]).where(mentor_montages.c.request_sig == rsig)
                       .where(mentor_montages.c.status.in_(("preparing", "queued", "rendering", "ready")))
                       .order_by(mentor_montages.c.updated_at.desc()).limit(1))
    if same:
        return {**(await shape(ctx, same)), "reused": True}
    active = await database.fetch_val(select(func.count()).select_from(mentor_montages).where(mentor_montages.c.pair_id == ctx["pair_id"])
                                      .where(mentor_montages.c.status.in_(MR.ACTIVE))) or 0
    if int(active) >= PAIR_ACTIVE_CAP:
        raise C.err(429, "MONTAGE_BUSY", f"Para ma już {PAIR_ACTIVE_CAP} filmy w przygotowaniu. Poczekaj, aż któryś będzie gotowy.")
    now = C.now()
    mid = R.new_id()
    row = {"id": mid, "pair_id": ctx["pair_id"], "compilation_id": req["compilation_id"], "name": req["name"],
           "description": req["description"] or None, "items_json": C.dumps(req["items"]), "states_json": "{}",
           "skip_missing": bool(body.skip_missing), "status": "preparing", "stage": "clips", "progress": 0.0, "request_sig": rsig,
           "estimate_s": MR.estimate_render_s(req["film_s"], 720, len(req["items"]) + 2), "created_by": actor.judge_id,
           "acted_by": actor.acted_by, "created_at": now, "updated_at": now, "waiting_since": now}
    await database.execute(mentor_montages.insert().values(**row))
    states = await assess(ctx, req["items"], req["clips"], actor, order=True, shared=req["shared"])
    status = MR.next_status([states[i["clip_id"]]["state"] for i in req["items"]], bool(body.skip_missing))
    await database.execute(update(mentor_montages).where(mentor_montages.c.id == mid).values(
        states_json=C.dumps(states), status=status if status != "failed" else "preparing", updated_at=C.now()))
    await C.touch(ctx, actor.judge_id, "montage_created", "compilations", data={"id": mid, "compilation_id": req["compilation_id"]})
    wake_worker()
    fresh = await C.one(select(mentor_montages).where(mentor_montages.c.id == mid))
    return await shape(ctx, fresh)


async def _montage(montage_id: str, actor: Any, action: str = "view") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    row = await C.one(select(mentor_montages).where(mentor_montages.c.id == montage_id))
    if not row or row.get("status") == "cancelled":
        raise C.err(404, "NOT_FOUND", "Nie ma takiego filmu.")
    ctx = await C.pair_context(row["pair_id"], actor, action=action)
    return ctx, row


@router.get("/pairs/{pair_id}/montages")
async def list_montages(pair_id: str, compilation_id: Optional[str] = Query(None), limit: int = Query(20, ge=1, le=60),
                        actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    query = select(mentor_montages).where(mentor_montages.c.pair_id == ctx["pair_id"]).where(mentor_montages.c.status != "cancelled")
    if compilation_id:
        query = query.where(mentor_montages.c.compilation_id == R.s(compilation_id))
    rows = await C.rows(query.order_by(mentor_montages.c.updated_at.desc()).limit(limit))
    return {"montages": [await shape(ctx, r, with_items=False) for r in rows]}


@router.get("/montages/{montage_id}")
async def get_montage(montage_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _montage(montage_id, actor)
    if row["status"] == "preparing" and time.monotonic() - _woken.get(row["id"], 0.0) > 5.0:
        # Odpytywanie odświeża gotowość od razu (kopia skończona, gwizdki ustawione), najwyżej raz na 5 s na film.
        _woken[row["id"]] = time.monotonic()
        wake_worker()
    return await shape(ctx, row)


@router.post("/montages/{montage_id}/retry")
async def retry_montage(montage_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _montage(montage_id, actor, "create")
    if row["status"] in ("queued", "rendering"):
        return await shape(ctx, row)
    items = _j(row.get("items_json"), [])
    clips = await _clips(row["pair_id"], [i["clip_id"] for i in items])
    states = await assess(ctx, [{**i, "_retry": True} for i in items], clips, actor, order=True)
    status = MR.next_status([states.get(i["clip_id"], {}).get("state") or "blocked" for i in items], bool(row.get("skip_missing")))
    await database.execute(update(mentor_montages).where(mentor_montages.c.id == row["id"]).values(
        status=status if status != "failed" else "preparing", stage="clips", progress=0.0, message=None, states_json=C.dumps(states),
        film_key=None, chapters_json=None, ready_at=None, expires_at=None, attempts=0, waiting_since=C.now(), updated_at=C.now()))
    if row.get("film_key"):
        M.forget_object(row.get("film_key"))
    await C.touch(ctx, actor.judge_id, "montage_retry", "compilations", data={"id": row["id"]})
    wake_worker()
    return await shape(ctx, await C.one(select(mentor_montages).where(mentor_montages.c.id == row["id"])))


class SkipBody(BaseModel):
    skip_missing: bool = True


@router.patch("/montages/{montage_id}")
async def patch_montage(montage_id: str, body: SkipBody, actor: Actor = Depends(mentor_actor)):
    """„Pomiń brakujące” w trakcie przygotowania: film rusza z tym, co gotowe (bez klipów czekających na akcję)."""
    ctx, row = await _montage(montage_id, actor, "create")
    if row["status"] != "preparing":
        return await shape(ctx, row)
    await database.execute(update(mentor_montages).where(mentor_montages.c.id == row["id"]).values(skip_missing=bool(body.skip_missing),
                                                                                                    updated_at=C.now()))
    wake_worker()
    return await shape(ctx, await C.one(select(mentor_montages).where(mentor_montages.c.id == row["id"])))


@router.delete("/montages/{montage_id}")
async def delete_montage(montage_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _montage(montage_id, actor)
    if not C.may(ctx, "edit", owner=R.s(row.get("created_by")) == actor.judge_id):
        raise C.err(403, "FORBIDDEN", "Film może usunąć jego autor albo administrator.")
    await database.execute(update(mentor_montages).where(mentor_montages.c.id == row["id"]).values(status="cancelled", updated_at=C.now()))
    keys = [row.get("film_key"), row.get("poster_key")]
    await asyncio.to_thread(M.delete_objects, [k for k in keys if k])
    _live.pop(row["id"], None)
    await C.touch(ctx, actor.judge_id, "montage_deleted", "compilations", data={"id": row["id"]})
    return {"ok": True}


# ─── Worker: przygotowanie ──────────────────────────────────────────────────


async def _worker_ctx(row: Dict[str, Any]) -> Tuple[Dict[str, Any], Any]:
    """Kontekst pary i aktor zamawiającego bez żądania HTTP (worker): zamówienia klipów idą na jego konto (limit Bastionu)."""
    from app.db import mentoring_pairs

    pair = await C.one(select(mentoring_pairs).where(mentoring_pairs.c.id == row["pair_id"])) or {}
    judges = [R.s(j) for j in R.json_value(pair.get("judge_ids"), [])]
    actor = C.MentorActor(row["created_by"], acted_by=row.get("acted_by"))
    ctx = {"pair_id": row["pair_id"], "pair_key": "|".join(sorted(judges)), "judge_ids": judges, "actor": actor, "role": "pair",
           "enabled": True, "manages": False, "pair": pair, "mentor_ids": [], "all_mentor_ids": []}
    return ctx, actor


async def tick_preparing() -> int:
    """Przegląd filmów w przygotowaniu: zamawia brakujące pliki (gdy zwolni się kolejka), przenosi gotowe do renderu."""
    rows = await C.rows(select(mentor_montages).where(mentor_montages.c.status == "preparing").order_by(mentor_montages.c.created_at.asc()))
    for row in rows:
        try:
            await _tick_one(row)
        except Exception:  # noqa: BLE001 - jeden film nie zatrzymuje pozostałych
            logger.warning("montaż: przegląd %s nieudany", row["id"], exc_info=True)
    return len(rows)


async def _tick_one(row: Dict[str, Any]) -> None:
    ctx, actor = await _worker_ctx(row)
    items = _j(row.get("items_json"), [])
    clips = await _clips(row["pair_id"], [i["clip_id"] for i in items])
    old = _j(row.get("states_json"), {})
    # Zamawiamy tylko to, co jeszcze nie ruszyło (klipy odblokowane kopią albo gwizdkami, miejsce w kolejce Bastionu).
    states = await assess(ctx, items, clips, actor, order=True)
    status = MR.next_status([states[i["clip_id"]]["state"] for i in items], bool(row.get("skip_missing")))
    values: Dict[str, Any] = {"states_json": C.dumps(states)}
    since = row.get("waiting_since") or row.get("created_at")
    expired = since is not None and C.now() - _aware(since) > timedelta(hours=MR.PREPARE_LIMIT_H)
    if status == "queued":
        values.update(status="queued", stage="queued")
    elif status == "failed" or (expired and status == "preparing"):
        values.update(status="failed", stage=None, message="Żaden klip nie jest gotowy do filmu. Sprawdź powody przy klipach i spróbuj ponownie."
                      if status == "failed" else f"Czekaliśmy {MR.PREPARE_LIMIT_H} godzin na klipy. Odblokuj brakujące albo pomiń je i zrób film ponownie.")
    # Zapis tylko przy zmianie, która coś znaczy: status filmu albo stan / akcja pozycji. Postęp kopii z YouTube
    # i podpowiedzi zmieniają się co chwilę - te idą do wiersza bez śladu w dzienniku i bez budzenia klientów pary.
    meaningful = bool(values.get("status")) or _shape_of(old) != _shape_of(states)
    if meaningful or old != states:
        values["updated_at"] = C.now() if meaningful else row.get("updated_at") or C.now()
        done = await _guarded(row["id"], ("preparing",), values)
        if meaningful and done:
            await C.touch(row["pair_id"], row["created_by"], "montage_state", "compilations", data={"id": row["id"]})


async def _guarded(montage_id: str, expected: Sequence[str], values: Dict[str, Any]) -> bool:
    """Przejście stanu tylko z oczekiwanego statusu (RETURNING: działa tak samo w PostgreSQL i SQLite). Film usunięty
    albo przejęty w międzyczasie nie wraca do życia."""
    row = await database.fetch_one(update(mentor_montages).where(mentor_montages.c.id == montage_id)
                                   .where(mentor_montages.c.status.in_(list(expected))).values(**values).returning(mentor_montages.c.id))
    return row is not None


def _shape_of(states: Dict[str, Any]) -> Dict[str, Any]:
    return {k: (v.get("state"), v.get("action"), v.get("reason")) for k, v in (states or {}).items()}


def _aware(value: Any):
    from datetime import datetime, timezone

    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


# ─── Worker: render ─────────────────────────────────────────────────────────


class Progress:
    """Postęp renderu: kroki (odcinki + sklejka) w pamięci, co kilka kroków także w bazie."""

    def __init__(self, montage_id: str, total: int):
        self.id, self.total, self.done = montage_id, max(1, total), 0
        self._saved = 0.0

    async def step(self, stage: str, weight: float = 1.0) -> None:
        self.done += weight
        fraction = min(0.99, self.done / self.total)
        _live[self.id] = {"stage": stage, "progress": fraction}
        if fraction - self._saved >= 0.08:
            self._saved = fraction
            await database.execute(update(mentor_montages).where(mentor_montages.c.id == self.id).values(progress=fraction, stage=stage))

    def stage(self, stage: str) -> None:
        _live[self.id] = {"stage": stage, "progress": min(0.99, self.done / self.total)}


async def _clip_source(clip: Dict[str, Any]) -> Tuple[float, float]:
    """(przesunięcie początku klipu w jego pliku MP4, długość klipu). Bastion tnie od pełnej sekundy w dół: przesunięcie
    bierzemy z zapisanego zasobu bieżącej rewizji; plik i Veo zaczynają się dokładnie od klipu."""
    from app.db import mentor_clip_assets as A

    duration = max(MR.MIN_CLIP_S, float(clip["end_s"]) - float(clip["start_s"]))
    asset = await C.one(select(A).where(A.c.clip_id == clip["id"]).where(A.c.revision == int(clip.get("media_rev") or 1))
                        .where(A.c.status == "ready"))
    if not asset or asset.get("storage_key") != clip.get("mp4_key") or asset.get("source_start_s") is None:
        return 0.0, duration
    override = R.json_value(clip.get("mp4_source_json"), {})
    start = float(override["start_s"]) if override.get("video_id") else float(clip["start_s"])
    return max(0.0, start - float(asset["source_start_s"])), duration


async def _download(url: str, target: str) -> bool:
    import httpx

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
            async with client.stream("GET", url) as response:
                if response.status_code != 200:
                    return False
                with open(target, "wb") as handle:
                    async for chunk in response.aiter_bytes(1 << 20):
                        handle.write(chunk)
        return os.path.getsize(target) > 0
    except Exception:  # noqa: BLE001
        logger.info("montaż: pobranie zapamiętanego odcinka nieudane", exc_info=True)
        return False


async def _cached(pair_id: str, sig: str, kind: str, target: str, render: Callable[[], Any]) -> bool:
    """Odcinek z księgi (R2) albo render i zapis do księgi. Zwraca True, gdy był w księdze."""
    if M.storage_ready():
        hit = await C.one(select(mentor_montage_assets).where(mentor_montage_assets.c.sig == sig))
        if hit:
            url = M.presign_get(hit["key"], M.SOURCE_URL_TTL)
            if url and await _download(url, target):
                await database.execute(update(mentor_montage_assets).where(mentor_montage_assets.c.sig == sig).values(used_at=C.now()))
                return True
    await render()
    if M.storage_ready():
        try:
            key = M.object_key(pair_id, "montage-parts", f"{sig}.{MV.SEGMENT_EXT}")
            size = await asyncio.to_thread(M.put_file, target, key, "video/x-matroska")
            await database.execute(delete(mentor_montage_assets).where(mentor_montage_assets.c.sig == sig))
            await database.execute(mentor_montage_assets.insert().values(sig=sig, pair_id=pair_id, kind=kind, key=key, size=size,
                                                                          created_at=C.now(), used_at=C.now()))
        except Exception:  # noqa: BLE001 - brak zapisu w księdze nie psuje filmu
            logger.info("montaż: zapis odcinka do księgi nieudany", exc_info=True)
    return False


_ff_version: Optional[str] = None


async def _ffmpeg_version() -> str:
    """Wersja ffmpeg w odcisku odcinków: po aktualizacji kodera stare odcinki nie trafiają do sklejki z nowymi."""
    global _ff_version
    if _ff_version is None:
        try:
            done = await asyncio.to_thread(subprocess.run, ["ffmpeg", "-hide_banner", "-version"], capture_output=True, text=True, timeout=30)
            _ff_version = ((done.stdout or "").splitlines() or ["?"])[0][:80]
        except Exception:  # noqa: BLE001
            _ff_version = "?"
    return _ff_version


class FfmpegFailed(RuntimeError):
    """Nieudane polecenie ffmpeg. `reason` to krótki ludzki powód (trafia do `message` filmu), pełny dziennik jest w logu."""

    def __init__(self, stderr: str):
        text = (stderr or "").strip()
        super().__init__(f"ffmpeg: {text[:300]} ... {text[-600:]}" if len(text) > 900 else f"ffmpeg: {text}")
        self.reason = ffmpeg_reason(text)


def ffmpeg_reason(stderr: str) -> str:
    low = (stderr or "").lower()
    if any(k in low for k in ("server returned", "connection", "no such file", "http error", "i/o error", "timed out")):
        return "plik klipu jest niedostępny"
    if "before eof" in low or "nothing was written" in low or "invalid argument" in low:
        return "z klipu nie da się odczytać obrazu w wybranym fragmencie"
    if "out of memory" in low or "cannot allocate" in low:
        return "serwerowi zabrakło pamięci"
    return "błąd kodowania odcinka"


async def _ffmpeg(args: List[str], timeout: float = RENDER_TIMEOUT_S) -> None:
    done = await asyncio.to_thread(M._run, args, timeout)
    if done.returncode != 0 or not os.path.exists(args[-1]):
        raise FfmpegFailed(done.stderr or "")


def zoom_pass(source: Dict[str, Any], start: float, dur: float, track: List[Dict[str, float]], video_start_s: float,
              src_w: int, src_h: int, width: int, height: int, target: str) -> None:
    """Wypalenie ścieżki zoomu: klatki źródła w pełnej rozdzielczości, kadr z dokładnością podpiksela (PIL `box`), dopasowanie
    do kadru filmu. Ten sam model ruchu co panel (`MR.zoom_window`), więc film pokazuje dokładnie to, co mentor nagrał."""
    from PIL import Image

    frame_bytes = src_w * src_h * 3
    dec = subprocess.Popen(MV.zoom_decode_args(source, start, dur), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    enc = subprocess.Popen(MV.zoom_encode_args(width, height, source, start, dur, target), stdin=subprocess.PIPE,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    scale = min(width / float(src_w), height / float(src_h))
    fit_w, fit_h = max(2, int(round(src_w * scale))), max(2, int(round(src_h * scale)))
    canvas = Image.new("RGB", (width, height)) if (fit_w, fit_h) != (width, height) else None
    try:
        index = 0
        while True:
            buf = bytearray()
            while len(buf) < frame_bytes:
                chunk = dec.stdout.read(frame_bytes - len(buf))
                if not chunk:
                    break
                buf.extend(chunk)
            if len(buf) < frame_bytes:
                break
            left, top, size = MR.zoom_window(track, video_start_s + index / float(MR.FPS))
            image = Image.frombuffer("RGB", (src_w, src_h), bytes(buf), "raw", "RGB", 0, 1)
            box = (left * src_w, top * src_h, (left + size) * src_w, (top + size) * src_h)
            framed = image.resize((fit_w, fit_h), Image.BICUBIC, box=box)
            if canvas is not None:
                canvas.paste(framed, ((width - fit_w) // 2, (height - fit_h) // 2))
                framed = canvas
            enc.stdin.write(framed.tobytes())
            index += 1
    finally:
        try:
            enc.stdin.close()
        except Exception:  # noqa: BLE001
            pass
        dec.stdout.close()
        dec.wait(timeout=60)
        enc.wait(timeout=RENDER_TIMEOUT_S)
    if enc.returncode != 0 or not os.path.exists(target):
        raise RuntimeError(f"zoom: {(enc.stderr.read() if enc.stderr else b'')[-400:]!r}")


async def _entries(row: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Gotowe pozycje filmu w kolejności z pełną treścią plansz (mecz, minuta, kategoria, etykieta, notatka) i źródłem."""
    from app import mentor_bastion_media as BM
    from app.mentor_video_rules import clean_sync

    ctx, actor = await _worker_ctx(row)
    shared = D.Context(ctx)
    items = _j(row.get("items_json"), [])
    clips = await _clips(row["pair_id"], [i["clip_id"] for i in items])
    states = await assess(ctx, items, clips, actor, order=False, shared=shared)
    entries: List[Dict[str, Any]] = []
    rows = await shared.category_rows()
    names = {r["id"]: R.s(r.get("name")) for r in rows}
    unreadable: List[str] = []
    not_ready = 0
    for item in items:
        clip = clips.get(item["clip_id"])
        if not clip or (states.get(item["clip_id"]) or {}).get("state") != "ready" or not clip.get("mp4_key"):
            not_ready += 1
            continue
        url = M.presign_get(clip["mp4_key"], M.SOURCE_URL_TTL)
        try:
            if not url:
                raise RuntimeError("brak adresu pliku")
            info = await asyncio.to_thread(BM.ffprobe_file, url)
        except Exception:  # noqa: BLE001
            logger.warning("montaż: plik klipu %s nieczytelny", clip["id"], exc_info=True)
            unreadable.append(R.s(clip.get("title")) or "Klip")
            continue
        offset, duration = await _clip_source(clip)
        file_s = float(info.get("duration_s") or 0.0)
        if file_s:
            offset = min(offset, max(0.0, file_s - MR.MIN_CLIP_S))
            duration = max(MR.MIN_CLIP_S, min(duration, file_s - offset))
        video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == clip["video_id"])) or {}
        sync = clean_sync(R.json_value(video.get("sync_json"), {}))
        match = await shared.card(clip["match_id"])
        seconds = DR.match_time_s(clip.get("match_ms"), float(clip["start_s"]), sync)
        label = item.get("label") or ""
        entries.append({
            "clip_id": clip["id"], "match_id": clip["match_id"], "clip": clip, "match": match,
            # Tożsamość treści pliku: ten sam klucz R2 bywa nadpisany nowym cięciem (inne źródło, poprawione gwizdki).
            "source": {"url": url, "has_audio": bool(info.get("has_audio")), "file_s": file_s,
                       "key": MR.sig(clip["mp4_key"], clip.get("mp4_size"), clip.get("mp4_source_json"), clip.get("media_rev"))},
            "src_w": int(info.get("width") or 1280), "src_h": int(info.get("height") or 720),
            "offset": offset, "duration": duration, "zoom": MR.parse_zoom(clip.get("zoom_track_json")),
            "title": R.s(clip.get("title")) or "Klip", "minute": MR.clock(seconds),
            "half": DR.card_time_label(clip.get("match_ms"), float(clip["start_s"]), sync),
            "category": D._category_of(clip, names), "category_color": D._category_color(clip, rows),
            "label": label, "label_color": MR.label_color(label) or "", "note": item.get("note") or R.s(clip.get("note")),
        })
    return entries, unreadable, not_ready


def _match_view(match: Dict[str, Any], crests: Dict[str, Any], colors: Dict[str, Any]) -> Dict[str, Any]:
    code = R.s(match.get("code"))
    return {"home": R.s(match.get("home")), "away": R.s(match.get("away")), "code": code,
            "code_color": DR.match_number_color(code) if code else "", "date": DR.card_date(match.get("date")),
            "competition": R.s(match.get("competition")), "crests": crests, "colors": colors}


async def process_montage(row: Dict[str, Any]) -> None:
    mid = row["id"]
    attempts = int(row.get("attempts") or 0) + 1
    # Przejęcie warunkowe: film usunięty albo przejęty w międzyczasie nie wraca do życia.
    claimed = await _guarded(mid, ("queued",), dict(status="rendering", stage="prepare", progress=0.0, started_at=C.now(), attempts=attempts,
                                                     updated_at=C.now()))
    if not claimed:
        return
    if attempts > MAX_ATTEMPTS:
        raise MR.MontageError(409, "MONTAGE_ATTEMPTS", "Film nie złożył się po kilku próbach. Sprawdź klipy i spróbuj ponownie.")
    _live[mid] = {"stage": "prepare", "progress": 0.0}
    folder = await asyncio.to_thread(M.make_tmpdir, "montage-")
    try:
        entries, unreadable, not_ready = await _entries(row)
        if unreadable:
            # Plik klipu „gotowy”, a nie da się go odczytać (zniknął z magazynu, uszkodzony): błąd z nazwą klipu, bez pętli.
            raise MR.MontageError(409, "MONTAGE_FILE", f"Nie da się odczytać pliku klipu „{unreadable[0]}”. Ponów film - wytniemy go od nowa.")
        if not entries:
            raise MR.MontageError(409, "MONTAGE_EMPTY", "Żaden klip nie jest gotowy do filmu.")
        if not row.get("skip_missing") and not_ready:
            # Wyścig: klip zmienił się między przeglądem a renderem. Wracamy do przygotowania (warunkowo).
            await _guarded(mid, ("rendering",), dict(status="preparing", stage="clips", updated_at=C.now()))
            _live.pop(mid, None)
            return
        await _render(row, entries, folder)
    finally:
        await asyncio.to_thread(shutil.rmtree, folder, True)


def _thumb(Image: Any, path: str) -> Any:
    with Image.open(path) as shot:
        return shot.convert("RGB").resize((480, 270), Image.LANCZOS)


async def _render(row: Dict[str, Any], entries: List[Dict[str, Any]], folder: str) -> None:
    from PIL import Image

    mid, pair_id = row["id"], row["pair_id"]
    width, height = MR.target_size([e["src_h"] for e in entries])
    total = len(entries)
    match_ids = [e["match_id"] for e in entries]
    flags = MR.chapter_flags(match_ids)
    numbers = MR.chapter_numbers(match_ids)
    chapters_total = sum(1 for f in flags if f)
    plan = MR.timeline([e["duration"] for e in entries], flags, total, MC.CREDITS_VISIBLE)
    progress = Progress(mid, total + 3 + sum(1.5 for e in entries if e["zoom"]))
    name = R.s(row.get("name")) or "Zestawienie"

    # Herby i barwy każdego meczu raz (pamięć herbów jest wspólna z planszą klipu).
    views: Dict[str, Dict[str, Any]] = {}
    for e in entries:
        if e["match_id"] not in views:
            crests, colors = await D.card_assets(e["match"])
            views[e["match_id"]] = _match_view(e["match"], crests, colors)
    per_match = {mid_: sum(1 for m in match_ids if m == mid_) for mid_ in views}

    # Zoom: plik roboczy z wypalonym kadrem staje się źródłem klipu (przesunięcie 0).
    for i, e in enumerate(entries):
        if e["zoom"]:
            progress.stage("zoom")
            target = os.path.join(folder, f"zoom-{i}.mp4")
            await asyncio.to_thread(zoom_pass, e["source"], e["offset"], e["duration"], e["zoom"], float(e["clip"]["start_s"]),
                                    e["src_w"], e["src_h"], width, height, target)
            e["source"] = {"url": target, "has_audio": e["source"]["has_audio"], "key": f"{e['source']['key']}|zoom|{MR.sig(e['zoom'])}"}
            e["offset"] = 0.0
            await progress.step("zoom", 1.5)

    def item_key(e: Dict[str, Any], i: int) -> Dict[str, Any]:
        return {"src": e["source"]["key"], "off": round(e["offset"], 3), "dur": round(e["duration"], 3), "pos": i + 1, "total": total,
                "label": e["label"], "note": e["note"], "audio": e["source"]["has_audio"]}

    def overlay_png(e: Dict[str, Any], i: int) -> str:
        path = os.path.join(folder, f"over-{i}.png")
        if not os.path.exists(path):
            image = MC.compose_badge(i + 1, total, e["label"], e["label_color"], width, height)
            note = MC.compose_note(e["note"], width, height)
            if note is not None:
                image.alpha_composite(note)
            image.save(path, "PNG", compress_level=1)
        return path

    def save_layers(comp: Dict[str, Any], prefix: str, motion: Optional[str] = None) -> Dict[str, Any]:
        bg = comp["background"].convert("RGBA")
        bg.alpha_composite(comp["text"])
        bg_path = os.path.join(folder, f"{prefix}-bg.png")
        bg.convert("RGB").save(bg_path, "PNG", compress_level=1)
        layers = []
        for j, layer in enumerate(comp.get("layers") or []):
            path = os.path.join(folder, f"{prefix}-l{j}.png")
            layer["image"].save(path, "PNG", compress_level=1)
            layers.append({"path": path, "x": layer["x"], "y": layer["y"], "motion": layer.get("motion") or motion,
                           "delay": layer.get("delay") or 0.0, "fade": motion == "row"})
        return {"background": bg_path, "layers": layers}

    look = {"v": MR.LOOK_VERSION, "w": width, "h": height, "ff": await _ffmpeg_version()}
    parts: List[str] = []

    # Okładka: mecze w kolejności filmu, barwa każdego klipu z numeru jego meczu, kadry pierwszych klipów na taśmę.
    order = list(dict.fromkeys(match_ids))
    clip_matches = [order.index(m) for m in match_ids]
    cover_frames: List[Any] = []
    frame_keys: List[Any] = []
    for i, e in enumerate(entries[:MC.frame_count(total)]):
        at = e["offset"] + min(1.0, e["duration"] * 0.5)
        path = os.path.join(folder, f"cover-frame-{i}.png")
        frame_keys.append([e["source"]["key"], round(at, 3)])
        try:
            await _ffmpeg(MV.frame_args(e["source"], at, width, height, path), 120)
            cover_frames.append(await asyncio.to_thread(_thumb, Image, path))
        except Exception:  # noqa: BLE001 - brak kadru to ciemne okienko z numerem, film rusza dalej
            cover_frames.append(None)
    cover_info = {"name": name, "description": R.s(row.get("description")), "clips": total, "film_s": plan["total_s"],
                  "matches": [{k: v for k, v in views[m].items() if k not in ("crests",)} for m in order],
                  "clip_matches": clip_matches, "frames": frame_keys}
    cover_comp = await asyncio.to_thread(lambda: MC.compose_cover(MC.cover_data(
        name, R.s(row.get("description")), [views[m] for m in order], total, plan["total_s"], clip_matches, cover_frames), width, height))
    cover_still = os.path.join(folder, "cover.png")
    await asyncio.to_thread(lambda: MC.flatten(cover_comp).save(cover_still, "PNG", compress_level=1))
    cover_path = os.path.join(folder, f"part-cover.{MV.SEGMENT_EXT}")
    cover_sig = MR.sig("cover", look, cover_info)

    async def render_cover():
        card = await asyncio.to_thread(save_layers, cover_comp, "cover", "row")
        await _ffmpeg(MV.cover_args(card, MR.COVER_S, width, height, cover_path))

    progress.stage("cover")
    await _cached(pair_id, cover_sig, "segment", cover_path, render_cover)
    parts.append(cover_path)
    await progress.step("cover")

    # Odcinki klipów.
    for i, (e, seg) in enumerate(zip(entries, plan["segments"])):
        prev = entries[i - 1] if i else None
        view = views[e["match_id"]]
        chapter_info = {**{k: v for k, v in view.items() if k != "crests"}, "clips": per_match[e["match_id"]], "number": numbers[i],
                        "total": chapters_total} if seg["chapter"] else None
        bar_info = {"minute": e["minute"], "half": e["half"], "label": e["label"], "label_color": e["label_color"], "category": e["category"],
                    "category_color": e["category_color"], "title": e["title"], "code": view["code"], "code_color": view["code_color"],
                    "home": view["home"], "away": view["away"], "position": i + 1, "total": total}
        tail_key = {"cover": cover_sig} if prev is None else item_key(prev, i - 1)
        seg_sig = MR.sig("clip", look, tail_key, chapter_info, bar_info, item_key(e, i),
                         {k: seg[k] for k in ("fades", "offsets", "body_s", "tail_in", "frames")})
        target = os.path.join(folder, f"part-{i:03d}.{MV.SEGMENT_EXT}")

        async def render_segment(e=e, seg=seg, prev=prev, view=view, chapter_info=chapter_info, bar_info=bar_info, i=i, target=target):
            frame_path = os.path.join(folder, f"frame-{i}.png")
            await _ffmpeg(MV.frame_args(e["source"], e["offset"] + 0.02, width, height, frame_path), 300)
            # Obrazy (PIL) liczą się w wątku: kilkaset ms na PNG blokowało pętlę zdarzeń serwera.
            def compose_plates():
                frame = Image.open(frame_path).convert("RGB")
                # Tekst belki dojeżdża lekko od dołu: rozdzielamy tło (rozmyta klatka) i warstwę tekstu.
                bar_comp = MC.compose_bar(frame, bar_info, width, height)
                bg_path = os.path.join(folder, f"bar-{i}-plain.png")
                bar_comp["background"].save(bg_path, "PNG", compress_level=1)
                text_path = os.path.join(folder, f"bar-{i}-text.png")
                bar_comp["text"].save(text_path, "PNG", compress_level=1)
                bar = {"background": bg_path, "layers": [{"path": text_path, "x": 0, "y": 0, "motion": "rise", "delay": 0.05, "fade": True}]}
                chapter = None
                if chapter_info is not None:
                    chapter = save_layers(MC.compose_chapter({**chapter_info, "crests": view["crests"]}, width, height), f"chap-{i}")
                return bar, chapter

            bar, chapter = await asyncio.to_thread(compose_plates)
            if prev is None:
                tail = {"still": cover_still}
            else:
                tail = {"source": prev["source"], "start": prev["offset"] + prev["duration"] - seg["tail_in"],
                        "overlay": await asyncio.to_thread(overlay_png, prev, i - 1)}
            body = {"source": e["source"], "start": e["offset"], "overlay": await asyncio.to_thread(overlay_png, e, i)}
            await _ffmpeg(MV.clip_segment_args(seg, tail=tail, chapter=chapter, bar=bar, body=body, width=width, height=height, target=target))

        progress.stage("clips")
        await _cached(pair_id, seg_sig, "segment", target, render_segment)
        parts.append(target)
        await progress.step("clips")

    # Koniec: spis klipów.
    last = entries[-1]
    rows_info = [{"code": views[e["match_id"]]["code"], "code_color": views[e["match_id"]]["code_color"], "minute": e["minute"],
                  "label": e["label"], "label_color": e["label_color"], "title": e["title"]} for e in entries]
    info_lines = [f"{total} {MR.plural(total, 'klip', 'klipy', 'klipów')} · {chapters_total} {MR.plural(chapters_total, 'mecz', 'mecze', 'meczów')}",
                  f"Czas filmu {MR.duration_label(plan['total_s'])}"]
    end_sig = MR.sig("end", look, item_key(last, total - 1), rows_info, info_lines, name, plan["end"])
    end_path = os.path.join(folder, f"part-end.{MV.SEGMENT_EXT}")

    async def render_end():
        def compose_end():
            comp = MC.compose_credits({"name": name, "info": info_lines, "rows": rows_info}, width, height)
            bg = comp["background"].convert("RGBA")
            bg.alpha_composite(comp["text"])
            bg_path = os.path.join(folder, "end-bg.png")
            bg.convert("RGB").save(bg_path, "PNG", compress_level=1)
            list_path = os.path.join(folder, "end-list.png")
            comp["list"].save(list_path, "PNG", compress_level=1)
            upper, lower = MC.credit_masks(bg.convert("RGB"), comp["viewport"], comp["list_x"], comp["fade_h"])
            up_path, low_path = os.path.join(folder, "end-up.png"), os.path.join(folder, "end-low.png")
            upper.save(up_path, "PNG")
            lower.save(low_path, "PNG")
            top, bottom = comp["viewport"]
            distance = max(0, comp["list_h"] - (bottom - top))
            layers = [{"path": list_path, "x": comp["list_x"], "y": comp["list_y"], "motion": "scroll",
                       "y_expr": MV.scroll_expr(comp["list_y"], distance, plan["end"]["card_s"]), "fade": True, "delay": 0.1},
                      {"path": up_path, "x": comp["list_x"], "y": 0},
                      {"path": low_path, "x": comp["list_x"], "y": comp["viewport"][1] - comp["fade_h"]}]
            return bg_path, layers

        bg_path, layers = await asyncio.to_thread(compose_end)
        tail = {"source": last["source"], "start": last["offset"] + last["duration"] - plan["end"]["tail_in"], "overlay": await asyncio.to_thread(overlay_png, last, total - 1)}
        await _ffmpeg(MV.end_args(plan["end"], tail=tail, credits={"background": bg_path, "layers": layers}, width=width, height=height,
                                  target=end_path))

    progress.stage("end")
    await _cached(pair_id, end_sig, "segment", end_path, render_end)
    parts.append(end_path)
    await progress.step("end")

    # Sklejka z rozdziałami.
    progress.stage("join")
    chapter_entries = [{"clip_id": e["clip_id"], "match_id": e["match_id"], "position": i + 1, "minute": e["minute"], "label": e["label"],
                        "title": e["title"]} for i, e in enumerate(entries)]
    chapters = MR.film_chapters(plan, chapter_entries, name)
    listing = os.path.join(folder, "parts.txt")
    with open(listing, "w", encoding="utf-8") as handle:
        handle.write(MV.concat_listing(parts))
    meta = os.path.join(folder, "chapters.txt")
    with open(meta, "w", encoding="utf-8") as handle:
        handle.write(MR.ffmetadata(chapters, name))
    film = os.path.join(folder, "film.mp4")
    await _ffmpeg(MV.concat_args(listing, meta, film))
    await progress.step("join")
    progress.stage("upload")
    from app import mentor_bastion_media as BM

    probe = await asyncio.to_thread(BM.ffprobe_file, film)
    key = M.object_key(pair_id, "montages", f"{mid}.mp4")
    size = await asyncio.to_thread(M.put_file, film, key, "video/mp4")
    poster = os.path.join(folder, "poster.jpg")
    MC.flatten(cover_comp).resize((1280, 720), Image.LANCZOS).save(poster, "JPEG", quality=88)
    poster_key = M.object_key(pair_id, "montages", f"{mid}.jpg")
    await asyncio.to_thread(M.put_file, poster, poster_key, "image/jpeg")
    fresh = await C.one(select(mentor_montages).where(mentor_montages.c.id == mid))
    if not fresh or fresh.get("status") != "rendering":
        await asyncio.to_thread(M.delete_objects, [key, poster_key])  # film usunięty w trakcie renderu
        return
    now = C.now()
    became = await _guarded(mid, ("rendering",), dict(
        status="ready", stage=None, progress=1.0, message=None, film_key=key, poster_key=poster_key, size=size,
        duration_s=round(float(probe.get("duration_s") or plan["total_s"]), 2), width=width, height=height,
        chapters_json=C.dumps(chapters), rendered_json=C.dumps([e["clip_id"] for e in entries]), ready_at=now,
        expires_at=now + timedelta(days=MR.TTL_DAYS), updated_at=now))
    if not became:
        await asyncio.to_thread(M.delete_objects, [key, poster_key])  # film usunięty tuż przed zapisem
        _live.pop(mid, None)
        return
    _live.pop(mid, None)
    await C.touch(pair_id, row["created_by"], "montage_ready", "compilations", data={"id": mid})
    try:
        from app.mentor_panel_notify import notify

        wctx, _actor = await _worker_ctx(row)
        cid = R.s(row.get("compilation_id"))
        path = f"/mentor/{pair_id}/zestawienia/{cid}" if cid else f"/mentor/{pair_id}/klipy"
        await notify(wctx, "", "Film gotowy", f"„{row.get('name')}” - {MR.duration_label(plan['total_s'])}. Możesz obejrzeć i pobrać.",
                     recipients=[row["created_by"]], link=f"https://www.bazapodreka.app{path}", target="montage", tag=f"montage-{mid}",
                     extra={"montageId": mid, "compilationId": cid})
    except Exception:  # noqa: BLE001 - powiadomienie to dodatek
        logger.info("montaż: powiadomienie o gotowym filmie nieudane", exc_info=True)


async def next_render() -> Optional[Dict[str, Any]]:
    return await C.one(select(mentor_montages).where(mentor_montages.c.status == "queued").order_by(mentor_montages.c.updated_at.asc()).limit(1))


async def render_next() -> bool:
    row = await next_render()
    if not row:
        return False
    try:
        await process_montage(row)
    except Exception as exc:  # noqa: BLE001
        logger.warning("montaż: render %s nieudany: %s", row["id"], exc, exc_info=not isinstance(exc, MR.MontageError))
        if isinstance(exc, MR.MontageError):
            message = exc.message
        elif isinstance(exc, FfmpegFailed):
            message = f"Nie udało się złożyć odcinka: {exc.reason}. Spróbuj ponownie."
        else:
            message = "Nie udało się złożyć filmu. Spróbuj ponownie."
        failed = await _guarded(row["id"], ("queued", "rendering"), dict(status="failed", stage=None, message=message, updated_at=C.now()))
        _live.pop(row["id"], None)
        if failed:
            await C.touch(row["pair_id"], row["created_by"], "montage_failed", "compilations", data={"id": row["id"]})
    return True


async def resume_interrupted() -> None:
    """Po restarcie render w toku zaczyna się od nowa (odcinki z księgi wracają od razu)."""
    await database.execute(update(mentor_montages).where(mentor_montages.c.status == "rendering").values(status="queued", stage="queued"))


async def retention_once() -> Dict[str, int]:
    """Gotowe filmy po 30 dniach tracą plik (wiersz zostaje jako „wygasły”, można zrobić ponownie); odcinki w księdze nieużywane
    od 30 dni znikają z magazynu."""
    now = C.now()
    old = await C.rows(select(mentor_montages).where(mentor_montages.c.status == "ready").where(mentor_montages.c.expires_at < now))
    for row in old:
        await asyncio.to_thread(M.delete_objects, [row.get("film_key")])
        await database.execute(update(mentor_montages).where(mentor_montages.c.id == row["id"]).values(status="expired", film_key=None,
                                                                                                        updated_at=now))
    stale = await C.rows(select(mentor_montage_assets).where(mentor_montage_assets.c.used_at < now - timedelta(days=MR.TTL_DAYS)))
    if stale:
        await asyncio.to_thread(M.delete_objects, [r["key"] for r in stale])
        await database.execute(delete(mentor_montage_assets).where(mentor_montage_assets.c.sig.in_([r["sig"] for r in stale])))
    return {"expired": len(old), "parts": len(stale)}


async def run_montage_worker() -> None:
    """Pętla: przegląd przygotowań co `TICK_S` (gdy jakieś są), jeden render naraz, retencja co godzinę."""
    global _wake
    _wake = asyncio.Event()
    await asyncio.sleep(25)
    try:
        await resume_interrupted()
    except Exception:  # noqa: BLE001
        logger.warning("montaż: wznowienie po restarcie nieudane", exc_info=True)
    last_retention = 0.0
    while True:
        try:
            preparing = await tick_preparing()
            busy = await render_next()
            if time.monotonic() - last_retention > 3600:
                last_retention = time.monotonic()
                await retention_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("montaż: przebieg workera nieudany")
            busy, preparing = False, 0
        if busy:
            continue
        _wake.clear()
        try:
            await asyncio.wait_for(_wake.wait(), timeout=TICK_S if preparing else 60)
        except asyncio.TimeoutError:
            pass

"""Kosz nagrań meczu w panelu „Mentor" (28.10.2026).

Usunięcie nagrania (link YouTube/Vimeo/Bastion) nie kasuje wiersza: `deleted_at` + `trash_json`
(co dokładnie zniknęło razem z nim) na 30 dni. W tym czasie można je przywrócić.

Razem z nagraniem znikają: klipy wirtualne (bez gotowego MP4), komentarze zakotwiczone w tym nagraniu
i wątki, które przez to opustoszały (wiersz wątku trafia do `trash_json` i wraca przy przywróceniu).
Klipy z gotowym MP4 w magazynie zostają w Bibliotece jako samodzielne - wiersz nagrania zostaje jako
ukryty nagrobek, żeby ich odtwarzanie i opisy dalej działały.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update

from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app.db import (
    database,
    mentor_clip_assets,
    mentor_clips,
    mentor_comments,
    mentor_match_videos,
    mentor_threads,
)

logger = logging.getLogger(__name__)

TRASH_DAYS = 30
_DATETIME_KEYS = ("created_at", "updated_at", "last_comment_at")


def alive(table=mentor_match_videos):
    """Warunek „nagranie nie leży w koszu" - do wszystkich odczytów list i zapisów."""
    return table.c.deleted_at.is_(None)


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=lambda v: v.isoformat() if hasattr(v, "isoformat") else str(v))


def _loads(value: Any) -> Dict[str, Any]:
    try:
        out = json.loads(value) if isinstance(value, str) and value else {}
    except ValueError:
        return {}
    return out if isinstance(out, dict) else {}


def _aware(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    return value


def expires_at(row: Dict[str, Any]) -> Optional[datetime]:
    stamp = _aware(row.get("deleted_at"))
    return stamp + timedelta(days=TRASH_DAYS) if stamp else None


def in_trash(row: Dict[str, Any]) -> bool:
    """W koszu i jeszcze do przywrócenia (po sprzątaniu zostaje tylko nagrobek)."""
    return row.get("deleted_at") is not None and not _loads(row.get("trash_json")).get("purged")


# ─── Plan: co zniknie ───────────────────────────────────────────────────────


async def plan(ctx: Dict[str, Any], video: Dict[str, Any]) -> Dict[str, Any]:
    """Liczy skutki usunięcia nagrania; ten sam plan wykonuje `move_to_trash`."""
    vid = R.s(video["id"])
    clips = await C.rows(select(mentor_clips).where(mentor_clips.c.pair_id == ctx["pair_id"])
                         .where(mentor_clips.c.video_id == vid).where(mentor_clips.c.deleted_at.is_(None)))
    ids = [c["id"] for c in clips]
    ready = set()
    if ids:
        for a in await C.rows(select(mentor_clip_assets.c.clip_id, mentor_clip_assets.c.revision)
                              .where(mentor_clip_assets.c.clip_id.in_(ids)).where(mentor_clip_assets.c.status == "ready")):
            ready.add((a["clip_id"], int(a["revision"] or 0)))
    kept, virtual = [], []
    for c in clips:
        has_file = (c["id"], int(c.get("media_rev") or 1)) in ready or (c.get("mp4_status") == "ready" and c.get("mp4_key"))
        (kept if has_file else virtual).append(c["id"])
    # Wątki klipów, które zostają, nie są ruszane. Reszta: komentarze z kotwicą w tym nagraniu + wątki klipów wirtualnych.
    thread_rows = await C.rows(select(mentor_threads).where(mentor_threads.c.pair_id == ctx["pair_id"]))
    keep_threads = {t["id"] for t in thread_rows if t.get("target_kind") == "clip" and t.get("target_id") in set(kept)}
    virtual_threads = {t["id"] for t in thread_rows if t.get("target_kind") == "clip" and t.get("target_id") in set(virtual)}
    by_id = {t["id"]: t for t in thread_rows}
    live = await C.rows(select(mentor_comments.c.id, mentor_comments.c.thread_id, mentor_comments.c.video_id)
                        .where(mentor_comments.c.deleted_at.is_(None)))
    live = [c for c in live if c["thread_id"] in by_id]
    comment_ids = [c["id"] for c in live if c["thread_id"] not in keep_threads
                   and (c["video_id"] == vid or c["thread_id"] in virtual_threads)]
    gone = set(comment_ids)
    touched = {c["thread_id"] for c in live if c["id"] in gone} | virtual_threads
    emptied = sorted(t for t in touched
                     if t in virtual_threads or not any(c["thread_id"] == t and c["id"] not in gone for c in live))
    return {"virtual_clip_ids": virtual, "kept_clip_ids": kept, "comment_ids": comment_ids, "thread_ids": emptied,
            "threads": [by_id[t] for t in emptied if t in by_id]}


def counts(found: Dict[str, Any]) -> Dict[str, int]:
    return {"virtual_clips": len(found["virtual_clip_ids"]), "kept_clips": len(found["kept_clip_ids"]),
            "threads": len(found["thread_ids"]), "comments": len(found["comment_ids"])}


def restorable(video: Dict[str, Any]) -> bool:
    """Wgrane nagrania (plik w R2) kasujemy od razu - do kosza trafiają tylko linki."""
    return (video.get("kind") or "link") != "upload"


async def impact(ctx: Dict[str, Any], video: Dict[str, Any]) -> Dict[str, Any]:
    found = await plan(ctx, video)
    return {"video_id": video["id"], **counts(found), "restorable": restorable(video), "retention_days": TRASH_DAYS}


# ─── Kosz i przywracanie ────────────────────────────────────────────────────


async def move_to_trash(ctx: Dict[str, Any], video: Dict[str, Any], actor_id: str) -> Dict[str, Any]:
    found = await plan(ctx, video)
    stamp = C.now()
    for cid in found["virtual_clip_ids"]:
        await database.execute(update(mentor_clips).where(mentor_clips.c.id == cid)
                               .values(deleted_at=stamp, public_token=None, published_at=None))
        try:
            from app import mentor_bastion_jobs as J

            await J.discard_clip_media(cid)  # zadania w toku anulowane (gotowych plików klip wirtualny nie ma)
        except Exception:  # noqa: BLE001
            logger.warning("mentor: anulowanie zadań klipu przy usuwaniu nagrania nieudane", exc_info=True)
    if found["comment_ids"]:
        await database.execute(update(mentor_comments).where(mentor_comments.c.id.in_(found["comment_ids"])).values(deleted_at=stamp))
    for tid in found["thread_ids"]:
        await database.execute(mentor_threads.delete().where(mentor_threads.c.id == tid))
    trash = {"clip_ids": found["virtual_clip_ids"], "kept_clip_ids": found["kept_clip_ids"],
             "comment_ids": found["comment_ids"], "threads": found["threads"]}
    await database.execute(update(mentor_match_videos).where(mentor_match_videos.c.id == video["id"])
                           .values(deleted_at=stamp, deleted_by=R.s(actor_id), trash_json=_dump(trash)))
    return {**counts(found), "expires_at": stamp + timedelta(days=TRASH_DAYS)}


async def restore(video: Dict[str, Any]) -> Dict[str, int]:
    trash = _loads(video.get("trash_json"))
    clip_ids = [R.s(i) for i in trash.get("clip_ids") or []]
    comment_ids = [R.s(i) for i in trash.get("comment_ids") or []]
    if clip_ids:
        await database.execute(update(mentor_clips).where(mentor_clips.c.id.in_(clip_ids)).values(deleted_at=None))
    for snap in trash.get("threads") or []:
        if not isinstance(snap, dict) or not snap.get("id"):
            continue
        if await C.one(select(mentor_threads.c.id).where(mentor_threads.c.id == snap["id"])):
            continue
        values = {k: (_aware(v) if k in _DATETIME_KEYS else v) for k, v in snap.items() if k in mentor_threads.c}
        await database.execute(mentor_threads.insert().values(**values))
    if comment_ids:
        await database.execute(update(mentor_comments).where(mentor_comments.c.id.in_(comment_ids)).values(deleted_at=None))
    await database.execute(update(mentor_match_videos).where(mentor_match_videos.c.id == video["id"])
                           .values(deleted_at=None, deleted_by=None, trash_json=None))
    return {"clips": len(clip_ids), "comments": len(comment_ids), "threads": len(trash.get("threads") or [])}


async def trashed_for_match(ctx: Dict[str, Any], match_id: str) -> List[Dict[str, Any]]:
    found = await C.rows(select(mentor_match_videos).where(mentor_match_videos.c.match_id == R.s(match_id))
                         .where(mentor_match_videos.c.pair_key == ctx["pair_key"])
                         .where(mentor_match_videos.c.deleted_at.is_not(None))
                         .order_by(mentor_match_videos.c.deleted_at.desc()))
    return [r for r in found if in_trash(r)]


def trash_shape(row: Dict[str, Any], names: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    trash = _loads(row.get("trash_json"))
    return {
        "id": row["id"], "provider": row.get("provider"), "kind": row.get("kind") or "link", "url": row.get("url"),
        "title": row.get("title") or "", "thumbnail_url": row.get("thumbnail_url"), "duration_s": row.get("duration_s"),
        "deleted_at": row.get("deleted_at"), "deleted_by": C.person(names, row.get("deleted_by")),
        "expires_at": expires_at(row),
        "virtual_clips": len(trash.get("clip_ids") or []), "kept_clips": len(trash.get("kept_clip_ids") or []),
        "threads": len(trash.get("threads") or []), "comments": len(trash.get("comment_ids") or []),
    }


async def trash_payload(ctx: Dict[str, Any], match_id: str) -> List[Dict[str, Any]]:
    found = await trashed_for_match(ctx, match_id)
    names = await C.people({r.get("deleted_by") for r in found})
    return [trash_shape(r, names) for r in found]


async def purge_expired(now: datetime) -> int:
    """Zadanie dzienne: po 30 dniach kosz się zamyka. Wiersz znika, chyba że trzyma klipy z MP4 (wtedy nagrobek)."""
    limit = now - timedelta(days=TRASH_DAYS)
    done = 0
    for row in await C.rows(select(mentor_match_videos).where(mentor_match_videos.c.deleted_at.is_not(None))
                            .where(mentor_match_videos.c.deleted_at < limit)):
        if not in_trash(row):
            continue
        holders = await C.one(select(mentor_clips.c.id).where(mentor_clips.c.video_id == row["id"])
                              .where(mentor_clips.c.deleted_at.is_(None)).limit(1))
        if holders:
            await database.execute(update(mentor_match_videos).where(mentor_match_videos.c.id == row["id"])
                                   .values(trash_json=_dump({"purged": True})))
        else:
            await database.execute(mentor_match_videos.delete().where(mentor_match_videos.c.id == row["id"]))
        done += 1
    return done

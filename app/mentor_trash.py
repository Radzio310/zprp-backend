"""Kosz pary w panelu „Mentor" (25.11.2026) - jedno miejsce w Ustawieniach na wszystko, co usunięto.

Usunięte klipy, zrzuty klatek, zestawienia, filmy z montażu i nagrania meczów czekają tu 30 dni; w tym czasie
można je przywrócić albo usunąć na zawsze. Po 30 dniach sprzątanie dzienne kasuje pliki z magazynu.

  - `GET    /mentor-panel/pairs/{p}/trash` - zawartość kosza pary (najnowsze na górze),
  - `POST   /mentor-panel/pairs/{p}/trash/{kind}/{id}/restore` - przywrócenie,
  - `DELETE /mentor-panel/pairs/{p}/trash/{kind}/{id}` - usunięcie na zawsze (bez cofania).

`kind`: clip | shot | compilation | montage | video. Klip, zrzut, zestawienie i film są w koszu, gdy mają `deleted_by`
(znacznik od 25.11.2026; dawniej usunięte nie mają plików, więc nie wracają). Nagrania mają własny kosz
(`mentor_video_trash`) z tymi samymi 30 dniami - tu są widoczne razem z resztą.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends
from sqlalchemy import delete, func, select, update

from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app.db import (database, mentor_clips, mentor_compilation_items, mentor_compilations, mentor_match_videos, mentor_montages,
                    mentor_shots)
from app.mentor_panel_auth import mentor_actor

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/mentor-panel", tags=["Mentor"])
Actor = C.MentorActor

TRASH_DAYS = 30
KINDS = ("clip", "shot", "compilation", "montage", "video")


def expires(row: Dict[str, Any]) -> Optional[datetime]:
    at = R.aware(row.get("deleted_at"))
    return at + timedelta(days=TRASH_DAYS) if at else None


def _fresh(row: Dict[str, Any], now: datetime) -> bool:
    at = R.aware(row.get("deleted_at"))
    return bool(at and at >= now - timedelta(days=TRASH_DAYS) and row.get("deleted_by"))


def _presign(key: Optional[str]) -> Optional[str]:
    if not key:
        return None
    from app import mentor_panel_media as M

    try:
        return M.presign_get(key, M.PLAY_URL_TTL)
    except Exception:  # noqa: BLE001 - brak podglądu nie psuje kosza
        return None


# ─── Odczyt ─────────────────────────────────────────────────────────────────


async def _rows(ctx: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    now = C.now()
    since = now - timedelta(days=TRASH_DAYS)
    pid = ctx["pair_id"]
    clips = await C.rows(select(mentor_clips).where(mentor_clips.c.pair_id == pid).where(mentor_clips.c.deleted_by.is_not(None))
                         .where(mentor_clips.c.deleted_at >= since))
    shots = await C.rows(select(mentor_shots).where(mentor_shots.c.pair_id == pid).where(mentor_shots.c.deleted_by.is_not(None))
                         .where(mentor_shots.c.deleted_at >= since))
    comps = await C.rows(select(mentor_compilations).where(mentor_compilations.c.pair_id == pid)
                         .where(mentor_compilations.c.deleted_by.is_not(None)).where(mentor_compilations.c.deleted_at >= since))
    films = await C.rows(select(mentor_montages).where(mentor_montages.c.pair_id == pid).where(mentor_montages.c.deleted_by.is_not(None))
                         .where(mentor_montages.c.deleted_at >= since).where(mentor_montages.c.status != "cancelled"))
    from app import mentor_video_trash as T

    videos = [r for r in await C.rows(select(mentor_match_videos).where(mentor_match_videos.c.pair_key == ctx["pair_key"])
                                      .where(mentor_match_videos.c.deleted_at.is_not(None)).where(mentor_match_videos.c.deleted_at >= since))
              if T.in_trash(r)]
    return {"clip": clips, "shot": shots, "compilation": comps, "montage": films, "video": videos}


def _may_clip(ctx: Dict[str, Any], row: Dict[str, Any]) -> bool:
    return C.may(ctx, "edit", owner=R.s(row.get("author_id")) == ctx["actor"].judge_id)


def _may(ctx: Dict[str, Any], kind: str, row: Dict[str, Any]) -> bool:
    if kind in ("clip", "shot"):
        return _may_clip(ctx, row)
    if kind in ("compilation", "montage"):
        return C.may(ctx, "edit", owner=R.s(row.get("created_by")) == ctx["actor"].judge_id)
    return C.may(ctx, "video")


async def trash_payload(ctx: Dict[str, Any]) -> Dict[str, Any]:
    found = await _rows(ctx)
    names = await C.people({r.get("deleted_by") for rows in found.values() for r in rows})
    match_ids = {R.s(r.get("match_id")) for k in ("clip", "shot", "video") for r in found[k] if r.get("match_id")}
    cards: Dict[str, Dict[str, Any]] = {}
    if match_ids:
        try:
            cards = {c["match_id"]: c for c in await C.pair_match_cards(ctx["judge_ids"]) if c.get("match_id") in match_ids}
            if any(m.startswith("tr_") for m in match_ids):
                from app.mentor_trybuna import lookup_cards

                cards.update(await lookup_cards(ctx["pair_id"], [m for m in match_ids if m.startswith("tr_")]))
        except Exception:  # noqa: BLE001 - karta meczu to tylko podpis
            logger.warning("mentor: karty meczów w koszu nieczytelne", exc_info=True)
    thumbs = await _video_thumbs([r.get("video_id") for r in found["clip"]])
    counts = await _comp_counts([r["id"] for r in found["compilation"]])
    items: List[Dict[str, Any]] = []

    def base(kind: str, row: Dict[str, Any], title: str) -> Dict[str, Any]:
        can = _may(ctx, kind, row)
        return {"kind": kind, "id": row["id"], "title": title, "deleted_at": row.get("deleted_at"),
                "deleted_by": C.person(names, row.get("deleted_by")) if row.get("deleted_by") else None, "expires_at": expires(row),
                "can_restore": can, "can_purge": can, "match_id": row.get("match_id"),
                "match": R.slim_match(cards.get(R.s(row.get("match_id")))) if row.get("match_id") else None}

    for r in found["clip"]:
        items.append({**base("clip", r, R.s(r.get("title")) or "Klip"), "thumb_url": thumbs.get(R.s(r.get("video_id"))),
                      "start_s": r.get("start_s"), "end_s": r.get("end_s"), "duration_s": _len(r), "match_ms": r.get("match_ms"),
                      "verdict": r.get("verdict")})
    for r in found["shot"]:
        items.append({**base("shot", r, R.s(r.get("title")) or "Zrzut klatki"), "thumb_url": _presign(r.get("thumb_key") or r.get("image_key")),
                      "at_s": r.get("at_s")})
    for r in found["compilation"]:
        items.append({**base("compilation", r, R.s(r.get("name")) or "Zestawienie"), "items_count": counts.get(r["id"], 0)})
    for r in found["montage"]:
        items.append({**base("montage", r, R.s(r.get("name")) or "Film"), "thumb_url": _presign(r.get("poster_key")),
                      "duration_s": r.get("duration_s"), "status": r.get("status"), "compilation_id": r.get("compilation_id")})
    for r in found["video"]:
        items.append({**base("video", r, R.s(r.get("title")) or "Nagranie meczu"), "thumb_url": r.get("thumbnail_url"),
                      "provider": r.get("provider"), "duration_s": r.get("duration_s")})
    items.sort(key=lambda i: R.aware(i["deleted_at"]) or C.now(), reverse=True)
    return {"items": items, "days": TRASH_DAYS}


def _len(row: Dict[str, Any]) -> Optional[float]:
    try:
        return round(float(row["end_s"]) - float(row["start_s"]), 2)
    except (KeyError, TypeError, ValueError):
        return None


async def _video_thumbs(video_ids: List[Any]) -> Dict[str, Optional[str]]:
    ids = list({R.s(v) for v in video_ids if R.s(v)})
    if not ids:
        return {}
    rows = await C.rows(select(mentor_match_videos.c.id, mentor_match_videos.c.thumbnail_url).where(mentor_match_videos.c.id.in_(ids)))
    return {r["id"]: r.get("thumbnail_url") for r in rows}


async def _comp_counts(comp_ids: List[str]) -> Dict[str, int]:
    if not comp_ids:
        return {}
    rows = await C.rows(select(mentor_compilation_items.c.compilation_id, func.count().label("n"))
                        .where(mentor_compilation_items.c.compilation_id.in_(comp_ids)).group_by(mentor_compilation_items.c.compilation_id))
    return {r["compilation_id"]: int(r["n"]) for r in rows}


# ─── Przywracanie i usuwanie na zawsze ──────────────────────────────────────

_TABLES = {"clip": mentor_clips, "shot": mentor_shots, "compilation": mentor_compilations, "montage": mentor_montages}


async def _find(ctx: Dict[str, Any], kind: str, item_id: str) -> Dict[str, Any]:
    if kind not in KINDS:
        raise C.err(404, "NOT_FOUND", "Nie ma takiej pozycji w koszu.")
    if kind == "video":
        from app import mentor_video_trash as T

        row = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == R.s(item_id)))
        if not row or R.s(row.get("pair_key")) != ctx["pair_key"] or not T.in_trash(row):
            raise C.err(404, "NOT_IN_TRASH", "Tego nagrania nie ma w koszu - mogło zostać już przywrócone albo usunięte na zawsze.")
        return row
    table = _TABLES[kind]
    row = await C.one(select(table).where(table.c.id == R.s(item_id)))
    if not row or row.get("pair_id") != ctx["pair_id"] or not _fresh(row, C.now()) or (kind == "montage" and row.get("status") == "cancelled"):
        raise C.err(404, "NOT_IN_TRASH", "Tej pozycji nie ma w koszu - mogła zostać już przywrócona albo usunięta na zawsze.")
    return row


def _guard(ctx: Dict[str, Any], kind: str, row: Dict[str, Any]) -> None:
    if not _may(ctx, kind, row):
        raise C.err(403, "FORBIDDEN", "Przywrócić albo usunąć na zawsze może autor albo administrator.")


async def restore_row(ctx: Dict[str, Any], kind: str, row: Dict[str, Any]) -> Dict[str, Any]:
    if kind == "video":
        from app import mentor_video_trash as T

        back = await T.restore(row)
        return {"match_id": row.get("match_id"), **back}
    table = _TABLES[kind]
    values: Dict[str, Any] = {"deleted_at": None, "deleted_by": None}
    if kind in ("compilation", "montage", "shot", "clip"):
        values["updated_at"] = C.now()  # przywrócone wraca na górę list (a film - do nagłówka zestawienia)
    await database.execute(update(table).where(table.c.id == row["id"]).where(table.c.deleted_at.is_not(None)).values(**values))
    if kind == "clip":
        try:
            from app.mentor_shots import on_clip_saved

            await on_clip_saved({**row, "deleted_at": None})  # zrzuty `auto` w zakresie wracają do klipu
        except Exception:  # noqa: BLE001
            logger.warning("mentor: zrzuty przywróconego klipu nieprzypięte", exc_info=True)
    return {"match_id": row.get("match_id"), "compilation_id": row.get("compilation_id") if kind == "montage" else None}


async def purge_clip(row: Dict[str, Any]) -> None:
    """Koniec kosza klipu: pliki MP4 (wszystkie rewizje) i zadania cięcia znikają; wiersz zostaje jako usunięty (bez znacznika)."""
    await database.execute(update(mentor_clips).where(mentor_clips.c.id == row["id"]).values(deleted_by=None, mp4_status="none"))
    if row.get("mp4_key"):
        from app.mentor_panel_media import forget_object

        forget_object(row.get("mp4_key"))
    try:
        from app import mentor_bastion_jobs as J

        await J.discard_clip_media(row["id"])
    except Exception:  # noqa: BLE001
        logger.warning("mentor: pliki klipu %s z kosza nieusunięte", row.get("id"), exc_info=True)


async def purge_shot(row: Dict[str, Any]) -> None:
    await database.execute(update(mentor_shots).where(mentor_shots.c.id == row["id"]).values(
        deleted_by=None, image_key=None, thumb_key=None, image_status="none", image_reason=None))
    from app.mentor_shots import store_forget

    store_forget(row.get("image_key"), row.get("thumb_key"))


async def purge_compilation(row: Dict[str, Any]) -> None:
    await database.execute(delete(mentor_compilation_items).where(mentor_compilation_items.c.compilation_id == row["id"]))
    await database.execute(delete(mentor_compilations).where(mentor_compilations.c.id == row["id"]))


async def purge_row(kind: str, row: Dict[str, Any]) -> None:
    if kind == "clip":
        await purge_clip(row)
    elif kind == "shot":
        await purge_shot(row)
    elif kind == "compilation":
        await purge_compilation(row)
    elif kind == "montage":
        from app.mentor_montage import purge_montage

        await purge_montage(row)
        await database.execute(update(mentor_montages).where(mentor_montages.c.id == row["id"]).values(deleted_by=None))
    else:
        from app import mentor_video_trash as T

        await T.purge_row(row)


async def purge_expired(now: datetime) -> Dict[str, int]:
    """Zadanie dzienne: po 30 dniach pliki klipów, zrzutów i filmów znikają z magazynu, zestawienia z bazy.
    Nagrania sprząta `mentor_video_trash.purge_expired` (ta sama pętla retencji)."""
    limit = now - timedelta(days=TRASH_DAYS)
    done: Dict[str, int] = {}
    for kind, table in _TABLES.items():
        rows = await C.rows(select(table).where(table.c.deleted_by.is_not(None)).where(table.c.deleted_at.is_not(None))
                            .where(table.c.deleted_at < limit))
        for row in rows:
            try:
                await purge_row(kind, row)
                done[kind] = done.get(kind, 0) + 1
            except Exception:  # noqa: BLE001 - jedna pozycja nie zatrzymuje sprzątania
                logger.warning("mentor: sprzątanie kosza (%s %s) nieudane", kind, row.get("id"), exc_info=True)
    return done


# ─── Trasy ──────────────────────────────────────────────────────────────────


@router.get("/pairs/{pair_id}/trash")
async def get_trash(pair_id: str, actor: Actor = Depends(mentor_actor)):
    ctx = await C.pair_context(pair_id, actor)
    return await trash_payload(ctx)


async def _target(pair_id: str, kind: str, item_id: str, actor: Actor) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    ctx = await C.pair_context(pair_id, actor)
    row = await _find(ctx, kind, item_id)
    _guard(ctx, kind, row)
    return ctx, row


@router.post("/pairs/{pair_id}/trash/{kind}/{item_id}/restore")
async def restore_item(pair_id: str, kind: str, item_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _target(pair_id, kind, item_id, actor)
    back = await restore_row(ctx, kind, row)
    await C.touch(ctx, actor.judge_id, f"{kind}_restored", "trash", row.get("match_id"), {"id": row["id"], "kind": kind})
    return {"ok": True, "kind": kind, "id": row["id"], **back}


@router.delete("/pairs/{pair_id}/trash/{kind}/{item_id}")
async def purge_item(pair_id: str, kind: str, item_id: str, actor: Actor = Depends(mentor_actor)):
    ctx, row = await _target(pair_id, kind, item_id, actor)
    await purge_row(kind, row)
    await C.touch(ctx, actor.judge_id, f"{kind}_purged", "trash", row.get("match_id"), {"id": row["id"], "kind": kind})
    return {"ok": True}

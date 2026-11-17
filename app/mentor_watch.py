"""Miejsce oglądania nagrania w panelu „Mentor" (17.11.2026): trasy zapisu i odczytu.

Miejsce jest MOJE (per sędzia, z JWT albo sesji web), osobne dla każdego nagrania meczu i wspólne dla urządzeń.
Bramki jak przy nagraniach meczu: dostęp do pary (`pair_context`) i nagranie tej pary (`_pair_video`). Nikt inny nie
czyta cudzego miejsca - wiersze zawsze filtrujemy po `judge_id` pytającego. Reguły: `app/mentor_watch_rules.py`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app import mentor_watch_rules as W
from app.db import database, mentor_match_videos, mentor_watch_progress
from app.mentor_panel_auth import mentor_actor

router = APIRouter(prefix="/mentor-panel", tags=["Mentor Oglądanie"])
Actor = C.MentorActor
T = mentor_watch_progress
MAX_BATCH = 200


def _media():
    from app import mentor_panel_media as M

    return M


class WatchBody(BaseModel):
    position_s: float = Field(ge=0)
    duration_s: Optional[float] = None
    #: `phone` | `tablet` | `desktop`.
    device: Optional[str] = Field(default=None, max_length=12)
    #: Czas zapisu z urządzenia (ms od 1970 albo ISO); brak = teraz serwera. „Ostatni wygrywa".
    saved_at: Optional[Any] = None
    #: Klient zna DOKŁADNY czas gry (ślad zegara ProEla) i jest on >= 2 x połowa - 150 s (domyślnie 57:30): koniec oglądania.
    reached_end: Optional[bool] = None
    #: `player` (domyślnie). `calibration` i `clip` (kreator kalibracji, podgląd klipu) są ignorowane.
    source: Optional[str] = Field(default=None, max_length=20)


class DismissBody(BaseModel):
    #: `saved_at` odrzucanego miejsca z odczytu (zabezpiecza przed odrzuceniem nowszego zapisu z innego urządzenia).
    saved_at: Optional[Any] = None


async def _own_row(judge_id: str, video_id: str) -> Optional[Dict[str, Any]]:
    return await C.one(select(T).where(T.c.judge_id == judge_id).where(T.c.video_id == video_id))


def _shape(row: Dict[str, Any], video: Dict[str, Any]) -> Dict[str, Any]:
    return W.shape(row, float(video["duration_s"]) if video.get("duration_s") else None)


@router.put("/pairs/{pair_id}/matches/{match_id}/videos/{video_id}/watch")
async def save_watch(pair_id: str, match_id: str, video_id: str, body: WatchBody, actor: Actor = Depends(mentor_actor)):
    """Zapis miejsca. Odpowiedź: `{applied, ignored?, watch}`; `applied: false` = zapis starszy niż zapisany (zostaje nowszy)."""
    ctx = await C.pair_context(pair_id, actor)
    video = await _media()._pair_video(ctx, match_id, video_id)
    if actor.acted_by:
        return {"applied": False, "ignored": "acting", "watch": None}
    save = W.clean_save(body.model_dump(), C.now())
    existing = await _own_row(actor.judge_id, video_id)
    if "ignored" in save:
        return {"applied": False, "ignored": save["ignored"], "watch": _shape(existing, video) if existing else None}
    merged = W.merge_save(existing, save)
    values = merged["values"]
    if values is not None:
        values = {**values, "updated_at": C.now()}
        if existing is None:
            await database.execute(T.insert().values(judge_id=actor.judge_id, video_id=video_id, pair_id=ctx["pair_id"],
                                                     match_id=video["match_id"], **values))
        else:
            await database.execute(update(T).where(T.c.judge_id == actor.judge_id).where(T.c.video_id == video_id).values(**values))
    row = await _own_row(actor.judge_id, video_id)
    return {"applied": bool(merged["apply"]), "watch": _shape(row, video) if row else None}


@router.get("/pairs/{pair_id}/matches/{match_id}/videos/{video_id}/watch")
async def get_watch(pair_id: str, match_id: str, video_id: str, actor: Actor = Depends(mentor_actor)):
    """Moje miejsce w tym nagraniu: `{watch: null}` albo kształt z `propose`, `finished`, `percent`, `device`, `saved_at`."""
    ctx = await C.pair_context(pair_id, actor)
    video = await _media()._pair_video(ctx, match_id, video_id)
    row = await _own_row(actor.judge_id, video_id)
    return {"watch": _shape(row, video) if row else None}


@router.post("/pairs/{pair_id}/matches/{match_id}/videos/{video_id}/watch/dismiss")
async def dismiss_watch(pair_id: str, match_id: str, video_id: str, body: DismissBody, actor: Actor = Depends(mentor_actor)):
    """Świadome odrzucenie propozycji: dotyczy TEGO zapisanego miejsca (nowszy zapis znów może być proponowany)."""
    ctx = await C.pair_context(pair_id, actor)
    video = await _media()._pair_video(ctx, match_id, video_id)
    row = await _own_row(actor.judge_id, video_id)
    if not row or actor.acted_by:
        return {"watch": _shape(row, video) if row else None}
    wanted = W.aware(body.saved_at)
    current = W.aware(row.get("saved_at"))
    if wanted is not None and current is not None and abs((wanted - current).total_seconds()) > 0.001:
        return {"watch": _shape(row, video), "dismissed": False}  # w międzyczasie jest nowszy zapis
    await database.execute(update(T).where(T.c.judge_id == actor.judge_id).where(T.c.video_id == video_id)
                           .values(dismissed_saved_at=row["saved_at"]))
    return {"watch": _shape(await _own_row(actor.judge_id, video_id), video), "dismissed": True}


async def _live_videos(video_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    if not video_ids:
        return {}
    found = await C.rows(select(mentor_match_videos).where(mentor_match_videos.c.id.in_(video_ids))
                         .where(mentor_match_videos.c.deleted_at.is_(None)))
    return {v["id"]: v for v in found}


def _newest_per_match(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    best: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        mid = R.s(r.get("match_id"))
        cur = best.get(mid)
        if cur is None or (W.aware(r.get("saved_at")) or 0) > (W.aware(cur.get("saved_at")) or 0):
            best[mid] = r
    return list(best.values())


@router.get("/pairs/{pair_id}/watch")
async def watch_for_matches(pair_id: str, match_ids: str = Query("", max_length=8000), actor: Actor = Depends(mentor_actor)):
    """Postęp dla listy meczów (cienki pasek na kartach): `?match_ids=a,b,c` (do 200).
    Odpowiedź `{progress: {match_id: shape}}` - dla meczu z kilkoma nagraniami najświeżej zapisane. Mecze bez zapisu pomijamy."""
    ctx = await C.pair_context(pair_id, actor)
    ids = [x for x in dict.fromkeys(R.s(i) for i in match_ids.split(",")) if x][:MAX_BATCH]
    if not ids:
        return {"progress": {}}
    rows = await C.rows(select(T).where(T.c.judge_id == actor.judge_id).where(T.c.pair_id == ctx["pair_id"]).where(T.c.match_id.in_(ids)))
    videos = await _live_videos([r["video_id"] for r in rows])
    rows = [r for r in rows if r["video_id"] in videos]
    return {"progress": {r["match_id"]: _shape(r, videos[r["video_id"]]) for r in _newest_per_match(rows)}}


async def _recent_items(ctx: Dict[str, Any], judge_id: str, limit: int) -> List[Dict[str, Any]]:
    rows = await C.rows(select(T).where(T.c.judge_id == judge_id).where(T.c.pair_id == ctx["pair_id"]).order_by(T.c.saved_at.desc()).limit(200))
    videos = await _live_videos([r["video_id"] for r in rows])
    out: List[Dict[str, Any]] = []
    for r in _newest_per_match([r for r in rows if r["video_id"] in videos]):
        shaped = _shape(r, videos[r["video_id"]])
        if shaped["finished"] or shaped["dismissed"]:
            continue
        out.append((shaped, r))
    out.sort(key=lambda pair: W.aware(pair[1].get("saved_at")) or 0, reverse=True)
    items: List[Dict[str, Any]] = []
    for shaped, r in out[:limit]:
        card = await C.match_card(ctx, r["match_id"], required=False)
        payload = await _media()._video_payload(ctx, r["video_id"])
        items.append({**shaped,
                      "video": {k: payload.get(k) for k in ("id", "provider", "kind", "title", "thumbnail_url", "poster_url")},
                      "match": {k: card.get(k) for k in R.SLIM_MATCH_KEYS} if card else None})
    return items


@router.get("/pairs/{pair_id}/watch/recent")
async def recent_for_pair(pair_id: str, limit: int = Query(10, ge=1, le=30), actor: Actor = Depends(mentor_actor)):
    """„Oglądaj dalej" w jednej parze: ostatnio oglądane, nieukończone i nieodrzucone (po jednym na mecz), od najnowszego."""
    ctx = await C.pair_context(pair_id, actor)
    return {"items": await _recent_items(ctx, actor.judge_id, limit)}


@router.get("/watch/recent")
async def recent_all(limit: int = Query(10, ge=1, le=30), actor: Actor = Depends(mentor_actor)):
    """To samo przez wszystkie pary, do których sędzia ma dziś dostęp (para bez dostępu jest pomijana). Do kafla na pulpicie."""
    pair_ids = [r["pair_id"] for r in await C.rows(select(T.c.pair_id).where(T.c.judge_id == actor.judge_id)
                                                  .order_by(T.c.saved_at.desc()).limit(200))]
    items: List[Dict[str, Any]] = []
    for pid in list(dict.fromkeys(pair_ids))[:12]:
        try:
            ctx = await C.pair_context(pid, actor)
        except HTTPException:
            continue
        items += await _recent_items(ctx, actor.judge_id, limit)
    items.sort(key=lambda i: i.get("saved_at") or "", reverse=True)
    return {"items": items[:limit]}


async def forget_video(video_id: str) -> None:
    """Nagranie skasowane na stałe: znikają miejsca wszystkich oglądających. (Kosz 30 dni zostawia je do przywrócenia.)"""
    await database.execute(T.delete().where(T.c.video_id == video_id))

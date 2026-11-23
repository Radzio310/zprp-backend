"""Sytuacje z arkuszy - wspólnie poprawiony czas w nagraniu (23.11.2026). Kontrakt: `docs/mentor-panel.md`, sekcja 17.

Sytuacja z arkusza zna tylko minutę meczu, a panel wylicza z niej sekundę nagrania (oś ProEla). Para i mentorzy
z prawem do nagrań (`video`, jak kalibracja) mogą ją poprawić RAZ dla wszystkich: początek i koniec w danym nagraniu.
Sytuacja gra wtedy jak klip. „Przywróć czas automatyczny” zdejmuje poprawkę.

  PUT    /pairs/{p}/matches/{m}/situations/{key}/time   {video_id, start_s, end_s}
  DELETE /pairs/{p}/matches/{m}/situations/{key}/time?video_id=
Pokój meczu oddaje poprawki w `situation_times` (`room_times`).
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app.db import database, mentor_situation_times
from app.mentor_panel_auth import mentor_actor

router = APIRouter()
Actor = C.MentorActor

KEY_RE = re.compile(r"^s_[0-9a-f]{14}(-\d{1,3})?$")


class TimeBody(BaseModel):
    video_id: str = Field(..., min_length=1, max_length=80)
    start_s: float = Field(..., ge=0)
    end_s: float = Field(..., gt=0)


def clean_range(start_s: float, end_s: float) -> tuple:
    """Zakres sytuacji jak klipu: koniec po początku, najwyżej `R.MAX_CLIP_S`, dziesiąte części sekundy."""
    start, end = round(max(0.0, float(start_s)), 1), round(float(end_s), 1)
    if end <= start:
        raise C.err(422, "RANGE_BAD", "Koniec sytuacji musi być po jej początku.")
    if end - start > R.MAX_CLIP_S:
        raise C.err(422, "RANGE_TOO_LONG", f"Sytuacja może trwać najwyżej {R.MAX_CLIP_S // 60} min.")
    return start, end


def _key(key: str) -> str:
    if not KEY_RE.match(key or ""):
        raise C.err(404, "SITUATION_NOT_FOUND", "Nie ma takiej sytuacji w arkuszach meczu.")
    return key


def shape(row: Dict[str, Any], people: Dict[str, Any]) -> Dict[str, Any]:
    return {"key": row["situation_key"], "video_id": row["video_id"], "start_s": float(row["start_s"]), "end_s": float(row["end_s"]),
            "updated_by": C.person(people, row.get("updated_by")) if row.get("updated_by") else None,
            "updated_at": row["updated_at"].isoformat() if hasattr(row.get("updated_at"), "isoformat") else R.s(row.get("updated_at")) or None}


async def room_times(ctx: Dict[str, Any], match_id: str) -> List[Dict[str, Any]]:
    found = await C.rows(select(mentor_situation_times).where(mentor_situation_times.c.pair_id == ctx["pair_id"])
                         .where(mentor_situation_times.c.match_id == match_id))
    people = await C.people({r.get("updated_by") for r in found if r.get("updated_by")})
    return [shape(r, people) for r in found]


async def _ctx(pair_id: str, match_id: str, video_id: str, actor: Actor):
    from app.mentor_panel_media import _pair_video

    ctx = await C.pair_context(pair_id, actor, action="video")
    card = await C.match_card(ctx, match_id)
    await _pair_video(ctx, card["match_id"], video_id)
    return ctx, card["match_id"]


@router.put("/pairs/{pair_id}/matches/{match_id}/situations/{key}/time")
async def set_time(pair_id: str, match_id: str, key: str, body: TimeBody, actor: Actor = Depends(mentor_actor)):
    key = _key(key)
    ctx, mid = await _ctx(pair_id, match_id, body.video_id, actor)
    start, end = clean_range(body.start_s, body.end_s)
    where = ((mentor_situation_times.c.pair_id == ctx["pair_id"]) & (mentor_situation_times.c.match_id == mid)
             & (mentor_situation_times.c.video_id == body.video_id) & (mentor_situation_times.c.situation_key == key))
    found = await C.one(select(mentor_situation_times).where(where))
    values = {"start_s": start, "end_s": end, "updated_by": actor.judge_id, "updated_at": C.now()}
    if found:
        await database.execute(mentor_situation_times.update().where(where).values(**values))
    else:
        await database.execute(mentor_situation_times.insert().values(id=str(uuid.uuid4()), pair_id=ctx["pair_id"], match_id=mid,
                                                                      video_id=body.video_id, situation_key=key, **values))
    await C.touch(ctx, actor.judge_id, "situation_time_set", "videos", mid, {"key": key, "video_id": body.video_id})
    row = await C.one(select(mentor_situation_times).where(where))
    return shape(row, await C.people({actor.judge_id}))


@router.delete("/pairs/{pair_id}/matches/{match_id}/situations/{key}/time")
async def clear_time(pair_id: str, match_id: str, key: str, video_id: str = Query(..., min_length=1, max_length=80),
                     actor: Actor = Depends(mentor_actor)):
    key = _key(key)
    ctx, mid = await _ctx(pair_id, match_id, video_id, actor)
    await database.execute(mentor_situation_times.delete().where(mentor_situation_times.c.pair_id == ctx["pair_id"])
                           .where(mentor_situation_times.c.match_id == mid).where(mentor_situation_times.c.video_id == video_id)
                           .where(mentor_situation_times.c.situation_key == key))
    await C.touch(ctx, actor.judge_id, "situation_time_cleared", "videos", mid, {"key": key, "video_id": video_id})
    return {"ok": True}

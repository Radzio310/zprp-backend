"""Szkice ocen młodych sędziów na serwerze (dokończenie na innym urządzeniu).

Tylko autor (numer sędziego z tokenu) widzi i zmienia swoje szkice.
Tabela żyje w tym module (nie w db.py): zakładana przy imporcie, bo
`create_all` w db.py biegnie wcześniej, niż ten moduł dokłada schemat.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, String, Table, Text, delete, func, select

from app.db import database, engine, metadata
from app.deps import get_jwt_payload
from app.province_guard import actor_judge_id
from app.young_rating_drafts_rules import (
    clean_key,
    encode_payload,
    payload_dict,
)

young_rating_drafts = Table(
    "young_rating_drafts",
    metadata,
    Column("judge_id", String, primary_key=True),
    Column("draft_key", String, primary_key=True),
    #: Napis JSON - serwer go nie rozbiera (sterownik oddaje JSONB napisem).
    Column("payload", Text, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)
young_rating_drafts.create(engine, checkfirst=True)

router = APIRouter(prefix="/young_rating_drafts", tags=["young-rating-drafts"])


class DraftIn(BaseModel):
    key: str
    payload: dict[str, Any]


def _me(payload: Optional[dict]) -> str:
    judge = actor_judge_id(payload)
    if not judge:
        raise HTTPException(status_code=401, detail="Zaloguj się ponownie")
    return judge


def _out(row) -> dict:
    ts = row["updated_at"]
    return {
        "key": row["draft_key"],
        "payload": payload_dict(row["payload"]),
        "updated_at": ts.isoformat() if ts is not None else None,
    }


@router.get("")
async def get_drafts(key: Optional[str] = None, token: dict = Depends(get_jwt_payload)):
    """Bez `key`: wszystkie moje szkice. Z `key`: jeden (404, gdy brak)."""
    me = _me(token)
    t = young_rating_drafts
    if key is not None:
        k = clean_key(key)
        if not k:
            raise HTTPException(status_code=422, detail="Zły klucz szkicu")
        row = await database.fetch_one(
            select(t).where(t.c.judge_id == me, t.c.draft_key == k)
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Brak szkicu")
        return _out(row)
    rows = await database.fetch_all(
        select(t).where(t.c.judge_id == me).order_by(t.c.updated_at.desc()).limit(100)
    )
    return {"drafts": [_out(r) for r in rows]}


@router.put("")
async def put_draft(body: DraftIn, token: dict = Depends(get_jwt_payload)):
    me = _me(token)
    k = clean_key(body.key)
    text = encode_payload(body.payload)
    if not k or text is None:
        raise HTTPException(status_code=422, detail="Zły szkic")
    t = young_rating_drafts
    # Bez dialektowego upsertu: ten sam kod działa na Postgresie i SQLite w testach.
    async with database.transaction():
        n = await database.fetch_val(
            select(func.count()).select_from(t).where(t.c.judge_id == me, t.c.draft_key == k)
        )
        if n:
            await database.execute(
                t.update()
                .where(t.c.judge_id == me, t.c.draft_key == k)
                .values(payload=text, updated_at=func.now())
            )
        else:
            await database.execute(
                t.insert().values(judge_id=me, draft_key=k, payload=text)
            )
    return {"ok": True}


@router.delete("")
async def delete_draft(key: str, token: dict = Depends(get_jwt_payload)):
    me = _me(token)
    k = clean_key(key)
    if not k:
        raise HTTPException(status_code=422, detail="Zły klucz szkicu")
    t = young_rating_drafts
    await database.execute(delete(t).where(t.c.judge_id == me, t.c.draft_key == k))
    return {"ok": True}

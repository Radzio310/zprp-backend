# app/board.py
# Tablica Komisji Okręgowej — posty, zadania, członkowie, rankingi

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, insert, update, delete, case

from app.db import database, board_posts, board_tasks, board_members, board_rankings, board_events
from app.deps import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/board", tags=["Board"])

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _norm_province(p: str) -> str:
    return (p or "").strip().upper()


def _row_to_dict(row) -> dict:
    return dict(row._mapping)

# ---------------------------------------------------------------------------
# ── POSTS ──────────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class CreatePostRequest(BaseModel):
    province: str
    type: str = "announcement"   # announcement | decision | note | link
    title: Optional[str] = None
    content: Optional[str] = None
    url: Optional[str] = None
    author_id: Optional[str] = None
    author_name: Optional[str] = None
    pinned: bool = False


class UpdatePostRequest(BaseModel):
    type: Optional[str] = None
    title: Optional[str] = None
    content: Optional[str] = None
    url: Optional[str] = None
    author_name: Optional[str] = None
    pinned: Optional[bool] = None


@router.get("/posts")
async def list_posts(
    province: str = Query(...),
    _user: str = Depends(get_current_user),
):
    prov = _norm_province(province)
    stmt = (
        select(board_posts)
        .where(board_posts.c.province == prov)
        .order_by(board_posts.c.pinned.desc(), board_posts.c.created_at.desc())
    )
    rows = await database.fetch_all(stmt)
    return [_row_to_dict(r) for r in rows]


@router.post("/posts", status_code=201)
async def create_post(
    body: CreatePostRequest,
    _user: str = Depends(get_current_user),
):
    prov = _norm_province(body.province)
    stmt = insert(board_posts).values(
        province=prov,
        type=body.type,
        title=body.title,
        content=body.content,
        url=body.url,
        author_id=body.author_id,
        author_name=body.author_name,
        pinned=body.pinned,
    ).returning(board_posts)
    row = await database.fetch_one(stmt)
    return _row_to_dict(row)


@router.patch("/posts/{post_id}")
async def update_post(
    post_id: int,
    body: UpdatePostRequest,
    _user: str = Depends(get_current_user),
):
    values: dict[str, Any] = {}
    if body.type is not None:
        values["type"] = body.type
    if body.title is not None:
        values["title"] = body.title
    if body.content is not None:
        values["content"] = body.content
    if body.url is not None:
        values["url"] = body.url
    if body.author_name is not None:
        values["author_name"] = body.author_name
    if body.pinned is not None:
        values["pinned"] = body.pinned
    if not values:
        raise HTTPException(status_code=400, detail="Brak pól do aktualizacji")

    stmt = (
        update(board_posts)
        .where(board_posts.c.id == post_id)
        .values(**values)
        .returning(board_posts)
    )
    row = await database.fetch_one(stmt)
    if row is None:
        raise HTTPException(status_code=404, detail="Post nie istnieje")
    return _row_to_dict(row)


@router.delete("/posts/{post_id}", status_code=204)
async def delete_post(
    post_id: int,
    _user: str = Depends(get_current_user),
):
    stmt = delete(board_posts).where(board_posts.c.id == post_id)
    await database.execute(stmt)


class ReorderPostsRequest(BaseModel):
    ordered_ids: List[int]  # IDs w nowej kolejności (od indeksu 0)


@router.post("/posts/reorder", status_code=200)
async def reorder_posts(
    body: ReorderPostsRequest,
    _user: str = Depends(get_current_user),
):
    for idx, post_id in enumerate(body.ordered_ids):
        await database.execute(
            update(board_posts)
            .where(board_posts.c.id == post_id)
            .values(order_index=idx)
        )
    return {"ok": True}

# ---------------------------------------------------------------------------
# ── TASKS ──────────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class CreateTaskRequest(BaseModel):
    province: str
    title: str
    description: Optional[str] = None
    status: str = "todo"          # todo | in_progress | done
    priority: Optional[str] = None  # low | medium | high
    assignee_ids: List[str] = []
    due_date: Optional[str] = None  # YYYY-MM-DD
    order_index: int = 0


class UpdateTaskRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    assignee_ids: Optional[List[str]] = None
    due_date: Optional[str] = None
    order_index: Optional[int] = None


@router.get("/tasks")
async def list_tasks(
    province: str = Query(...),
    _user: str = Depends(get_current_user),
):
    prov = _norm_province(province)
    stmt = (
        select(board_tasks)
        .where(board_tasks.c.province == prov)
        .order_by(board_tasks.c.status, board_tasks.c.order_index, board_tasks.c.created_at)
    )
    rows = await database.fetch_all(stmt)
    return [_row_to_dict(r) for r in rows]


@router.post("/tasks", status_code=201)
async def create_task(
    body: CreateTaskRequest,
    _user: str = Depends(get_current_user),
):
    prov = _norm_province(body.province)
    stmt = insert(board_tasks).values(
        province=prov,
        title=body.title,
        description=body.description,
        status=body.status,
        priority=body.priority,
        assignee_ids=body.assignee_ids,
        due_date=body.due_date,
        order_index=body.order_index,
    ).returning(board_tasks)
    row = await database.fetch_one(stmt)
    return _row_to_dict(row)


@router.patch("/tasks/{task_id}")
async def update_task(
    task_id: int,
    body: UpdateTaskRequest,
    _user: str = Depends(get_current_user),
):
    values: dict[str, Any] = {}
    if body.title is not None:
        values["title"] = body.title
    if body.description is not None:
        values["description"] = body.description
    if body.status is not None:
        values["status"] = body.status
    if body.priority is not None:
        values["priority"] = body.priority
    if body.assignee_ids is not None:
        values["assignee_ids"] = body.assignee_ids
    if body.due_date is not None:
        values["due_date"] = body.due_date
    if body.order_index is not None:
        values["order_index"] = body.order_index
    if not values:
        raise HTTPException(status_code=400, detail="Brak pól do aktualizacji")

    stmt = (
        update(board_tasks)
        .where(board_tasks.c.id == task_id)
        .values(**values)
        .returning(board_tasks)
    )
    row = await database.fetch_one(stmt)
    if row is None:
        raise HTTPException(status_code=404, detail="Zadanie nie istnieje")
    return _row_to_dict(row)


@router.delete("/tasks/{task_id}", status_code=204)
async def delete_task(
    task_id: int,
    _user: str = Depends(get_current_user),
):
    stmt = delete(board_tasks).where(board_tasks.c.id == task_id)
    await database.execute(stmt)

# ---------------------------------------------------------------------------
# ── MEMBERS ────────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class CreateMemberRequest(BaseModel):
    province: str
    name: str
    judge_id: Optional[str] = None
    role: Optional[str] = None    # Przewodniczący | Sekretarz | Członek itp.
    icon: Optional[str] = None    # Ionicons name, np. "person-outline"
    color: Optional[str] = None   # kolor hex, np. "#D7C2A6"


class UpdateMemberRequest(BaseModel):
    name: Optional[str] = None
    judge_id: Optional[str] = None
    role: Optional[str] = None
    icon: Optional[str] = None
    color: Optional[str] = None


@router.get("/members")
async def list_members(
    province: str = Query(...),
    _user: str = Depends(get_current_user),
):
    prov = _norm_province(province)
    stmt = (
        select(board_members)
        .where(board_members.c.province == prov)
        .order_by(board_members.c.created_at)
    )
    rows = await database.fetch_all(stmt)
    return [_row_to_dict(r) for r in rows]


@router.post("/members", status_code=201)
async def create_member(
    body: CreateMemberRequest,
    _user: str = Depends(get_current_user),
):
    prov = _norm_province(body.province)
    stmt = insert(board_members).values(
        province=prov,
        name=body.name,
        judge_id=body.judge_id,
        role=body.role,
        icon=body.icon,
        color=body.color,
    ).returning(board_members)
    row = await database.fetch_one(stmt)
    return _row_to_dict(row)


@router.patch("/members/{member_id}")
async def update_member(
    member_id: int,
    body: UpdateMemberRequest,
    _user: str = Depends(get_current_user),
):
    values: dict[str, Any] = {}
    if body.name is not None:
        values["name"] = body.name
    if body.judge_id is not None:
        values["judge_id"] = body.judge_id
    if body.role is not None:
        values["role"] = body.role
    if body.icon is not None:
        values["icon"] = body.icon
    if body.color is not None:
        values["color"] = body.color
    if not values:
        raise HTTPException(status_code=400, detail="Brak pól do aktualizacji")

    stmt = (
        update(board_members)
        .where(board_members.c.id == member_id)
        .values(**values)
        .returning(board_members)
    )
    row = await database.fetch_one(stmt)
    if row is None:
        raise HTTPException(status_code=404, detail="Członek nie istnieje")
    return _row_to_dict(row)


@router.delete("/members/{member_id}", status_code=204)
async def delete_member(
    member_id: int,
    _user: str = Depends(get_current_user),
):
    stmt = delete(board_members).where(board_members.c.id == member_id)
    await database.execute(stmt)

# ---------------------------------------------------------------------------
# ── RANKINGS ───────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class RankingRow(BaseModel):
    pos: int
    name: str
    score: str = ""
    note: str = ""


class CreateRankingRequest(BaseModel):
    province: str
    title: str
    rows: List[RankingRow] = []


class UpdateRankingRequest(BaseModel):
    title: Optional[str] = None
    rows: Optional[List[RankingRow]] = None


@router.get("/rankings")
async def list_rankings(
    province: str = Query(...),
    _user: str = Depends(get_current_user),
):
    prov = _norm_province(province)
    stmt = (
        select(board_rankings)
        .where(board_rankings.c.province == prov)
        .order_by(board_rankings.c.created_at)
    )
    rows = await database.fetch_all(stmt)
    return [_row_to_dict(r) for r in rows]


@router.post("/rankings", status_code=201)
async def create_ranking(
    body: CreateRankingRequest,
    _user: str = Depends(get_current_user),
):
    prov = _norm_province(body.province)
    rows_data = [r.model_dump() for r in body.rows]
    stmt = insert(board_rankings).values(
        province=prov,
        title=body.title,
        rows_json=rows_data,
    ).returning(board_rankings)
    row = await database.fetch_one(stmt)
    return _row_to_dict(row)


@router.patch("/rankings/{ranking_id}")
async def update_ranking(
    ranking_id: int,
    body: UpdateRankingRequest,
    _user: str = Depends(get_current_user),
):
    values: dict[str, Any] = {}
    if body.title is not None:
        values["title"] = body.title
    if body.rows is not None:
        values["rows_json"] = [r.model_dump() for r in body.rows]
    if not values:
        raise HTTPException(status_code=400, detail="Brak pól do aktualizacji")

    stmt = (
        update(board_rankings)
        .where(board_rankings.c.id == ranking_id)
        .values(**values)
        .returning(board_rankings)
    )
    row = await database.fetch_one(stmt)
    if row is None:
        raise HTTPException(status_code=404, detail="Ranking nie istnieje")
    return _row_to_dict(row)


@router.delete("/rankings/{ranking_id}", status_code=204)
async def delete_ranking(
    ranking_id: int,
    _user: str = Depends(get_current_user),
):
    stmt = delete(board_rankings).where(board_rankings.c.id == ranking_id)
    await database.execute(stmt)

# ---------------------------------------------------------------------------
# ── EVENTS (Kalendarz) ─────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class CreateEventRequest(BaseModel):
    province: str
    title: str
    description: Optional[str] = None
    date: str                         # YYYY-MM-DD
    time_start: Optional[str] = None  # HH:MM
    time_end: Optional[str] = None    # HH:MM
    location: Optional[str] = None
    priority: Optional[str] = None    # low | medium | high
    color: Optional[str] = None       # hex
    assignee_id: Optional[int] = None # board_member id


class UpdateEventRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    date: Optional[str] = None
    time_start: Optional[str] = None
    time_end: Optional[str] = None
    location: Optional[str] = None
    priority: Optional[str] = None
    color: Optional[str] = None
    assignee_id: Optional[int] = None


@router.get("/events")
async def list_events(
    province: str = Query(...),
    month: Optional[str] = Query(default=None),  # YYYY-MM — filtr miesiąca
    _user: str = Depends(get_current_user),
):
    prov = _norm_province(province)
    stmt = (
        select(board_events)
        .where(board_events.c.province == prov)
        .order_by(board_events.c.date, board_events.c.time_start)
    )
    rows = await database.fetch_all(stmt)
    result = [_row_to_dict(r) for r in rows]
    if month:
        result = [r for r in result if r["date"].startswith(month)]
    return result


@router.post("/events", status_code=201)
async def create_event(
    body: CreateEventRequest,
    _user: str = Depends(get_current_user),
):
    prov = _norm_province(body.province)
    stmt = insert(board_events).values(
        province=prov,
        title=body.title,
        description=body.description,
        date=body.date,
        time_start=body.time_start,
        time_end=body.time_end,
        location=body.location,
        priority=body.priority,
        color=body.color,
        assignee_id=body.assignee_id,
    ).returning(board_events)
    row = await database.fetch_one(stmt)
    return _row_to_dict(row)


@router.patch("/events/{event_id}")
async def update_event(
    event_id: int,
    body: UpdateEventRequest,
    _user: str = Depends(get_current_user),
):
    values: dict[str, Any] = {}
    for field in ("title", "description", "date", "time_start", "time_end",
                  "location", "priority", "color", "assignee_id"):
        v = getattr(body, field)
        if v is not None:
            values[field] = v
    if not values:
        raise HTTPException(status_code=400, detail="Brak pól do aktualizacji")

    stmt = (
        update(board_events)
        .where(board_events.c.id == event_id)
        .values(**values)
        .returning(board_events)
    )
    row = await database.fetch_one(stmt)
    if row is None:
        raise HTTPException(status_code=404, detail="Wydarzenie nie istnieje")
    return _row_to_dict(row)


@router.delete("/events/{event_id}", status_code=204)
async def delete_event(
    event_id: int,
    _user: str = Depends(get_current_user),
):
    stmt = delete(board_events).where(board_events.c.id == event_id)
    await database.execute(stmt)

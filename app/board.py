# app/board.py
"""
Tablica Komisji Okręgowej (BAZA_web) - wpisy, zadania, kalendarz, skład komisji,
komentarze, załączniki, oś zdarzeń i kosz.

Przebudowa z 16.09.2026, decyzje użytkownika (reguły w `app/board_rules.py`):
  - tablicę okręgu czyta i edytuje TYLKO komisja tego okręgu: sędzia z odznaką
    „Komisja Sędziowska”, osoba dopisana ręcznie, VIP okręgu z uprawnieniem
    tablicy i admin BAZY. Tożsamość wyłącznie z tokenu,
  - skład komisji wynika z odznak; opis, rolę i wygląd edytuje się ręcznie,
  - usuwanie od razu, z koszem na 30 dni (`deleted_at`),
  - każda zmiana trafia na oś zdarzeń (`board_activity`), a najwyższe `id`
    okręgu jest wersją tablicy - z niej odświeżanie na żywo,
  - Rankingi zniknęły z ekranu; trasy zostają, ale też tylko dla komisji.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, func, insert, select, update

from app import board_rules as B
from app.admin_alerts import admin_judge_ids
from app.db import (
    baza_vips,
    board_activity,
    board_attachments,
    board_comments,
    board_events,
    board_members,
    board_posts,
    board_rankings,
    board_tasks,
    board_visits,
    database,
    province_judges,
)
from app.deps import get_jwt_payload
from app.settlement_province import canonical, display, spellings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/board", tags=["Board"])

#: Wiersze w jednej porcji osi zdarzeń.
ACTIVITY_PAGE = 40
#: Zdarzenia, które podbijają wersję tablicy (odświeżanie na żywo), ale nie
#: trafiają na oś: przestawienie kolejności i poprawka komentarza.
QUIET_ACTIONS = ("reordered", "touched")
#: Kosz czyścimy najwyżej raz na godzinę na okręg - przy okazji migawki.
PURGE_EVERY_S = 3600

_member_locks: Dict[str, asyncio.Lock] = {}
_last_purge: Dict[str, float] = {}


# ---------------------------------------------------------------------------
# Pomocnicze
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _norm_province(value: str) -> str:
    return display(value)


def _json(value: Any, fallback: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return fallback
    return fallback if value is None else value


def _row(row: Any) -> Dict[str, Any]:
    data = dict(row._mapping) if hasattr(row, "_mapping") else dict(row)
    data.pop("data", None)
    if "checklist" in data:
        data["checklist"] = _json(data["checklist"], [])
    if "details_json" in data:
        data["details_json"] = _json(data["details_json"], {})
    if "rows_json" in data:
        data["rows_json"] = _json(data["rows_json"], [])
    if "assignee_ids" in data:
        data["assignee_ids"] = [str(item) for item in (data["assignee_ids"] or [])]
    return data


def _bad(error: B.Invalid) -> HTTPException:
    return HTTPException(status_code=400, detail=str(error))


def _live(table):
    return table.c.deleted_at.is_(None)


# ---------------------------------------------------------------------------
# Tożsamość i dostęp
# ---------------------------------------------------------------------------


async def _actor(payload: dict) -> B.Actor:
    judge_id = _s(payload.get("judge_id"))
    name = ""
    if judge_id:
        row = await database.fetch_one(
            select(province_judges.c.full_name).where(province_judges.c.judge_id == judge_id)
        )
        name = _s(row["full_name"]) if row else ""
    actor = B.actor_from_payload(payload, judge_name=name)
    if actor is None:
        raise HTTPException(status_code=403, detail=B.NO_ACCESS_ACCOUNT)
    return actor


async def _verdict(actor: B.Actor, province: str) -> Dict[str, Any]:
    prov = _norm_province(province)
    if actor.is_org:
        row = await database.fetch_one(
            select(baza_vips.c.province, baza_vips.c.permissions_json).where(
                baza_vips.c.username == actor.key[len("org:"):]
            )
        )
        return B.resolve_access(
            is_org=True,
            is_judge=False,
            vip_same_province=bool(row and canonical(row["province"]) and canonical(row["province"]) == canonical(prov)),
            vip_permissions_raw=row["permissions_json"] if row else None,
        )
    if actor.judge_id in await admin_judge_ids():
        return B.resolve_access(is_org=False, is_judge=True, is_admin=True)
    judge = await database.fetch_one(
        select(province_judges.c.badges).where(
            and_(
                province_judges.c.judge_id == actor.judge_id,
                province_judges.c.province.in_(spellings(prov)),
            )
        )
    )
    manual = await database.fetch_one(
        select(board_members.c.id).where(
            and_(
                board_members.c.province.in_(spellings(prov)),
                board_members.c.judge_id == actor.judge_id,
                board_members.c.source == "manual",
                _live(board_members),
            )
        )
    )
    return B.resolve_access(
        is_org=False,
        is_judge=True,
        has_badge=bool(judge and B.has_committee_badge(judge["badges"])),
        manual_member=manual is not None,
    )


async def _require(payload: dict, province: str) -> B.Actor:
    """Aktor z dostępem do tablicy okręgu albo 403 z powodem."""
    actor = await _actor(payload)
    verdict = await _verdict(actor, province)
    if not verdict["can_write"]:
        raise HTTPException(status_code=403, detail=verdict["reason"])
    return actor


async def _log(
    province: str,
    actor: Optional[B.Actor],
    action: str,
    target_type: str,
    target_id: Optional[int],
    title: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Wpis na oś zdarzeń. Nieudany zapis historii nie wywraca samej zmiany."""
    try:
        await database.execute(
            insert(board_activity).values(
                province=_norm_province(province),
                actor_key=actor.key if actor else None,
                actor_name=actor.name if actor else None,
                action=action,
                target_type=target_type,
                target_id=target_id,
                title=(title or "")[:200] or None,
                details_json=details or {},
                created_at=_now(),
            )
        )
    except Exception:  # noqa: BLE001
        logger.warning("[board] zapis osi zdarzeń nieudany", exc_info=True)


async def _version(province: str) -> int:
    row = await database.fetch_one(
        select(func.max(board_activity.c.id).label("v")).where(board_activity.c.province.in_(spellings(province)))
    )
    return int(row["v"] or 0) if row else 0


async def _owned(table, item_id: int, label: str) -> Dict[str, Any]:
    row = await database.fetch_one(select(table).where(table.c.id == item_id))
    if row is None or row["deleted_at"] is not None:
        raise HTTPException(status_code=404, detail=f"{label} nie istnieje albo leży w koszu")
    return dict(row._mapping)


@router.get("/access")
async def check_board_access(province: str = Query(...), payload: dict = Depends(get_jwt_payload)):
    """Werdykt dla kafla i ekranu: `can_read`, `can_write`, `role`, `reason`."""
    try:
        actor = await _actor(payload)
    except HTTPException as error:
        return {"can_read": False, "can_write": False, "role": None, "reason": error.detail}
    verdict = await _verdict(actor, province)
    return {**verdict, "user_key": actor.key, "user_name": actor.name}


# ---------------------------------------------------------------------------
# Skład komisji z odznak
# ---------------------------------------------------------------------------


async def _sync_members(province: str) -> None:
    prov = _norm_province(province)
    lock = _member_locks.setdefault(canonical(prov) or prov, asyncio.Lock())
    async with lock:
        judges = await database.fetch_all(
            select(province_judges.c.judge_id, province_judges.c.full_name, province_judges.c.badges).where(
                province_judges.c.province.in_(spellings(prov))
            )
        )
        badge_judges = [dict(row._mapping) for row in judges if B.has_committee_badge(row["badges"])]
        rows = await database.fetch_all(
            select(board_members.c.id, board_members.c.judge_id, board_members.c.source, board_members.c.active).where(
                and_(board_members.c.province.in_(spellings(prov)), _live(board_members))
            )
        )
        plan = B.plan_member_sync(badge_judges, [dict(row._mapping) for row in rows])
        for item in plan.inserts:
            inserted = await database.fetch_one(
                insert(board_members)
                .values(
                    province=prov, judge_id=item["judge_id"], name=item["name"], source="badge", active=True,
                    created_at=_now(), updated_at=_now(),
                )
                .returning(board_members.c.id)
            )
            await _log(prov, None, "joined", "member", int(inserted["id"]) if inserted else None, item["name"])
        if plan.activate:
            await database.execute(
                update(board_members).where(board_members.c.id.in_(plan.activate)).values(active=True, updated_at=_now())
            )
        if plan.deactivate:
            await database.execute(
                update(board_members).where(board_members.c.id.in_(plan.deactivate)).values(active=False, updated_at=_now())
            )
            for member_id in plan.deactivate:
                await _log(prov, None, "left", "member", member_id)


async def _members(province: str) -> List[Dict[str, Any]]:
    prov = _norm_province(province)
    rows = await database.fetch_all(
        select(board_members)
        .where(and_(board_members.c.province.in_(spellings(prov)), _live(board_members)))
        .order_by(board_members.c.created_at, board_members.c.id)
    )
    members = [_row(row) for row in B.dedupe_members([dict(row._mapping) for row in rows])]
    judge_ids = [m["judge_id"] for m in members if m.get("judge_id")]
    photos: Dict[str, Tuple[str, bool]] = {}
    if judge_ids:
        for row in await database.fetch_all(
            select(province_judges.c.judge_id, province_judges.c.photo_url, province_judges.c.badges).where(
                province_judges.c.judge_id.in_(judge_ids)
            )
        ):
            photos[_s(row["judge_id"])] = (_s(row["photo_url"]), B.has_committee_badge(row["badges"]))
    for member in members:
        photo, badge = photos.get(_s(member.get("judge_id")), ("", False))
        member["photo_url"] = photo or None
        member["has_badge"] = badge
    return members


# ---------------------------------------------------------------------------
# Migawka, wersja, wizyta, oś zdarzeń
# ---------------------------------------------------------------------------


async def _purge(province: str) -> None:
    """Czyści kosz starszy niż 30 dni - najwyżej raz na godzinę na okręg."""
    key = canonical(province) or province
    if time.monotonic() - _last_purge.get(key, 0.0) < PURGE_EVERY_S:
        return
    _last_purge[key] = time.monotonic()
    cutoff = B.trash_cutoff(_now())
    names = spellings(province)
    try:
        gone = await database.fetch_all(
            select(board_members.c.id).where(
                and_(board_members.c.province.in_(names), board_members.c.deleted_at < cutoff)
            )
        )
        for row in gone:
            await _forget_member(province, int(row["id"]))
        for table in (board_posts, board_tasks, board_events, board_members, board_comments, board_attachments):
            await database.execute(delete(table).where(and_(table.c.province.in_(names), table.c.deleted_at < cutoff)))
    except Exception:  # noqa: BLE001
        logger.warning("[board] czyszczenie kosza nieudane", exc_info=True)


async def _forget_member(province: str, member_id: int) -> None:
    """Członek usunięty na zawsze nie zostaje „duchem” w zadaniach i wydarzeniach."""
    names = spellings(province)
    key = str(member_id)
    for task in await database.fetch_all(
        select(board_tasks.c.id, board_tasks.c.assignee_ids).where(board_tasks.c.province.in_(names))
    ):
        assignees = [str(item) for item in (task["assignee_ids"] or [])]
        if key in assignees:
            await database.execute(
                update(board_tasks).where(board_tasks.c.id == task["id"]).values(
                    assignee_ids=[item for item in assignees if item != key]
                )
            )
    await database.execute(
        update(board_events)
        .where(and_(board_events.c.province.in_(names), board_events.c.assignee_id == member_id))
        .values(assignee_id=None)
    )


@router.get("/snapshot")
async def snapshot(province: str = Query(...), payload: dict = Depends(get_jwt_payload)):
    """Cała tablica jednym zapytaniem - pierwsze wejście i odświeżanie na żywo."""
    actor = await _require(payload, province)
    prov = _norm_province(province)
    names = spellings(prov)
    await _purge(prov)
    await _sync_members(prov)

    posts = await database.fetch_all(
        select(board_posts)
        .where(and_(board_posts.c.province.in_(names), _live(board_posts)))
        .order_by(board_posts.c.pinned.desc(), board_posts.c.order_index, board_posts.c.created_at.desc())
    )
    tasks = await database.fetch_all(
        select(board_tasks)
        .where(and_(board_tasks.c.province.in_(names), _live(board_tasks)))
        .order_by(board_tasks.c.status, board_tasks.c.order_index, board_tasks.c.id)
    )
    events = await database.fetch_all(
        select(board_events)
        .where(and_(board_events.c.province.in_(names), _live(board_events)))
        .order_by(board_events.c.date, board_events.c.time_start)
    )
    counts = await database.fetch_all(
        select(board_comments.c.target_type, board_comments.c.target_id, func.count().label("n"))
        .where(and_(board_comments.c.province.in_(names), _live(board_comments)))
        .group_by(board_comments.c.target_type, board_comments.c.target_id)
    )
    files = await database.fetch_all(
        select(
            board_attachments.c.id,
            board_attachments.c.target_type,
            board_attachments.c.target_id,
            board_attachments.c.name,
            board_attachments.c.mime,
            board_attachments.c.size,
            board_attachments.c.uploaded_by_name,
            board_attachments.c.created_at,
        )
        .where(
            and_(
                board_attachments.c.province.in_(names),
                _live(board_attachments),
                board_attachments.c.target_type.in_(("post", "task")),
            )
        )
        .order_by(board_attachments.c.id)
    )
    attachments: Dict[str, List[Dict[str, Any]]] = {}
    for row in files:
        attachments.setdefault(f"{row['target_type']}:{row['target_id']}", []).append(_row(row))

    members = await _members(prov)
    verdict = await _verdict(actor, prov)
    me_member = next(
        (m for m in members if actor.judge_id and _s(m.get("judge_id")) == actor.judge_id and m.get("active")),
        None,
    )
    return {
        "province": prov,
        "access": verdict,
        "me": {
            "key": actor.key,
            "name": actor.name,
            "judge_id": actor.judge_id or None,
            "member_id": me_member["id"] if me_member else None,
            "role": verdict.get("role"),
        },
        "posts": [_row(row) for row in posts],
        "tasks": [_row(row) for row in tasks],
        "events": [_row(row) for row in events],
        "members": members,
        "comment_counts": {f"{row['target_type']}:{row['target_id']}": int(row["n"]) for row in counts},
        "attachments": attachments,
        "version": await _version(prov),
        "server_time": _now().isoformat(),
    }


@router.get("/version")
async def version(province: str = Query(...), payload: dict = Depends(get_jwt_payload)):
    """Tanie pytanie „czy coś się zmieniło” dla odświeżania na żywo."""
    await _require(payload, province)
    return {"version": await _version(_norm_province(province))}


class VisitRequest(BaseModel):
    province: str


@router.post("/visit")
async def visit(body: VisitRequest, payload: dict = Depends(get_jwt_payload)):
    """Zapisuje wizytę i oddaje poprzednią - z niej „nowe od ostatniej wizyty”."""
    actor = await _require(payload, body.province)
    prov = _norm_province(body.province)
    key = canonical(prov) or prov
    previous = await database.fetch_one(
        select(board_visits.c.seen_at).where(and_(board_visits.c.province == key, board_visits.c.user_key == actor.key))
    )
    now = _now()
    if previous:
        await database.execute(
            update(board_visits)
            .where(and_(board_visits.c.province == key, board_visits.c.user_key == actor.key))
            .values(seen_at=now)
        )
    else:
        await database.execute(insert(board_visits).values(province=key, user_key=actor.key, seen_at=now))
    return {"previous_seen_at": previous["seen_at"].isoformat() if previous else None, "seen_at": now.isoformat()}


@router.get("/activity")
async def activity(
    province: str = Query(...),
    before: Optional[int] = Query(None),
    limit: int = Query(ACTIVITY_PAGE, ge=1, le=100),
    payload: dict = Depends(get_jwt_payload),
):
    await _require(payload, province)
    prov = _norm_province(province)
    conditions = [board_activity.c.province.in_(spellings(prov)), board_activity.c.action.not_in(QUIET_ACTIONS)]
    if before:
        conditions.append(board_activity.c.id < before)
    rows = await database.fetch_all(
        select(board_activity).where(and_(*conditions)).order_by(board_activity.c.id.desc()).limit(limit)
    )
    items = [_row(row) for row in rows]
    return {"items": items, "next_before": items[-1]["id"] if len(items) == limit else None}


# ---------------------------------------------------------------------------
# Wpisy
# ---------------------------------------------------------------------------


class CreatePostRequest(BaseModel):
    province: str
    type: str = "announcement"
    title: Optional[str] = None
    content: Optional[str] = None
    url: Optional[str] = None
    pinned: bool = False


class UpdatePostRequest(BaseModel):
    type: Optional[str] = None
    title: Optional[str] = None
    content: Optional[str] = None
    url: Optional[str] = None
    pinned: Optional[bool] = None


def _post_values(body: BaseModel, *, partial: bool) -> Dict[str, Any]:
    fields = body.model_fields_set if partial else set(type(body).model_fields)
    values: Dict[str, Any] = {}
    if "type" in fields and getattr(body, "type", None) is not None:
        values["type"] = B.clean_choice(body.type, B.POST_TYPES, "rodzaj wpisu", nullable=False)
    if "title" in fields:
        values["title"] = B.clean_title(body.title, required=False)
    if "content" in fields:
        values["content"] = B.clean_text(body.content)
    if "url" in fields:
        values["url"] = B.clean_url(body.url)
    if "pinned" in fields and getattr(body, "pinned", None) is not None:
        values["pinned"] = bool(body.pinned)
    return values


@router.get("/posts")
async def list_posts(province: str = Query(...), payload: dict = Depends(get_jwt_payload)):
    await _require(payload, province)
    rows = await database.fetch_all(
        select(board_posts)
        .where(and_(board_posts.c.province.in_(spellings(_norm_province(province))), _live(board_posts)))
        .order_by(board_posts.c.pinned.desc(), board_posts.c.order_index, board_posts.c.created_at.desc())
    )
    return [_row(row) for row in rows]


@router.post("/posts", status_code=201)
async def create_post(body: CreatePostRequest, payload: dict = Depends(get_jwt_payload)):
    actor = await _require(payload, body.province)
    prov = _norm_province(body.province)
    try:
        values = _post_values(body, partial=False)
    except B.Invalid as error:
        raise _bad(error)
    if not (values.get("title") or values.get("content") or values.get("url")):
        raise HTTPException(status_code=400, detail="Wpis potrzebuje tytułu, treści albo linku")
    first = await database.fetch_one(
        select(func.min(board_posts.c.order_index).label("m")).where(
            and_(board_posts.c.province.in_(spellings(prov)), _live(board_posts))
        )
    )
    now = _now()
    row = await database.fetch_one(
        insert(board_posts)
        .values(
            province=prov,
            author_id=actor.judge_id or actor.key,
            author_name=actor.name,
            order_index=int(first["m"]) - 1 if first and first["m"] is not None else 0,
            created_at=now,
            updated_at=now,
            **values,
        )
        .returning(board_posts)
    )
    item = _row(row)
    await _log(prov, actor, "created", "post", item["id"], item.get("title") or (item.get("content") or "")[:80], {"type": item["type"]})
    return item


@router.patch("/posts/{post_id}")
async def update_post(post_id: int, body: UpdatePostRequest, payload: dict = Depends(get_jwt_payload)):
    existing = await _owned(board_posts, post_id, "Wpis")
    actor = await _require(payload, existing["province"])
    try:
        values = _post_values(body, partial=True)
    except B.Invalid as error:
        raise _bad(error)
    if not values:
        raise HTTPException(status_code=400, detail="Brak pól do zmiany")
    row = await database.fetch_one(
        update(board_posts).where(board_posts.c.id == post_id).values(updated_at=_now(), **values).returning(board_posts)
    )
    item = _row(row)
    action = "pinned" if set(values) == {"pinned"} and values["pinned"] else "unpinned" if set(values) == {"pinned"} else "updated"
    await _log(existing["province"], actor, action, "post", post_id, item.get("title") or (item.get("content") or "")[:80])
    return item


@router.delete("/posts/{post_id}", status_code=204)
async def delete_post(post_id: int, payload: dict = Depends(get_jwt_payload)):
    existing = await _owned(board_posts, post_id, "Wpis")
    actor = await _require(payload, existing["province"])
    await database.execute(update(board_posts).where(board_posts.c.id == post_id).values(deleted_at=_now()))
    await _log(existing["province"], actor, "deleted", "post", post_id, existing.get("title") or (existing.get("content") or "")[:80])


class ReorderPostsRequest(BaseModel):
    ordered_ids: List[int]


@router.post("/posts/reorder", status_code=200)
async def reorder_posts(body: ReorderPostsRequest, payload: dict = Depends(get_jwt_payload)):
    if not body.ordered_ids:
        return {"ok": True}
    rows = await database.fetch_all(
        select(board_posts.c.id, board_posts.c.province).where(
            and_(board_posts.c.id.in_(body.ordered_ids), _live(board_posts))
        )
    )
    if len(rows) != len(set(body.ordered_ids)):
        raise HTTPException(status_code=404, detail="Część wpisów już nie istnieje - odśwież tablicę")
    provinces = {canonical(row["province"]) for row in rows}
    if len(provinces) != 1:
        raise HTTPException(status_code=400, detail="Nie można mieszać wpisów z różnych okręgów")
    province = rows[0]["province"]
    actor = await _require(payload, province)
    async with database.transaction():
        for index, post_id in enumerate(body.ordered_ids):
            await database.execute(update(board_posts).where(board_posts.c.id == post_id).values(order_index=index))
    await _log(province, actor, "reordered", "post", None)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Zadania
# ---------------------------------------------------------------------------


class ChecklistItem(BaseModel):
    id: str = ""
    text: str
    done: bool = False


class CreateTaskRequest(BaseModel):
    province: str
    title: str
    description: Optional[str] = None
    status: str = "todo"
    priority: Optional[str] = None
    assignee_ids: List[str] = Field(default_factory=list)
    due_date: Optional[str] = None
    checklist: List[ChecklistItem] = Field(default_factory=list)


class UpdateTaskRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    assignee_ids: Optional[List[str]] = None
    due_date: Optional[str] = None
    order_index: Optional[int] = None
    checklist: Optional[List[ChecklistItem]] = None


async def _clean_assignees(province: str, ids: List[str]) -> List[str]:
    wanted = [_s(item) for item in ids if _s(item).isdigit()]
    if not wanted:
        return []
    rows = await database.fetch_all(
        select(board_members.c.id).where(
            and_(
                board_members.c.province.in_(spellings(province)),
                board_members.c.id.in_([int(item) for item in wanted]),
                _live(board_members),
            )
        )
    )
    known = {str(row["id"]) for row in rows}
    out: List[str] = []
    for item in wanted:
        if item in known and item not in out:
            out.append(item)
    return out


@router.get("/tasks")
async def list_tasks(province: str = Query(...), payload: dict = Depends(get_jwt_payload)):
    await _require(payload, province)
    rows = await database.fetch_all(
        select(board_tasks)
        .where(and_(board_tasks.c.province.in_(spellings(_norm_province(province))), _live(board_tasks)))
        .order_by(board_tasks.c.status, board_tasks.c.order_index, board_tasks.c.id)
    )
    return [_row(row) for row in rows]


@router.post("/tasks", status_code=201)
async def create_task(body: CreateTaskRequest, payload: dict = Depends(get_jwt_payload)):
    actor = await _require(payload, body.province)
    prov = _norm_province(body.province)
    try:
        title = B.clean_title(body.title, required=True)
        status = B.clean_choice(body.status, B.TASK_STATUSES, "status", nullable=False)
        priority = B.clean_choice(body.priority, B.PRIORITIES, "priorytet")
        description = B.clean_text(body.description)
        due_date = B.clean_date(body.due_date)
        checklist = B.clean_checklist([item.model_dump() for item in body.checklist])
    except B.Invalid as error:
        raise _bad(error)
    first = await database.fetch_one(
        select(func.min(board_tasks.c.order_index).label("m")).where(
            and_(board_tasks.c.province.in_(spellings(prov)), board_tasks.c.status == status, _live(board_tasks))
        )
    )
    now = _now()
    row = await database.fetch_one(
        insert(board_tasks)
        .values(
            province=prov,
            title=title,
            description=description,
            status=status,
            priority=priority,
            assignee_ids=await _clean_assignees(prov, body.assignee_ids),
            due_date=due_date,
            order_index=int(first["m"]) - 1 if first and first["m"] is not None else 0,
            checklist=checklist,
            created_by=actor.key,
            created_by_name=actor.name,
            completed_at=now if status == "done" else None,
            created_at=now,
            updated_at=now,
        )
        .returning(board_tasks)
    )
    item = _row(row)
    await _log(prov, actor, "created", "task", item["id"], item["title"], {"status": status})
    return item


@router.patch("/tasks/{task_id}")
async def update_task(task_id: int, body: UpdateTaskRequest, payload: dict = Depends(get_jwt_payload)):
    existing = await _owned(board_tasks, task_id, "Zadanie")
    actor = await _require(payload, existing["province"])
    fields = body.model_fields_set
    values: Dict[str, Any] = {}
    try:
        if "title" in fields and body.title is not None:
            values["title"] = B.clean_title(body.title, required=True)
        if "description" in fields:
            values["description"] = B.clean_text(body.description)
        if "status" in fields and body.status is not None:
            values["status"] = B.clean_choice(body.status, B.TASK_STATUSES, "status", nullable=False)
        if "priority" in fields:
            values["priority"] = B.clean_choice(body.priority, B.PRIORITIES, "priorytet")
        if "due_date" in fields:
            values["due_date"] = B.clean_date(body.due_date)
        if "checklist" in fields and body.checklist is not None:
            values["checklist"] = B.clean_checklist([item.model_dump() for item in body.checklist])
        if "order_index" in fields and body.order_index is not None:
            values["order_index"] = int(body.order_index)
    except B.Invalid as error:
        raise _bad(error)
    if "assignee_ids" in fields and body.assignee_ids is not None:
        values["assignee_ids"] = await _clean_assignees(existing["province"], body.assignee_ids)
    if not values:
        raise HTTPException(status_code=400, detail="Brak pól do zmiany")
    status_changed = "status" in values and values["status"] != existing["status"]
    if status_changed:
        values["completed_at"] = _now() if values["status"] == "done" else None
    row = await database.fetch_one(
        update(board_tasks).where(board_tasks.c.id == task_id).values(updated_at=_now(), **values).returning(board_tasks)
    )
    item = _row(row)
    if status_changed:
        await _log(existing["province"], actor, "moved", "task", task_id, item["title"], {"from": existing["status"], "to": item["status"]})
    elif set(values) - {"order_index"}:
        details: Dict[str, Any] = {"fields": sorted(set(values) - {"order_index"})}
        if set(values) == {"checklist"}:
            done = sum(1 for entry in item["checklist"] if entry.get("done"))
            details = {"checklist": f"{done}/{len(item['checklist'])}"}
        await _log(existing["province"], actor, "updated", "task", task_id, item["title"], details)
    return item


class MoveTaskRequest(BaseModel):
    status: str
    index: int = 0


@router.post("/tasks/{task_id}/move")
async def move_task(task_id: int, body: MoveTaskRequest, payload: dict = Depends(get_jwt_payload)):
    """Upuszczenie karty: kolumna i miejsce w kolumnie jednym zapisem."""
    existing = await _owned(board_tasks, task_id, "Zadanie")
    actor = await _require(payload, existing["province"])
    names = spellings(existing["province"])
    rows = await database.fetch_all(
        select(board_tasks.c.id, board_tasks.c.status, board_tasks.c.order_index).where(
            and_(board_tasks.c.province.in_(names), _live(board_tasks))
        )
    )
    try:
        changes = B.plan_task_move([dict(row._mapping) for row in rows], task_id, body.status, body.index)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Nieznana kolumna: {body.status}")
    now = _now()
    async with database.transaction():
        for item_id, status, index in changes:
            values: Dict[str, Any] = {"status": status, "order_index": index}
            if item_id == task_id:
                values["updated_at"] = now
                if status != existing["status"]:
                    values["completed_at"] = now if status == "done" else None
            await database.execute(update(board_tasks).where(board_tasks.c.id == item_id).values(**values))
    if body.status != existing["status"]:
        await _log(existing["province"], actor, "moved", "task", task_id, existing["title"], {"from": existing["status"], "to": body.status})
    else:
        await _log(existing["province"], actor, "reordered", "task", task_id)
    row = await database.fetch_one(select(board_tasks).where(board_tasks.c.id == task_id))
    return _row(row)


@router.delete("/tasks/{task_id}", status_code=204)
async def delete_task(task_id: int, payload: dict = Depends(get_jwt_payload)):
    existing = await _owned(board_tasks, task_id, "Zadanie")
    actor = await _require(payload, existing["province"])
    await database.execute(update(board_tasks).where(board_tasks.c.id == task_id).values(deleted_at=_now()))
    await _log(existing["province"], actor, "deleted", "task", task_id, existing["title"])


# ---------------------------------------------------------------------------
# Członkowie
# ---------------------------------------------------------------------------


class CreateMemberRequest(BaseModel):
    province: str
    name: Optional[str] = None
    judge_id: Optional[str] = None
    role: Optional[str] = None
    description: Optional[str] = None
    icon: Optional[str] = None
    color: Optional[str] = None


class UpdateMemberRequest(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    description: Optional[str] = None
    icon: Optional[str] = None
    color: Optional[str] = None


@router.get("/members")
async def list_members(province: str = Query(...), payload: dict = Depends(get_jwt_payload)):
    await _require(payload, province)
    await _sync_members(province)
    return await _members(province)


@router.get("/judges")
async def list_judges(province: str = Query(...), payload: dict = Depends(get_jwt_payload)):
    """Sędziowie okręgu do ręcznego dopisania - bez tych, którzy już są w komisji."""
    await _require(payload, province)
    prov = _norm_province(province)
    taken = {
        _s(row["judge_id"])
        for row in await database.fetch_all(
            select(board_members.c.judge_id).where(
                and_(board_members.c.province.in_(spellings(prov)), _live(board_members), board_members.c.judge_id.is_not(None))
            )
        )
    }
    rows = await database.fetch_all(
        select(province_judges.c.judge_id, province_judges.c.full_name, province_judges.c.photo_url).where(
            province_judges.c.province.in_(spellings(prov))
        )
    )
    judges = [
        {"judge_id": _s(row["judge_id"]), "name": _s(row["full_name"]), "photo_url": _s(row["photo_url"]) or None}
        for row in rows
        if _s(row["judge_id"]) not in taken
    ]
    judges.sort(key=lambda item: item["name"].casefold())
    return judges


@router.post("/members", status_code=201)
async def create_member(body: CreateMemberRequest, payload: dict = Depends(get_jwt_payload)):
    actor = await _require(payload, body.province)
    prov = _norm_province(body.province)
    judge_id = _s(body.judge_id) or None
    name = _s(body.name)
    if judge_id:
        duplicate = await database.fetch_one(
            select(board_members.c.id).where(
                and_(board_members.c.province.in_(spellings(prov)), board_members.c.judge_id == judge_id, _live(board_members))
            )
        )
        if duplicate:
            raise HTTPException(status_code=409, detail="Ta osoba już jest w komisji")
        judge = await database.fetch_one(
            select(province_judges.c.full_name).where(province_judges.c.judge_id == judge_id)
        )
        name = name or (_s(judge["full_name"]) if judge else "")
    try:
        name = B.clean_title(name, required=True, label="Imię i nazwisko")
        values = {
            "role": B.clean_title(body.role, required=False, label="Rola"),
            "description": B.clean_text(body.description, limit=2000),
            "icon": _s(body.icon)[:60] or None,
            "color": B.clean_color(body.color),
        }
    except B.Invalid as error:
        raise _bad(error)
    now = _now()
    row = await database.fetch_one(
        insert(board_members)
        .values(province=prov, judge_id=judge_id, name=name, source="manual", active=True, created_at=now, updated_at=now, **values)
        .returning(board_members)
    )
    item = _row(row)
    await _log(prov, actor, "added", "member", item["id"], name)
    return item


@router.patch("/members/{member_id}")
async def update_member(member_id: int, body: UpdateMemberRequest, payload: dict = Depends(get_jwt_payload)):
    existing = await _owned(board_members, member_id, "Członek komisji")
    actor = await _require(payload, existing["province"])
    fields = body.model_fields_set
    values: Dict[str, Any] = {}
    try:
        if "name" in fields and body.name is not None:
            values["name"] = B.clean_title(body.name, required=True, label="Imię i nazwisko")
        if "role" in fields:
            values["role"] = B.clean_title(body.role, required=False, label="Rola")
        if "description" in fields:
            values["description"] = B.clean_text(body.description, limit=2000)
        if "icon" in fields:
            values["icon"] = _s(body.icon)[:60] or None
        if "color" in fields:
            values["color"] = B.clean_color(body.color)
    except B.Invalid as error:
        raise _bad(error)
    if not values:
        raise HTTPException(status_code=400, detail="Brak pól do zmiany")
    row = await database.fetch_one(
        update(board_members).where(board_members.c.id == member_id).values(updated_at=_now(), **values).returning(board_members)
    )
    item = _row(row)
    await _log(existing["province"], actor, "updated", "member", member_id, item["name"])
    return item


@router.delete("/members/{member_id}", status_code=204)
async def delete_member(member_id: int, payload: dict = Depends(get_jwt_payload)):
    existing = await _owned(board_members, member_id, "Członek komisji")
    actor = await _require(payload, existing["province"])
    if existing.get("source") == "badge" and existing.get("active"):
        raise HTTPException(
            status_code=400,
            detail="Ta osoba jest w komisji z odznaki „Komisja Sędziowska” - zdejmij odznakę w panelu sędziów okręgu",
        )
    await database.execute(update(board_members).where(board_members.c.id == member_id).values(deleted_at=_now()))
    await _log(existing["province"], actor, "deleted", "member", member_id, existing["name"])


# ---------------------------------------------------------------------------
# Wydarzenia
# ---------------------------------------------------------------------------


class CreateEventRequest(BaseModel):
    province: str
    title: str
    description: Optional[str] = None
    date: str
    time_start: Optional[str] = None
    time_end: Optional[str] = None
    location: Optional[str] = None
    priority: Optional[str] = None
    color: Optional[str] = None
    assignee_id: Optional[int] = None


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


async def _clean_assignee(province: str, member_id: Optional[int]) -> Optional[int]:
    if member_id is None:
        return None
    known = await _clean_assignees(province, [str(member_id)])
    return int(known[0]) if known else None


@router.get("/events")
async def list_events(
    province: str = Query(...),
    month: Optional[str] = Query(default=None),
    payload: dict = Depends(get_jwt_payload),
):
    await _require(payload, province)
    rows = await database.fetch_all(
        select(board_events)
        .where(and_(board_events.c.province.in_(spellings(_norm_province(province))), _live(board_events)))
        .order_by(board_events.c.date, board_events.c.time_start)
    )
    result = [_row(row) for row in rows]
    return [item for item in result if not month or str(item["date"]).startswith(month)]


@router.post("/events", status_code=201)
async def create_event(body: CreateEventRequest, payload: dict = Depends(get_jwt_payload)):
    actor = await _require(payload, body.province)
    prov = _norm_province(body.province)
    try:
        start, end = B.clean_time_range(B.clean_time(body.time_start), B.clean_time(body.time_end))
        values = {
            "title": B.clean_title(body.title, required=True),
            "description": B.clean_text(body.description),
            "date": B.clean_date(body.date, required=True),
            "time_start": start,
            "time_end": end,
            "location": B.clean_title(body.location, required=False, label="Miejsce"),
            "priority": B.clean_choice(body.priority, B.PRIORITIES, "priorytet"),
            "color": B.clean_color(body.color),
        }
    except B.Invalid as error:
        raise _bad(error)
    now = _now()
    row = await database.fetch_one(
        insert(board_events)
        .values(
            province=prov,
            assignee_id=await _clean_assignee(prov, body.assignee_id),
            created_by=actor.key,
            created_by_name=actor.name,
            created_at=now,
            updated_at=now,
            **values,
        )
        .returning(board_events)
    )
    item = _row(row)
    await _log(prov, actor, "created", "event", item["id"], item["title"], {"date": item["date"], "time": item.get("time_start")})
    return item


@router.patch("/events/{event_id}")
async def update_event(event_id: int, body: UpdateEventRequest, payload: dict = Depends(get_jwt_payload)):
    existing = await _owned(board_events, event_id, "Wydarzenie")
    actor = await _require(payload, existing["province"])
    fields = body.model_fields_set
    values: Dict[str, Any] = {}
    try:
        if "title" in fields and body.title is not None:
            values["title"] = B.clean_title(body.title, required=True)
        if "description" in fields:
            values["description"] = B.clean_text(body.description)
        if "date" in fields and body.date is not None:
            values["date"] = B.clean_date(body.date, required=True)
        if "time_start" in fields:
            values["time_start"] = B.clean_time(body.time_start)
        if "time_end" in fields:
            values["time_end"] = B.clean_time(body.time_end)
        if "location" in fields:
            values["location"] = B.clean_title(body.location, required=False, label="Miejsce")
        if "priority" in fields:
            values["priority"] = B.clean_choice(body.priority, B.PRIORITIES, "priorytet")
        if "color" in fields:
            values["color"] = B.clean_color(body.color)
        # Przeciągnięcie w kalendarzu wysyła początek i koniec razem; zmiana
        # jednego pola sprawdza się z tym, co już leży w bazie.
        B.clean_time_range(
            values["time_start"] if "time_start" in values else existing.get("time_start"),
            values["time_end"] if "time_end" in values else existing.get("time_end"),
        )
    except B.Invalid as error:
        raise _bad(error)
    if "assignee_id" in fields:
        values["assignee_id"] = await _clean_assignee(existing["province"], body.assignee_id)
    if not values:
        raise HTTPException(status_code=400, detail="Brak pól do zmiany")
    row = await database.fetch_one(
        update(board_events).where(board_events.c.id == event_id).values(updated_at=_now(), **values).returning(board_events)
    )
    item = _row(row)
    moved = ("date" in values and values["date"] != existing["date"]) or (
        "time_start" in values and values["time_start"] != existing.get("time_start")
    )
    await _log(
        existing["province"],
        actor,
        "rescheduled" if moved else "updated",
        "event",
        event_id,
        item["title"],
        {"date": item["date"], "time": item.get("time_start")} if moved else {},
    )
    return item


@router.delete("/events/{event_id}", status_code=204)
async def delete_event(event_id: int, payload: dict = Depends(get_jwt_payload)):
    existing = await _owned(board_events, event_id, "Wydarzenie")
    actor = await _require(payload, existing["province"])
    await database.execute(update(board_events).where(board_events.c.id == event_id).values(deleted_at=_now()))
    await _log(existing["province"], actor, "deleted", "event", event_id, existing["title"])


# ---------------------------------------------------------------------------
# Komentarze
# ---------------------------------------------------------------------------

_COMMENT_TARGETS = {"post": (board_posts, "Wpis"), "task": (board_tasks, "Zadanie")}


async def _target(target_type: str, target_id: int) -> Dict[str, Any]:
    spec = _COMMENT_TARGETS.get(target_type)
    if spec is None:
        raise HTTPException(status_code=400, detail="Komentarze są pod wpisami i zadaniami")
    return await _owned(spec[0], target_id, spec[1])


def _target_title(target: Dict[str, Any]) -> str:
    return _s(target.get("title")) or _s(target.get("content"))[:80]


class CommentRequest(BaseModel):
    province: str
    target_type: str
    target_id: int
    body: str


class UpdateCommentRequest(BaseModel):
    body: str


@router.get("/comments")
async def list_comments(
    province: str = Query(...),
    target_type: str = Query(...),
    target_id: int = Query(...),
    payload: dict = Depends(get_jwt_payload),
):
    actor = await _require(payload, province)
    target = await _target(target_type, target_id)
    if canonical(target["province"]) != canonical(province):
        raise HTTPException(status_code=404, detail="Nie ma tego na tablicy tego okręgu")
    rows = await database.fetch_all(
        select(board_comments)
        .where(
            and_(
                board_comments.c.target_type == target_type,
                board_comments.c.target_id == target_id,
                _live(board_comments),
            )
        )
        .order_by(board_comments.c.id)
    )
    comments = [_row(row) for row in rows]
    files: Dict[int, List[Dict[str, Any]]] = {}
    if comments:
        for row in await database.fetch_all(
            select(
                board_attachments.c.id,
                board_attachments.c.target_id,
                board_attachments.c.name,
                board_attachments.c.mime,
                board_attachments.c.size,
                board_attachments.c.created_at,
            ).where(
                and_(
                    board_attachments.c.target_type == "comment",
                    board_attachments.c.target_id.in_([c["id"] for c in comments]),
                    _live(board_attachments),
                )
            )
        ):
            files.setdefault(int(row["target_id"]), []).append(_row(row))
    for comment in comments:
        comment["attachments"] = files.get(int(comment["id"]), [])
        comment["mine"] = comment["author_key"] == actor.key
    return {"items": comments}


@router.post("/comments", status_code=201)
async def create_comment(body: CommentRequest, payload: dict = Depends(get_jwt_payload)):
    actor = await _require(payload, body.province)
    target = await _target(body.target_type, body.target_id)
    if canonical(target["province"]) != canonical(body.province):
        raise HTTPException(status_code=404, detail="Nie ma tego na tablicy tego okręgu")
    try:
        text = B.clean_text(body.body, limit=B.COMMENT_MAX)
    except B.Invalid as error:
        raise _bad(error)
    if not text:
        raise HTTPException(status_code=400, detail="Komentarz jest pusty")
    row = await database.fetch_one(
        insert(board_comments)
        .values(
            province=_norm_province(target["province"]),
            target_type=body.target_type,
            target_id=body.target_id,
            author_key=actor.key,
            author_name=actor.name,
            author_judge_id=actor.judge_id or None,
            body=text,
            created_at=_now(),
        )
        .returning(board_comments)
    )
    item = _row(row)
    item["attachments"] = []
    item["mine"] = True
    await _log(
        target["province"], actor, "commented", body.target_type, body.target_id, _target_title(target),
        {"comment_id": item["id"], "excerpt": text[:140]},
    )
    return item


async def _own_comment(comment_id: int, payload: dict) -> Tuple[Dict[str, Any], B.Actor]:
    existing = await _owned(board_comments, comment_id, "Komentarz")
    actor = await _require(payload, existing["province"])
    verdict = await _verdict(actor, existing["province"])
    if existing["author_key"] != actor.key and verdict.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Komentarz zmienia i usuwa tylko jego autor")
    return existing, actor


@router.patch("/comments/{comment_id}")
async def update_comment(comment_id: int, body: UpdateCommentRequest, payload: dict = Depends(get_jwt_payload)):
    existing, actor = await _own_comment(comment_id, payload)
    try:
        text = B.clean_text(body.body, limit=B.COMMENT_MAX)
    except B.Invalid as error:
        raise _bad(error)
    if not text:
        raise HTTPException(status_code=400, detail="Komentarz jest pusty")
    row = await database.fetch_one(
        update(board_comments).where(board_comments.c.id == comment_id).values(body=text, updated_at=_now()).returning(board_comments)
    )
    await _log(existing["province"], actor, "touched", "comment", comment_id)
    item = _row(row)
    item["mine"] = item["author_key"] == actor.key
    return item


@router.delete("/comments/{comment_id}", status_code=204)
async def delete_comment(comment_id: int, payload: dict = Depends(get_jwt_payload)):
    existing, actor = await _own_comment(comment_id, payload)
    await database.execute(update(board_comments).where(board_comments.c.id == comment_id).values(deleted_at=_now()))
    await _log(existing["province"], actor, "deleted", "comment", comment_id, existing["body"][:80])


# ---------------------------------------------------------------------------
# Załączniki
# ---------------------------------------------------------------------------

_ATTACH_TARGETS = {"post": (board_posts, "Wpis"), "task": (board_tasks, "Zadanie"), "comment": (board_comments, "Komentarz")}


@router.post("/attachments", status_code=201)
async def upload_attachment(
    province: str = Form(...),
    target_type: str = Form(...),
    target_id: int = Form(...),
    file: UploadFile = File(...),
    payload: dict = Depends(get_jwt_payload),
):
    actor = await _require(payload, province)
    spec = _ATTACH_TARGETS.get(target_type)
    if spec is None:
        raise HTTPException(status_code=400, detail="Załącznik dodaje się do wpisu, zadania albo komentarza")
    target = await _owned(spec[0], target_id, spec[1])
    if canonical(target["province"]) != canonical(province):
        raise HTTPException(status_code=404, detail="Nie ma tego na tablicy tego okręgu")
    mime = B.attachment_mime(file.filename or "", file.content_type or "")
    if not mime:
        raise HTTPException(status_code=400, detail="Załącznikiem może być PDF albo zdjęcie (JPG, PNG, WEBP, HEIC, GIF)")
    count = await database.fetch_one(
        select(func.count().label("n")).select_from(board_attachments).where(
            and_(board_attachments.c.target_type == target_type, board_attachments.c.target_id == target_id, _live(board_attachments))
        )
    )
    if count and int(count["n"] or 0) >= B.ATTACHMENTS_PER_TARGET:
        raise HTTPException(status_code=400, detail=f"Najwyżej {B.ATTACHMENTS_PER_TARGET} załączników w jednym miejscu")
    data = bytearray()
    try:
        while True:
            chunk = await file.read(256 * 1024)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > B.ATTACHMENT_MAX_BYTES:
                raise HTTPException(status_code=413, detail="Plik jest większy niż 10 MB")
    finally:
        await file.close()
    if not data:
        raise HTTPException(status_code=400, detail="Plik jest pusty")
    if not B.sniff_matches(mime, bytes(data[:16])):
        raise HTTPException(status_code=400, detail="Zawartość pliku nie zgadza się z jego typem")
    name = B.safe_filename(file.filename or "", mime)
    row = await database.fetch_one(
        insert(board_attachments)
        .values(
            province=_norm_province(target["province"]),
            target_type=target_type,
            target_id=target_id,
            name=name,
            mime=mime,
            size=len(data),
            data=bytes(data),
            uploaded_by=actor.key,
            uploaded_by_name=actor.name,
            created_at=_now(),
        )
        .returning(
            board_attachments.c.id,
            board_attachments.c.target_type,
            board_attachments.c.target_id,
            board_attachments.c.name,
            board_attachments.c.mime,
            board_attachments.c.size,
            board_attachments.c.uploaded_by_name,
            board_attachments.c.created_at,
        )
    )
    item = _row(row)
    log_type, log_id = target_type, target_id
    title = _target_title(target) if target_type != "comment" else _s(target.get("body"))[:80]
    if target_type == "comment":
        log_type, log_id = _s(target["target_type"]), int(target["target_id"])
    await _log(target["province"], actor, "attached", log_type, log_id, title, {"attachment_id": item["id"], "name": name})
    return item


@router.get("/attachments/{attachment_id}")
async def download_attachment(attachment_id: int, payload: dict = Depends(get_jwt_payload)):
    row = await database.fetch_one(select(board_attachments).where(board_attachments.c.id == attachment_id))
    if row is None or row["deleted_at"] is not None:
        raise HTTPException(status_code=404, detail="Załącznik nie istnieje albo leży w koszu")
    await _require(payload, row["province"])
    name = _s(row["name"]) or "zalacznik"
    disposition = f"inline; filename=\"{B.ascii_filename(name)}\"; filename*=UTF-8''{quote(name)}"
    return Response(
        content=bytes(row["data"]),
        media_type=row["mime"],
        headers={"Content-Disposition": disposition, "Cache-Control": "private, max-age=3600"},
    )


@router.delete("/attachments/{attachment_id}", status_code=204)
async def delete_attachment(attachment_id: int, payload: dict = Depends(get_jwt_payload)):
    row = await database.fetch_one(
        select(
            board_attachments.c.id, board_attachments.c.province, board_attachments.c.name, board_attachments.c.deleted_at
        ).where(board_attachments.c.id == attachment_id)
    )
    if row is None or row["deleted_at"] is not None:
        raise HTTPException(status_code=404, detail="Załącznik nie istnieje albo leży w koszu")
    actor = await _require(payload, row["province"])
    await database.execute(update(board_attachments).where(board_attachments.c.id == attachment_id).values(deleted_at=_now()))
    await _log(row["province"], actor, "deleted", "attachment", attachment_id, row["name"])


# ---------------------------------------------------------------------------
# Kosz
# ---------------------------------------------------------------------------

_TRASH_TABLES = {
    "post": board_posts,
    "task": board_tasks,
    "event": board_events,
    "member": board_members,
    "comment": board_comments,
    "attachment": board_attachments,
}


def _trash_title(kind: str, row: Dict[str, Any]) -> str:
    if kind == "post":
        return _s(row.get("title")) or _s(row.get("content"))[:80] or "Wpis"
    if kind == "comment":
        return _s(row.get("body"))[:80]
    if kind == "member" or kind == "attachment":
        return _s(row.get("name"))
    return _s(row.get("title"))


@router.get("/trash")
async def trash(province: str = Query(...), payload: dict = Depends(get_jwt_payload)):
    await _require(payload, province)
    prov = _norm_province(province)
    names = spellings(prov)
    now = _now()
    cutoff = B.trash_cutoff(now)
    who: Dict[Tuple[str, int], str] = {}
    for row in await database.fetch_all(
        select(board_activity.c.target_type, board_activity.c.target_id, board_activity.c.actor_name)
        .where(
            and_(
                board_activity.c.province.in_(names),
                board_activity.c.action == "deleted",
                board_activity.c.created_at >= cutoff,
            )
        )
        .order_by(board_activity.c.id)
    ):
        if row["target_id"] is not None:
            who[(row["target_type"], int(row["target_id"]))] = _s(row["actor_name"])
    items: List[Dict[str, Any]] = []
    for kind, table in _TRASH_TABLES.items():
        columns = [column for column in table.c if column.name != "data"]
        for row in await database.fetch_all(
            select(*columns).where(
                and_(table.c.province.in_(names), table.c.deleted_at.is_not(None), table.c.deleted_at >= cutoff)
            )
        ):
            data = dict(row._mapping)
            items.append(
                {
                    "kind": kind,
                    "id": int(data["id"]),
                    "title": _trash_title(kind, data),
                    "deleted_at": data["deleted_at"].isoformat(),
                    "deleted_by": who.get((kind, int(data["id"]))) or None,
                    "days_left": B.days_left(data["deleted_at"], now),
                    "extra": {
                        "type": data.get("type"),
                        "status": data.get("status"),
                        "date": data.get("date"),
                        "target_type": data.get("target_type"),
                        "mime": data.get("mime"),
                    },
                }
            )
    items.sort(key=lambda item: item["deleted_at"], reverse=True)
    return {"items": items, "days": B.TRASH_DAYS}


class RestoreRequest(BaseModel):
    kind: str
    id: int


@router.post("/restore")
async def restore(body: RestoreRequest, payload: dict = Depends(get_jwt_payload)):
    table = _TRASH_TABLES.get(body.kind)
    if table is None:
        raise HTTPException(status_code=400, detail="Tego nie da się przywrócić")
    row = await database.fetch_one(select(table.c.id, table.c.province, table.c.deleted_at).where(table.c.id == body.id))
    if row is None:
        raise HTTPException(status_code=404, detail="Kosz został już opróżniony")
    actor = await _require(payload, row["province"])
    if row["deleted_at"] is None:
        return {"ok": True, "restored": False}
    if not B.restorable(row["deleted_at"], _now()):
        raise HTTPException(status_code=410, detail=f"Minęło {B.TRASH_DAYS} dni - tego już nie da się przywrócić")
    if body.kind == "member":
        member = await database.fetch_one(select(board_members.c.judge_id).where(board_members.c.id == body.id))
        if member and member["judge_id"]:
            duplicate = await database.fetch_one(
                select(board_members.c.id).where(
                    and_(
                        board_members.c.province.in_(spellings(row["province"])),
                        board_members.c.judge_id == member["judge_id"],
                        _live(board_members),
                    )
                )
            )
            if duplicate:
                raise HTTPException(status_code=409, detail="Ta osoba jest już znowu w komisji")
    await database.execute(update(table).where(table.c.id == body.id).values(deleted_at=None))
    full = await database.fetch_one(select(*[c for c in table.c if c.name != "data"]).where(table.c.id == body.id))
    await _log(row["province"], actor, "restored", body.kind, body.id, _trash_title(body.kind, dict(full._mapping)))
    return {"ok": True, "restored": True}


# ---------------------------------------------------------------------------
# Rankingi - zakładka usunięta z ekranu 16.09.2026; dane i trasy zostają
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
async def list_rankings(province: str = Query(...), payload: dict = Depends(get_jwt_payload)):
    await _require(payload, province)
    rows = await database.fetch_all(
        select(board_rankings)
        .where(board_rankings.c.province.in_(spellings(_norm_province(province))))
        .order_by(board_rankings.c.created_at)
    )
    return [_row(row) for row in rows]


@router.post("/rankings", status_code=201)
async def create_ranking(body: CreateRankingRequest, payload: dict = Depends(get_jwt_payload)):
    await _require(payload, body.province)
    row = await database.fetch_one(
        insert(board_rankings)
        .values(province=_norm_province(body.province), title=body.title, rows_json=[r.model_dump() for r in body.rows])
        .returning(board_rankings)
    )
    return _row(row)


@router.patch("/rankings/{ranking_id}")
async def update_ranking(ranking_id: int, body: UpdateRankingRequest, payload: dict = Depends(get_jwt_payload)):
    existing = await database.fetch_one(select(board_rankings.c.province).where(board_rankings.c.id == ranking_id))
    if existing is None:
        raise HTTPException(status_code=404, detail="Ranking nie istnieje")
    await _require(payload, existing["province"])
    values: Dict[str, Any] = {}
    if body.title is not None:
        values["title"] = body.title
    if body.rows is not None:
        values["rows_json"] = [r.model_dump() for r in body.rows]
    if not values:
        raise HTTPException(status_code=400, detail="Brak pól do zmiany")
    row = await database.fetch_one(
        update(board_rankings).where(board_rankings.c.id == ranking_id).values(**values).returning(board_rankings)
    )
    return _row(row)


@router.delete("/rankings/{ranking_id}", status_code=204)
async def delete_ranking(ranking_id: int, payload: dict = Depends(get_jwt_payload)):
    existing = await database.fetch_one(select(board_rankings.c.province).where(board_rankings.c.id == ranking_id))
    if existing is None:
        raise HTTPException(status_code=404, detail="Ranking nie istnieje")
    await _require(payload, existing["province"])
    await database.execute(delete(board_rankings).where(board_rankings.c.id == ranking_id))

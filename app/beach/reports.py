"""
Beach Reports — system zgłoszeń user ↔ admin (mini-chat).

Uprawnienia:
  - Każdy zalogowany user beach: tworzy zgłoszenia i odpowiada na własne
  - Admin: widzi wszystkie zgłoszenia, odpowiada, zmienia status
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, Depends
from sqlalchemy import select, insert, update, func as sa_func

from app.db import (
    database,
    beach_reports,
    beach_report_messages,
    beach_admins,
    beach_users,
)
from app.schemas import (
    BeachReportCreateRequest,
    BeachReportMessageItem,
    BeachReportItem,
    BeachReportDetailResponse,
    BeachReportsListResponse,
    BeachReportReplyRequest,
    BeachReportStatusRequest,
    BeachReportUnreadCountResponse,
    BeachReportAdminStats,
    BeachReportAdminListResponse,
)
from app.deps import beach_get_current_user_id

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/beach/reports", tags=["Beach: Reports"])


# ─────────────────── helpers ───────────────────

async def _is_admin(user_id: int) -> bool:
    row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    return bool(row)


async def _get_report_or_404(report_id: int) -> dict:
    row = await database.fetch_one(
        select(beach_reports).where(beach_reports.c.id == report_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Zgłoszenie nie istnieje")
    return dict(row)


async def _get_message_count(report_id: int) -> int:
    row = await database.fetch_one(
        select(sa_func.count(beach_report_messages.c.id)).where(
            beach_report_messages.c.report_id == report_id
        )
    )
    return row[0] if row else 0


async def _get_last_message(report_id: int) -> Optional[str]:
    row = await database.fetch_one(
        select(beach_report_messages.c.content)
        .where(beach_report_messages.c.report_id == report_id)
        .order_by(beach_report_messages.c.id.desc())
        .limit(1)
    )
    if not row:
        return None
    content = row["content"]
    return content[:120] + "…" if len(content) > 120 else content


def _row_to_report_item(row: dict, message_count: int = 0, last_message: Optional[str] = None) -> BeachReportItem:
    return BeachReportItem(
        id=row["id"],
        user_id=row["user_id"],
        user_name=row["user_name"],
        user_phone=row.get("user_phone"),
        user_email=row.get("user_email"),
        type=row["type"],
        status=row["status"],
        unread_by_admin=bool(row["unread_by_admin"]),
        unread_by_user=bool(row["unread_by_user"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        last_message=last_message,
        message_count=message_count,
    )


def _msg_row_to_item(row: dict) -> BeachReportMessageItem:
    return BeachReportMessageItem(
        id=row["id"],
        report_id=row["report_id"],
        sender_type=row["sender_type"],
        sender_user_id=row["sender_user_id"],
        sender_name=row.get("sender_name"),
        content=row["content"],
        created_at=row["created_at"],
    )


# ─────────────────── USER endpoints ───────────────────

@router.get("/unread-count", response_model=BeachReportUnreadCountResponse)
async def get_unread_count(user_id: int = Depends(beach_get_current_user_id)):
    """Liczba zgłoszeń z nową odpowiedzią admina (dla in-app check)."""
    row = await database.fetch_one(
        select(sa_func.count(beach_reports.c.id)).where(
            (beach_reports.c.user_id == user_id)
            & (beach_reports.c.unread_by_user == True)  # noqa: E712
        )
    )
    count = row[0] if row else 0
    return BeachReportUnreadCountResponse(unread_count=count)


@router.get("/", response_model=BeachReportsListResponse)
async def get_my_reports(user_id: int = Depends(beach_get_current_user_id)):
    """Lista własnych zgłoszeń (bez auto-mark — mark następuje przy otwarciu wątku)."""
    rows = await database.fetch_all(
        select(beach_reports)
        .where(beach_reports.c.user_id == user_id)
        .order_by(beach_reports.c.updated_at.desc())
    )

    report_items: List[BeachReportItem] = []
    for row in rows:
        d = dict(row)
        cnt = await _get_message_count(d["id"])
        last = await _get_last_message(d["id"])
        report_items.append(_row_to_report_item(d, cnt, last))

    unread_count = sum(1 for r in report_items if r.unread_by_user)
    return BeachReportsListResponse(
        reports=report_items,
        total=len(report_items),
        unread_count=unread_count,
    )


@router.post("/", status_code=201, response_model=BeachReportDetailResponse)
async def create_report(
    body: BeachReportCreateRequest,
    user_id: int = Depends(beach_get_current_user_id),
):
    """Utwórz nowe zgłoszenie (z pierwszą wiadomością)."""
    # pobierz dane kontaktowe z profilu
    user_row = await database.fetch_one(
        select(
            beach_users.c.full_name,
            beach_users.c.phone,
            beach_users.c.email,
        ).where(beach_users.c.id == user_id)
    )
    if not user_row:
        raise HTTPException(status_code=403, detail="Nie znaleziono użytkownika")

    user_name = user_row["full_name"]
    user_phone = user_row["phone"]
    user_email = user_row["email"]

    now = datetime.now(timezone.utc)

    # utwórz raport
    report_id = await database.execute(
        insert(beach_reports).values(
            user_id=user_id,
            type=body.type,
            status="open",
            user_name=user_name,
            user_phone=user_phone,
            user_email=user_email,
            unread_by_admin=True,
            unread_by_user=False,
            created_at=now,
            updated_at=now,
        )
    )

    # dodaj pierwszą wiadomość
    msg_id = await database.execute(
        insert(beach_report_messages).values(
            report_id=report_id,
            sender_type="user",
            sender_user_id=user_id,
            sender_name=user_name,
            content=body.content,
            created_at=now,
        )
    )

    # zwróć szczegóły
    report_row = await _get_report_or_404(report_id)
    msg_row = await database.fetch_one(
        select(beach_report_messages).where(beach_report_messages.c.id == msg_id)
    )

    return BeachReportDetailResponse(
        report=_row_to_report_item(report_row, 1, body.content[:120]),
        messages=[_msg_row_to_item(dict(msg_row))],
    )


@router.get("/{report_id}", response_model=BeachReportDetailResponse)
async def get_report_thread(
    report_id: int,
    user_id: int = Depends(beach_get_current_user_id),
):
    """Pełny wątek zgłoszenia. Auto-markuje unread_by_user=false."""
    report_row = await _get_report_or_404(report_id)
    if report_row["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Brak dostępu do zgłoszenia")

    # auto-mark jako przeczytane przez usera
    if report_row["unread_by_user"]:
        await database.execute(
            update(beach_reports)
            .where(beach_reports.c.id == report_id)
            .values(unread_by_user=False)
        )
        report_row["unread_by_user"] = False

    msgs = await database.fetch_all(
        select(beach_report_messages)
        .where(beach_report_messages.c.report_id == report_id)
        .order_by(beach_report_messages.c.id.asc())
    )

    cnt = len(msgs)
    last = msgs[-1]["content"] if msgs else None
    if last and len(last) > 120:
        last = last[:120] + "…"

    return BeachReportDetailResponse(
        report=_row_to_report_item(report_row, cnt, last),
        messages=[_msg_row_to_item(dict(m)) for m in msgs],
    )


@router.post("/{report_id}/messages", status_code=201, response_model=BeachReportDetailResponse)
async def reply_to_report(
    report_id: int,
    body: BeachReportReplyRequest,
    user_id: int = Depends(beach_get_current_user_id),
):
    """Dodaj wiadomość do wątku (user lub admin)."""
    report_row = await _get_report_or_404(report_id)
    is_admin = await _is_admin(user_id)

    # user może odpowiadać tylko na własne; admin na wszystkie
    if not is_admin and report_row["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Brak dostępu do zgłoszenia")

    if report_row["status"] == "closed" and not is_admin:
        raise HTTPException(status_code=400, detail="Zgłoszenie jest zamknięte")

    # pobierz imię nadawcy
    sender_row = await database.fetch_one(
        select(beach_users.c.full_name).where(beach_users.c.id == user_id)
    )
    sender_name = sender_row["full_name"] if sender_row else None
    sender_type = "admin" if is_admin else "user"

    now = datetime.now(timezone.utc)

    await database.execute(
        insert(beach_report_messages).values(
            report_id=report_id,
            sender_type=sender_type,
            sender_user_id=user_id,
            sender_name=sender_name,
            content=body.content,
            created_at=now,
        )
    )

    # ustaw flagi unread + updated_at
    update_vals: dict = {"updated_at": now}
    if sender_type == "admin":
        update_vals["unread_by_user"] = True
    else:
        update_vals["unread_by_admin"] = True

    await database.execute(
        update(beach_reports).where(beach_reports.c.id == report_id).values(**update_vals)
    )

    # zwróć zaktualizowany wątek
    report_row = await _get_report_or_404(report_id)
    msgs = await database.fetch_all(
        select(beach_report_messages)
        .where(beach_report_messages.c.report_id == report_id)
        .order_by(beach_report_messages.c.id.asc())
    )
    cnt = len(msgs)
    last = msgs[-1]["content"] if msgs else None
    if last and len(last) > 120:
        last = last[:120] + "…"

    return BeachReportDetailResponse(
        report=_row_to_report_item(dict(report_row), cnt, last),
        messages=[_msg_row_to_item(dict(m)) for m in msgs],
    )


# ─────────────────── ADMIN endpoints ───────────────────

@router.get("/admin/stats", response_model=BeachReportAdminStats)
async def get_admin_stats(user_id: int = Depends(beach_get_current_user_id)):
    """Statystyki dla panelu admina."""
    if not await _is_admin(user_id):
        raise HTTPException(status_code=403, detail="Brak uprawnień")

    async def _count(where_clause) -> int:
        row = await database.fetch_one(
            select(sa_func.count(beach_reports.c.id)).where(where_clause)
        )
        return row[0] if row else 0

    open_c = await _count(beach_reports.c.status == "open")
    in_progress_c = await _count(beach_reports.c.status == "in_progress")
    closed_c = await _count(beach_reports.c.status == "closed")
    unread_c = await _count(beach_reports.c.unread_by_admin == True)  # noqa: E712

    return BeachReportAdminStats(
        open=open_c,
        in_progress=in_progress_c,
        closed=closed_c,
        unread_admin=unread_c,
    )


@router.get("/admin/", response_model=BeachReportAdminListResponse)
async def get_admin_reports(
    status: Optional[str] = Query(None),
    type: Optional[str] = Query(None),
    user_id: int = Depends(beach_get_current_user_id),
):
    """Lista wszystkich zgłoszeń dla admina z opcjonalnym filtrowaniem."""
    if not await _is_admin(user_id):
        raise HTTPException(status_code=403, detail="Brak uprawnień")

    query = select(beach_reports).order_by(beach_reports.c.updated_at.desc())
    if status:
        query = query.where(beach_reports.c.status == status)
    if type:
        query = query.where(beach_reports.c.type == type)

    rows = await database.fetch_all(query)

    report_items: List[BeachReportItem] = []
    for row in rows:
        d = dict(row)
        cnt = await _get_message_count(d["id"])
        last = await _get_last_message(d["id"])
        report_items.append(_row_to_report_item(d, cnt, last))

    # stats
    async def _count(where_clause) -> int:
        r = await database.fetch_one(
            select(sa_func.count(beach_reports.c.id)).where(where_clause)
        )
        return r[0] if r else 0

    stats = BeachReportAdminStats(
        open=await _count(beach_reports.c.status == "open"),
        in_progress=await _count(beach_reports.c.status == "in_progress"),
        closed=await _count(beach_reports.c.status == "closed"),
        unread_admin=await _count(beach_reports.c.unread_by_admin == True),  # noqa: E712
    )

    return BeachReportAdminListResponse(
        reports=report_items,
        total=len(report_items),
        stats=stats,
    )


@router.get("/admin/{report_id}", response_model=BeachReportDetailResponse)
async def get_admin_report_thread(
    report_id: int,
    user_id: int = Depends(beach_get_current_user_id),
):
    """Pełny wątek dla admina. Auto-markuje unread_by_admin=false."""
    if not await _is_admin(user_id):
        raise HTTPException(status_code=403, detail="Brak uprawnień")

    report_row = await _get_report_or_404(report_id)

    if report_row["unread_by_admin"]:
        await database.execute(
            update(beach_reports)
            .where(beach_reports.c.id == report_id)
            .values(unread_by_admin=False)
        )
        report_row["unread_by_admin"] = False

    msgs = await database.fetch_all(
        select(beach_report_messages)
        .where(beach_report_messages.c.report_id == report_id)
        .order_by(beach_report_messages.c.id.asc())
    )

    cnt = len(msgs)
    last = msgs[-1]["content"] if msgs else None
    if last and len(last) > 120:
        last = last[:120] + "…"

    return BeachReportDetailResponse(
        report=_row_to_report_item(report_row, cnt, last),
        messages=[_msg_row_to_item(dict(m)) for m in msgs],
    )


@router.patch("/admin/{report_id}/status", response_model=BeachReportItem)
async def update_report_status(
    report_id: int,
    body: BeachReportStatusRequest,
    user_id: int = Depends(beach_get_current_user_id),
):
    """Zmiana statusu zgłoszenia przez admina."""
    if not await _is_admin(user_id):
        raise HTTPException(status_code=403, detail="Brak uprawnień")

    report_row = await _get_report_or_404(report_id)

    now = datetime.now(timezone.utc)
    await database.execute(
        update(beach_reports)
        .where(beach_reports.c.id == report_id)
        .values(status=body.status, updated_at=now)
    )

    updated_row = await _get_report_or_404(report_id)
    cnt = await _get_message_count(report_id)
    last = await _get_last_message(report_id)
    return _row_to_report_item(updated_row, cnt, last)

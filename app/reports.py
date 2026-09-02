"""
Zgłoszenia BAZA — komunikator sędzia ↔ admin.

Odpowiednik app/beach/reports.py, przełożony na model tożsamości BAZY: tu nie ma
tokenów ani beach_users, wszystko idzie po `judge_id` (string). Adminem jest ten,
kogo judge_id siedzi w admin_settings.allowed_admins.

Wstecz kompatybilne:
  • tabela user_reports zostaje ta sama, dochodzą do niej kolumny wątku,
  • stare endpointy /admin/reports (POST, GET, read/unread, DELETE) działają
    bez zmian — stary APK nie zauważy różnicy,
  • kolumna `is_read` jest utrzymywana równolegle do `unread_by_admin`,
    żeby stary panel dalej pokazywał prawidłowy stan.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from sqlalchemy import func as sa_func, select, update

from app.db import (
    admin_settings,
    database,
    login_records,
    user_report_messages,
    user_reports,
)
from app.admin_alerts import notify_admins
from app.push.push import send_push_to_judges
from app.schemas import (
    CreateUserReportRequest,
    ListUserReportsResponse,
    ReportAdminStats,
    ReportDetailResponse,
    ReportMessageItem,
    ReportReplyRequest,
    ReportStatusRequest,
    ReportUnreadCountResponse,
    UserReportItem,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reports", tags=["Zgłoszenia (komunikator)"])

_RAILWAY_VOLUME = os.getenv("RAILWAY_VOLUME_MOUNT_PATH")
_STATIC_DIR = (
    os.path.join(_RAILWAY_VOLUME, "static")
    if _RAILWAY_VOLUME
    else os.path.join(os.path.dirname(__file__), "..", "static")
)
_ATTACH_DIR = os.path.join(_STATIC_DIR, "reports")

# Zadania w tle trzeba trzymać, inaczej garbage collector potrafi je uprzątnąć
# zanim się wykonają.
_bg_tasks: set = set()

# Znacznik ostatniego sprzątania zdjęć (epoch sekundy).
_last_cleanup_ts: float = 0.0

TYPE_LABELS = {
    "pomysl": "Pomysł",
    "awaria": "Awaria",
    "pytanie": "Pytanie",
}


def _spawn(coro) -> None:
    """Odpala zadanie w tle i trzyma na nie referencję."""
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)


# ─────────────────────────── uprawnienia ───────────────────────────

async def _admin_ids() -> List[str]:
    row = await database.fetch_one(
        select(admin_settings.c.allowed_admins).where(admin_settings.c.id == 1)
    )
    return [str(a) for a in ((row["allowed_admins"] if row else []) or [])]


async def _is_admin(judge_id: Optional[str]) -> bool:
    if not judge_id:
        return False
    return str(judge_id) in await _admin_ids()


async def _require_access(report_row: dict, judge_id: str) -> bool:
    """Zwraca True, gdy pytający jest adminem. Rzuca 403, gdy nie ma dostępu."""
    is_admin = await _is_admin(judge_id)
    if is_admin:
        return True
    if str(report_row["judge_id"]) != str(judge_id):
        raise HTTPException(403, detail="Brak dostępu do tego zgłoszenia")
    return False


# ─────────────────────────── mapowanie wierszy ───────────────────────────

def _row_to_item(
    row: dict,
    message_count: int = 0,
    last_message: Optional[str] = None,
    last_message_at: Optional[datetime] = None,
) -> UserReportItem:
    return UserReportItem(
        id=row["id"],
        judge_id=row["judge_id"],
        full_name=row["full_name"],
        phone=row["phone"],
        email=row.get("email"),
        type=row["type"],
        content=row["content"],
        created_at=row["created_at"],
        is_read=bool(row.get("is_read", False)),
        status=row.get("status") or "open",
        title=row.get("title"),
        unread_by_admin=bool(row.get("unread_by_admin", False)),
        unread_by_user=bool(row.get("unread_by_user", False)),
        updated_at=row.get("updated_at"),
        message_count=message_count,
        last_message=last_message,
        last_message_at=last_message_at,
    )


def _msg_to_item(row: dict) -> ReportMessageItem:
    return ReportMessageItem(
        id=row["id"],
        report_id=row["report_id"],
        sender_type=row["sender_type"],
        sender_id=row["sender_id"],
        sender_name=row.get("sender_name"),
        content=row["content"],
        attachment_url=row.get("attachment_url"),
        created_at=row["created_at"],
    )


async def _thread_stats(report_ids: List[int]) -> Dict[int, dict]:
    """Liczba wiadomości i ostatnia wiadomość dla każdego wątku — jednym zapytaniem."""
    if not report_ids:
        return {}
    counts = await database.fetch_all(
        select(
            user_report_messages.c.report_id,
            sa_func.count().label("cnt"),
            sa_func.max(user_report_messages.c.created_at).label("last_at"),
        )
        .where(user_report_messages.c.report_id.in_(report_ids))
        .group_by(user_report_messages.c.report_id)
    )
    stats: Dict[int, dict] = {
        r["report_id"]: {"cnt": r["cnt"], "last_at": r["last_at"], "last": None}
        for r in counts
    }
    if not stats:
        return {}
    # Treść ostatniej wiadomości — tylko dla wątków, które w ogóle jakąś mają.
    last_rows = await database.fetch_all(
        select(
            user_report_messages.c.report_id,
            user_report_messages.c.content,
            user_report_messages.c.created_at,
        )
        .where(user_report_messages.c.report_id.in_(list(stats.keys())))
        .order_by(user_report_messages.c.created_at.desc())
    )
    for r in last_rows:
        entry = stats.get(r["report_id"])
        if entry and entry["last"] is None:
            entry["last"] = r["content"]
    return stats


# ─────────────────────────── tytuły z AI ───────────────────────────

async def _generate_title_bg(report_id: int, content: str, type_key: str) -> None:
    """
    Dokleja krótki tytuł do zgłoszenia. Leci w tle — użytkownik nie czeka na AI,
    a gdy się nie uda, zgłoszenie po prostu zostaje bez tytułu i panel pokazuje
    początek treści.
    """
    try:
        import openai

        client = openai.AsyncOpenAI()
        label = TYPE_LABELS.get(type_key, "Zgłoszenie")
        resp = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Jesteś asystentem aplikacji BAZA — narzędzia dla sędziów piłki "
                        "ręcznej w Polsce (obsady, ryczałty, protokoły, przepisy). "
                        "Tworzysz krótkie, konkretne tytuły (max 55 znaków, po polsku) "
                        "dla zgłoszeń użytkowników. Odpowiedz TYLKO tytułem — bez "
                        "cudzysłowów, bez kropki na końcu."
                    ),
                },
                {"role": "user", "content": f"[{label}] {content[:600]}"},
            ],
            max_tokens=25,
            temperature=0.4,
        )
        title = (resp.choices[0].message.content or "").strip().strip('"').strip("'")
        if title:
            await database.execute(
                update(user_reports)
                .where(user_reports.c.id == report_id)
                .values(title=title[:120])
            )
    except Exception:
        logger.warning("Nie udało się wygenerować tytułu dla zgłoszenia %s", report_id)


# ─────────────────────────── sprzątanie załączników ───────────────────────────

def _url_to_fs_path(url: str) -> Optional[str]:
    if not url or url == "__archived__":
        return None
    idx = url.find("/static/")
    if idx == -1:
        return None
    return os.path.join(_STATIC_DIR, url[idx + len("/static/") :])


async def _cleanup_old_attachments(days: int = 60) -> int:
    """
    Kasuje pliki starsze niż `days` i oznacza je w bazie jako `__archived__`.
    Wołane rzadko (raz na dobę) przy okazji zwykłego ruchu — bez osobnego crona.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = await database.fetch_all(
        select(user_report_messages.c.id, user_report_messages.c.attachment_url).where(
            (user_report_messages.c.created_at < cutoff)
            & (user_report_messages.c.attachment_url.isnot(None))
            & (user_report_messages.c.attachment_url != "__archived__")
        )
    )
    removed = 0
    for row in rows:
        path = _url_to_fs_path(row["attachment_url"])
        if path and os.path.exists(path):
            try:
                os.remove(path)
                removed += 1
            except Exception:
                continue
        await database.execute(
            update(user_report_messages)
            .where(user_report_messages.c.id == row["id"])
            .values(attachment_url="__archived__")
        )
    return removed


def _maybe_cleanup() -> None:
    global _last_cleanup_ts
    now = time.time()
    if now - _last_cleanup_ts < 24 * 3600:
        return
    _last_cleanup_ts = now
    _spawn(_cleanup_old_attachments())


# ─────────────────────────── powiadomienia ───────────────────────────

async def _notify_admins_new_report(report_id: int, name: str, type_key: str, preview: str) -> None:
    """Nowe zgłoszenie → administratorzy.

    Idzie wspólną drogą (`app.admin_alerts`), żeby wyłącznik powiadomień
    administracyjnych działał tu tak samo jak przy pozostałych zdarzeniach.
    Wcześniej ten moduł miał własną wysyłkę i nie dało się go wyciszyć.
    """
    await notify_admins(
        "new_report",
        TYPE_LABELS.get(type_key, "Zgłoszenie"),
        f"👤 {name}\n„{preview}”",
        reference=report_id,
        extra={"report_id": report_id},
    )


async def _notify_user_reply(report_id: int, judge_id: str, title: str) -> None:
    try:
        await send_push_to_judges(
            [judge_id],
            title="💬 Odpowiedź na Twoje zgłoszenie",
            body=f"📝 {title}\nMasz nową wiadomość — dotknij, aby przeczytać.",
            data={"type": "report_reply", "report_id": str(report_id)},
        )
    except Exception as e:
        logger.warning("_notify_user_reply: %s", e)


# ═══════════════════════════ ENDPOINTY UŻYTKOWNIKA ═══════════════════════════

@router.get("/mine", response_model=ListUserReportsResponse, summary="Moje zgłoszenia")
async def list_my_reports(judge_id: str = Query(..., description="ID sędziego")):
    rows = await database.fetch_all(
        select(user_reports)
        .where(user_reports.c.judge_id == str(judge_id))
        .order_by(user_reports.c.updated_at.desc(), user_reports.c.created_at.desc())
    )
    dicts = [dict(r) for r in rows]
    stats = await _thread_stats([d["id"] for d in dicts])
    return ListUserReportsResponse(
        reports=[
            _row_to_item(
                d,
                message_count=stats.get(d["id"], {}).get("cnt", 0),
                last_message=stats.get(d["id"], {}).get("last"),
                last_message_at=stats.get(d["id"], {}).get("last_at"),
            )
            for d in dicts
        ]
    )


@router.get(
    "/mine/unread-count",
    response_model=ReportUnreadCountResponse,
    summary="Ile moich zgłoszeń ma nieprzeczytaną odpowiedź",
)
async def my_unread_count(judge_id: str = Query(...)):
    row = await database.fetch_one(
        select(sa_func.count()).select_from(user_reports).where(
            (user_reports.c.judge_id == str(judge_id))
            & (user_reports.c.unread_by_user.is_(True))
        )
    )
    return ReportUnreadCountResponse(unread_count=int(row[0] if row else 0))


@router.post("/", response_model=ReportDetailResponse, status_code=201, summary="Nowe zgłoszenie")
async def create_report(req: CreateUserReportRequest):
    content = (req.content or "").strip()
    if not content:
        raise HTTPException(400, detail="Treść zgłoszenia nie może być pusta")

    now = datetime.now(timezone.utc)
    report_id = await database.execute(
        user_reports.insert().values(
            judge_id=str(req.judge_id),
            full_name=req.full_name,
            phone=req.phone,
            email=req.email,
            type=req.type,
            content=content,
            status="open",
            is_read=False,
            unread_by_admin=True,
            unread_by_user=False,
            created_at=now,
            updated_at=now,
        )
    )

    _spawn(_generate_title_bg(report_id, content, req.type))
    _spawn(
        _notify_admins_new_report(
            report_id,
            req.full_name,
            req.type,
            content[:90] + ("…" if len(content) > 90 else ""),
        )
    )
    _maybe_cleanup()

    row = await database.fetch_one(select(user_reports).where(user_reports.c.id == report_id))
    return ReportDetailResponse(report=_row_to_item(dict(row)), messages=[])


@router.get("/{report_id}", response_model=ReportDetailResponse, summary="Wątek zgłoszenia")
async def get_report(
    report_id: int,
    judge_id: str = Query(...),
    as_user: bool = Query(False),
):
    row = await database.fetch_one(select(user_reports).where(user_reports.c.id == report_id))
    if not row:
        raise HTTPException(404, detail="Nie znaleziono zgłoszenia")
    data = dict(row)
    is_admin = await _require_access(data, judge_id)
    is_owner = str(data["judge_id"]) == str(judge_id)
    if as_user and not is_owner:
        raise HTTPException(403, detail="Tylko autor może otworzyć zgłoszenie jako użytkownik")
    viewer_is_admin = is_admin and not (as_user and is_owner)

    # Otwarcie wątku = przeczytanie go przez tę stronę.
    if viewer_is_admin and data.get("unread_by_admin"):
        await database.execute(
            update(user_reports)
            .where(user_reports.c.id == report_id)
            # `is_read` trzymamy zgodnie z unread_by_admin dla starego panelu.
            .values(unread_by_admin=False, is_read=True)
        )
        data["unread_by_admin"] = False
        data["is_read"] = True
    elif not viewer_is_admin and data.get("unread_by_user"):
        await database.execute(
            update(user_reports)
            .where(user_reports.c.id == report_id)
            .values(unread_by_user=False)
        )
        data["unread_by_user"] = False

    msgs = await database.fetch_all(
        select(user_report_messages)
        .where(user_report_messages.c.report_id == report_id)
        .order_by(user_report_messages.c.created_at.asc())
    )
    return ReportDetailResponse(
        report=_row_to_item(data, message_count=len(msgs)),
        messages=[_msg_to_item(dict(m)) for m in msgs],
    )


@router.post(
    "/{report_id}/messages",
    response_model=ReportDetailResponse,
    status_code=201,
    summary="Odpowiedz w wątku",
)
async def reply(report_id: int, req: ReportReplyRequest):
    content = (req.content or "").strip()
    if not content and not req.attachment_url:
        raise HTTPException(400, detail="Wiadomość nie może być pusta")

    row = await database.fetch_one(select(user_reports).where(user_reports.c.id == report_id))
    if not row:
        raise HTTPException(404, detail="Nie znaleziono zgłoszenia")
    data = dict(row)
    is_admin = await _require_access(data, req.judge_id)
    is_owner = str(data["judge_id"]) == str(req.judge_id)
    if req.force_user and not is_owner:
        raise HTTPException(403, detail="Tylko autor może pisać jako użytkownik")
    sender_type = "user" if (not is_admin or req.force_user) else "admin"

    sender_name = req.full_name
    if not sender_name:
        rec = await database.fetch_one(
            select(login_records.c.full_name).where(
                login_records.c.judge_id == str(req.judge_id)
            )
        )
        sender_name = rec["full_name"] if rec else None

    await database.execute(
        user_report_messages.insert().values(
            report_id=report_id,
            sender_type=sender_type,
            sender_id=str(req.judge_id),
            sender_name=sender_name,
            content=content,
            attachment_url=req.attachment_url,
            created_at=datetime.now(timezone.utc),
        )
    )

    # Odpowiedź admina zamyka jego nieprzeczytane i zapala je użytkownikowi
    # (i odwrotnie). Status "open" przechodzi w "in_progress", gdy admin
    # pierwszy raz odpisze — bez ręcznego klikania.
    if sender_type == "admin":
        values: Dict[str, Any] = {"unread_by_admin": False, "is_read": True, "unread_by_user": True}
        if data.get("status") == "open":
            values["status"] = "in_progress"
        await database.execute(
            update(user_reports).where(user_reports.c.id == report_id).values(**values)
        )
        _spawn(
            _notify_user_reply(
                report_id,
                str(data["judge_id"]),
                data.get("title") or "Twoje zgłoszenie",
            )
        )
    else:
        await database.execute(
            update(user_reports)
            .where(user_reports.c.id == report_id)
            .values(unread_by_admin=True, is_read=False, unread_by_user=False)
        )
        # Odpowiedź użytkownika jest częścią TEGO SAMEGO wątku. Wcześniej szła
        # boczną drogą bez trwałej skrzynki i ze starym typem payloadu, przez co
        # admin nie miał ciągłości rozmowy ani poprawnego deep-linku.
        _spawn(
            notify_admins(
                "report_reply",
                data.get("title") or "Zgłoszenie",
                f"👤 {data['full_name']}\n„{content[:90]}”",
                # Odpowiedzi w jednym wątku mogą przyjść wielokrotnie. Pusty
                # klucz wyłącza deduplikację, a report_id nadal jedzie osobno
                # jako cel nawigacji do właściwej rozmowy.
                reference="",
                extra={"report_id": report_id},
                exclude_judge_id=str(req.judge_id),
            )
        )

    return await get_report(
        report_id,
        judge_id=req.judge_id,
        as_user=sender_type == "user" and is_owner,
    )


@router.post("/{report_id}/upload-attachment", summary="Wgraj zdjęcie do wiadomości")
async def upload_attachment(report_id: int, judge_id: str = Query(...), file: UploadFile = File(...)):
    row = await database.fetch_one(select(user_reports).where(user_reports.c.id == report_id))
    if not row:
        raise HTTPException(404, detail="Nie znaleziono zgłoszenia")
    await _require_access(dict(row), judge_id)

    ext = os.path.splitext(file.filename or "")[1].lower() or ".jpg"
    if ext not in (".jpg", ".jpeg", ".png", ".webp", ".heic"):
        raise HTTPException(400, detail="Dozwolone są tylko zdjęcia")

    os.makedirs(_ATTACH_DIR, exist_ok=True)
    name = f"{report_id}_{uuid.uuid4().hex}{ext}"
    path = os.path.join(_ATTACH_DIR, name)
    try:
        with open(path, "wb") as out:
            shutil.copyfileobj(file.file, out)
    except Exception as e:
        raise HTTPException(500, detail=f"Nie udało się zapisać pliku: {e!r}")
    finally:
        await file.close()

    return {"ok": True, "url": f"/static/reports/{name}"}


@router.delete("/{report_id}", status_code=204, summary="Usuń zgłoszenie")
async def delete_report(report_id: int, judge_id: str = Query(...)):
    row = await database.fetch_one(select(user_reports).where(user_reports.c.id == report_id))
    if not row:
        raise HTTPException(404, detail="Nie znaleziono zgłoszenia")
    await _require_access(dict(row), judge_id)

    # Pliki idą razem z wątkiem — inaczej zostałyby sierotami na wolumenie.
    msgs = await database.fetch_all(
        select(user_report_messages.c.attachment_url).where(
            user_report_messages.c.report_id == report_id
        )
    )
    for m in msgs:
        path = _url_to_fs_path(m["attachment_url"] or "")
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass

    await database.execute(
        user_report_messages.delete().where(user_report_messages.c.report_id == report_id)
    )
    await database.execute(user_reports.delete().where(user_reports.c.id == report_id))
    return None


# ═══════════════════════════ ENDPOINTY ADMINA ═══════════════════════════

@router.get("/admin/stats", response_model=ReportAdminStats, summary="Statystyki zgłoszeń")
async def admin_stats():
    rows = await database.fetch_all(
        select(user_reports.c.status, user_reports.c.type, user_reports.c.unread_by_admin)
    )
    by_type: Dict[str, int] = {}
    stats = {"total": 0, "unread": 0, "open": 0, "in_progress": 0, "closed": 0}
    for r in rows:
        stats["total"] += 1
        if r["unread_by_admin"]:
            stats["unread"] += 1
        status = r["status"] or "open"
        if status in stats:
            stats[status] += 1
        key = r["type"] or "inne"
        by_type[key] = by_type.get(key, 0) + 1
    return ReportAdminStats(**stats, by_type=by_type)


@router.get("/admin/list", response_model=ListUserReportsResponse, summary="Wszystkie zgłoszenia")
async def admin_list(
    status: Optional[str] = Query(None, description="open | in_progress | closed"),
    type: Optional[str] = Query(None, description="pomysl | awaria | pytanie"),
    unread_only: bool = Query(False),
    limit: int = Query(0, description="0 = bez limitu"),
):
    q = select(user_reports)
    if status:
        q = q.where(user_reports.c.status == status)
    if type:
        q = q.where(user_reports.c.type == type)
    if unread_only:
        q = q.where(user_reports.c.unread_by_admin.is_(True))
    q = q.order_by(user_reports.c.updated_at.desc(), user_reports.c.created_at.desc())
    if limit and limit > 0:
        q = q.limit(limit)

    rows = await database.fetch_all(q)
    dicts = [dict(r) for r in rows]
    stats = await _thread_stats([d["id"] for d in dicts])
    return ListUserReportsResponse(
        reports=[
            _row_to_item(
                d,
                message_count=stats.get(d["id"], {}).get("cnt", 0),
                last_message=stats.get(d["id"], {}).get("last"),
                last_message_at=stats.get(d["id"], {}).get("last_at"),
            )
            for d in dicts
        ]
    )


@router.patch("/{report_id}/status", response_model=UserReportItem, summary="Zmień status zgłoszenia")
async def set_status(report_id: int, req: ReportStatusRequest, judge_id: str = Query(...)):
    if not await _is_admin(judge_id):
        raise HTTPException(403, detail="Tylko admin może zmienić status")
    await database.execute(
        update(user_reports).where(user_reports.c.id == report_id).values(status=req.status)
    )
    row = await database.fetch_one(select(user_reports).where(user_reports.c.id == report_id))
    if not row:
        raise HTTPException(404, detail="Nie znaleziono zgłoszenia")
    return _row_to_item(dict(row))


@router.patch(
    "/{report_id}/admin-unread",
    response_model=UserReportItem,
    summary="Oznacz zgłoszenie jako nieprzeczytane dla admina",
)
async def set_admin_unread(
    report_id: int,
    payload: Dict[str, bool],
    judge_id: str = Query(...),
):
    if not await _is_admin(judge_id):
        raise HTTPException(403, detail="Tylko admin może zmienić stan odczytu")
    row = await database.fetch_one(
        select(user_reports).where(user_reports.c.id == report_id)
    )
    if not row:
        raise HTTPException(404, detail="Nie znaleziono zgłoszenia")
    unread = bool(payload.get("unread", True))
    await database.execute(
        update(user_reports)
        .where(user_reports.c.id == report_id)
        .values(unread_by_admin=unread, is_read=not unread)
    )
    next_row = await database.fetch_one(
        select(user_reports).where(user_reports.c.id == report_id)
    )
    return _row_to_item(dict(next_row))

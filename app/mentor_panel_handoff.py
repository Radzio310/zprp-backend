"""
Panel „Mentor" - przesiadka z telefonu na komputer (trasy). Reguły:
`app/mentor_handoff_rules.py`.

  POST /mentor-panel/handoff/short          {path} -> {code, short, url, expires_at}
  GET  /mentor-panel/handoff/short/{code}   -> {path, url, expires_at}
  POST /mentor-panel/handoff/email          {path, code?} -> {sent, to}   (zalogowany)

Skrót tworzy też anonimowy telefon (ekran stoi przed logowaniem) - z limitem
po adresie IP. Odczyt kodu liczy chybienia po IP (zgadywanie 4 znaków).
Mail idzie na adres z konta (te same źródła co maile okręgu: profil logowania
w aplikacji, potem „Kontakty") - nigdy na adres podany w żądaniu.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, insert, select, update

from app import mentor_handoff_rules as H
from app import mentor_panel_core as C
from app.db import database, mentor_short_links
from app.mentor_panel_auth import mentor_actor
from app.pod_reka_login_rules import AttemptLimiter, client_key

logger = logging.getLogger("app.mentor_panel")

router = APIRouter(prefix="/mentor-panel/handoff", tags=["Mentor"])

_CREATE_LIMITER = AttemptLimiter(limit=40)
_MISS_LIMITER = AttemptLimiter(limit=25)
_EMAIL_LIMITER = AttemptLimiter(limit=5)


def _ip(request: Request) -> str:
    return client_key(request.headers.get("x-forwarded-for") or "", request.client.host if request.client else "")


def _fail(exc: H.HandoffError):
    return C.err(exc.status, exc.code, exc.message)


def _iso(value: Any) -> Optional[str]:
    if isinstance(value, datetime):
        aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return aware.isoformat()
    return str(value) if value else None


def _aware(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def _payload(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "code": row["code"],
        "short": H.short_label(row["code"]),
        "url": H.full_url(row["path"]),
        "path": row["path"],
        "expires_at": _iso(row["expires_at"]),
    }


class ShortBody(BaseModel):
    path: str = Field(..., max_length=H.MAX_PATH)


@router.post("/short")
async def create_short(body: ShortBody, request: Request):
    ip = _ip(request)
    if _CREATE_LIMITER.blocked(ip):
        raise C.err(429, "RATE_LIMITED", "Za dużo kodów naraz. Spróbuj za kilka minut.")
    try:
        path = H.clean_path(body.path)
    except H.HandoffError as exc:
        raise _fail(exc)
    _CREATE_LIMITER.fail(ip)
    now = C.now()
    await database.execute(delete(mentor_short_links).where(mentor_short_links.c.expires_at < now))
    reuse = await C.one(
        select(mentor_short_links)
        .where(and_(mentor_short_links.c.path == path, mentor_short_links.c.created_at > now - H.REUSE_WINDOW))
        .order_by(mentor_short_links.c.created_at.desc())
        .limit(1)
    )
    if reuse and (_aware(reuse["expires_at"]) or now) > now:
        return _payload(reuse)
    for _ in range(8):
        code = H.new_code()
        if await C.one(select(mentor_short_links.c.code).where(mentor_short_links.c.code == code)):
            continue
        row = {"code": code, "path": path, "created_at": now, "expires_at": now + H.SHORT_TTL, "hits": 0}
        await database.execute(insert(mentor_short_links).values(**row))
        return _payload(row)
    raise C.err(503, "CODE_BUSY", "Nie udało się przydzielić kodu. Spróbuj ponownie.")


@router.get("/short/{code}")
async def resolve_short(code: str, request: Request):
    ip = _ip(request)
    if _MISS_LIMITER.blocked(ip):
        raise C.err(429, "RATE_LIMITED", "Za dużo prób. Odczekaj kilka minut i wpisz kod ponownie.")
    clean = H.normalize_code(code)
    row = await C.one(select(mentor_short_links).where(mentor_short_links.c.code == clean)) if clean else None
    if not row:
        _MISS_LIMITER.fail(ip)
        raise C.err(404, "SHORT_UNKNOWN", "Nie znamy takiego kodu. Sprawdź znaki na telefonie.")
    if (_aware(row["expires_at"]) or C.now()) <= C.now():
        raise C.err(410, "SHORT_EXPIRED", "Ten kod już wygasł. Na telefonie pojawi się nowy po odświeżeniu.")
    try:
        await database.execute(
            update(mentor_short_links).where(mentor_short_links.c.code == clean).values(hits=mentor_short_links.c.hits + 1)
        )
    except Exception:  # noqa: BLE001
        pass
    return {"path": row["path"], "url": H.full_url(row["path"]), "expires_at": _iso(row["expires_at"])}


class EmailBody(BaseModel):
    path: str = Field(..., max_length=H.MAX_PATH)
    code: Optional[str] = Field(default=None, max_length=12)


async def account_email(actor: C.MentorActor) -> str:
    """Adres z konta sędziego (te same źródła co maile okręgu i zbiorczy mail Mentora)."""
    from app.district_alerts import _judge_email_detail

    found = await _judge_email_detail(actor.province, [actor.judge_id], {actor.judge_id: actor.display_name})
    return (found.get(actor.judge_id) or ("", ""))[0]


async def deliver(address: str, subject: str, body: str, text: str) -> None:
    from app.province_alert_emails import send_alert_email

    await send_alert_email([address], subject, body, text, sender="BAZA · Mentor", tag="mentor-handoff")


@router.post("/email")
async def email_link(body: EmailBody, actor: C.MentorActor = Depends(mentor_actor)):
    if _EMAIL_LIMITER.blocked(actor.judge_id):
        raise C.err(429, "RATE_LIMITED", "Link już poleciał kilka razy. Sprawdź skrzynkę, także folder Oferty i Spam.")
    try:
        path = H.clean_path(body.path)
    except H.HandoffError as exc:
        raise _fail(exc)
    address = ""
    try:
        address = await account_email(actor)
    except Exception:  # noqa: BLE001
        logger.warning("mentor: adres konta nieznany", exc_info=True)
    if not address:
        raise C.err(404, "NO_EMAIL", "Twoje konto nie ma adresu e-mail. Skopiuj link albo przepisz kod na komputerze.")
    code = H.normalize_code(body.code) if body.code else None
    subject, html_body, text = H.email_content(path, code, actor.display_name)
    _EMAIL_LIMITER.fail(actor.judge_id)
    try:
        await deliver(address, subject, html_body, text)
    except Exception:  # noqa: BLE001
        logger.warning("mentor: mail z linkiem nieudany", exc_info=True)
        raise C.err(502, "MAIL_FAILED", "Poczta nie przyjęła listu. Spróbuj za chwilę albo skopiuj link.")
    return {"sent": True, "to": H.mask_email(address)}

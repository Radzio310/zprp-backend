"""
Panel „Mentor" - kto pyta i logowanie web (`docs/mentor-panel.md`, 4.1).

Dwie drogi, jedna zależność `mentor_actor`:
  - `Authorization: Bearer <JWT sędziego>` - aplikacja BAZA,
  - ciasteczko `baza_mentor_session` (httpOnly, 30 dni) - BAZA_web; każdy zapis
    niesie nagłówek `X-CSRF-Token` (wzór: sesja klubowa `app/pod_reka.py`).

Logowanie web: kod QR na komputerze zatwierdzony w aplikacji (zalogowany
sędzia) albo zapasowo login i hasło ZPRP (jak `exam_live._web_login`, z limitem
prób). Sesję trzymamy jako skrót - surowy token zna tylko przeglądarka.

Token CSRF nie leży w bazie: to HMAC(SECRET_KEY, skrót sesji + losowa sól
z `csrf_hash`). Dzięki temu `GET /auth/me` oddaje go stronie po odświeżeniu
bez unieważniania drugiej karty, a `GET /auth/csrf` wymienia sól.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import and_, select, update

from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app.db import database, mentor_qr_logins, mentor_web_sessions
from app.pod_reka_login_rules import AttemptLimiter, client_key

router = APIRouter(prefix="/mentor-panel", tags=["Mentor"])

SESSION_COOKIE = "baza_mentor_session"
CSRF_COOKIE = "baza_mentor_csrf"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
APPROVE_WEB = "https://www.bazapodreka.app/mentor/zaloguj"
APPROVE_APP = "refhandballapp://mentor/login"
QR_POLL_MAX_S = 25

_LOGIN_LIMITER = AttemptLimiter()
_QR_LIMITER = AttemptLimiter(limit=30)
_qr_events: Dict[str, asyncio.Event] = {}


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _secret() -> str:
    from app.deps import get_settings

    return get_settings().SECRET_KEY


def csrf_for(session: Dict[str, Any]) -> str:
    message = f"mentor-csrf:{session['session_hash']}:{session['csrf_hash']}".encode("utf-8")
    return hmac.new(_secret().encode("utf-8"), message, hashlib.sha256).hexdigest()


def _cookie_flags(request: Request) -> Dict[str, Any]:
    secure = request.url.scheme == "https"
    return {"secure": secure, "samesite": "none" if secure else "lax", "path": "/"}


def _set_cookies(request: Request, response: Response, raw: str, csrf: str) -> None:
    flags = _cookie_flags(request)
    age = int(R.SESSION_TTL.total_seconds())
    response.set_cookie(SESSION_COOKIE, raw, max_age=age, httponly=True, **flags)
    response.set_cookie(CSRF_COOKIE, csrf, max_age=age, httponly=False, **flags)
    response.headers["Cache-Control"] = "no-store"


async def create_session(judge_id: str, user_agent: str = "") -> tuple[str, Dict[str, Any]]:
    raw = secrets.token_urlsafe(48)
    stamp = C.now()
    row = {
        "id": R.new_id(), "judge_id": str(judge_id), "session_hash": _hash(raw),
        "csrf_hash": _hash(secrets.token_urlsafe(32)), "created_at": stamp,
        "expires_at": stamp + R.SESSION_TTL, "last_seen_at": stamp, "revoked_at": None,
        "user_agent": (user_agent or "")[:300] or None,
    }
    await database.execute(mentor_web_sessions.insert().values(**row))
    return raw, row


async def session_from_cookie(raw: Optional[str]) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    found = await C.one(select(mentor_web_sessions).where(and_(
        mentor_web_sessions.c.session_hash == _hash(raw), mentor_web_sessions.c.revoked_at.is_(None))))
    if not found:
        return None
    expires = R.aware(found.get("expires_at"))
    if not expires or expires <= C.now():
        return None
    return found


async def _decode_bearer(request: Request, token: str) -> Dict[str, Any]:
    from app.deps import get_jwt_payload

    return await get_jwt_payload(request, token)


async def mentor_actor(request: Request) -> C.MentorActor:
    """JWT aplikacji albo sesja web; przy zapisie z sesji web wymagany `X-CSRF-Token`."""
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        payload = await _decode_bearer(request, auth.split(" ", 1)[1].strip())
        judge_id = R.s(payload.get("judge_id"))
        if not judge_id:
            raise C.err(403, "NOT_JUDGE", "Panel Mentor jest dla kont sędziowskich.")
        return await C.load_actor(judge_id, via="jwt", display_name=R.s(payload.get("display_name")).split("|")[0].strip())
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        raise C.err(401, "UNAUTHENTICATED", "Zaloguj się kodem QR z aplikacji BAZA albo loginem ZPRP.")
    session = await session_from_cookie(raw)
    if not session:
        raise C.err(401, "SESSION_EXPIRED", "Sesja wygasła. Zaloguj się ponownie.")
    if request.method.upper() not in SAFE_METHODS:
        sent = request.headers.get("x-csrf-token") or ""
        if not sent or not hmac.compare_digest(sent, csrf_for(session)):
            raise C.err(403, "CSRF", "Token zabezpieczający wygasł. Odśwież stronę i spróbuj ponownie.")
    last = R.aware(session.get("last_seen_at"))
    if not last or last < C.now() - timedelta(minutes=5):
        try:
            await database.execute(update(mentor_web_sessions).where(mentor_web_sessions.c.id == session["id"])
                                   .values(last_seen_at=C.now()))
        except Exception:  # noqa: BLE001
            pass
    return await C.load_actor(session["judge_id"], via="web", session=session)


async def jwt_actor(request: Request) -> C.MentorActor:
    """Tylko aplikacja (JWT) - zatwierdzenie logowania komputera."""
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise C.err(401, "APP_ONLY", "Logowanie komputera zatwierdza się w aplikacji BAZA.")
    return await mentor_actor(request)


def me_payload(actor: C.MentorActor) -> Dict[str, Any]:
    return {
        "judge_id": actor.judge_id, "display_name": actor.display_name, "is_admin": actor.is_admin,
        "photo_url": actor.photo_url, "province": actor.province, "via": actor.via,
        "csrf": csrf_for(actor.session) if actor.via == "web" and actor.session else None,
    }


# ─── QR ─────────────────────────────────────────────────────────────────────


@router.post("/auth/qr")
async def qr_start(request: Request):
    address = client_key(request.headers.get("x-forwarded-for", ""), request.client.host if request.client else "")
    key = f"qr:{address}"
    if _QR_LIMITER.blocked(key):
        raise C.err(429, "RATE_LIMITED", "Za dużo kodów logowania naraz. Spróbuj za kilka minut.")
    _QR_LIMITER.fail(key)
    poll_token = secrets.token_urlsafe(24)
    stamp = C.now()
    for _ in range(5):
        code = R.new_qr_code()
        try:
            await database.execute(mentor_qr_logins.insert().values(
                code=code, poll_hash=_hash(poll_token), created_at=stamp, expires_at=stamp + R.QR_TTL,
                user_agent=(request.headers.get("user-agent") or "")[:300] or None,
            ))
            break
        except Exception:  # noqa: BLE001 - kolizja kodu: losujemy jeszcze raz
            continue
    else:
        raise C.err(503, "QR_UNAVAILABLE", "Nie udało się utworzyć kodu. Spróbuj ponownie.")
    return {"code": code, "poll_token": poll_token, "expires_at": stamp + R.QR_TTL,
            "approve_url": f"{APPROVE_WEB}/{code}", "app_url": f"{APPROVE_APP}/{code}"}


async def _qr_row(code: str) -> Optional[Dict[str, Any]]:
    return await C.one(select(mentor_qr_logins).where(mentor_qr_logins.c.code == code))


@router.get("/auth/qr/{code}")
async def qr_poll(code: str, request: Request, response: Response, poll_token: str = Query("", max_length=200),
                  wait: int = Query(20, ge=0, le=QR_POLL_MAX_S)):
    code = R.normalize_qr_code(code)
    row = await _qr_row(code) if code else None
    if not row or not poll_token or not hmac.compare_digest(_hash(poll_token), R.s(row.get("poll_hash"))):
        raise C.err(404, "QR_NOT_FOUND", "Ten kod logowania nie istnieje albo wygasł.")
    deadline = time.monotonic() + wait
    status = R.qr_status(row, C.now())
    while status == "waiting" and time.monotonic() < deadline:
        ev = _qr_events.setdefault(code, asyncio.Event())
        try:
            await asyncio.wait_for(ev.wait(), timeout=min(2.0, max(0.05, deadline - time.monotonic())))
        except asyncio.TimeoutError:
            pass
        row = await _qr_row(code)
        status = R.qr_status(row, C.now())
    if status != "approved":
        if status == "expired":
            _qr_events.pop(code, None)
        return {"status": status}
    await database.execute(update(mentor_qr_logins).where(mentor_qr_logins.c.code == code)
                           .where(mentor_qr_logins.c.consumed_at.is_(None)).values(consumed_at=C.now()))
    _qr_events.pop(code, None)
    raw, session = await create_session(row["approved_by"], request.headers.get("user-agent") or "")
    csrf = csrf_for(session)
    _set_cookies(request, response, raw, csrf)
    actor = await C.load_actor(row["approved_by"], via="web", session=session)
    return {"status": "approved", "me": me_payload(actor), "csrf": csrf}


@router.post("/auth/qr/{code}/approve")
async def qr_approve(code: str, actor: C.MentorActor = Depends(jwt_actor)):
    code = R.normalize_qr_code(code)
    row = await _qr_row(code) if code else None
    status = R.qr_status(row, C.now())
    if status != "waiting":
        raise C.err(409 if status == "approved" else 404, "QR_USED" if status == "approved" else "QR_EXPIRED",
                    "Ten kod został już użyty." if status == "approved" else "Kod wygasł - odśwież stronę na komputerze.")
    await database.execute(update(mentor_qr_logins).where(mentor_qr_logins.c.code == code)
                           .where(mentor_qr_logins.c.approved_by.is_(None))
                           .values(approved_by=actor.judge_id, approved_at=C.now()))
    ev = _qr_events.get(code)
    if ev:
        ev.set()
    return {"ok": True, "device_hint": R.device_hint(row.get("user_agent"))}


# ─── Login i hasło ZPRP ─────────────────────────────────────────────────────


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=200)


async def _zprp_login(username: str, password: str) -> Dict[str, Any]:
    """Ten sam login ZPRP co w aplikacji (`app.auth.login`), jak `exam_live._web_login`."""
    from fastapi import HTTPException

    from app.auth import LoginRequest, login
    from app.deps import get_settings

    try:
        res = await login(LoginRequest(username=username, password=password), get_settings())
    except HTTPException as error:
        if error.status_code == 401:
            raise R.RuleError(401, "BAD_CREDENTIALS", "Login albo hasło się nie zgadza. To te same dane, co w aplikacji BAZA.")
        raise R.RuleError(502, "LOGIN_DOWN", "Logowanie chwilowo nie działa. Spróbuj za moment.")
    except Exception:  # noqa: BLE001 - serwer ZPRP nie odpowiada
        raise R.RuleError(502, "LOGIN_DOWN", "Serwer ZPRP nie odpowiada. Spróbuj za moment.")
    data = res if isinstance(res, dict) else res.model_dump()
    return data


@router.post("/auth/login")
async def password_login(body: LoginBody, request: Request, response: Response):
    address = client_key(request.headers.get("x-forwarded-for", ""), request.client.host if request.client else "")
    keys = (f"ip:{address}", f"user:{body.username.strip().lower()}")
    if _LOGIN_LIMITER.blocked(*keys):
        retry = _LOGIN_LIMITER.retry_after(*keys)
        raise C.err(429, "RATE_LIMITED", f"Za dużo nieudanych prób. Spróbuj ponownie za {max(1, retry // 60)} min.")
    try:
        data = await _zprp_login(body.username.strip(), body.password)
    except R.RuleError as exc:
        if exc.status == 401:
            _LOGIN_LIMITER.fail(*keys)
        raise C.rule_error(exc) from exc
    judge_id = R.s(data.get("judge_id"))
    if not judge_id:
        _LOGIN_LIMITER.fail(*keys)
        raise C.err(403, "NOT_JUDGE", "To konto nie ma numeru sędziego. Panel Mentor jest dla kont sędziowskich.")
    _LOGIN_LIMITER.success(*keys)
    raw, session = await create_session(judge_id, request.headers.get("user-agent") or "")
    csrf = csrf_for(session)
    _set_cookies(request, response, raw, csrf)
    actor = await C.load_actor(judge_id, via="web", session=session,
                               display_name=R.s(data.get("display_name")).split("|")[0].strip())
    return {"me": me_payload(actor), "csrf": csrf}


@router.get("/auth/me")
async def auth_me(actor: C.MentorActor = Depends(mentor_actor)):
    return me_payload(actor)


@router.get("/auth/csrf")
async def auth_csrf(request: Request, response: Response, actor: C.MentorActor = Depends(mentor_actor)):
    if actor.via != "web" or not actor.session:
        return {"csrf": None}
    salt = _hash(secrets.token_urlsafe(32))
    await database.execute(update(mentor_web_sessions).where(mentor_web_sessions.c.id == actor.session["id"])
                           .values(csrf_hash=salt))
    session = {**actor.session, "csrf_hash": salt}
    csrf = csrf_for(session)
    flags = _cookie_flags(request)
    response.set_cookie(CSRF_COOKIE, csrf, max_age=int(R.SESSION_TTL.total_seconds()), httponly=False, **flags)
    response.headers["Cache-Control"] = "no-store"
    return {"csrf": csrf}


@router.post("/auth/logout")
async def auth_logout(request: Request, response: Response):
    """Bez CSRF (jak `pod_reka`): wylogowanie cudzej sesji nic atakującemu nie daje."""
    raw = request.cookies.get(SESSION_COOKIE)
    if raw:
        await database.execute(update(mentor_web_sessions).where(mentor_web_sessions.c.session_hash == _hash(raw))
                               .where(mentor_web_sessions.c.revoked_at.is_(None)).values(revoked_at=C.now()))
    flags = _cookie_flags(request)
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path="/", secure=flags["secure"], httponly=name == SESSION_COOKIE, samesite=flags["samesite"])
    return {"ok": True}


async def cleanup_auth(now: Optional[datetime] = None) -> Dict[str, int]:
    """Sprzątanie dzienne: stare kody QR i dawno wygasłe sesje."""
    from sqlalchemy import delete, or_

    stamp = now or datetime.now(timezone.utc)
    await database.execute(delete(mentor_qr_logins).where(mentor_qr_logins.c.expires_at < stamp - timedelta(days=1)))
    await database.execute(delete(mentor_web_sessions).where(or_(
        mentor_web_sessions.c.expires_at < stamp - timedelta(days=7),
        mentor_web_sessions.c.revoked_at < stamp - timedelta(days=7),
    )))
    return {"ok": 1}

"""
Panel okręgowy (/panel) - logowanie komputera kodem QR z aplikacji BAZA.

Wzór: logowanie panelu Mentor (`app/mentor_panel_auth.py`), z jedną różnicą.
Panel okręgowy woła trasy `/zprp/*` i `/baza_web/profile`, które logują się
do baza.zprp.pl danymi użytkownika, oraz odnawia JWT loginem i hasłem. Dlatego
telefon przy zatwierdzeniu wysyła swoje dane logowania (zaszyfrowane kluczem
publicznym serwera, jak każde wywołanie aplikacji), a komputer dostaje zamiast
hasła pieczęć (`app/panel_web_seal.py`), ważną `SEAL_TTL`.

Trasy (`docs/panel-web-qr.md`):
  POST /panel-web/auth/qr                   kod do pokazania na komputerze
  GET  /panel-web/auth/qr/{code}            długie odpytywanie komputera
  POST /panel-web/auth/qr/{code}/approve    zatwierdzenie z aplikacji (JWT + dane)
  POST /panel-web/auth/token                świeży JWT dla komputera z pieczęci

Zatwierdza zawsze to konto, na które aplikacja jest teraz zalogowana: login
w danych musi być loginem z JWT aplikacji.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, select, update

from app import mentor_panel_rules as R
from app import panel_web_seal as S
from app.db import database, panel_web_qr_logins
from app.pod_reka_login_rules import AttemptLimiter, client_key

router = APIRouter(prefix="/panel-web", tags=["Panel okręgowy"])

APPROVE_WEB = "https://www.bazapodreka.app/okreg/zaloguj"
APPROVE_APP = "refhandballapp://panel/login"
QR_POLL_MAX_S = 25

_QR_LIMITER = AttemptLimiter(limit=30)
_APPROVE_LIMITER = AttemptLimiter(limit=10)
_TOKEN_LIMITER = AttemptLimiter(limit=60)
_qr_events: Dict[str, asyncio.Event] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _err(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code, {"code": code, "message": message})


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _address(request: Request) -> str:
    return client_key(request.headers.get("x-forwarded-for", ""), request.client.host if request.client else "")


def _secret() -> str:
    from app.deps import get_settings

    return get_settings().SECRET_KEY


def _keys():
    """(prawdziwy klucz prywatny, klucz publiczny) - bez otwierania pieczęci."""
    from app.deps import get_rsa_keys

    private_key, public_key = get_rsa_keys()
    return getattr(private_key, "inner", private_key), public_key


def _decrypt_plain(private_key, enc_b64: str) -> bytes:
    try:
        return private_key.decrypt(base64.b64decode(enc_b64), padding.PKCS1v15())
    except Exception as exc:  # noqa: BLE001 - zły base64, cudzy klucz
        raise _err(400, "BAD_PAYLOAD", "Nie udało się odczytać danych logowania.") from exc


async def _decode_bearer(request: Request, token: str) -> Dict[str, Any]:
    from app.deps import get_jwt_payload

    return await get_jwt_payload(request, token)


async def _app_payload(request: Request) -> Dict[str, Any]:
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise _err(401, "APP_ONLY", "Logowanie komputera zatwierdza się w aplikacji BAZA.")
    try:
        payload = await _decode_bearer(request, auth.split(" ", 1)[1].strip())
    except HTTPException as exc:
        raise _err(401, "APP_SESSION", "Sesja aplikacji wygasła. Zaloguj się ponownie w aplikacji.") from exc
    if payload.get("scope"):
        # Tokeny stron (egzamin, formularze) nie zatwierdzają logowania komputera.
        raise _err(403, "APP_ONLY", "Logowanie komputera zatwierdza się w aplikacji BAZA.")
    return payload


async def _panel_login(username: str, password: str) -> Dict[str, Any]:
    """To samo, co robi `/baza_web/login` przy logowaniu hasłem (VIP, zakładki ZPRP)."""
    from app.baza_web import BazaWebLoginRequest, baza_web_login
    from app.deps import get_settings

    data = await baza_web_login(BazaWebLoginRequest(username=username, password=password), get_settings())
    return data if isinstance(data, dict) else data.model_dump()


async def _panel_profile(username: str, password: str, judge_id: str) -> Optional[Dict[str, Any]]:
    """Profil sędziego jak z `/baza_web/profile` - komputer zalogowany kodem nie zawoła go sam."""
    from app.baza_web import BazaWebProfileRequest, baza_web_profile
    from app.deps import get_settings

    try:
        res = await baza_web_profile(BazaWebProfileRequest(username=username, password=password, judge_id=judge_id), get_settings())
    except Exception:  # noqa: BLE001 - profil jest dodatkiem, logowanie bez niego też działa
        return None
    data = res if isinstance(res, dict) else res.model_dump()
    profile = data.get("profile") if data.get("success") else None
    if profile is not None and not isinstance(profile, dict):
        profile = profile.model_dump()
    return profile


async def _jwt_login(username: str, password: str) -> Dict[str, Any]:
    from app.auth import LoginRequest, login
    from app.deps import get_settings

    res = await login(LoginRequest(username=username, password=password), get_settings())
    return res if isinstance(res, dict) else res.model_dump()


async def _row(code: str) -> Optional[Dict[str, Any]]:
    found = await database.fetch_one(select(panel_web_qr_logins).where(panel_web_qr_logins.c.code == code))
    return dict(found) if found else None


# ─── Kod na komputerze ──────────────────────────────────────────────────────


@router.post("/auth/qr")
async def qr_start(request: Request):
    key = f"qr:{_address(request)}"
    if _QR_LIMITER.blocked(key):
        raise _err(429, "RATE_LIMITED", "Za dużo kodów logowania naraz. Spróbuj za kilka minut.")
    _QR_LIMITER.fail(key)
    stamp = _now()
    # Sprzątanie po drodze: kody sprzed doby (zatwierdzone dane i tak znikają przy odbiorze).
    try:
        await database.execute(delete(panel_web_qr_logins).where(panel_web_qr_logins.c.expires_at < stamp - timedelta(days=1)))
    except Exception:  # noqa: BLE001
        pass
    poll_token = secrets.token_urlsafe(24)
    for _ in range(5):
        code = R.new_qr_code()
        try:
            await database.execute(panel_web_qr_logins.insert().values(
                code=code, poll_hash=_hash(poll_token), created_at=stamp, expires_at=stamp + R.QR_TTL,
                user_agent=(request.headers.get("user-agent") or "")[:300] or None,
            ))
            break
        except Exception:  # noqa: BLE001 - kolizja kodu: losujemy jeszcze raz
            continue
    else:
        raise _err(503, "QR_UNAVAILABLE", "Nie udało się utworzyć kodu. Spróbuj ponownie.")
    return {"code": code, "poll_token": poll_token, "expires_at": stamp + R.QR_TTL,
            "approve_url": f"{APPROVE_WEB}/{code}", "app_url": f"{APPROVE_APP}/{code}"}


@router.get("/auth/qr/{code}")
async def qr_poll(code: str, poll_token: str = Query("", max_length=200), wait: int = Query(20, ge=0, le=QR_POLL_MAX_S)):
    code = R.normalize_qr_code(code)
    row = await _row(code) if code else None
    if not row or not poll_token or not hmac.compare_digest(_hash(poll_token), R.s(row.get("poll_hash"))):
        raise _err(404, "QR_NOT_FOUND", "Ten kod logowania nie istnieje albo wygasł.")
    deadline = time.monotonic() + wait
    status = R.qr_status(row, _now())
    while status == "waiting" and time.monotonic() < deadline:
        ev = _qr_events.setdefault(code, asyncio.Event())
        try:
            await asyncio.wait_for(ev.wait(), timeout=min(2.0, max(0.05, deadline - time.monotonic())))
        except asyncio.TimeoutError:
            pass
        row = await _row(code)
        status = R.qr_status(row, _now())
    if status != "approved":
        if status == "expired":
            _qr_events.pop(code, None)
        return {"status": status}
    # Odbiór jednorazowy: dane znikają z bazy w tej samej chwili.
    await database.execute(
        update(panel_web_qr_logins).where(panel_web_qr_logins.c.code == code)
        .where(panel_web_qr_logins.c.consumed_at.is_(None))
        .values(consumed_at=_now(), sealed=None, payload_json=None)
    )
    _qr_events.pop(code, None)
    if not row.get("sealed"):
        return {"status": "expired"}
    return {
        "status": "approved",
        "username": row.get("username"),
        "password": row.get("sealed"),
        "sealed_expires_at": row.get("sealed_expires_at"),
        "login": row.get("payload_json") or {},
    }


# ─── Zatwierdzenie w aplikacji ──────────────────────────────────────────────


class ApproveBody(BaseModel):
    #: Login i hasło ZPRP konta zalogowanego w aplikacji, zaszyfrowane kluczem
    #: publicznym serwera (jak `callBackendWithEncryptedCreds` aplikacji).
    username: str = Field(min_length=1, max_length=2000)
    password: str = Field(min_length=1, max_length=2000)


@router.post("/auth/qr/{code}/approve")
async def qr_approve(code: str, body: ApproveBody, request: Request):
    payload = await _app_payload(request)
    limiter_key = f"approve:{R.s(payload.get('sub')).lower() or _address(request)}"
    if _APPROVE_LIMITER.blocked(limiter_key):
        raise _err(429, "RATE_LIMITED", "Za dużo prób naraz. Spróbuj za kilka minut.")
    code = R.normalize_qr_code(code)
    row = await _row(code) if code else None
    status = R.qr_status(row, _now())
    if status != "waiting":
        raise _err(409 if status == "approved" else 404, "QR_USED" if status == "approved" else "QR_EXPIRED",
                   "Ten kod został już użyty." if status == "approved" else "Kod wygasł - odśwież stronę na komputerze.")
    private_key, public_key = _keys()
    plain_password = _decrypt_plain(private_key, body.password)
    if S.is_sealed(plain_password):
        raise _err(400, "BAD_PAYLOAD", "Zatwierdź logowanie danymi z aplikacji.")
    username = _decrypt_plain(private_key, body.username).decode("utf-8", errors="strict").strip()
    password = plain_password.decode("utf-8", errors="strict")
    if not username or username.lower() != R.s(payload.get("sub")).strip().lower():
        _APPROVE_LIMITER.fail(limiter_key)
        raise _err(403, "ACCOUNT_MISMATCH", "Dane logowania nie należą do konta zalogowanego w aplikacji.")
    login = await _panel_login(username, password)
    if not login.get("success"):
        _APPROVE_LIMITER.fail(limiter_key)
        error = R.s(login.get("error"))
        if error.startswith("Błąd serwera"):
            raise _err(502, "LOGIN_DOWN", "Serwer ZPRP nie odpowiada. Spróbuj za moment.")
        raise _err(401, "BAD_CREDENTIALS", "ZPRP nie przyjął danych logowania z aplikacji. Zaloguj się w aplikacji ponownie.")
    if R.s(login.get("judge_id")):
        login = {**login, "profile": await _panel_profile(username, password, R.s(login.get("judge_id")))}
    try:
        sealed, sealed_expires = S.seal(password, _secret())
    except S.SealError as exc:
        raise _err(400, "PASSWORD_TOO_LONG", "Tego hasła nie da się przekazać kodem QR. Zaloguj się na komputerze hasłem.") from exc
    approved_by = R.s(login.get("judge_id")) or R.s(payload.get("judge_id")) or username
    wrapped = S.rsa_wrap(public_key, sealed)
    await database.execute(
        update(panel_web_qr_logins).where(panel_web_qr_logins.c.code == code)
        .where(panel_web_qr_logins.c.approved_by.is_(None)).where(panel_web_qr_logins.c.consumed_at.is_(None))
        .values(approved_by=approved_by, approved_at=_now(), username=username,
                sealed=wrapped, sealed_expires_at=sealed_expires, payload_json=json.loads(json.dumps(login, default=str)))
    )
    mine = await _row(code)
    if not mine or mine.get("sealed") != wrapped:
        # Ktoś zatwierdził ten kod chwilę wcześniej.
        raise _err(409, "QR_USED", "Ten kod został już użyty.")
    _APPROVE_LIMITER.success(limiter_key)
    ev = _qr_events.get(code)
    if ev:
        ev.set()
    return {"ok": True, "device_hint": R.device_hint(row.get("user_agent")),
            "display_name": R.s(login.get("display_name")).split("|")[0].strip(),
            "sealed_expires_at": sealed_expires}


# ─── JWT dla komputera ──────────────────────────────────────────────────────


class TokenBody(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    #: Szyfrogram pieczęci z odbioru kodu (`password` z `GET /auth/qr/{code}`).
    password: str = Field(min_length=1, max_length=2000)


@router.post("/auth/token")
async def token(body: TokenBody, request: Request):
    """Odpowiednik `/auth/login` dla komputera zalogowanego kodem - bez jawnego hasła."""
    key = f"token:{_address(request)}"
    if _TOKEN_LIMITER.blocked(key):
        raise _err(429, "RATE_LIMITED", "Za dużo prób naraz. Spróbuj za kilka minut.")
    private_key, _ = _keys()
    plain = _decrypt_plain(private_key, body.password)
    if not S.is_sealed(plain):
        _TOKEN_LIMITER.fail(key)
        raise _err(400, "NOT_SEALED", "Ta trasa przyjmuje tylko logowanie kodem QR.")
    try:
        data = S.unseal(plain, _secret())
    except S.SealError as exc:
        _TOKEN_LIMITER.fail(key)
        raise _err(401, "SESSION_EXPIRED", "Logowanie kodem wygasło. Zaloguj się ponownie kodem QR.") from exc
    try:
        res = await _jwt_login(body.username.strip(), data["p"])
    except HTTPException as exc:
        if exc.status_code == 401:
            raise _err(401, "BAD_CREDENTIALS", "ZPRP nie przyjął danych logowania. Zaloguj się ponownie kodem QR.") from exc
        raise _err(502, "LOGIN_DOWN", "Serwer ZPRP nie odpowiada. Spróbuj za moment.") from exc
    except Exception as exc:  # noqa: BLE001 - serwer ZPRP nie odpowiada
        raise _err(502, "LOGIN_DOWN", "Serwer ZPRP nie odpowiada. Spróbuj za moment.") from exc
    return {**res, "sealed_expires_at": datetime.fromtimestamp(int(data["e"]), tz=timezone.utc)}

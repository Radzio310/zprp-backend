# app/proel_zprp.py
#
# Proxy do oficjalnego API ProEl na baza.zprp.pl (/api/proel/v1/).
#
# Po co proxy, skoro aplikacja mogłaby wołać baza.zprp.pl sama: każde żądanie
# inicjujące sesję wymaga statycznego `app_key`, a klucz wkompilowany w APK
# jest kluczem publicznym — do wyjęcia jednym unzipem. `PROEL_APP_KEY` żyje
# więc wyłącznie w env na Railway i tylko ten moduł go dotyka. Aplikacja
# dostaje z powrotem `hash_sesji`, który sam w sobie daje dostęp tylko do
# JEDNEGO meczu.
#
# Dwa warianty autoryzacji upstreamu (dokumentacja v1.8):
#   A (token meczu):     {app_key, token_proel: "X8R2K", id_zawody: 0, nr_sedzia: ""}
#   B (mecz + sędzia):   {app_key, token_proel: "", id_zawody: 12345, nr_sedzia: "12345"}
# Sukces: {status: "success", message, hash_sesji, mecz_info: {IdZawody}}.
# Sesja jest przesuwna (+1 h na każde żądanie); wygaśnięcie → 401 SESSION_EXPIRED.
#
# Endpointy wysyłki wyników dojdą w API później — ten moduł jest projektowany
# tak, żeby dodanie ich było tylko kolejnym `_post_upstream`.

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Optional, Tuple

import httpx
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from app.proel_users import rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/proel/zprp", tags=["ProEl: ZPRP API"])

_UPSTREAM_TIMEOUT_S = 15.0

#: Token meczu: 5 znaków A–Z/0–9. Walidujemy PRZED żądaniem — literówka nie
#: powinna kosztować ani wywołania upstreamu, ani wpisu do limitera.
TOKEN_RE = re.compile(r"^[A-Z0-9]{5}$")

# Limity prób autoryzacji per IP. Token ma 36^5 ≈ 60 mln kombinacji — przy
# 40/h zgadywanie zajmuje ~170 lat, a prawdziwy użytkownik, który dwa razy
# machnął się w literce, nawet ich nie zauważy.
TOKEN_LIMITS = (("proel_auth_token_ip", 8, 60), ("proel_auth_token_ip_h", 40, 3600))
JUDGE_LIMITS = (("proel_auth_judge_ip", 20, 60),)


def _base_url() -> str:
    return (
        os.getenv("PROEL_ZPRP_BASE_URL", "https://baza.zprp.pl/api/proel/v1")
        .rstrip("/")
    )


async def _post_upstream(endpoint: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Jedyny punkt sieciowy modułu — testy podmieniają wyłącznie tę funkcję.

    Zwraca (status, json|{}). Wyjątki sieciowe przechodzą wyżej i są mapowane
    w `_call_upstream` — tu ich nie tykamy, żeby monkeypatch w testach mógł
    symulować także timeouty.
    """
    async with httpx.AsyncClient(timeout=_UPSTREAM_TIMEOUT_S) as client:
        resp = await client.post(f"{_base_url()}/{endpoint}", json=payload)
    try:
        data = resp.json()
    except Exception:
        data = {}
    return resp.status_code, data if isinstance(data, dict) else {}


async def _call_upstream(endpoint: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Wywołanie z mapowaniem błędów transportu na kody dla aplikacji."""
    try:
        return await _post_upstream(endpoint, payload)
    except httpx.TimeoutException:
        logger.warning("ProEl ZPRP upstream timeout endpoint=%s", endpoint)
        raise HTTPException(
            status_code=504,
            detail={"code": "UPSTREAM_TIMEOUT", "message": "Serwer ZPRP nie odpowiada. Spróbuj ponownie."},
        )
    except httpx.HTTPError as exc:
        logger.warning("ProEl ZPRP upstream network error endpoint=%s err=%s", endpoint, type(exc).__name__)
        raise HTTPException(
            status_code=502,
            detail={"code": "UPSTREAM_ERROR", "message": "Błąd połączenia z serwerem ZPRP."},
        )


def _client_ip(request: Optional[Request], forwarded: Optional[str]) -> str:
    # X-Forwarded-For: client, proxy1, proxy2 — bierzemy pierwszy (wzorzec
    # z app/beach/auth_email.py; na Railway to jedyne prawdziwe IP klienta).
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request is not None and request.client:
        return request.client.host or ""
    return ""


def _require_app_key() -> str:
    key = (os.getenv("PROEL_APP_KEY") or "").strip()
    if not key:
        # 503, nie 500: to brak konfiguracji po naszej stronie, a aplikacja ma
        # pokazać „chwilowo niedostępne", nie „błąd”.
        raise HTTPException(
            status_code=503,
            detail={"code": "PROEL_CONFIG", "message": "Integracja ZPRP nie jest skonfigurowana na serwerze."},
        )
    return key


class ZprpAuthRequest(BaseModel):
    """Wariant A: samo `token`. Wariant B: `id_zawody` + `nr_sedzia`."""

    token: Optional[str] = None
    id_zawody: Optional[int] = None
    nr_sedzia: Optional[str] = None


class ZprpLogoutRequest(BaseModel):
    hash_sesji: str


def _normalized_token(raw: Optional[str]) -> str:
    return (raw or "").strip().upper()


async def authorize(payload: ZprpAuthRequest, client_ip: str) -> Dict[str, Any]:
    """Rdzeń autoryzacji — wydzielony z trasy, żeby testował się bez FastAPI.

    Kolejność jest częścią zabezpieczenia: najpierw walidacja kształtu (zero
    kosztów), potem limiter (zapis próby NIEZALEŻNIE od wyniku — brute force
    liczy się próbami, nie sukcesami), dopiero na końcu upstream.
    """
    token = _normalized_token(payload.token)
    variant_a = bool(token)
    variant_b = payload.id_zawody is not None and bool(str(payload.nr_sedzia or "").strip())

    if not variant_a and not variant_b:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Podaj token meczu albo IdZawody z numerem sędziego."},
        )
    if variant_a and not TOKEN_RE.match(token):
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_TOKEN", "message": "Token meczu ma 5 znaków: litery i cyfry."},
        )

    app_key = _require_app_key()

    limits = TOKEN_LIMITS if variant_a else JUDGE_LIMITS
    for scope, limit, window in limits:
        await rate_limit.enforce(scope, client_ip, limit, window)
    for scope, _limit, _window in limits:
        await rate_limit.record(scope, client_ip)

    if variant_a:
        upstream_payload = {"app_key": app_key, "token_proel": token, "id_zawody": 0, "nr_sedzia": ""}
    else:
        upstream_payload = {
            "app_key": app_key,
            "token_proel": "",
            "id_zawody": int(payload.id_zawody or 0),
            "nr_sedzia": str(payload.nr_sedzia or "").strip(),
        }

    status, data = await _call_upstream("auth.php", upstream_payload)

    if status == 200 and str(data.get("status") or "").lower() == "success":
        mecz_info = data.get("mecz_info") or {}
        id_zawody = mecz_info.get("IdZawody")
        try:
            id_zawody = int(id_zawody)
        except (TypeError, ValueError):
            id_zawody = int(payload.id_zawody or 0) or None
        return {
            "status": "success",
            "hash_sesji": str(data.get("hash_sesji") or ""),
            "id_zawody": id_zawody,
            "message": str(data.get("message") or ""),
        }

    if status == 401:
        # Jednolity komunikat niezależnie od tego, CO było złe — informacja
        # „token istnieje, ale nie twój" byłaby prezentem dla zgadującego.
        raise HTTPException(
            status_code=401,
            detail={
                "code": "INVALID_CREDENTIALS",
                "message": "Nieprawidłowy token meczu."
                if variant_a
                else "Brak uprawnień do tego meczu.",
            },
        )
    if status == 403:
        # INVALID_APP_IDENTIFIER = zły app_key albo ProEl wyłączony po ich
        # stronie. To NASZ problem konfiguracyjny, nie użytkownika — stąd 502
        # i alarmowy log (sygnał do rotacji klucza).
        logger.error("ProEl ZPRP odrzucił app_key (INVALID_APP_IDENTIFIER) — sprawdź PROEL_APP_KEY")
        raise HTTPException(
            status_code=502,
            detail={"code": "PROEL_CONFIG", "message": "Serwer ZPRP odrzucił aplikację. Zgłoś to administratorowi BAZY."},
        )
    if status == 400:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Serwer ZPRP odrzucił żądanie (zła struktura)."},
        )

    logger.warning("ProEl ZPRP auth: nieoczekiwany status=%s", status)
    raise HTTPException(
        status_code=502,
        detail={"code": "UPSTREAM_ERROR", "message": "Nieoczekiwana odpowiedź serwera ZPRP."},
    )


async def close_session(hash_sesji: str) -> Dict[str, Any]:
    """Logout: 404 upstreamu to też sukces — sesja i tak jest martwa."""
    cleaned = (hash_sesji or "").strip()
    if not cleaned:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Brak hash_sesji."},
        )
    _require_app_key()
    status, _data = await _call_upstream("logout.php", {"hash_sesji": cleaned})
    if status == 200:
        return {"status": "success", "already_expired": False}
    if status == 404:
        return {"status": "success", "already_expired": True}
    logger.warning("ProEl ZPRP logout: nieoczekiwany status=%s", status)
    raise HTTPException(
        status_code=502,
        detail={"code": "UPSTREAM_ERROR", "message": "Nieoczekiwana odpowiedź serwera ZPRP."},
    )


@router.post(
    "/auth",
    summary="Autoryzacja meczu w ZPRP: token meczu (A) albo IdZawody+nr sędziego (B)",
)
async def zprp_auth(
    payload: ZprpAuthRequest,
    request: Request,
    x_forwarded_for: Optional[str] = Header(None),
):
    return await authorize(payload, _client_ip(request, x_forwarded_for))


@router.post(
    "/logout",
    summary="Zamknięcie sesji ZPRP (best-effort — wygasła też liczy się za sukces)",
)
async def zprp_logout(payload: ZprpLogoutRequest):
    return await close_session(payload.hash_sesji)

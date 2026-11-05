"""
Bramka klucza klienta - MIDDLEWARE (reguły: `app/client_key_rules.py`).

Czysty ASGI (bez BaseHTTPMiddleware, bez buforowania odpowiedzi, WebSockety
przechodzą bez zmian - egzamin na żywo uwierzytelnia się pierwszą ramką).
Montowany POD CORS (w main.py dodany przed CORSMiddleware), więc preflight
i odpowiedź 401 dostają nagłówki CORS jak każda inna.

Konfiguracja (Railway):
  CLIENT_KEYS      = web:<klucz>,app:<klucz>,www:<klucz>@/public/baza-stats|...
  CLIENT_KEY_MODE  = off | report | enforce   (bez kluczy zawsze off)
  CLIENT_KEY_OPEN  = /dodatkowa/sciezka,/inna (opcjonalnie)

W trybie `report` nic nie jest blokowane: liczymy, kto przyszedł bez klucza
(`GET /admin/client-key/report`, tylko administrator), żeby przed `enforce`
zobaczyć, czy żaden prawdziwy klient nie został za drzwiami.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import Counter
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends
from jose import JWTError, jwt

from app.client_key_rules import HEADER, QUERY_PARAM, Settings, decide, parse_settings

log = logging.getLogger("client_key")

_settings: Optional[Settings] = None
_report: Counter = Counter()
_clients: Counter = Counter()
_last_log: Dict[str, float] = {}
_LOG_EVERY_S = 3600.0


def current_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = parse_settings(
            os.getenv("CLIENT_KEY_MODE"), os.getenv("CLIENT_KEYS"), os.getenv("CLIENT_KEY_OPEN")
        )
        log.info("client-key: tryb=%s, klientow=%d", _settings.mode, len(_settings.keys))
    return _settings


def _token_valid(token: str) -> bool:
    """Czy to token wydany przez ten serwer: JWT BAZA (podpis; data ważności
    NIE jest wymagana - stara aplikacja z wygasłym tokenem to dalej nasz
    użytkownik, a trasa i tak sprawdza token po swojemu), token Beach albo
    token konta ProEl."""
    if not token:
        return False
    try:
        secret, alg = _jwt_secret()
        jwt.decode(token, secret, algorithms=[alg], options={"verify_exp": False, "verify_aud": False})
        return True
    except Exception:  # noqa: BLE001 - nie JWT BAZA, próbujemy dalej
        pass
    for verify in (_beach_verify, _proel_verify):
        try:
            if verify(token):
                return True
        except Exception:  # noqa: BLE001 - zły token = brak tokenu
            continue
    return False


def _jwt_secret() -> "tuple[str, str]":
    """Ten sam sekret co `app.deps.Settings` (env SECRET_KEY / ALGORITHM)."""
    secret = os.getenv("SECRET_KEY")
    alg = os.getenv("ALGORITHM")
    if secret and alg:
        return secret, alg
    from app.deps import get_settings

    s = get_settings()
    return s.SECRET_KEY, s.ALGORITHM


def _beach_verify(token: str) -> bool:
    from app.deps import beach_verify_access_token

    return bool(beach_verify_access_token(token))


def _proel_verify(token: str) -> bool:
    from app.proel_users.tokens import verify_access_token

    return bool(verify_access_token(token))


def _elevation_valid(token: str) -> bool:
    if not token:
        return False
    try:
        from app.proel_elevation import verify_elevation_token

        return bool(verify_elevation_token(token))
    except Exception:  # noqa: BLE001
        return False


def _bucket(path: str) -> str:
    """Grupa do raportu: dwa pierwsze segmenty (bez identyfikatorów)."""
    parts = [p for p in path.split("/") if p][:2]
    parts = ["{id}" if any(ch.isdigit() for ch in p) and len(p) > 3 else p for p in parts]
    return "/" + "/".join(parts)


class ClientKeyMiddleware:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        settings = current_settings()
        if settings.mode == "off":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
        presented = headers.get(HEADER)
        if not presented:
            qs = (scope.get("query_string") or b"").decode("latin-1")
            for part in qs.split("&"):
                name, _, value = part.partition("=")
                if name == QUERY_PARAM and value:
                    from urllib.parse import unquote

                    presented = unquote(value)
                    break
        auth = headers.get("authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not token:
            token = headers.get("x-admin-token", "").strip()
        path = scope.get("path") or "/"
        method = scope.get("method") or "GET"

        valid = (_token_valid(token) if token else False) or _elevation_valid(headers.get("x-elevation", "").strip())
        verdict = decide(settings, method, path, presented, valid)
        if verdict.reason.startswith("key:"):
            _clients[verdict.reason[4:]] += 1
        elif verdict.reason == "token":
            _clients["token"] += 1
        if verdict.would_block:
            b = f"{method} {_bucket(path)}"
            _report[b] += 1
            now = time.monotonic()
            if now - _last_log.get(b, -_LOG_EVERY_S) >= _LOG_EVERY_S:
                _last_log[b] = now
                log.warning(
                    "client-key %s: %s (ua=%s, origin=%s)",
                    "ZABLOKOWANE" if not verdict.allow else "bez klucza",
                    b,
                    headers.get("user-agent", "")[:120],
                    headers.get("origin", ""),
                )
        if verdict.allow:
            await self.app(scope, receive, send)
            return

        body = json.dumps(
            {
                "error": "CLIENT_KEY_REQUIRED",
                "code": "CLIENT_KEY_REQUIRED",
                "message": "Ten adres jest dostępny tylko z aplikacji BAZA, BAZA pod RĘKĄ albo po zalogowaniu.",
            },
            ensure_ascii=False,
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"application/json; charset=utf-8"), (b"cache-control", b"no-store")],
            }
        )
        await send({"type": "http.response.body", "body": body})


# ── Raport dla administratora ──────────────────────────────────────────────

router = APIRouter(prefix="/admin/client-key", tags=["Bezpieczeństwo"])


def _admin_dep():
    from app.access_control import require_app_admin

    return require_app_admin


@router.get("/report", summary="Kto przychodzi bez klucza klienta (od startu serwera)")
async def client_key_report(_admin: dict = Depends(_admin_dep())) -> Dict[str, Any]:
    s = current_settings()
    return {
        "mode": s.mode,
        "clients": sorted(s.names.values()),
        "allowed_by": dict(_clients.most_common()),
        "without_key": [{"route": k, "count": v} for k, v in _report.most_common(200)],
    }

# app/proel_users/tokens.py
#
# Tokeny dostępu kont ProEl — HMAC, wzorem beachowych z app/deps.py:145-224.
#
# Dwie ŚWIADOME różnice względem Beacha:
#
#  1. Payload niesie `aud: "proel"` i weryfikacja wymaga go TWARDO. Beach i
#     ProEl mogą (fallbackiem) dzielić sekret `SECRET_KEY`, a numeryczne `uid`
#     kolidują między tabelami — bez `aud` token beachowego użytkownika #7
#     uwierzytelniałby proelowego użytkownika #7. Beachowe tokeny nie mają
#     `aud` wcale, więc test `aud == "proel"` odcina je bez dotykania Beacha.
#
#  2. Sekret: PROEL_AUTH_SECRET → SECRET_KEY. CELOWO bez fallbacku do
#     BEACH_AUTH_SECRET — ustawienie beachowego sekretu nie może po cichu
#     zacząć podpisywać tokenów ProEla.

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Optional

from fastapi import Header, HTTPException

TOKEN_AUDIENCE = "proel"
_DEFAULT_TTL_SECONDS = 60 * 60 * 24 * 30  # 30 dni, jak w Beach


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _auth_secret() -> str:
    s = os.getenv("PROEL_AUTH_SECRET", "").strip()
    if s:
        return s
    s = os.getenv("SECRET_KEY", "").strip()
    if s:
        return s
    # Ostatnia deska w dev — na produkcji SECRET_KEY jest wymagany przez
    # Settings, więc tu nie trafimy.
    return "CHANGE_ME_PROEL_AUTH_SECRET"


def create_access_token(user_id: int, *, ttl_seconds: Optional[int] = None) -> str:
    """Token = payload_b64.sig_b64; payload {uid, iat, exp, v, aud}."""
    ttl_env = os.getenv("PROEL_AUTH_TOKEN_TTL_SECONDS", "").strip()
    ttl_default = int(ttl_env) if ttl_env.isdigit() else _DEFAULT_TTL_SECONDS
    ttl = int(ttl_seconds or ttl_default)

    now = int(time.time())
    payload = {
        "uid": int(user_id),
        "iat": now,
        "exp": now + ttl,
        "v": 1,
        "aud": TOKEN_AUDIENCE,
    }
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(_auth_secret().encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).digest()
    return f"{payload_b64}.{_b64url_encode(sig)}"


def verify_access_token(token: str) -> dict:
    try:
        payload_b64, sig_b64 = token.split(".", 1)
    except ValueError:
        raise HTTPException(status_code=401, detail="Niepoprawny token")

    expected = hmac.new(_auth_secret().encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url_encode(expected), sig_b64):
        raise HTTPException(status_code=401, detail="Niepoprawny token")

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=401, detail="Niepoprawny token")

    uid = payload.get("uid")
    if uid is None or not isinstance(uid, int):
        raise HTTPException(status_code=401, detail="Niepoprawny token")
    # Twarda bramka publiczności — patrz nagłówek modułu.
    if payload.get("aud") != TOKEN_AUDIENCE:
        raise HTTPException(status_code=401, detail="Niepoprawny token")
    if int(time.time()) >= int(payload.get("exp") or 0):
        raise HTTPException(status_code=401, detail="Token wygasł")
    return payload


def _bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, value = parts[0].strip().lower(), parts[1].strip()
    return value if scheme == "bearer" and value else None


async def proel_get_current_user_id(
    authorization: Optional[str] = Header(default=None),
) -> int:
    token = _bearer(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Brak autoryzacji")
    return int(verify_access_token(token)["uid"])


async def proel_get_optional_user_id(
    authorization: Optional[str] = Header(default=None),
) -> Optional[int]:
    token = _bearer(authorization)
    if not token:
        return None
    try:
        return int(verify_access_token(token)["uid"])
    except Exception:
        return None

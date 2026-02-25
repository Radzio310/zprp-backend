import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

# ====================================
# SETTINGS
# ====================================

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    # Core auth settings
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int

    # ZPRP application settings
    ZPRP_BASE_URL: str

    # Google OAuth2 Calendar
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    BACKEND_URL: str
    FRONTEND_DEEP_LINK: str

    # PEM prywatnego klucza RSA (multi-line stored as literal '\n')
    RSA_PRIVATE_KEY: str

# Dependency: settings singleton

def get_settings() -> Settings:
    return Settings()

# ====================================
# RSA KEYS
# ====================================

def get_rsa_keys():
    settings = get_settings()
    pem_str = settings.RSA_PRIVATE_KEY.replace('\\n', '\n')
    private_key = serialization.load_pem_private_key(
        data=pem_str.encode('utf-8'),
        password=None,
        backend=default_backend(),
    )
    public_key = private_key.public_key()
    return private_key, public_key

# ====================================
# AUTHENTICATION DEPENDENCY
# ====================================

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    """
    Dekoduje JWT i zwraca login użytkownika (pole 'sub').
    Jeśli token jest nieważny lub brak pola 'sub' → 401.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_login: str = payload.get("sub")
        if user_login is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return user_login

# =====================================================================
# BEACH (dodatek) — HMAC token auth jak w Twojej innej aplikacji
# - nie rusza JWT/OAuth2 z BAZA
# - używa Authorization: Bearer <token>
# =====================================================================

import base64
import hashlib
import hmac
import json
import time
from typing import Optional

from fastapi import Header


def _beach_b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

def _beach_b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _beach_auth_secret() -> str:
    """
    Sekret do HMAC tokenów BEACH.
    Preferuj env: BEACH_AUTH_SECRET
    Fallback: AUTH_SECRET (jeśli kiedyś dodasz)
    Fallback2: SECRET_KEY (z Twojego obecnego Settings) – żeby działało od razu
    """
    s = os.getenv("BEACH_AUTH_SECRET", "").strip()
    if s:
        return s
    s = os.getenv("AUTH_SECRET", "").strip()
    if s:
        return s
    try:
        return get_settings().SECRET_KEY
    except Exception:
        return "CHANGE_ME_BEACH_AUTH_SECRET"


def beach_create_access_token(user_id: int, *, ttl_seconds: Optional[int] = None) -> str:
    """
    Token = payload_b64.sig_b64
    payload: {uid, iat, exp, v}
    """
    ttl_env = os.getenv("BEACH_AUTH_TOKEN_TTL_SECONDS", "").strip()
    ttl_default = int(ttl_env) if ttl_env.isdigit() else (60 * 60 * 24 * 30)
    ttl = int(ttl_seconds or ttl_default)

    now = int(time.time())
    payload = {
        "uid": int(user_id),
        "iat": now,
        "exp": now + ttl,
        "v": 1,
    }

    payload_b64 = _beach_b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(
        _beach_auth_secret().encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    sig_b64 = _beach_b64url_encode(sig)

    return f"{payload_b64}.{sig_b64}"


def beach_verify_access_token(token: str) -> dict:
    try:
        payload_b64, sig_b64 = token.split(".", 1)
    except ValueError:
        raise HTTPException(status_code=401, detail="Niepoprawny token")

    expected_sig = hmac.new(
        _beach_auth_secret().encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    expected_sig_b64 = _beach_b64url_encode(expected_sig)

    if not hmac.compare_digest(expected_sig_b64, sig_b64):
        raise HTTPException(status_code=401, detail="Niepoprawny token")

    try:
        payload = json.loads(_beach_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=401, detail="Niepoprawny token")

    exp = int(payload.get("exp") or 0)
    uid = payload.get("uid")
    if uid is None or not isinstance(uid, int):
        raise HTTPException(status_code=401, detail="Niepoprawny token")

    if int(time.time()) >= exp:
        raise HTTPException(status_code=401, detail="Token wygasł")

    return payload


def _beach_get_bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, value = parts[0].strip().lower(), parts[1].strip()
    if scheme != "bearer" or not value:
        return None
    return value


async def beach_get_current_user_id(
    authorization: Optional[str] = Header(default=None),
) -> int:
    token = _beach_get_bearer_token(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Brak autoryzacji")
    payload = beach_verify_access_token(token)
    return int(payload["uid"])
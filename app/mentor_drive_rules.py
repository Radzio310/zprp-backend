"""Teczka pary (Dysk Google): reguły czyste - flaga, podpisany state, szyfrowanie tokenów, układ folderów, ponowienia.

Bez bazy i bez sieci (testowalne bez Postgresa).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse

SCOPE = "https://www.googleapis.com/auth/drive.file"
DEFAULT_REDIRECT = "https://zprp-backend-production.up.railway.app/mentor-panel/drive/callback"
DEFAULT_APP_ID = "1097952142834"
STATE_TTL_S = 900
LAYOUTS = ("match_category", "match", "category", "flat")
DEFAULT_LAYOUT = "match_category"
MAX_ATTEMPTS = 6
LEASE_S = 600
CHUNK = 8 * 1024 * 1024  # wielokrotność 256 KiB, jak chce resumable upload
BATCH_LIMIT = 50
MP4_WAIT = timedelta(hours=24)
ACTIVE_STATES = ("waiting_mp4", "queued", "working")
RETRY_DELAYS_S = (30, 120, 600, 1800, 7200, 21600)


def enabled() -> bool:
    return os.getenv("MENTOR_DRIVE_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")


def redirect_uri() -> str:
    return os.getenv("MENTOR_DRIVE_REDIRECT_URI", "").strip() or DEFAULT_REDIRECT


def app_id() -> str:
    return os.getenv("MENTOR_DRIVE_APP_ID", "").strip() or DEFAULT_APP_ID


# ─── state OAuth (podpisany, krótkotrwały) ───────────────────────────────────


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_state(payload: Dict[str, Any], secret: str, now: datetime, ttl_s: int = STATE_TTL_S) -> str:
    body = dict(payload)
    body["exp"] = int((now + timedelta(seconds=ttl_s)).timestamp())
    raw = _b64(json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    mac = hmac.new(secret.encode("utf-8"), f"mentor-drive-state:{raw}".encode("utf-8"), hashlib.sha256).digest()
    return f"{raw}.{_b64(mac)}"


def verify_state(token: Any, secret: str, now: datetime) -> Optional[Dict[str, Any]]:
    try:
        raw, mac = str(token or "").split(".", 1)
        want = hmac.new(secret.encode("utf-8"), f"mentor-drive-state:{raw}".encode("utf-8"), hashlib.sha256).digest()
        if not hmac.compare_digest(want, _unb64(mac)):
            return None
        body = json.loads(_unb64(raw).decode("utf-8"))
    except Exception:  # noqa: BLE001 - każdy śmieć to po prostu zły state
        return None
    if not isinstance(body, dict) or int(body.get("exp") or 0) < int(now.timestamp()):
        return None
    return body


def return_url_ok(url: Any) -> bool:
    """Dokąd wolno odesłać przeglądarkę po zgodzie: nasze domeny (https), localhost (dev) albo schemat aplikacji."""
    text = str(url or "").strip()
    if not text:
        return False
    parsed = urlparse(text)
    default = "bazapodreka.app,www.bazapodreka.app,bazaapp.online"
    hosts = {h.strip().lower() for h in os.getenv("MENTOR_DRIVE_RETURN_HOSTS", default).split(",") if h.strip()}
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "https":
        return host in hosts
    if parsed.scheme == "http":
        return host in ("localhost", "127.0.0.1")
    return parsed.scheme in ("baza", "bazaapp") and not parsed.username


def append_query(url: str, params: Dict[str, str]) -> str:
    base, _, frag = url.partition("#")
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{urlencode(params)}" + (f"#{frag}" if frag else "")


# ─── tokeny (AES-GCM) ────────────────────────────────────────────────────────


def token_key(secret: str) -> bytes:
    """Klucz z `MENTOR_DRIVE_TOKEN_KEY` (base64 32 B albo dowolne hasło), inaczej pochodna `SECRET_KEY`."""
    raw = os.getenv("MENTOR_DRIVE_TOKEN_KEY", "").strip()
    if raw:
        try:
            key = base64.b64decode(raw + "=" * (-len(raw) % 4))
            if len(key) == 32:
                return key
        except Exception:  # noqa: BLE001
            pass
        return hashlib.sha256(raw.encode("utf-8")).digest()
    return hashlib.sha256(f"mentor-drive-tokens:{secret}".encode("utf-8")).digest()


def seal_tokens(tokens: Dict[str, Any], key: bytes, aad: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    data = AESGCM(key).encrypt(nonce, json.dumps(tokens, separators=(",", ":")).encode("utf-8"), aad.encode("utf-8"))
    return base64.b64encode(b"\x01" + nonce + data).decode("ascii")


def unseal_tokens(blob: str, key: bytes, aad: str) -> Optional[Dict[str, Any]]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        raw = base64.b64decode(blob)
        if raw[:1] != b"\x01":
            return None
        data = json.loads(AESGCM(key).decrypt(raw[1:13], raw[13:], aad.encode("utf-8")).decode("utf-8"))
    except Exception:  # noqa: BLE001 - zły klucz / uszkodzone: traktujemy jak brak tokenu
        return None
    return data if isinstance(data, dict) else None


def token_fresh(tokens: Dict[str, Any], now: datetime, margin_s: int = 90) -> bool:
    try:
        return bool(tokens.get("access_token")) and float(tokens.get("expires_at") or 0) > now.timestamp() + margin_s
    except (TypeError, ValueError):
        return False


# ─── e-mail, nazwy, układ ────────────────────────────────────────────────────

_EMAIL = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


def clean_email(value: Any) -> Optional[str]:
    text = str(value or "").strip().lower()
    return text if len(text) <= 254 and _EMAIL.match(text) else None


def clean_layout(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    return text if text in LAYOUTS else None


def drive_name(value: Any, fallback: str = "Bez nazwy") -> str:
    text = re.sub(r"[\x00-\x1f]", " ", str(value or ""))
    text = re.sub(r"\s+", " ", text.replace("–", "-").replace("—", "-")).strip().strip(".")
    return text[:120] or fallback


def subpath(layout: str, match_label: Any, category: Any) -> List[str]:
    """Kolejne foldery pod folderem pary wg układu (`match_category` = mecz > kategoria)."""
    match, cat = drive_name(match_label, "Mecz"), drive_name(category, "Bez kategorii")
    return {"match_category": [match, cat], "match": [match], "category": [cat]}.get(layout, [])


def default_folder_name(names: List[str]) -> str:
    who = " i ".join(drive_name(n) for n in names if n)
    return drive_name(f"BAZA - Teczka pary: {who}" if who else "BAZA - Teczka pary")


def retry_delay(attempts: int) -> timedelta:
    return timedelta(seconds=RETRY_DELAYS_S[min(max(attempts, 1), len(RETRY_DELAYS_S)) - 1])


def classify(status: int, reason: str = "") -> str:
    """Co zrobić z błędem Google: `revoked` (trzeba połączyć ponownie), `folder` (folder zniknął / brak dostępu),
    `retry` (chwilowe), `fatal` (to zadanie się nie uda)."""
    reason = (reason or "").lower()
    if reason in ("invalid_grant", "unauthorized_client", "invalid_token", "autherror"):
        return "revoked"
    if status == 401:
        return "revoked"
    if status == 404:
        return "folder"
    if status == 403 and reason in ("insufficientfilepermissions", "insufficientpermissions", "forbidden", "appnotauthorizedtofile"):
        return "folder"
    if status in (0, 408, 429, 500, 502, 503, 504) or (status == 403 and any(k in reason for k in ("ratelimit", "quota", "userrate"))):
        return "retry"
    return "fatal"

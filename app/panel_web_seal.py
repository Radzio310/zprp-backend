"""
Panel okręgowy (/panel) - zapieczętowane hasło ZPRP po logowaniu kodem QR.

Moduł-liść: bez bazy, bez sieci, bez FastAPI.

Panel na komputerze woła trasy `/zprp/*`, `/baza_web/profile` i podobne, które
logują się do baza.zprp.pl danymi użytkownika. Przeglądarka szyfruje je kluczem
publicznym serwera (JSEncrypt, PKCS#1 v1.5), a trasa odszyfrowuje je kluczem
prywatnym z `deps.get_rsa_keys`.

Po logowaniu kodem QR przeglądarka nie zna hasła. Zatwierdzający telefon wysyła je
serwerowi (zaszyfrowane), a serwer oddaje stronie gotowy szyfrogram RSA, w którym
leży nie hasło, tylko „pieczęć”:

    "bzs1:" + base64url(nonce | AES-GCM({"p": hasło, "e": wygasa_unix}))

Klucz AES pochodzi z `SECRET_KEY`, więc pieczęć otworzy tylko ten serwer, a po
`SEAL_TTL` przestaje działać. Strona wysyła ten szyfrogram w polu `password`
dokładnie tam, gdzie dziś wysyła własny, więc żadnej trasy `/zprp/*` nie trzeba
zmieniać: `SealAwareKey.decrypt` otwiera pieczęć zamiast zwrócić ją jako hasło.

Uczciwie: pieczęć jest do wygaśnięcia równoważna hasłu dla tras, które go
używają (jak dziś hasło jawnym tekstem w pamięci przeglądarki - tylko krócej
i bez ujawniania samego hasła). Wylogowanie usuwa ją z przeglądarki.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SEAL_PREFIX = b"bzs1:"
SEAL_TTL = timedelta(hours=12)
_AAD = b"baza-panel-web-seal-v1"
#: PKCS#1 v1.5 przy kluczu 2048 bitów mieści 245 bajtów jawnego tekstu.
_RSA_PLAIN_MAX = 245


class SealError(ValueError):
    """Pieczęć nieczytelna albo przeterminowana (`reason`: `invalid` | `expired`)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _key(secret: str) -> bytes:
    return hashlib.sha256(("panel-web-seal:" + (secret or "")).encode("utf-8")).digest()


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def seal(password: str, secret: str, now: Optional[datetime] = None, ttl: timedelta = SEAL_TTL) -> tuple[bytes, datetime]:
    """Pieczęć (bajty z przedrostkiem `bzs1:`) i chwila jej wygaśnięcia."""
    stamp = now or datetime.now(timezone.utc)
    expires = stamp + ttl
    body = json.dumps({"p": password, "e": int(expires.timestamp())}, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(12)
    sealed = SEAL_PREFIX + _b64e(nonce + AESGCM(_key(secret)).encrypt(nonce, body, _AAD)).encode("ascii")
    if len(sealed) > _RSA_PLAIN_MAX:
        raise SealError("too_long")
    return sealed, expires


def unseal(sealed: bytes, secret: str, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Treść pieczęci `{"p": hasło, "e": wygasa_unix}`; `SealError`, gdy nieczytelna albo stara."""
    if not sealed.startswith(SEAL_PREFIX):
        raise SealError("invalid")
    try:
        raw = _b64d(sealed[len(SEAL_PREFIX):].decode("ascii"))
        body = AESGCM(_key(secret)).decrypt(raw[:12], raw[12:], _AAD)
        data = json.loads(body.decode("utf-8"))
        expires = int(data["e"])
        password = data["p"]
    except Exception as exc:  # noqa: BLE001 - zła sól, ucięty napis, cudza pieczęć
        raise SealError("invalid") from exc
    stamp = now or datetime.now(timezone.utc)
    if not isinstance(password, str) or expires <= int(stamp.timestamp()):
        raise SealError("expired")
    return data


def is_sealed(plain: bytes) -> bool:
    return isinstance(plain, (bytes, bytearray)) and bytes(plain).startswith(SEAL_PREFIX)


def rsa_wrap(public_key, plain: bytes) -> str:
    """Szyfrogram w formacie JSEncrypt (base64 z PKCS#1 v1.5) - tak, jak szyfruje strona."""
    return base64.b64encode(public_key.encrypt(plain, padding.PKCS1v15())).decode("ascii")


class SealAwareKey:
    """Klucz prywatny, który przy odszyfrowaniu otwiera też pieczęć panelu.

    Wszystko poza `decrypt` przechodzi do prawdziwego klucza bez zmian.
    """

    def __init__(self, inner, secret_getter):
        self._inner = inner
        self._secret_getter = secret_getter

    def decrypt(self, ciphertext, pad, *args, **kwargs):
        plain = self._inner.decrypt(ciphertext, pad, *args, **kwargs)
        if not is_sealed(plain):
            return plain
        data = unseal(bytes(plain), self._secret_getter())
        return data["p"].encode("utf-8")

    @property
    def inner(self):
        return self._inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

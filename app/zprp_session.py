"""Małe, bezstanowe helpery sesji HTML baza.zprp.pl.

Moduł celowo nie importuje bazy aplikacji. Pobieranie chronionego PDF-u nie
powinno uruchamiać modeli okręgowych ani wymagać Postgresa.
"""

import base64
import logging

from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import HTTPException
from httpx import AsyncClient

from app.utils import fetch_with_correct_encoding

logger = logging.getLogger(__name__)


def decrypt_field(enc_b64: str, private_key) -> str:
    try:
        cipher = base64.b64decode(enc_b64)
        plain = private_key.decrypt(cipher, padding.PKCS1v15())
        return plain.decode("utf-8")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Błąd deszyfrowania: {exc}") from exc


async def login_and_client(user: str, password: str, settings) -> AsyncClient:
    client = AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
    )
    response, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": user, "haslo": password, "from": "/index.php?"},
    )
    if "/index.php" not in response.url.path:
        await client.aclose()
        logger.error("Logowanie nie powiodło się dla user %s", user)
        raise HTTPException(status_code=401, detail="Logowanie nie powiodło się")
    client.cookies.update(response.cookies)
    return client

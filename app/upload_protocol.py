# app/upload_protocol.py

import logging
import base64
from typing import Optional

from fastapi import (
    APIRouter,
    HTTPException,
    Depends,
    UploadFile,
    File,
    Form,
    status,
)
from httpx import AsyncClient
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from app.deps import get_settings, get_rsa_keys, Settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Protocol"])


def _decrypt_field(enc_b64: str, private_key) -> str:
    """
    Odszyfrowuje pole zaszyfrowane RSA+Base64 (tak jak w ShortResultRequest).
    """
    try:
        cipher = base64.b64decode(enc_b64)
        plain = private_key.decrypt(
            cipher,
            padding.PKCS1v15(),
        )
        return plain.decode("utf-8")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Błąd deszyfrowania: {e}",
        )


async def _login_and_client(user: str, pwd: str, settings: Settings) -> AsyncClient:
    """
    Logowanie do ZPRP z użyciem httpx.AsyncClient, analogicznie jak w results.py.
    """
    client = AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True,
    )
    from app.utils import fetch_with_correct_encoding  # lokalny import, żeby uniknąć pętli

    resp_login, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": user, "haslo": pwd, "from": "/index.php?"},
    )
    if "/index.php" not in resp_login.url.path:
        await client.aclose()
        logger.error("Logowanie nie powiodło się dla user %s", user)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Logowanie do ZPRP nie powiodło się",
        )

    client.cookies.update(resp_login.cookies)
    return client


async def _send_protocol_attachment(
    client: AsyncClient,
    match_id: str,
    user: str,
    upload_file: UploadFile,
) -> None:
    """
    Wysyła załącznik (PDF/JPG) do formularza 'zawody_dodaj_zalacznik.php' w systemie ZPRP.

    Odwzorowuje formularz:

        <form action="zawody_dodaj_zalacznik.php" method="post"
              enctype="multipart/form-data">
          <input type="hidden" name="IdZawody" value="...">
          <input type="hidden" name="user" value="...">
          <input type="file" name="zalacznik" accept="image/jpeg,application/pdf">
          <input type="submit" name="przycisk" value="ZAPISZ">
        </form>
    """
    # 1) Walidacja typu MIME
    allowed_mime_types = {"application/pdf", "image/jpeg"}
    content_type: Optional[str] = upload_file.content_type

    if content_type not in allowed_mime_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Nieobsługiwany typ pliku: {content_type}. "
                f"Dozwolone: PDF (application/pdf) lub JPG (image/jpeg)."
            ),
        )

    # 2) Odczyt pliku do pamięci
    try:
        file_bytes = await upload_file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Nie udało się odczytać pliku: {exc}",
        )

    if not file_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Przesłany plik jest pusty.",
        )

    filename = upload_file.filename or "zalacznik"

    data = {
        "IdZawody": str(match_id),
        "user": user,
        "przycisk": "ZAPISZ",
    }

    files = {
        "zalacznik": (
            filename,
            file_bytes,
            content_type or "application/octet-stream",
        )
    }

    # 3) Wysłanie formularza do ZPRP
    try:
        resp = await client.post(
            "/zawody_dodaj_zalacznik.php",
            data=data,
            files=files,
        )
    except Exception as exc:
        logger.error("Błąd połączenia z ZPRP podczas wysyłki załącznika: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Błąd połączenia z serwerem ZPRP podczas wysyłki: {exc}",
        )

    # 4) Interpretacja odpowiedzi HTML
    text = resp.content.decode("iso-8859-2", errors="replace")

    if resp.status_code != 200:
        logger.error(
            "ZPRP zwrócił status %s przy dodawaniu załącznika: %s",
            resp.status_code,
            text[:200],
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Serwer ZPRP zwrócił status {resp.status_code} "
                f"przy dodawaniu załącznika."
            ),
        )

    # TODO: dostosuj warunek sukcesu do realnej odpowiedzi ZPRP, jeśli będzie inna.
    if "Załącznik zapisany" not in text and "Załącznik dodany" not in text:
        logger.error(
            "Nie udało się potwierdzić zapisu załącznika w ZPRP. Fragment odpowiedzi: %s",
            text[:300],
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "Nie udało się potwierdzić, że załącznik został zapisany "
                "w systemie ZPRP."
            ),
        )


@router.post(
    "/judge/protocol/upload",
    summary="Wyślij protokół meczu (PDF/JPG) do systemu ZPRP z pełnym szyfrowaniem",
)
async def upload_protocol(
    # wszystkie pola tekstowe przychodzą zaszyfrowane RSA+Base64 tak jak w ShortResultRequest
    username: str = Form(..., description="Zaszyfrowany login (Base64-RSA)"),
    password: str = Form(..., description="Zaszyfrowane hasło (Base64-RSA)"),
    judge_id: str = Form(..., description="Zaszyfrowane ID sędziego (Base64-RSA)"),
    match_id: str = Form(..., description="Zaszyfrowane IdZawody (Base64-RSA)"),
    details_path: Optional[str] = Form(
        None,
        description="Zaszyfrowana ścieżka szczegółów meczu (opcjonalnie, Base64-RSA)",
    ),
    attachment: UploadFile = File(
        ...,
        description="Plik PDF/JPG z protokołem meczu",
    ),
    settings: Settings = Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Endpoint wywoływany z aplikacji mobilnej.

    Front używa `prepareEncryptedPayload`, więc:
      - username, password, judge_id, match_id, details_path
        są zaszyfrowane RSA i zakodowane Base64.
      - attachment to multipartowy plik (UploadFile).

    1. Odszyfrowuje poświadczenia.
    2. Loguje do ZPRP za pomocą httpx.AsyncClient.
    3. W tej samej sesji wysyła formularz `zawody_dodaj_zalacznik.php` z:
       - IdZawody = odszyfrowany `match_id`
       - user = odszyfrowany `username`
       - zalacznik = przesłany plik
       - przycisk = "ZAPISZ"
    4. Po wykryciu sukcesu zwraca JSON { "success": true, ... }.
    """
    private_key, _ = keys

    # 1) Deszyfrowanie pól tekstowych
    try:
        user_plain = _decrypt_field(username, private_key)
        pass_plain = _decrypt_field(password, private_key)
        judge_plain = _decrypt_field(judge_id, private_key)  # na razie tylko do logów / spójności
        match_id_plain = _decrypt_field(match_id, private_key)
        details_path_plain = (
            _decrypt_field(details_path, private_key) if details_path else None
        )
    except HTTPException:
        # błąd deszyfrowania został już opakowany w HTTPException
        raise

    logger.info(
        "upload_protocol: user=%s, judge_id=%s, match_id=%s, details_path=%s",
        user_plain,
        judge_plain,
        match_id_plain,
        details_path_plain,
    )

    # 2) Logowanie do ZPRP + wysyłka załącznika
    client: Optional[AsyncClient] = None
    try:
        client = await _login_and_client(user_plain, pass_plain, settings)

        await _send_protocol_attachment(
            client=client,
            match_id=match_id_plain,
            user=user_plain,
            upload_file=attachment,
        )
    except HTTPException:
        # przekaż dalej HTTPException (status + detail)
        raise
    except Exception as e:
        logger.error("upload_protocol: nieoczekiwany błąd: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Nie udało się wysłać protokołu: {e}",
        )
    finally:
        if client is not None:
            try:
                await client.aclose()
            except Exception:
                pass

    # 3) Sukces – spójny format z innymi endpointami /judge/*
    return {
        "success": True,
        "filename": attachment.filename,
    }

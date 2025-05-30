import logging
import base64
import re

from fastapi import APIRouter, Form, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from httpx import AsyncClient

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from app.deps import get_settings, get_rsa_keys
from app.utils import fetch_with_correct_encoding

# skonfiguruj logger
logger = logging.getLogger("edit_photo")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

router = APIRouter(prefix="/judge", tags=["judge"])


def decrypt_field(private_key, enc_b64: str) -> str:
    try:
        cipher = base64.b64decode(enc_b64)
        plain = private_key.decrypt(cipher, padding=padding.PKCS1v15())
        text = plain.decode("utf-8")
        logger.debug(f"Decrypted field to: {text}")
        return text
    except Exception as e:
        logger.error(f"Decryption error for field: {e}")
        raise HTTPException(status_code=400, detail=f"Decryption error: {e}")


async def authenticate(client: AsyncClient, settings, username: str, password: str):
    """
    Loguje się do ZPRP i ładuje ciasteczka do client.cookies.
    """
    logger.debug(f"Logging in as '{username}' to {settings.ZPRP_BASE_URL}/login.php")
    resp, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": username, "haslo": password, "from": "/index.php?"},
    )
    logger.debug(f"Login response URL: {resp.url} status: {resp.status_code}")

    if "/index.php" not in resp.url.path:
        logger.error("Login failed, did not redirect to index.php")
        raise HTTPException(status_code=401, detail="Logowanie nie powiodło się")

    # Załaduj ciasteczka do wewnętrznego „jar” klienta
    client.cookies.update(resp.cookies)
    logger.debug(f"Session cookies after login: {client.cookies.get_dict()}")


@router.post(
    "/photo",
    summary="Upload & replace judge photo on baza.zprp.pl",
    status_code=status.HTTP_200_OK,
)
async def upload_judge_photo(
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    foto: str = Form(...),  # "data:image/jpeg;base64,..." lub czysty base64
    settings=Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    # 1) odszyfruj dane
    user_plain = decrypt_field(private_key, username)
    pass_plain = decrypt_field(private_key, password)
    judge_plain = decrypt_field(private_key, judge_id)

    # 2) dekoduj obraz
    _, _, b64data = foto.partition("base64,")
    try:
        image_bytes = base64.b64decode(b64data or foto)
        logger.debug(f"Decoded image: {len(image_bytes)} bytes")
    except Exception as e:
        logger.error(f"Base64 decode error: {e}")
        raise HTTPException(status_code=400, detail="Niepoprawny format obrazka")

    # 3) użyj jednego klienta z follow_redirects i utrzymaj ciasteczka
    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True
    ) as client:
        # 3a) logowanie i załadowanie ciasteczek
        await authenticate(client, settings, user_plain, pass_plain)

        # 3b) upload pliku
        logger.debug("Uploading image to sedzia_foto_dodaj3.php …")
        files = {"foto": ("profile.jpg", image_bytes, "image/jpeg")}
        data = {"NrSedzia": judge_plain, "user": user_plain}
        upload_resp = await client.post(
            "/sedzia_foto_dodaj3.php",
            data=data,
            files=files,
            headers={"Accept": "text/html"},
        )
        logger.debug(f"Upload status: {upload_resp.status_code}")
        logger.debug(f"Upload response snippet: {upload_resp.text[:200]!r}")

        text = upload_resp.text.lower()
        if upload_resp.status_code != 200 or "zdjęcie zostało zapisane" not in text:
            detail = "Upload nie powiódł się"
            if "error" in text:
                snippet = text.split("error", 1)[1][:200]
                detail += f": {snippet}"
                logger.error(f"Detected error fragment: {snippet!r}")
            raise HTTPException(status_code=500, detail=detail)

        # 3c) fetch strony edycji, by wyciągnąć nowy src
        logger.debug("Fetching profile edit page …")
        profile_resp = await client.get(
            f"/index.php?a=sedzia&b=edycja&NrSedzia={judge_plain}"
        )
        logger.debug(f"Profile page status: {profile_resp.status_code}")
        html = profile_resp.text
        logger.debug(f"Profile HTML snippet: {html[:200]!r}")

    # 4) regex do <img src="foto_sedzia/...">
    m = re.search(r'<img[^>]+src="(foto_sedzia/[^"]+)"', html)
    if not m:
        logger.warning("Could not find <img src='foto_sedzia/...'> in profile HTML")
        return JSONResponse({"success": True})

    photo_path = m.group(1)
    photo_url = settings.ZPRP_BASE_URL.rstrip("/") + "/" + photo_path.lstrip("/")
    logger.info(f"New photo URL: {photo_url}")

    return JSONResponse({"success": True, "photo_url": photo_url})

import logging
import base64
import re

from fastapi import APIRouter, Form, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from httpx import AsyncClient
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.asymmetric import padding

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
    resp, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": username, "haslo": password, "from": "/index.php?"},
    )
    if "/index.php" not in resp.url.path:
        raise HTTPException(status_code=401, detail="Logowanie nie powiodło się")

    client.cookies.update(resp.cookies)
    logger.debug(f"Session cookies: {dict(client.cookies)}")


@router.post("/photo", status_code=status.HTTP_200_OK)
async def upload_judge_photo(
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    foto: str = Form(...),
    settings=Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    # 1) odszyfruj
    user_plain = decrypt_field(private_key, username)
    pass_plain = decrypt_field(private_key, password)
    judge_plain = decrypt_field(private_key, judge_id)

    # 2) przygotuj obrazek
    _, _, b64data = foto.partition("base64,")
    try:
        image_bytes = base64.b64decode(b64data or foto)
    except Exception:
        raise HTTPException(status_code=400, detail="Niepoprawny format obrazka")

    # 3) logowanie + upload + pobranie strony edycji
    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True
    ) as client:
        await authenticate(client, settings, user_plain, pass_plain)

        # upload
        files = {"foto": ("profile.jpg", image_bytes, "image/jpeg")}
        data = {"NrSedzia": judge_plain, "user": user_plain}
        upload_resp = await client.post(
            "/sedzia_foto_dodaj3.php",
            data=data,
            files=files,
            headers={"Accept": "text/html"},
        )
        if upload_resp.status_code != 200:
            text = await upload_resp.aread()
            raise HTTPException(status_code=500, detail=f"Upload error HTTP {upload_resp.status_code}")

        # fetch edit page
        profile_resp = await client.get(f"/index.php?a=sedzia&b=edycja&NrSedzia={judge_plain}")
        if profile_resp.status_code != 200:
            raise HTTPException(status_code=500, detail="Nie udało się pobrać strony edycji")

        html = profile_resp.text

    # 4) znajdź tag <img> z foto_sedzia
    soup = BeautifulSoup(html, "html.parser")
    img = soup.find("img", src=re.compile(r"foto_sedzia", re.IGNORECASE))
    if not img or not img.get("src"):
        raise HTTPException(status_code=500, detail="Nie znaleziono zaktualizowanego zdjęcia")

    src = img["src"]
    # obsłuż zarówno relatywną, jak i absolutną ścieżkę
    if src.lower().startswith("http"):
        photo_url = src
    else:
        photo_url = settings.ZPRP_BASE_URL.rstrip("/") + "/" + src.lstrip("/")

    logger.info(f"New photo URL: {photo_url}")
    return JSONResponse({"success": True, "photo_url": photo_url})

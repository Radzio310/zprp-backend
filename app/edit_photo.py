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
        return plain.decode("utf-8")
    except Exception as e:
        logger.error("Decrypt error", exc_info=e)
        raise HTTPException(status_code=400, detail="Decryption error")


async def authenticate(client: AsyncClient, settings, username: str, password: str):
    resp, _ = await fetch_with_correct_encoding(
        client, "/login.php", method="POST",
        data={"login": username, "haslo": password, "from": "/index.php?"}
    )
    if "/index.php" not in resp.url.path:
        raise HTTPException(status_code=401, detail="Logowanie nie powiodło się")
    client.cookies.update(resp.cookies)


@router.post("/photo", status_code=status.HTTP_200_OK)
async def upload_judge_photo(
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    foto: str = Form(...),  # base64 z Croppie
    settings=Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    # 1) Odszyfruj pola
    user_plain = decrypt_field(private_key, username)
    pass_plain = decrypt_field(private_key, password)
    judge_plain = decrypt_field(private_key, judge_id)

    # 2) Base64 → bajty (dla POSTa "KADRUJ" nie potrzebujemy)
    _, _, b64data = foto.partition("base64,")
    try:
        image_bytes = base64.b64decode(b64data or foto)
    except Exception:
        raise HTTPException(status_code=400, detail="Niepoprawny format obrazka")

    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True
    ) as client:
        # A) Zaloguj się i zachowaj cookies
        await authenticate(client, settings, user_plain, pass_plain)

        # B) Krok I: wyślij plik do croppie-temp (button=KADRUJ)
        files1 = {"foto": ("upload.jpg", image_bytes, "image/jpeg")}
        data1 = {
            "NrSedzia": judge_plain,
            "user": user_plain,
            "button": "KADRUJ",
        }
        resp1 = await client.post(
            "/sedzia_foto_dodaj3.php",
            data=data1,
            files=files1,
            headers={"Accept": "text/html"},
        )
        if resp1.status_code != 200:
            raise HTTPException(status_code=500, detail=f"Stage 1 upload failed ({resp1.status_code})")

        html1 = resp1.text

        # C) Parsuj ścieżkę do tymczasowego obrazka z Croppie
        # Użyj bardziej elastycznego regexu by wychwycić bind i URL
        m = re.search(r"'bind'\s*,\s*\{\s*url\s*:\s*'([^']+)'", html1)
        if not m:
            # Prostsze dopasowanie samej ścieżki foto_sedzia_temp
            m = re.search(r"(foto_sedzia_temp/[^'\"\s]+)", html1)
        if not m:
            logger.error("Could not find croppie temp URL in HTML:\n%s", html1[:500])
            raise HTTPException(status_code=500, detail="Nie udało się wczytać Croppie")

        temp_path = m.group(1)
        logger.debug("Croppie temp image: %s", temp_path)

        # D) Krok II: wyślij base64 do finalnego zapisu (button=ZAPISZ)
        data2 = {
            "NrSedzia": judge_plain,
            "user": user_plain,
            "foto": foto,
            "button": "ZAPISZ",
        }
        resp2 = await client.post(
            "/sedzia_foto_dodaj3.php",
            data=data2,
            headers={"Accept": "text/html"},
        )
        if resp2.status_code != 200:
            raise HTTPException(status_code=500, detail=f"Stage 2 save failed ({resp2.status_code})")

        # E) Fetch strony edycji, by wyciągnąć finalne <img>
        prof = await client.get(f"/index.php?a=sedzia&b=edycja&NrSedzia={judge_plain}")
        if prof.status_code != 200:
            raise HTTPException(status_code=500, detail="Nie udało się pobrać strony edycji")

        soup = BeautifulSoup(prof.text, "html.parser")
        img = soup.find("img", src=re.compile(r"foto_sedzia/"))
        if not img or not img.get("src"):
            raise HTTPException(status_code=500, detail="Nie znaleziono finalnego zdjęcia")

        src = img["src"]
        if src.lower().startswith("http"):
            photo_url = src
        else:
            photo_url = settings.ZPRP_BASE_URL.rstrip("/") + "/" + src.lstrip("/")

    return JSONResponse({"success": True, "photo_url": photo_url})
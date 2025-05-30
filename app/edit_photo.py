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


@router.post("/photo", status_code=200)
async def upload_judge_photo(
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    foto: str = Form(...),
    settings=Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys
    # 1) decrypt as before
    user_plain = decrypt_field(private_key, username)
    pass_plain = decrypt_field(private_key, password)
    judge_plain = decrypt_field(private_key, judge_id)

    # 2) decode image bytes
    _, _, b64data = foto.partition("base64,")
    try:
        image_bytes = base64.b64decode(b64data or foto)
    except Exception:
        raise HTTPException(400, "Niepoprawny format obrazka")

    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        follow_redirects=True
    ) as client:
        # A) login & load cookies
        await authenticate(client, settings, user_plain, pass_plain)

        # B) First GET the upload form so we know its fields & file-input name
        form_page, html = await fetch_with_correct_encoding(
            client,
            f"/sedzia_foto_dodaj1.php?NrSedzia={judge_plain}",
            method="GET"
        )
        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form", {"id": "form_foto"})  # adjust selector if needed
        if not form:
            raise HTTPException(500, "Nie znalazłem formularza uploadu zdjęcia")

        # C) pull out all hidden/text inputs
        form_fields: dict[str,str] = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name: continue
            typ = inp.get("type", "text")
            if typ in ("hidden","text","password"):
                form_fields[name] = inp.get("value","")

        # D) find the <input type="file" name="...">
        file_input = form.find("input", {"type": "file"})
        if not file_input or not file_input.get("name"):
            raise HTTPException(500, "Formularz nie ma pola file!")
        file_field_name = file_input["name"]

        # E) POST back _all_ fields + file
        files = {
            file_field_name: ("profile.jpg", image_bytes, "image/jpeg")
        }
        resp = await client.post(
            form["action"],   # the URL from the form’s action
            data=form_fields,
            files=files,
            headers={"Accept":"text/html"},
        )
        if resp.status_code != 200:
            raise HTTPException(500, f"Upload error {resp.status_code}")

        # F) fetch edit page & extract new src exactly as before
        profile_resp = await client.get(
            f"/index.php?a=sedzia&b=edycja&NrSedzia={judge_plain}"
        )
        soup2 = BeautifulSoup(profile_resp.text, "html.parser")
        img = soup2.find("img", src=re.compile(r"foto_sedzia", re.IGNORECASE))
        if not img:
            raise HTTPException(500, "Nie znaleziono zaktualizowanego zdjęcia")
        src = img["src"]
        photo_url = src.startswith("http") and src or settings.ZPRP_BASE_URL.rstrip("/") + "/" + src.lstrip("/")

    return {"success": True, "photo_url": photo_url}

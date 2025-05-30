# app/edit_photo.py

from fastapi import APIRouter, Form, HTTPException, Depends, status
from httpx import AsyncClient
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import re

from fastapi.responses import JSONResponse

from app.deps import get_settings, get_rsa_keys
from app.utils import fetch_with_correct_encoding

router = APIRouter(prefix="/judge", tags=["judge"])


def decrypt_field(private_key, enc_b64: str) -> str:
    """Decrypt a base64-encoded RSA-encrypted field."""
    try:
        cipher = base64.b64decode(enc_b64)
        plain = private_key.decrypt(cipher, padding.PKCS1v15())
        return plain.decode("utf-8")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption error: {e}")


async def authenticate(
    client: AsyncClient, settings, username: str, password: str
) -> dict:
    """
    Log in to baza.zprp.pl via their PHP login form,
    return cookies for authenticated session.
    """
    resp, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": username, "haslo": password, "from": "/index.php?"},
    )
    # on successful login, they redirect into index.php
    if "/index.php" not in resp.url.path:
        raise HTTPException(status_code=401, detail="Logowanie nie powiodło się")
    return dict(resp.cookies)


@router.post(
    "/photo",
    summary="Upload & replace judge photo on baza.zprp.pl",
    status_code=status.HTTP_200_OK,
)
async def upload_judge_photo(
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    foto: str = Form(...),  # "data:image/jpeg;base64,..." or raw base64
    settings=Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    # 1) decrypt credentials & judge ID
    user_plain = decrypt_field(private_key, username)
    pass_plain = decrypt_field(private_key, password)
    judge_plain = decrypt_field(private_key, judge_id)

    # 2) extract raw JPEG bytes
    _, _, b64data = foto.partition("base64,")
    image_bytes = base64.b64decode(b64data or foto)

    # 3) open an HTTPX client to baza.zprp.pl
    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL, follow_redirects=True
    ) as client:

        # 3a) login
        cookies = await authenticate(client, settings, user_plain, pass_plain)

        # 3b) POST multipart to sedzia_foto_dodaj3.php
        files = {"foto": ("profile.jpg", image_bytes, "image/jpeg")}
        data = {"NrSedzia": judge_plain, "user": user_plain}
        upload_resp = await client.post(
            "/sedzia_foto_dodaj3.php",
            data=data,
            files=files,
            cookies=cookies,
            headers={"Accept": "text/html"},
        )

        # if not HTTP 200 or the returned HTML doesn't show success
        text = upload_resp.text.lower()
        if upload_resp.status_code != 200 or "zdjęcie zostało zapisane" not in text:
            detail = "Upload nie powiódł się"
            # if the page contains an error fragment, include it
            if "error" in text:
                detail += ": " + text.split("error", 1)[1][:200]
            raise HTTPException(status_code=500, detail=detail)

        # 3c) fetch the judge's profile page to extract the new photo URL
        profile_resp = await client.get(
            f"/?a=sedzia&b=edycja&NrSedzia={judge_plain}", cookies=cookies
        )
        html = profile_resp.text

    # 4) extract the <img src="foto_sedzia/..."> from the edit form
    m = re.search(r'<img[^>]+src="(foto_sedzia/[^"]+)"', html)
    if not m:
        # Couldn't find it, but upload succeeded
        return JSONResponse({"success": True})

    photo_path = m.group(1)
    photo_url = (
        settings.ZPRP_BASE_URL.rstrip("/") + "/" + photo_path.lstrip("/")
    )

    # 5) return success + new URL
    return JSONResponse({"success": True, "photo_url": photo_url})

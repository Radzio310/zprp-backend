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
    Log in to baza.zprp.pl via their PHP form.
    Returns the session cookies.
    """
    resp, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": username, "haslo": password, "from": "/index.php?"},
    )
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
    foto: str = Form(...),  # data:image/jpeg;base64,... or raw base64
    settings=Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    # 1) Decrypt incoming credentials and judge ID
    user_plain = decrypt_field(private_key, username)
    pass_plain = decrypt_field(private_key, password)
    judge_plain = decrypt_field(private_key, judge_id)

    # 2) Strip off any "data:image/..." prefix and base64-decode
    _, _, b64data = foto.partition("base64,")
    image_bytes = base64.b64decode(b64data or foto)

    # 3) Use HTTPX to drive the exact PHP flow on baza.zprp.pl
    async with AsyncClient(
        base_url=settings.ZPRP_BASE_URL, follow_redirects=True
    ) as client:
        # a) authenticate
        cookies = await authenticate(client, settings, user_plain, pass_plain)

        # b) upload/crop endpoint
        data = {"NrSedzia": judge_plain, "user": user_plain}
        files = {"foto": ("profile.jpg", image_bytes, "image/jpeg")}
        upload_resp = await client.post(
            "/sedzia_foto_dodaj3.php",
            data=data,
            files=files,
            cookies=cookies,
            headers={"Accept": "text/html"},
        )
        text_lower = upload_resp.text.lower()
        if upload_resp.status_code != 200 or "zdjęcie zostało zapisane" not in text_lower:
            detail = "Upload nie powiódł się"
            if "error" in text_lower:
                snippet = text_lower.split("error", 1)[1][:200]
                detail += f": {snippet}"
            raise HTTPException(status_code=500, detail=detail)

        # c) fetch the edit-profile page to grab the new <img src=...>
        profile_resp = await client.get(
            f"/?a=sedzia&b=edycja&NrSedzia={judge_plain}", cookies=cookies
        )
        html = profile_resp.text

    # 4) Extract the new photo path from the IMG tag
    m = re.search(r'<img[^>]+src="(foto_sedzia/[^"]+)"', html)
    if not m:
        # upload succeeded but we couldn't parse the new URL
        return JSONResponse({"success": True})

    photo_path = m.group(1)
    photo_url = settings.ZPRP_BASE_URL.rstrip("/") + "/" + photo_path.lstrip("/")

    # 5) Return success + the fresh URL
    return JSONResponse({"success": True, "photo_url": photo_url})

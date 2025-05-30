# app/edit_photo.py
from fastapi import APIRouter, Form, HTTPException, Depends, status
from httpx import AsyncClient
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import io

from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder

from app.deps import get_settings, get_rsa_keys
from app.utils import fetch_with_correct_encoding

router = APIRouter(prefix="/judge", tags=["judge"])


def decrypt_field(private_key, enc_b64: str) -> str:
    try:
        cipher = base64.b64decode(enc_b64)
        plain = private_key.decrypt(cipher, padding.PKCS1v15())
        return plain.decode()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption error: {e}")


async def authenticate(client: AsyncClient, settings, user_plain: str, pass_plain: str):
    resp, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": user_plain, "haslo": pass_plain, "from": "/index.php?"},
    )
    if "/index.php" not in resp.url.path:
        raise HTTPException(status_code=401, detail="Logowanie nie powiodło się")
    return dict(resp.cookies)


@router.post(
    "/photo",
    summary="Upload & crop new judge photo (base64)",
    status_code=status.HTTP_200_OK,
)
async def upload_judge_photo(
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    foto: str = Form(...),  # base64 JPEG string
    settings=Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    # odszyfrowanie pól
    user_plain = decrypt_field(private_key, username)
    pass_plain = decrypt_field(private_key, password)
    judge_plain = decrypt_field(private_key, judge_id)

    # wydobycie czystego base64 (usuń prefix data:image/jpeg;base64, jeśli jest)
    header, _, b64data = foto.partition("base64,")
    data = base64.b64decode(b64data or foto)

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True) as client:
        cookies = await authenticate(client, settings, user_plain, pass_plain)

        # przygotuj multipart → sedzia_foto_dodaj3.php
        files = {
            "foto": ("profile.jpg", data, "image/jpeg"),
        }
        form = {
            "NrSedzia": judge_plain,
            "user": user_plain,
        }
        resp = await client.post(
            "/sedzia_foto_dodaj3.php",
            data=form,
            files=files,
            cookies=cookies,
            headers={"Accept": "text/html"},
        )
        if resp.status_code != 200 or "error" in resp.text.lower():
            raise HTTPException(status_code=500, detail="Upload nie powiódł się")

    return JSONResponse({"success": True})

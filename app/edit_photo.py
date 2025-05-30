from fastapi import APIRouter, File, UploadFile, Form, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from httpx import AsyncClient
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

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
    # logowanie
    resp, _ = await fetch_with_correct_encoding(
        client,
        "/login.php",
        method="POST",
        data={"login": user_plain, "haslo": pass_plain, "from": "/index.php?"},
    )
    # jeśli w przekierowaniu nie ma index.php, to błąd
    if "/index.php" not in resp.url.path:
        raise HTTPException(status_code=401, detail="Logowanie nie powiodło się")
    return dict(resp.cookies)


@router.post(
    "/photo",
    summary="Upload new judge photo",
    status_code=status.HTTP_200_OK,
)
async def upload_judge_photo(
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    foto: UploadFile = File(...),
    settings=Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    # 1) odszyfrowanie
    user_plain = decrypt_field(private_key, username)
    pass_plain = decrypt_field(private_key, password)
    judge_plain = decrypt_field(private_key, judge_id)

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True) as client:
        # 2) uwierzytelnienie i pobranie ciasteczek
        cookies = await authenticate(client, settings, user_plain, pass_plain)

        # 3) zbuduj multipart/form-data i prześlij do ZPRP
        files = {
            "foto": (foto.filename, await foto.read(), foto.content_type),
        }
        data = {
            "NrSedzia": judge_plain,
            "user": user_plain,
        }
        resp = await client.post(
            "/sedzia_foto_dodaj3.php",
            data=data,
            files=files,
            cookies=cookies,
            headers={"Accept": "text/html"},
        )

        # 4) weryfikacja
        if resp.status_code != 200 or "error" in resp.text.lower():
            raise HTTPException(status_code=500, detail="Upload nie powiódł się")

    return {"success": True}


@router.delete(
    "/photo",
    summary="Delete existing judge photo",
    status_code=status.HTTP_200_OK,
)
async def delete_judge_photo(
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    settings=Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    """
    Usuwa istniejące zdjęcie sędziego. Zakładamy, że na stronie ZPRP jest endpoint
    sedzia_foto_usun.php, który przyjmuje identyczne pola NrSedzia i user.
    """
    private_key, _ = keys

    # odszyfruj pola
    user_plain = decrypt_field(private_key, username)
    pass_plain = decrypt_field(private_key, password)
    judge_plain = decrypt_field(private_key, judge_id)

    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True) as client:
        # uwierzytelnij
        cookies = await authenticate(client, settings, user_plain, pass_plain)

        # wywołaj „usuń zdjęcie”
        data = {
            "NrSedzia": judge_plain,
            "user": user_plain,
            "action": "usun"  # jeśli backend wymaga dodatkowego pola
        }
        resp = await client.post(
            "/sedzia_foto_usun.php",
            data=data,
            cookies=cookies,
            headers={"Accept": "text/html"},
        )

        if resp.status_code != 200 or "error" in resp.text.lower():
            raise HTTPException(status_code=500, detail="Usuwanie zdjęcia nie powiodło się")

    return {"success": True}


# Obsługa błędów 401 i 500 jednolity komunikat
@router.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
    )

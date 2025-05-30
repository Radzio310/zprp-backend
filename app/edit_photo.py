from fastapi import APIRouter, File, UploadFile, Form, HTTPException, Depends
from httpx import AsyncClient
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

from app.deps import get_settings, get_rsa_keys
from app.utils import fetch_with_correct_encoding

router = APIRouter(prefix="/judge")

@router.post("/photo")
async def upload_judge_photo(
    username: str = Form(...),
    password: str = Form(...),
    judge_id: str = Form(...),
    foto: UploadFile = File(...),
    settings=Depends(get_settings),
    keys=Depends(get_rsa_keys),
):
    private_key, _ = keys

    def decrypt_field(enc_b64: str) -> str:
        cipher = base64.b64decode(enc_b64)
        plain = private_key.decrypt(cipher, padding.PKCS1v15())
        return plain.decode()

    try:
        user_plain = decrypt_field(username)
        pass_plain = decrypt_field(password)
        judge_plain = decrypt_field(judge_id)
    except Exception as e:
        raise HTTPException(400, f"Decryption error: {e}")

    # 1) logowanie
    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True) as client:
        resp_login, _ = await fetch_with_correct_encoding(
            client, "/login.php",
            method="POST",
            data={"login": user_plain, "haslo": pass_plain, "from": "/index.php?"},
        )
        if "/index.php" not in resp_login.url.path:
            raise HTTPException(401, "Logowanie nie powiodło się")
        cookies = dict(resp_login.cookies)

        # 2) przygotowanie multipart/form-data do sedzia_foto_dodaj3.php
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
        # 3) sprawdź odpowiedź (np. kod 200 i brak błędu w HTML)
        if resp.status_code != 200 or "error" in resp.text.lower():
            raise HTTPException(500, "Upload nie powiódł się")
    return {"success": True}

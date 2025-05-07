# app/delegate.py

import os
import uuid
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.deps import get_settings, get_rsa_keys, Settings
from app.offtime import _decrypt_field, _login_and_client

router = APIRouter()

# katalog na tymczasowe pliki PDF
TMP_DIR = "tmp_pdfs"
os.makedirs(TMP_DIR, exist_ok=True)

class DelegateNoteRequest(BaseModel):
    username:    str  # Base64-RSA zaszyfrowany login
    password:    str  # Base64-RSA zaszyfrowane hasło
    judge_id:    str  # Base64-RSA zaszyfrowane judge_id
    delegate_url: str  # względna ścieżka do PDF, np. "./statystyki_sedzia_oc_PDF.php?…"

@router.post(
    "/judge/offtimes/delegateNote",
    summary="Pobierz ocenę sędziów jako PDF i wygeneruj link"
)
async def delegate_note(
    req: DelegateNoteRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
    keys = Depends(get_rsa_keys),
):
    private_key, _ = keys

    # 1) odszyfruj login, hasło i judge_id
    try:
        user  = _decrypt_field(req.username, private_key)
        pwd   = _decrypt_field(req.password, private_key)
        judge = _decrypt_field(req.judge_id, private_key)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Niepoprawny payload: {e}")

    # 2) zaloguj się i pobierz HTTPX client z ciasteczkami
    client = await _login_and_client(user, pwd, settings)

    try:
        # 3) pobierz PDF z ZPRP
        path = "/" + req.delegate_url.lstrip("./")
        resp = await client.get(path)
        ct = resp.headers.get("content-type", "")

        if resp.status_code != 200:
            raise HTTPException(
                502,
                f"ZPRP zwrócił {resp.status_code}, content-type={ct}"
            )

        # 4) wczytaj cały strumień do pamięci
        data = await resp.aread()

        # 5) wygeneruj unikatowy token i zapisz plik
        token = str(uuid.uuid4())
        filename = f"{token}.pdf"
        file_path = os.path.join(TMP_DIR, filename)
        with open(file_path, "wb") as f:
            f.write(data)

        # 6) skonstruuj URL do pobrania
        download_path = request.url_for("download_temp_pdf", token=token)
        return {"download_url": str(download_path)}

    finally:
        await client.aclose()

@router.get(
    "/temp/{token}",
    name="download_temp_pdf",
    summary="(tymczasowe) Pobierz PDF i usuń go"
)
async def download_temp_pdf(token: str):
    filename = f"{token}.pdf"
    file_path = os.path.join(TMP_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(404, "Plik wygasł lub nie istnieje")

    # zwróć plik i usuń po wysłaniu
    response = FileResponse(file_path, media_type="application/pdf")

    @response.call_on_close
    def _cleanup():
        try:
            os.remove(file_path)
        except OSError:
            pass

    return response

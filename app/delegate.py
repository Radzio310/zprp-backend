# app/delegate.py

import os
import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.deps import get_settings, get_rsa_keys, Settings
from app.offtime import _decrypt_field, _login_and_client  # teraz z odszyfrowaniem

router = APIRouter()

# katalog na tymczasowe pliki PDF
tmp_dir = os.path.abspath("tmp_pdfs")
os.makedirs(tmp_dir, exist_ok=True)

class DelegateNoteRequest(BaseModel):
    username:    str  # Base64-RSA zaszyfrowany login
    password:    str  # Base64-RSA zaszyfrowane hasło
    judge_id:    str  # Base64-RSA zaszyfrowane judge_id
    delegate_url: str  # względna ścieżka do PDF, np. "./statystyki_sedzia_oc_PDF.php?…"

@router.post(
    "/judge/offtimes/delegateNote",
    summary="Pobierz ocenę sędziów jako PDF i wygeneruj link (z szyfrowaniem)"
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

    # 2) logowanie
    client = await _login_and_client(user, pwd, settings)
    try:
        # 3) pobierz PDF z ZPRP
        path = "/" + req.delegate_url.lstrip("./")
        resp = await client.get(path)
        if resp.status_code != 200:
            ct = resp.headers.get("content-type", "")
            raise HTTPException(502, f"ZPRP zwrócił {resp.status_code}, content-type={ct}")
        data = await resp.aread()
    finally:
        await client.aclose()

    # 4) zapisz plik tymczasowo
    token = str(uuid.uuid4())
    filename = f"{token}.pdf"
    full_path = os.path.join(tmp_dir, filename)
    with open(full_path, "wb") as f:
        f.write(data)

    # 5) zwróć link do pobrania
    download_url = request.url_for("download_temp_pdf", token=token)
    return {"download_url": str(download_url)}

@router.get(
    "/temp/{token}",
    name="download_temp_pdf",
    summary="(tymczasowe) Pobierz PDF i usuń go"
)
async def download_temp_pdf(
    token: str,
    background_tasks: BackgroundTasks,
):
    filename = f"{token}.pdf"
    full_path = os.path.join(tmp_dir, filename)
    if not os.path.exists(full_path):
        raise HTTPException(404, "Plik nie istnieje lub wygasł")

    # usuń po wysłaniu
    background_tasks.add_task(os.remove, full_path)

    return FileResponse(
        path=full_path,
        media_type="application/pdf",
        filename=filename,
    )

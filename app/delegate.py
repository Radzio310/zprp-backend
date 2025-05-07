import os
import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.deps import get_settings, Settings
from app.offtime import _login_and_client  # plain login without encryption

router = APIRouter()

# katalog na tymczasowe pliki PDF
tmp_dir = os.path.abspath("tmp_pdfs")
os.makedirs(tmp_dir, exist_ok=True)

class DelegateNoteTestRequest(BaseModel):
    username:    str  # czysty login
    password:    str  # czyste hasło
    delegate_url: str  # względna ścieżka do PDF, np. "./statystyki_sedzia_oc_PDF.php?…"

@router.post(
    "/judge/offtimes/delegateNoteTest",
    summary="(TEST) Pobierz ocenę sędziów jako PDF i wygeneruj link bez szyfrowania"
)
async def delegate_note_test(
    req: DelegateNoteTestRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
):
    # 1) logujemy się "na czysto"
    client = await _login_and_client(req.username, req.password, settings)
    try:
        # 2) pobierz PDF z ZPRP
        path = "/" + req.delegate_url.lstrip("./")
        resp = await client.get(path)
        if resp.status_code != 200:
            ct = resp.headers.get("content-type", "")
            raise HTTPException(502, f"ZPRP zwrócił {resp.status_code}, content-type={ct}")
        data = await resp.aread()
    finally:
        await client.aclose()

    # 3) zapisz plik tymczasowo
    token = str(uuid.uuid4())
    filename = f"{token}.pdf"
    full_path = os.path.join(tmp_dir, filename)
    with open(full_path, "wb") as f:
        f.write(data)

    # 4) zwróć link do pobrania
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

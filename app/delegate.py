# app/delegate.py

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from app.deps import get_rsa_keys, get_settings, Settings
from app.offtime import _decrypt_field, _login_and_client

router = APIRouter()

class DelegateNoteRequest(BaseModel):
    username: str    # Base64-RSA
    password: str    # Base64-RSA
    judge_id: str    # Base64-RSA
    delegate_url: str  # względna ścieżka do PDF (np. "./statystyki_sedzia_oc_PDF.php?...")

@router.post("/judge/offtimes/delegateNote", summary="Pobierz ocenę sędziów jako PDF")
async def delegate_note(
    req: DelegateNoteRequest,
    settings: Settings = Depends(get_settings),
    keys = Depends(get_rsa_keys),
):
    private_key, _ = keys

    # 1) odszyfruj użytkownika / hasło / judge_id
    try:
        user = _decrypt_field(req.username, private_key)
        pwd = _decrypt_field(req.password, private_key)
        judge = _decrypt_field(req.judge_id, private_key)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Niepoprawny payload: {e}")

    # 2) zaloguj się i pobierz HTTPX client z ciasteczkami
    client = await _login_and_client(user, pwd, settings)
    try:
        # 3) zbuduj URL do PDF
        #    zakładamy, że delegate_url to coś w stylu "./statystyki_sedzia_oc_PDF.php?..."
        path = "/" + req.delegate_url.lstrip("./")

        resp = await client.get(path)
        content_type = resp.headers.get("content-type", "")
        if resp.status_code != 200 or "application/pdf" not in content_type:
            raise HTTPException(502, "Nie udało się pobrać PDF z serwera ZPRP")

        # 4) zwróć strumień
        return StreamingResponse(
            resp.aiter_bytes(),
            media_type="application/pdf"
        )
    finally:
        await client.aclose()

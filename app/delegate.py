# app/delegate.py

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from app.deps import get_settings, Settings
from app.offtime import _login_and_client  # normalne logowanie

router = APIRouter()

class DelegateNoteTestRequest(BaseModel):
    username: str     # czysty login
    password: str     # czyste hasło
    judge_id: str     # zwykłe judge_id
    delegate_url: str # np. "./statystyki_sedzia_oc_PDF.php?...")

@router.post("/judge/offtimes/delegateNoteTest", summary="(TEST) Pobierz ocenę sędziów jako PDF BEZ szyfrowania")
async def delegate_note_test(
    req: DelegateNoteTestRequest,
    settings: Settings = Depends(get_settings),
):
    # 1) logujemy się „na czysto”
    client = await _login_and_client(req.username, req.password, settings)

    try:
        # 2) zbuduj ścieżkę i pobierz PDF
        #    delegate_url może zaczynać się od "./" lub bez
        path = "/" + req.delegate_url.lstrip("./")

        resp = await client.get(path)
        ct = resp.headers.get("content-type", "")
        if resp.status_code != 200 or "application/pdf" not in ct:
            raise HTTPException(502, f"ZPRP zwrócił {resp.status_code}, content-type={ct}")

        # 3) zwróć strumień
        return StreamingResponse(resp.aiter_bytes(), media_type="application/pdf")

    finally:
        await client.aclose()

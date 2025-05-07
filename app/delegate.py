# app/delegate_test.py

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
import httpx
from app.deps import get_settings, Settings

router = APIRouter()

@router.get(
    "/judge/offtimes/delegateNoteTest",
    summary="(TEST) Pobierz ocenę sędziów jako PDF bez szyfrowania",
)
async def delegate_note_test(
    delegate_url: str = Query(
        ...,
        description="Końcówka URL (np. './statystyki_sedzia_oc_PDF.php?...')",
    ),
    settings: Settings = Depends(get_settings),
):
    # 1) zkonstrukcja pełnego URL
    #    upewniamy się, że zaczyna się od '/'
    path = delegate_url.lstrip("./")
    full_url = f"{settings.ZPRP_BASE_URL.rstrip('/')}/{path}"

    # 2) fetchujemy PDF
    async with httpx.AsyncClient(follow_redirects=True) as client:
        resp = await client.get(full_url)
        ctype = resp.headers.get("content-type", "")
        if resp.status_code != 200 or "application/pdf" not in ctype:
            body = (await resp.aread())[:200]
            raise HTTPException(
                status_code=502,
                detail=(
                    f"ZPRP zwrócił status {resp.status_code}, "
                    f"content-type {ctype!r}, body snippet {body!r}"
                ),
            )

        # 3) zwracamy strumień PDF
        return StreamingResponse(resp.aiter_bytes(), media_type="application/pdf")

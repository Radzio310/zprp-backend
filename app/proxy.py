# app/proxy.py

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi import Request
from pydantic import BaseModel
from typing import Optional, Any, Dict
import httpx

from app.auth import get_current_cookies
from app.deps import get_settings, Settings

router = APIRouter()

class ProxyRequest(BaseModel):
    method: str                 # "GET", "POST", "PUT", "DELETE" itp.
    path: str                   # np. "/index.php?a=statystyki&b=sedzia&NrSedzia=123"
    params: Optional[Dict[str, Any]] = None
    json: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None

@router.post("/proxy", tags=["proxy"])
async def proxy(
    req: ProxyRequest,
    cookies: dict = Depends(get_current_cookies),
    settings: Settings = Depends(get_settings),
):
    async with httpx.AsyncClient(
        base_url=settings.ZPRP_BASE_URL,
        cookies=cookies,
        follow_redirects=True
    ) as client:
        resp = await client.request(
            req.method.upper(),
            req.path,
            params=req.params,
            json=req.json,
            data=req.data,
        )

    if resp.status_code >= 400:
        # Jeśli upstream zwróci błąd, propagujemy go jako 502
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream error {resp.status_code}: {resp.text}"
        )

    # Staramy się zwrócić JSON, a jeśli się nie uda, to tekst
    try:
        return resp.json()
    except ValueError:
        return {"content": resp.text}

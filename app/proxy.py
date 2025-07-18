# app/proxy.py

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi import Request
from pydantic import BaseModel, Field
from typing import Optional, Any, Dict
import httpx

from app.auth import get_current_cookies
from app.deps import get_settings, Settings

router = APIRouter()

class ProxyRequest(BaseModel):
    method: str
    path: str
    params: Optional[Dict[str, Any]] = None
    json_body: Optional[Dict[str, Any]] = Field(None, alias="json")
    data: Optional[Dict[str, Any]] = None

    model_config = {
        "validate_by_name": True,    # pozwala wczytywać pola po ich nazwie nawet jeśli mają alias
        "populate_by_alias": True,   # pozwala zwracać .dict(by_alias=True)
    }

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
            json=req.json_body,
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

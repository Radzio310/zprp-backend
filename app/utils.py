# app/utils.py

import httpx
import chardet
from typing import Optional, Tuple

async def fetch_with_correct_encoding(
    client: httpx.AsyncClient,
    url: str,
    method: str = "GET",
    params: Optional[dict] = None,
    data: Optional[dict] = None,
    json: Optional[dict] = None,
    cookies: Optional[dict] = None,
) -> Tuple[httpx.Response, str]:
    """
    Wysyła żądanie i zwraca (response, text),
    automatycznie wykrywając i używając poprawnego kodowania znaków.
    """
    resp = await client.request(
        method,
        url,
        params=params,
        data=data,
        json=json,
        cookies=cookies,
        follow_redirects=True,
    )
    raw = resp.content
    detected = chardet.detect(raw)
    encoding = detected.get("encoding") or "utf-8"
    text = raw.decode(encoding, errors="replace")
    return resp, text

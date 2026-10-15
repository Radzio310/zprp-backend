"""Podgląd linku do nagrania - pobieranie z ochroną SSRF (bez bazy danych).

Reguły (co wolno pobrać, jak czytać odpowiedź) siedzą w liściu
`app/link_preview_rules.py`; tu jest tylko sieć:
  - DNS rozwiązywany przez nas, każdy adres sprawdzony przed połączeniem,
  - przekierowania ręcznie, krok po kroku, z ponownym sprawdzeniem,
  - odpowiedź czytana strumieniem i ucinana po limicie bajtów,
  - wynik w pamięci procesu (24 h; porażka 10 min).

Uwaga: między naszym DNS a połączeniem httpx rozwiązuje nazwę jeszcze raz.
Ryzyko podmiany (DNS rebinding) ogranicza krótki TTL wyniku i to, że
odpowiedź jest wyłącznie parsowana pod kątem `<meta>` - nigdy nie wraca
do klienta w surowej postaci.
"""

from __future__ import annotations

import asyncio
import json
import socket
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional

import httpx

from app.link_preview_rules import (
    CACHE_FAIL_TTL_S,
    CACHE_TTL_S,
    FETCH_TIMEOUT_S,
    MAX_HTML_BYTES,
    MAX_JSON_BYTES,
    MAX_REDIRECTS,
    TtlCache,
    UnsafeUrl,
    all_ips_allowed,
    check_url_shape,
    instant_preview,
    merge_preview,
    oembed_endpoint,
    parse_html_preview,
    preview_from_oembed,
    redirect_target,
)
from urllib.parse import urlparse

USER_AGENT = "Mozilla/5.0 (compatible; BAZA-LinkPreview/1.0; +https://bazaapp.online)"

_cache = TtlCache()

Resolver = Callable[[str], Awaitable[List[str]]]


async def _resolve(host: str) -> List[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


async def _fetch_limited(
    url: str,
    *,
    max_bytes: int,
    accept: str,
    resolver: Resolver,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> tuple[str, str]:
    """(końcowy adres, tekst) - z ręcznymi przekierowaniami i limitem bajtów."""
    current = check_url_shape(url)
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(FETCH_TIMEOUT_S),
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT, "Accept": accept, "Accept-Language": "pl,en;q=0.8"},
        transport=transport,
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            host = urlparse(current).hostname or ""
            all_ips_allowed(await resolver(host))
            async with client.stream("GET", current) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    current = redirect_target(current, response.headers.get("location"))
                    continue
                if response.status_code >= 400:
                    raise UnsafeUrl(f"Strona odpowiedziała błędem {response.status_code}.")
                chunks: List[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= max_bytes:
                        break
                raw = b"".join(chunks)[:max_bytes]
                encoding = response.encoding or "utf-8"
                try:
                    return current, raw.decode(encoding, errors="replace")
                except LookupError:
                    return current, raw.decode("utf-8", errors="replace")
        raise UnsafeUrl("Za dużo przekierowań.")


async def fetch_preview(
    url: str,
    *,
    resolver: Resolver = _resolve,
    transport: Optional[httpx.AsyncBaseTransport] = None,
    clock: Callable[[], float] = time.monotonic,
) -> Dict[str, Any]:
    """Podgląd linku: zawsze coś zwraca (co najmniej `instant_preview`).

    `UnsafeUrl` dla adresu, którego nie wolno pobrać - wołający zamienia to
    na 422 z komunikatem dla użytkownika.
    """
    clean = check_url_shape(url)
    now = clock()
    hit = _cache.get(clean, now)
    if hit is not None:
        return hit
    base = instant_preview(clean)
    result = base
    ok = False
    try:
        endpoint = oembed_endpoint(clean)
        if endpoint:
            _, body = await _fetch_limited(endpoint, max_bytes=MAX_JSON_BYTES, accept="application/json", resolver=resolver, transport=transport)
            data = json.loads(body)
            if isinstance(data, dict):
                result = merge_preview(base, preview_from_oembed(clean, data))
                ok = True
            if result["provider"] == "youtube" and not result.get("duration_s"):
                # oEmbed YouTube nie podaje długości - jest w nagłówku strony filmu.
                try:
                    final, page = await _fetch_limited(clean, max_bytes=MAX_HTML_BYTES * 2, accept="text/html", resolver=resolver, transport=transport)
                    duration = parse_html_preview(page, final).get("duration_s")
                    if duration:
                        result = {**result, "duration_s": duration}
                except Exception:  # noqa: BLE001 - długość jest dodatkiem
                    pass
        else:
            final, page = await _fetch_limited(clean, max_bytes=MAX_HTML_BYTES, accept="text/html,application/xhtml+xml", resolver=resolver, transport=transport)
            result = merge_preview(base, parse_html_preview(page, final))
            ok = True
    except UnsafeUrl:
        raise
    except Exception:  # noqa: BLE001 - brak podglądu to nie błąd dodania linku
        ok = False
    _cache.put(clean, result, now, CACHE_TTL_S if ok else CACHE_FAIL_TTL_S)
    return result


async def preview_or_instant(url: str, timeout_s: float = 6.0) -> Dict[str, Any]:
    """Wersja do zapisu nagrania: nigdy nie rzuca i nie czeka dłużej niż `timeout_s`."""
    try:
        return await asyncio.wait_for(fetch_preview(url), timeout_s)
    except Exception:  # noqa: BLE001
        try:
            return instant_preview(check_url_shape(url))
        except UnsafeUrl:
            return {"url": url, "provider": "video", "title": "", "thumbnail_url": "", "site_name": "", "duration_s": None}

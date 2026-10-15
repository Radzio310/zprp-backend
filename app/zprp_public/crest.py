"""Proxy herbów klubów z CORS oraz kolory klubu liczone po stronie serwera.

Pobieramy wyłącznie z hostów, które już występują w ``logo_url`` klubów
(brak otwartego proxy / SSRF), bez przekierowań, z limitem rozmiaru.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import time
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import select

from app.zprp_public import corrections

router = APIRouter(prefix="/api/v1/handball", tags=["handball_crest"])

MAX_BYTES = 2_000_000
CACHE_SECONDS = 7 * 24 * 3600
HOST_TTL = 600.0
_hosts: dict[str, Any] = {"at": 0.0, "set": set()}
_crests: dict[str, dict[str, Any]] = {}
_colors: dict[str, dict[str, Any]] = {}
MAX_ENTRIES = 400
CORS = {"Access-Control-Allow-Origin": "*", "Cross-Origin-Resource-Policy": "cross-origin"}
NO_COLORS = {"available": False, "primary": None, "secondary": None, "text": None}


def _host_ok(url: str) -> Optional[str]:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in {"http", "https"} or not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None  # adresy IP nigdy
    except ValueError:
        return host


async def allowed_hosts() -> set[str]:
    if time.monotonic() - _hosts["at"] < HOST_TTL and _hosts["set"]:
        return _hosts["set"]
    from app.db import database, zprp_public_clubs

    rows = await database.fetch_all(
        select(zprp_public_clubs.c.logo_url).where(zprp_public_clubs.c.logo_url.is_not(None)).distinct()
    )
    found = {h for r in rows if r["logo_url"] and (h := _host_ok(r["logo_url"]))}
    _hosts.update(at=time.monotonic(), set=found)
    return found


async def _club_logo(club_id: str) -> Optional[str]:
    from app.db import database, zprp_public_clubs

    row = await database.fetch_one(
        select(zprp_public_clubs.c.club_id, zprp_public_clubs.c.logo_url).where(zprp_public_clubs.c.club_id == club_id)
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono klubu")
    item = dict(row)
    await corrections.apply_one("club", item)
    return item.get("logo_url")


async def _fetch(url: str) -> dict[str, Any]:
    cached = _crests.get(url)
    if cached and time.monotonic() - cached["at"] < CACHE_SECONDS:
        return cached
    host = _host_ok(url)
    if not host or host not in await allowed_hosts():
        raise HTTPException(403, "Host herbu nie jest dozwolony")
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
            upstream = await client.get(url, headers={"Accept": "image/*"})
    except httpx.HTTPError as exc:
        raise HTTPException(502, "Nie udało się pobrać herbu") from exc
    ctype = upstream.headers.get("content-type", "").split(";")[0].strip().lower()
    if upstream.status_code != 200 or not ctype.startswith("image/"):
        raise HTTPException(404 if upstream.status_code == 404 else 502, "Herb niedostępny")
    if len(upstream.content) > MAX_BYTES:
        raise HTTPException(413, "Herb jest za duży")
    digest = hashlib.sha1(upstream.content).hexdigest()[:20]
    entry = {"body": upstream.content, "type": ctype, "etag": f'"{digest}"', "at": time.monotonic()}
    if len(_crests) >= MAX_ENTRIES:
        _crests.pop(next(iter(_crests)))
    _crests[url] = entry
    return entry


def _hex(rgb: tuple[int, int, int]) -> str:
    return "#%02x%02x%02x" % rgb


def extract_colors(data: bytes) -> Optional[dict[str, str]]:
    """Dominujące barwy herbu (pomija tło: przezroczyste, białe, szare, czarne)."""
    try:
        from PIL import Image
    except ImportError:  # pragma: no cover
        return None
    try:
        image = Image.open(io.BytesIO(data)).convert("RGBA")
    except Exception:  # noqa: BLE001 - np. SVG
        return None
    image.thumbnail((64, 64))
    buckets: dict[tuple[int, int, int], list[int]] = {}
    for r, g, b, a in image.getdata():
        if a < 200:
            continue
        mx, mn = max(r, g, b), min(r, g, b)
        if (mx > 235 and mn > 215) or mx < 40 or mx - mn < 28:  # biel, czerń, szarość
            continue
        slot = buckets.setdefault((r // 32, g // 32, b // 32), [0, 0, 0, 0])
        slot[0] += 1
        slot[1] += r
        slot[2] += g
        slot[3] += b
    if not buckets:
        return None
    ranked = sorted(buckets.values(), key=lambda s: s[0], reverse=True)

    def mean(slot: list[int]) -> tuple[int, int, int]:
        return (slot[1] // slot[0], slot[2] // slot[0], slot[3] // slot[0])

    primary = mean(ranked[0])
    secondary = None
    for slot in ranked[1:]:
        candidate = mean(slot)
        if sum(abs(a - b) for a, b in zip(candidate, primary)) > 120:
            secondary = candidate
            break
    luma = 0.2126 * primary[0] + 0.7152 * primary[1] + 0.0722 * primary[2]
    return {
        "primary": _hex(primary),
        "secondary": _hex(secondary or primary),
        "text": "#111111" if luma > 150 else "#ffffff",
    }


def _respond(request: Request, entry: dict[str, Any]) -> Response:
    headers = {**CORS, "ETag": entry["etag"], "Cache-Control": f"public, max-age={CACHE_SECONDS}, stale-while-revalidate=86400"}
    if request.headers.get("if-none-match") == entry["etag"]:
        return Response(status_code=304, headers=headers)
    return Response(content=entry["body"], media_type=entry["type"], headers=headers)


@router.get("/crest")
async def crest(request: Request, url: str = "", club_id: str = "") -> Response:
    target = url.strip()
    if not target and club_id.strip():
        target = await _club_logo(club_id.strip()) or ""
        if not target:
            raise HTTPException(404, "Klub nie ma herbu")
    if not target:
        raise HTTPException(400, "Podaj url lub club_id")
    return _respond(request, await _fetch(target))


@router.get("/clubs/{club_id}/colors")
async def club_colors(club_id: str, response: Response) -> dict[str, Any]:
    logo = await _club_logo(club_id)
    response.headers.update({**CORS, "Cache-Control": "public, max-age=86400"})
    if not logo:
        return {"club_id": club_id, **NO_COLORS}
    cached = _colors.get(logo)
    if cached is None:
        cached = extract_colors((await _fetch(logo))["body"]) or {}
        if len(_colors) >= MAX_ENTRIES:
            _colors.pop(next(iter(_colors)))
        _colors[logo] = cached
    if not cached:
        return {"club_id": club_id, **NO_COLORS}
    return {"club_id": club_id, "available": True, **cached}

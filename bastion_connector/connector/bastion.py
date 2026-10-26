"""Klient odczytu GET /api/game-context z dana sesja. Wewnetrzne API portalu (nie publiczna umowa),
wiec odpowiedz jest walidowana, a bledy mapowane na kody BAZY (handoff 8.1)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .urlrules import embed_url_ok


@dataclass
class GameResult:
    code: str  # OK | BASTION_AUTH_REQUIRED | BASTION_RESOURCE_FORBIDDEN | BASTION_RATE_LIMITED | BASTION_UNAVAILABLE | BASTION_BAD_RESPONSE | BASTION_EMBED_HOST_NOT_ALLOWED
    http_status: int | None = None
    embed_url: str | None = None
    video_state: str | None = None
    expires_at: int | None = None  # epoch z adresu embed, jezeli ma parametr czasu; inaczej None
    top_keys: list[str] = field(default_factory=list)
    detail: str | None = None


_EXPIRY_PARAMS = ("expires", "expire", "token_expires", "exp")


def embed_expiry(url: str) -> int | None:
    try:
        q = parse_qs(urlsplit(url).query)
    except ValueError:
        return None
    for name in _EXPIRY_PARAMS:
        for v in q.get(name, []):
            if v.isdigit() and 1_000_000_000 < int(v) < 4_000_000_000:
                return int(v)
    return None


def classify(http_status: int, body: Any, embed_suffixes: list[str]) -> GameResult:
    if http_status == 401:
        return GameResult("BASTION_AUTH_REQUIRED", 401)
    if http_status == 403:
        return GameResult("BASTION_RESOURCE_FORBIDDEN", 403)
    if http_status == 429:
        return GameResult("BASTION_RATE_LIMITED", 429)
    if http_status != 200:
        return GameResult("BASTION_UNAVAILABLE", http_status)
    if not isinstance(body, dict):
        return GameResult("BASTION_BAD_RESPONSE", 200, detail="odpowiedz nie jest obiektem JSON")
    video = body.get("video") if isinstance(body.get("video"), dict) else {}
    embed = video.get("embed_url") if isinstance(video.get("embed_url"), str) else None
    res = GameResult("OK", 200, video_state=video.get("state") if isinstance(video.get("state"), str) else None,
                     top_keys=sorted(body.keys())[:20])
    if embed:
        if not embed_url_ok(embed, embed_suffixes):
            host = urlsplit(embed).hostname
            return GameResult("BASTION_EMBED_HOST_NOT_ALLOWED", 200, video_state=res.video_state,
                              top_keys=res.top_keys, detail=f"host embed: {host}")
        res.embed_url = embed
        res.expires_at = embed_expiry(embed)
    return res


async def fetch_game_context(req, base_url: str, bunny_item_id: int, embed_suffixes: list[str]) -> GameResult:
    """req = APIRequestContext Playwrighta (browser_context.request albo playwright.request.new_context)."""
    try:
        resp = await req.get(f"{base_url}/api/game-context", params={"bunny_item_id": str(bunny_item_id)},
                             timeout=15000, max_redirects=0)
        try:
            body = await resp.json()
        except Exception:  # noqa: BLE001
            body = None
        return classify(resp.status, body, embed_suffixes)
    except Exception as e:  # noqa: BLE001 - timeout/siec to NIE dowod wygasniecia sesji
        return GameResult("BASTION_UNAVAILABLE", None, detail=type(e).__name__)

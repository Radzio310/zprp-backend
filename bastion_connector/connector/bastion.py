"""Klient odczytu GET /api/game-context z dana sesja. Wewnetrzne API portalu (nie publiczna umowa),
wiec odpowiedz jest walidowana, a bledy mapowane na kody BAZY (handoff 8.1)."""
from __future__ import annotations

import hashlib
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
    identity: dict = field(default_factory=dict)  # {id, label, source, viewer_keys}; puste, gdy brak klucza viewer


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


_ID_KEYS = ("discord_user_id", "discord_id", "user_id", "id", "uid", "sub")
_LABEL_KEYS = ("display_name", "displayName", "global_name", "name", "username", "nickname", "nick")


def _clean(v: Any, limit: int) -> str | None:
    if isinstance(v, bool) or not isinstance(v, (str, int)):
        return None
    t = str(v).strip()
    return t[:limit] if t else None


def extract_identity(body: Any) -> dict:
    """Tozsamosc konta z klucza `viewer` game-context. Publiczne skrypty portalu (game.js, portal.js) czytaja tylko
    `viewer.display_name` (i `user.display_name` z /api/me/sections); stabilnego id nie ujawniaja. Dlatego:
    id z pierwszego znanego pola id, jesli viewer je ma (source `viewer.<pole>`), inaczej odcisk nazwy wyswietlanej
    `dn:<sha256[:16]>` (source `viewer.display_name`; dwie osoby o tej samej nazwie nie sa rozroznialne).
    Zwraca tez NAZWY pol viewer (bez wartosci), zeby dalo sie sprawdzic ksztalt na zywo."""
    v = body.get("viewer") if isinstance(body, dict) else None
    if isinstance(v, dict):
        keys = sorted(str(k) for k in v)[:20]
        idk = next(((k, x) for k in _ID_KEYS if (x := _clean(v.get(k), 128))), None)
        label = next((x for k in _LABEL_KEYS if (x := _clean(v.get(k), 80))), None)
        if idk:
            return {"id": idk[1], "label": label or idk[1], "source": f"viewer.{idk[0]}", "viewer_keys": keys}
        if label:
            return {"id": "dn:" + hashlib.sha256(label.casefold().encode()).hexdigest()[:16], "label": label,
                    "source": "viewer.display_name", "viewer_keys": keys}
        return {"id": None, "label": None, "source": None, "viewer_keys": keys}
    x = _clean(v, 128)
    if x:
        return {"id": x, "label": x, "source": "viewer", "viewer_keys": []}
    return {"id": None, "label": None, "source": None, "viewer_keys": []}


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
                     top_keys=sorted(body.keys())[:20], identity=extract_identity(body))
    if embed:
        if not embed_url_ok(embed, embed_suffixes):
            host = urlsplit(embed).hostname
            return GameResult("BASTION_EMBED_HOST_NOT_ALLOWED", 200, video_state=res.video_state,
                              top_keys=res.top_keys, detail=f"host embed: {host}", identity=res.identity)
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

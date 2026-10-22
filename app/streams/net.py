"""Sieć transmisji: jedno pobieranie dla wszystkich źródeł + YouTube Data API v3.

* `fetch_text` - przez `app.link_preview._fetch_limited` (zapora SSRF na KAŻDYM
  skoku przekierowania, limit bajtów), krótki limit czasu, `None` zamiast
  wyjątku: źródło, które dziś milczy, po prostu nic nie daje.
* `YouTube` - klucz z `YOUTUBE_API_KEY`; każde wywołanie najpierw rezerwuje
  jednostki limitu (`quota_take`, w bazie - `app/streams/store.py`):
  `videos.list`/`channels.list`/`playlistItems.list` = 1, `search.list` = 100.
  Bez klucza albo po wyczerpaniu limitu metody zwracają `None`.

Parsowanie odpowiedzi (XML, HTML, JSON) idzie w wątku - pętla zdarzeń nie czeka.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlencode, urlparse

from app.streams import parsers as P

log = logging.getLogger(__name__)

API = "https://www.googleapis.com/youtube/v3/"
COSTS = {"videos": 1, "channels": 1, "playlistItems": 1, "search": 100}
TIMEOUT_S = 8.0
MAX_PAGE = 1_500_000
MAX_JSON = 600_000

#: Zgoda na ciasteczka - bez niej serwer z Europy dostaje stronę zgody YouTube.
YT_CONSENT = {"SOCS": "CAI", "CONSENT": "YES+"}

#: Podmieniane w testach (DNS i transport httpx).
resolver: Optional[Callable[[str], Awaitable[list[str]]]] = None
transport: Any = None


async def fetch_text(url: str, *, accept: str = "text/html,application/xhtml+xml,*/*;q=0.5",
                     max_bytes: int = MAX_PAGE, cookies: Optional[dict[str, str]] = None,
                     timeout: float = TIMEOUT_S) -> Optional[str]:
    """Adres → tekst albo None (zapora, limit czasu, 4xx/5xx, błąd sieci)."""
    from app import link_preview

    try:
        _, body = await asyncio.wait_for(
            link_preview._fetch_limited(url, max_bytes=max_bytes, accept=accept,
                                        resolver=resolver or link_preview._resolve,
                                        transport=transport, cookies=cookies),
            timeout,
        )
        return body
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - źródło milczy, reszta działa
        log.info("[streams] %s milczy: %s", urlparse(url).hostname or "?", type(exc).__name__)
        return None


def feed_url(channel_id: Optional[str] = None, playlist_id: Optional[str] = None) -> Optional[str]:
    if playlist_id:
        return f"https://www.youtube.com/feeds/videos.xml?playlist_id={playlist_id}"
    if channel_id:
        return f"https://www.youtube.com/feeds/videos.xml?channel_id={channel_id}"
    return None


async def fetch_feed(channel_id: Optional[str] = None, playlist_id: Optional[str] = None) -> Optional[tuple[str, dict]]:
    """(surowy tekst, sparsowany kanał) albo None."""
    url = feed_url(channel_id, playlist_id)
    if not url:
        return None
    body = await fetch_text(url, accept="application/atom+xml,application/xml,text/xml;q=0.9,*/*;q=0.5")
    if body is None:
        return None
    return body, await asyncio.to_thread(P.parse_feed, body)


async def fetch_page(url: str, parser: Callable[[str], Any], *, youtube: bool = False) -> Any:
    body = await fetch_text(url, cookies=YT_CONSENT if youtube else None)
    if body is None:
        return None
    return await asyncio.to_thread(parser, body)


QuotaTake = Callable[[int, bool], Awaitable[bool]]


class YouTube:
    """YouTube Data API v3 z limitem dobowym. `key=None` czyta `YOUTUBE_API_KEY`."""

    def __init__(self, quota_take: QuotaTake, key: Optional[str] = None):
        self.key = (key if key is not None else os.getenv("YOUTUBE_API_KEY", "")).strip()
        self.quota_take = quota_take
        self.calls = 0

    @property
    def enabled(self) -> bool:
        return bool(self.key)

    async def _get(self, endpoint: str, params: dict[str, Any]) -> Optional[dict]:
        if not self.key:
            return None
        if not await self.quota_take(COSTS[endpoint], endpoint == "search"):
            return None
        self.calls += 1
        body = await fetch_text(API + endpoint + "?" + urlencode({**params, "key": self.key}),
                                accept="application/json", max_bytes=MAX_JSON)
        if body is None:
            return None
        try:
            data = await asyncio.to_thread(json.loads, body)
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    async def videos(self, ids: list[str]) -> list[dict[str, Any]]:
        """Stan filmów (po 50 na wywołanie, 1 jednostka każde)."""
        out: list[dict[str, Any]] = []
        unique = list(dict.fromkeys(i for i in ids if i))
        for start in range(0, len(unique), 50):
            data = await self._get("videos", {"part": "snippet,liveStreamingDetails,contentDetails",
                                              "id": ",".join(unique[start:start + 50]), "maxResults": 50})
            if data is None:
                break
            out.extend(await asyncio.to_thread(P.parse_api_videos, data))
        return out

    async def channel(self, *, handle: Optional[str] = None, user: Optional[str] = None,
                      channel_id: Optional[str] = None) -> Optional[dict[str, Any]]:
        params: dict[str, Any] = {"part": "snippet,contentDetails"}
        if channel_id:
            params["id"] = channel_id
        elif handle:
            params["forHandle"] = handle if handle.startswith("@") else "@" + handle
        elif user:
            params["forUsername"] = user
        else:
            return None
        data = await self._get("channels", params)
        return P.parse_api_channel(data) if data else None

    async def search(self, query: str, event_type: str) -> list[str]:
        data = await self._get("search", {"part": "id", "type": "video", "eventType": event_type, "q": query,
                                          "maxResults": 10, "regionCode": "PL", "relevanceLanguage": "pl"})
        return P.parse_api_search(data) if data else []

    async def playlist(self, playlist_id: str) -> list[dict[str, Any]]:
        data = await self._get("playlistItems", {"part": "snippet,contentDetails", "playlistId": playlist_id,
                                                 "maxResults": 25})
        return P.parse_api_playlist_items(data) if data else []

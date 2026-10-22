"""Czyste parsery źródeł transmisji - tekst/JSON → kandydaci. Bez sieci i bazy.

Każde źródło ma tu swoją funkcję (jak śpiewnik w Communio): sieć woła
`app/streams/net.py`, a parser dostaje gotowy tekst. Testy biegną na
zapisanych próbkach (`tests/fixtures/streams/`). Parsery NIGDY nie rzucają:
nieczytelna odpowiedź = pusty wynik. Wołający uruchamia je w wątku
(`asyncio.to_thread`) - pętla zdarzeń nie czeka na parsowanie.

Źródła:
* `parse_feed`          kanał RSS (Atom) YouTube kanału albo playlisty,
* `parse_api_*`         odpowiedzi YouTube Data API v3,
* `parse_club_links`    strona główna klubu → kanał YouTube / strona Facebook,
* `parse_channel_page`  strona kanału (`/@uchwyt`) → `UC...` bez klucza API,
* `parse_live_page`     strona `/channel/UC.../live` → film trwającej/zapowiedzianej transmisji,
* `parse_hint_page`     strona z listą transmisji (podpowiedź) → filmy + kontekst.
"""

from __future__ import annotations

import html as html_lib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from app.link_preview_rules import iso_duration_seconds, youtube_id
from app.streams.seeds import NOT_CLUB_FACEBOOK, NOT_CLUB_HANDLES

NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "yt": "http://www.youtube.com/xml/schemas/2015",
    "media": "http://search.yahoo.com/mrss/",
}
_UC = re.compile(r"^UC[\w-]{22}$")
_VID = re.compile(r"^[A-Za-z0-9_-]{11}$")


def parse_time(value: Any) -> Optional[datetime]:
    """ISO 8601 (`2026-10-22T16:00:00Z`, `+00:00`, z ułamkiem) → aware UTC; inaczej None."""
    raw = str(value or "").strip()
    if not raw:
        return None
    raw = raw.replace("Z", "+00:00")
    raw = re.sub(r"\.(\d{1,6})\d*(?=[+-]|$)", lambda m: "." + m.group(1).ljust(6, "0"), raw)
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def thumb(video_id: str) -> str:
    return f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg"


# ---------------------------------------------------------------------------
# RSS YouTube
# ---------------------------------------------------------------------------


def parse_feed(text: str) -> dict[str, Any]:
    """Atom YouTube (`feeds/videos.xml?channel_id=` / `?playlist_id=`) → kanał + filmy.

    `{"channel_id", "title", "entries": [{video_id, title, channel_id, channel_title,
    published, updated, thumbnail_url, description, url}]}`. DOCTYPE/ENTITY = odmowa
    (obrona przed „billion laughs”).
    """
    empty: dict[str, Any] = {"channel_id": None, "title": None, "entries": []}
    body = str(text or "")
    if not body.strip() or "<!DOCTYPE" in body[:2000].upper() or "<!ENTITY" in body.upper():
        return empty
    try:
        root = ET.fromstring(body.encode("utf-8"))
    except ET.ParseError:
        return empty
    out: dict[str, Any] = {
        "channel_id": (root.findtext("yt:channelId", default="", namespaces=NS) or "").strip() or None,
        "title": (root.findtext("atom:title", default="", namespaces=NS) or "").strip() or None,
        "entries": [],
    }
    for entry in root.findall("atom:entry", NS):
        vid = (entry.findtext("yt:videoId", default="", namespaces=NS) or "").strip()
        if not _VID.match(vid):
            continue
        group = entry.find("media:group", NS)
        description = ""
        thumbnail = ""
        if group is not None:
            description = (group.findtext("media:description", default="", namespaces=NS) or "").strip()
            node = group.find("media:thumbnail", NS)
            if node is not None:
                thumbnail = node.get("url") or ""
        link = entry.find("atom:link[@rel='alternate']", NS)
        author = entry.find("atom:author", NS)
        out["entries"].append({
            "video_id": vid,
            "title": (entry.findtext("atom:title", default="", namespaces=NS) or "").strip(),
            "channel_id": (entry.findtext("yt:channelId", default="", namespaces=NS) or "").strip() or out["channel_id"],
            "channel_title": (author.findtext("atom:name", default="", namespaces=NS).strip() if author is not None else None)
            or out["title"],
            "published": parse_time(entry.findtext("atom:published", default="", namespaces=NS)),
            "updated": parse_time(entry.findtext("atom:updated", default="", namespaces=NS)),
            "thumbnail_url": thumbnail or thumb(vid),
            "description": description[:500],
            "url": (link.get("href") if link is not None else None) or f"https://www.youtube.com/watch?v={vid}",
        })
    return out


# ---------------------------------------------------------------------------
# YouTube Data API v3
# ---------------------------------------------------------------------------


def _items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            return []
    items = data.get("items") if isinstance(data, dict) else None
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []


def _best_thumb(snippet: dict[str, Any], vid: str) -> str:
    thumbs = snippet.get("thumbnails") if isinstance(snippet.get("thumbnails"), dict) else {}
    for size in ("maxres", "standard", "high", "medium", "default"):
        url = (thumbs.get(size) or {}).get("url") if isinstance(thumbs.get(size), dict) else None
        if url:
            return url
    return thumb(vid)


def parse_api_videos(data: Any) -> list[dict[str, Any]]:
    """`videos.list?part=snippet,liveStreamingDetails,contentDetails` → filmy ze stanem.

    Stan: `live` / `upcoming` z `liveBroadcastContent`, wszystko inne `vod`.
    `starts_at` = faktyczny start, potem planowany, potem publikacja.
    """
    out = []
    for item in _items(data):
        vid = str(item.get("id") or "")
        if not _VID.match(vid):
            continue
        sn = item.get("snippet") if isinstance(item.get("snippet"), dict) else {}
        live = item.get("liveStreamingDetails") if isinstance(item.get("liveStreamingDetails"), dict) else {}
        details = item.get("contentDetails") if isinstance(item.get("contentDetails"), dict) else {}
        content = str(sn.get("liveBroadcastContent") or "none")
        state = content if content in ("live", "upcoming") else "vod"
        scheduled = parse_time(live.get("scheduledStartTime"))
        actual = parse_time(live.get("actualStartTime"))
        published = parse_time(sn.get("publishedAt"))
        out.append({
            "video_id": vid,
            "title": str(sn.get("title") or "").strip(),
            "description": str(sn.get("description") or "")[:500],
            "channel_id": str(sn.get("channelId") or "") or None,
            "channel_title": str(sn.get("channelTitle") or "") or None,
            "state": state,
            "is_broadcast": bool(live),
            "scheduled_at": scheduled,
            "starts_at": actual or scheduled or published,
            "ended_at": parse_time(live.get("actualEndTime")),
            "published": published,
            "duration_s": iso_duration_seconds(details.get("duration")) if state == "vod" else None,
            "thumbnail_url": _best_thumb(sn, vid),
            "url": f"https://www.youtube.com/watch?v={vid}",
        })
    return out


def parse_api_search(data: Any) -> list[str]:
    """`search.list` → identyfikatory filmów (kolejność wyników)."""
    out = []
    for item in _items(data):
        ident = item.get("id") if isinstance(item.get("id"), dict) else {}
        vid = str(ident.get("videoId") or "")
        if _VID.match(vid) and vid not in out:
            out.append(vid)
    return out


def parse_api_channel(data: Any) -> Optional[dict[str, Any]]:
    """`channels.list?forHandle=` / `forUsername=` / `id=` → pierwszy kanał albo None."""
    for item in _items(data):
        cid = str(item.get("id") or "")
        if not _UC.match(cid):
            continue
        sn = item.get("snippet") if isinstance(item.get("snippet"), dict) else {}
        details = item.get("contentDetails") if isinstance(item.get("contentDetails"), dict) else {}
        related = details.get("relatedPlaylists") if isinstance(details.get("relatedPlaylists"), dict) else {}
        return {
            "channel_id": cid,
            "title": str(sn.get("title") or "") or None,
            "handle": str(sn.get("customUrl") or "") or None,
            "uploads": str(related.get("uploads") or "") or None,
        }
    return None


def parse_api_playlist_items(data: Any) -> list[dict[str, Any]]:
    """`playlistItems.list?part=snippet,contentDetails` → wpisy jak w RSS."""
    out = []
    for item in _items(data):
        sn = item.get("snippet") if isinstance(item.get("snippet"), dict) else {}
        details = item.get("contentDetails") if isinstance(item.get("contentDetails"), dict) else {}
        vid = str(details.get("videoId") or (sn.get("resourceId") or {}).get("videoId") or "")
        if not _VID.match(vid):
            continue
        out.append({
            "video_id": vid,
            "title": str(sn.get("title") or "").strip(),
            "channel_id": str(sn.get("videoOwnerChannelId") or sn.get("channelId") or "") or None,
            "channel_title": str(sn.get("videoOwnerChannelTitle") or sn.get("channelTitle") or "") or None,
            "published": parse_time(details.get("videoPublishedAt") or sn.get("publishedAt")),
            "updated": None,
            "thumbnail_url": _best_thumb(sn, vid),
            "description": str(sn.get("description") or "")[:500],
            "url": f"https://www.youtube.com/watch?v={vid}",
        })
    return out


# ---------------------------------------------------------------------------
# Strona klubu → kanały
# ---------------------------------------------------------------------------

_YT_LINK = re.compile(
    r"(?:https?:)?//(?:www\.|m\.)?youtube\.com/"
    r"(?:(channel)/(UC[\w-]{22})|@([\w.\-]{3,30})|(c|user)/([\w.\-]{2,60}))",
    re.I,
)
_FB_LINK = re.compile(
    r"(?:https?:)?//(?:www\.|m\.|pl-pl\.|business\.)?(?:facebook|fb)\.com/"
    r"(profile\.php\?id=\d{5,20}|[A-Za-z0-9.\-]{3,80})(?:/)?",
    re.I,
)


def _club_words(name: str) -> set[str]:
    from app.streams.rules import name_tokens

    return name_tokens(name)


def _overlap(label: str, club_name: str) -> int:
    words = _club_words(club_name)
    folded = re.sub(r"[^a-z0-9]", "", label.lower())
    return sum(1 for w in words if len(w) >= 4 and w[:5] in folded)


def parse_club_links(text: str, club_name: str = "") -> dict[str, list[dict[str, Any]]]:
    """Strona główna klubu → `{"youtube": [...], "facebook": [...]}` (najlepsze pierwsze).

    YouTube: `{"channel_id"}` albo `{"handle"}` albo `{"user"}`/`{"custom"}` + `url`.
    Pomija znane kanały związku/telewizji (stopki stron) i linki udostępniania.
    Kandydat z nazwą podobną do nazwy klubu idzie na początek.
    """
    body = html_lib.unescape(str(text or ""))
    youtube: list[dict[str, Any]] = []
    seen: set[str] = set()
    for m in _YT_LINK.finditer(body):
        if m.group(1):
            item = {"channel_id": m.group(2), "url": f"https://www.youtube.com/channel/{m.group(2)}"}
            ident = m.group(2)
        elif m.group(3):
            handle = m.group(3).rstrip(".")
            if handle.lower() in NOT_CLUB_HANDLES:
                continue
            item = {"handle": "@" + handle, "url": f"https://www.youtube.com/@{handle}"}
            ident = "@" + handle.lower()
        else:
            name = m.group(5).rstrip(".")
            if name.lower() in NOT_CLUB_HANDLES:
                continue
            kind = "user" if m.group(4).lower() == "user" else "custom"
            item = {kind: name, "url": f"https://www.youtube.com/{m.group(4).lower()}/{name}"}
            ident = f"{kind}:{name.lower()}"
        if ident in seen:
            continue
        seen.add(ident)
        youtube.append(item)
    facebook: list[dict[str, Any]] = []
    for m in _FB_LINK.finditer(body):
        path = m.group(1).rstrip(".")
        low = path.lower()
        if low.split("?")[0] in NOT_CLUB_FACEBOOK or low.endswith((".php", ".js", ".png", ".jpg")) and "profile.php" not in low:
            continue
        url = f"https://www.facebook.com/{path}"
        if url.lower() in {f["url"].lower() for f in facebook}:
            continue
        facebook.append({"url": url, "name": path})
    if club_name:
        youtube.sort(key=lambda i: -_overlap(i.get("handle") or i.get("user") or i.get("custom") or "", club_name))
        facebook.sort(key=lambda i: -_overlap(i["name"], club_name))
    return {"youtube": youtube[:3], "facebook": facebook[:2]}


# ---------------------------------------------------------------------------
# Strony YouTube bez klucza API
# ---------------------------------------------------------------------------

_EXTERNAL_ID = re.compile(r'"(?:externalId|channelId)"\s*:\s*"(UC[\w-]{22})"')
_CANONICAL = re.compile(r'<link[^>]+rel=["\']canonical["\'][^>]*href=["\']([^"\']+)["\']', re.I)
_CANONICAL_REV = re.compile(r'<link[^>]+href=["\']([^"\']+)["\'][^>]*rel=["\']canonical["\']', re.I)
_OG_TITLE = re.compile(r'<meta[^>]+property=["\']og:title["\'][^>]*content=["\']([^"\']*)["\']', re.I)


def _canonical(text: str) -> str:
    m = _CANONICAL.search(text) or _CANONICAL_REV.search(text)
    return html_lib.unescape(m.group(1)) if m else ""


def parse_channel_page(text: str) -> Optional[dict[str, Any]]:
    """Strona kanału (`youtube.com/@uchwyt`) → `{"channel_id", "title"}` albo None."""
    body = str(text or "")
    cid = ""
    canon = _canonical(body)
    m = re.search(r"/channel/(UC[\w-]{22})", canon)
    if m:
        cid = m.group(1)
    if not cid:
        m = re.search(r'<meta[^>]+itemprop=["\'](?:identifier|channelId)["\'][^>]*content=["\'](UC[\w-]{22})["\']', body, re.I)
        cid = m.group(1) if m else ""
    if not cid:
        m = _EXTERNAL_ID.search(body)
        cid = m.group(1) if m else ""
    if not cid:
        return None
    title = _OG_TITLE.search(body)
    return {"channel_id": cid, "title": html_lib.unescape(title.group(1)).strip() if title else None}


def parse_live_page(text: str) -> Optional[dict[str, Any]]:
    """Strona `/channel/UC.../live`: gdy kanał nadaje albo ma zapowiedź, kanoniczny
    adres to film (`watch?v=`); inaczej - sam kanał (None).

    `{"video_id", "live_now": bool, "title"}`; `live_now` z `"isLiveNow":true` (tylko
    podpowiedź - stan potwierdza API, gdy jest klucz).
    """
    body = str(text or "")
    vid = youtube_id(_canonical(body))
    if not vid:
        return None
    title = _OG_TITLE.search(body)
    return {"video_id": vid, "live_now": bool(re.search(r'"isLiveNow"\s*:\s*true', body)),
            "title": html_lib.unescape(title.group(1)).strip() if title else ""}


# ---------------------------------------------------------------------------
# Strona z podpowiedziami (lista transmisji) → filmy + kontekst
# ---------------------------------------------------------------------------

_ANY_YT = re.compile(
    r"(?:https?:)?//(?:www\.|m\.)?(?:youtube(?:-nocookie)?\.com/(?:watch\?[^\"'\s<>]*v=|embed/|live/|shorts/)|youtu\.be/)"
    r"([A-Za-z0-9_-]{11})"
)
_TIME = re.compile(r"\b([01]?\d|2[0-3])[:.]([0-5]\d)\b")


def parse_hint_page(text: str) -> list[dict[str, Any]]:
    """Strona z listą transmisji → `[{video_id, context, time_hint}]`.

    `context` - tekst bloku wokół linku (≤300 znaków; drużyny, godzina), żeby
    wiedzieć, którego meczu szukać. Ten kontekst NIGDY nie wychodzi na portal:
    film i tak sprawdza YouTube API, a dopasowanie robi jego tytuł.
    """
    from bs4 import BeautifulSoup

    body = str(text or "")
    if not body.strip():
        return []
    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:  # noqa: BLE001
        return []
    found: dict[str, dict[str, Any]] = {}
    for node in soup.find_all(["a", "iframe"]):
        ref = node.get("href") or node.get("src") or node.get("data-src") or ""
        m = _ANY_YT.search(str(ref))
        if not m:
            continue
        vid = m.group(1)
        block = node
        context = ""
        for _ in range(5):
            context = " ".join(block.get_text(" ", strip=True).split())
            if len(context) >= 25 or block.parent is None:
                break
            block = block.parent
        context = context[:300]
        hit = _TIME.search(context)
        entry = found.setdefault(vid, {"video_id": vid, "context": context, "time_hint": None})
        if len(context) > len(entry["context"]):
            entry["context"] = context
        if hit and not entry["time_hint"]:
            entry["time_hint"] = f"{int(hit.group(1)):02d}:{hit.group(2)}"
    # Linki zapisane w skryptach / atrybutach danych (bez znacznika <a>).
    for m in _ANY_YT.finditer(body):
        found.setdefault(m.group(1), {"video_id": m.group(1), "context": "", "time_hint": None})
    return list(found.values())


def youtube_url_parts(url: str) -> dict[str, str]:
    """Adres kanału/playlisty YouTube od admina → `{channel_id|handle|playlist_id|user}`."""
    raw = str(url or "").strip()
    parsed = urlparse(raw if "//" in raw else "https://" + raw)
    host = (parsed.hostname or "").lower()
    if not host.endswith("youtube.com"):
        return {}
    playlist = (parse_qs(parsed.query).get("list") or [""])[0]
    if playlist and parsed.path.strip("/") in ("playlist", ""):
        return {"playlist_id": playlist}
    parts = [p for p in parsed.path.split("/") if p]
    if not parts:
        return {}
    if parts[0] == "channel" and len(parts) > 1 and _UC.match(parts[1]):
        return {"channel_id": parts[1]}
    if parts[0].startswith("@"):
        return {"handle": parts[0]}
    if parts[0] in ("user", "c") and len(parts) > 1:
        return {"user": parts[1]} if parts[0] == "user" else {"custom": parts[1]}
    return {}

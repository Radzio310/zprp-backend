"""Podgląd linku do nagrania meczu - reguły bez sieci i bez bazy (liść).

Z czego składa się podgląd:
  - YouTube i Vimeo: oEmbed dostawcy (tytuł, miniatura; Vimeo także długość),
    a dla YouTube miniatura z `i.ytimg.com` od razu - bez pytania kogokolwiek,
  - każda inna strona: `og:image` / `og:title` (albo `<title>`) czytane przez
    serwer BAZY, bo telefon nie powinien sam chodzić po obcych adresach.

OCHRONA SSRF. Serwer pobiera adres wklejony przez użytkownika, więc:
  - wyłącznie http(s) i porty 80/443 (albo domyślne),
  - host rozwiązany przez DNS NIE może wskazywać na sieć prywatną, pętlę
    zwrotną, link-local, multicast, adres zarezerwowany ani metadane chmury
    (169.254.169.254) - sprawdzamy KAŻDY adres z odpowiedzi DNS,
  - przekierowania sprawdzamy krok po kroku (te same reguły), najwyżej 3,
  - limit czasu i limit rozmiaru odpowiedzi pilnuje `app/link_preview.py`.
Ten moduł daje czyste funkcje do tych decyzji - testowalne bez sieci.
"""

from __future__ import annotations

import html
import ipaddress
import re
from typing import Any, Dict, Iterable, Optional
from urllib.parse import parse_qs, quote, urljoin, urlparse

#: Najwięcej bajtów strony, które czytamy w poszukiwaniu `og:*` (sam nagłówek).
MAX_HTML_BYTES = 600_000
#: Odpowiedź oEmbed to mały JSON.
MAX_JSON_BYTES = 64_000
FETCH_TIMEOUT_S = 5.0
MAX_REDIRECTS = 3
CACHE_TTL_S = 24 * 3600
CACHE_FAIL_TTL_S = 10 * 60
CACHE_MAX = 512

ALLOWED_PORTS = {None, 80, 443}

_YT_ID = re.compile(r"^[A-Za-z0-9_-]{6,20}$")
_VIMEO_ID = re.compile(r"^\d{4,12}$")


class UnsafeUrl(ValueError):
    """Adresu nie wolno pobierać z serwera - komunikat jest po polsku dla użytkownika."""


def check_url_shape(url: str) -> str:
    """Kształt adresu (bez DNS). Zwraca adres przycięty albo rzuca `UnsafeUrl`."""
    value = str(url or "").strip()
    if not value or len(value) > 2048:
        raise UnsafeUrl("Link jest pusty albo za długi.")
    try:
        parsed = urlparse(value)
    except ValueError as exc:
        raise UnsafeUrl("Niepoprawny adres linku - sprawdź, czy został wklejony w całości.") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeUrl("Link musi zaczynać się od http:// lub https://.")
    if parsed.username or parsed.password:
        raise UnsafeUrl("Link z loginem i hasłem nie jest obsługiwany.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsafeUrl("Niepoprawny port w linku.") from exc
    if port not in ALLOWED_PORTS:
        raise UnsafeUrl("Podgląd działa tylko dla zwykłych stron internetowych (bez niestandardowego portu).")
    host = parsed.hostname.lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local") or host.endswith(".internal"):
        raise UnsafeUrl("Ten adres wskazuje na sieć wewnętrzną.")
    # Adres IP wpisany wprost - od razu ta sama reguła co po DNS.
    try:
        ipaddress.ip_address(host.strip("[]"))
        literal = True
    except ValueError:
        literal = False  # nazwa domenowa - sprawdzi ją DNS
    if literal:
        ip_allowed(host)
    return value


def ip_allowed(address: str) -> bool:
    """True dla publicznego adresu. Rzuca `UnsafeUrl` dla prywatnych/zastrzeżonych,
    `ValueError` gdy to w ogóle nie jest adres IP."""
    ip = ipaddress.ip_address(address.strip("[]"))
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    ):
        raise UnsafeUrl("Ten adres wskazuje na sieć wewnętrzną.")
    return True


def all_ips_allowed(addresses: Iterable[str]) -> bool:
    """Każdy adres z odpowiedzi DNS musi być publiczny (inaczej DNS rebinding)."""
    found = False
    for address in addresses:
        found = True
        ip_allowed(address)
    if not found:
        raise UnsafeUrl("Nie znaleziono tej strony - sprawdź, czy adres jest poprawny.")
    return True


def youtube_id(url: str) -> str:
    parsed = urlparse(str(url or "").strip())
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if host.startswith("m."):
        host = host[2:]
    vid = ""
    if host == "youtu.be":
        vid = parsed.path.strip("/").split("/")[0]
    elif host in {"youtube.com", "music.youtube.com", "youtube-nocookie.com"}:
        vid = (parse_qs(parsed.query).get("v") or [""])[0]
        if not vid:
            parts = [p for p in parsed.path.split("/") if p]
            if len(parts) >= 2 and parts[0].lower() in {"shorts", "live", "embed", "v"}:
                vid = parts[1]
    return vid if _YT_ID.match(vid or "") else ""


def vimeo_id(url: str) -> tuple[str, str]:
    """(id, hash prywatnego linku) - `vimeo.com/123/abc` albo `player.vimeo.com/video/123?h=abc`."""
    parsed = urlparse(str(url or "").strip())
    host = (parsed.hostname or "").lower()
    if not (host == "vimeo.com" or host.endswith(".vimeo.com")):
        return "", ""
    parts = [p for p in parsed.path.split("/") if p]
    vid = next((p for p in parts if _VIMEO_ID.match(p)), "")
    secret = (parse_qs(parsed.query).get("h") or [""])[0]
    if vid and not secret:
        idx = parts.index(vid)
        if idx + 1 < len(parts) and re.fullmatch(r"[0-9a-f]{6,20}", parts[idx + 1]):
            secret = parts[idx + 1]
    return vid, secret


def oembed_endpoint(url: str) -> Optional[str]:
    """Adres oEmbed dla znanego dostawcy (stały host - bez ryzyka SSRF)."""
    if youtube_id(url):
        return f"https://www.youtube.com/oembed?format=json&url={quote(url, safe='')}"
    if vimeo_id(url)[0]:
        return f"https://vimeo.com/api/oembed.json?url={quote(url, safe='')}"
    return None


def provider_of(url: str) -> str:
    if youtube_id(url):
        return "youtube"
    if vimeo_id(url)[0]:
        return "vimeo"
    host = (urlparse(str(url or "")).hostname or "").lower()
    if host.endswith("facebook.com") or host == "fb.watch":
        return "facebook"
    if host.endswith("streamable.com"):
        return "streamable"
    if host.endswith("drive.google.com"):
        return "google_drive"
    return "video"


def youtube_thumb(video_id: str) -> str:
    return f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg" if _YT_ID.match(video_id or "") else ""


_ISO_DURATION = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$")


def iso_duration_seconds(value: Any) -> Optional[int]:
    """`PT1H2M3S` -> 3723. Nieczytelne -> None."""
    m = _ISO_DURATION.match(str(value or "").strip().upper())
    if not m or not any(m.groups()):
        return None
    d, h, mi, s = m.groups()
    total = int(d or 0) * 86400 + int(h or 0) * 3600 + int(mi or 0) * 60 + float(s or 0)
    return int(total) if total > 0 else None


def _clean_text(value: Any, limit: int = 160) -> str:
    text = html.unescape(str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


_META = re.compile(r"<meta\b[^>]*>", re.I)
_ATTR = re.compile(r"""([a-zA-Z_:.-]+)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+))""")
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def parse_html_preview(text: str, base_url: str) -> Dict[str, Any]:
    """`og:title`/`og:image`/`og:site_name`/długość z nagłówka strony.

    Bez parsera DOM - wystarczą znaczniki `<meta>`, a obca strona nie powinna
    móc niczego „uruchomić" w naszym procesie.
    """
    meta: Dict[str, str] = {}
    for tag in _META.findall(text or ""):
        attrs = {}
        for name, _, a, b, c in _ATTR.findall(tag):
            attrs[name.lower()] = a if a else (b if b else c)
        key = (attrs.get("property") or attrs.get("name") or attrs.get("itemprop") or "").lower()
        content = attrs.get("content")
        if key and content and key not in meta:
            meta[key] = content
    title = meta.get("og:title") or meta.get("twitter:title")
    if not title:
        m = _TITLE.search(text or "")
        title = m.group(1) if m else ""
    image = meta.get("og:image:secure_url") or meta.get("og:image") or meta.get("twitter:image") or ""
    image = urljoin(base_url, html.unescape(image.strip())) if image else ""
    if image and urlparse(image).scheme not in {"http", "https"}:
        image = ""
    duration = (
        iso_duration_seconds(meta.get("duration"))
        or _int_or_none(meta.get("video:duration"))
        or _int_or_none(meta.get("og:video:duration"))
    )
    if duration is None:
        m = re.search(r'"lengthSeconds"\s*:\s*"(\d{1,6})"', text or "")
        duration = int(m.group(1)) if m else None
    return {
        "title": _clean_text(title),
        "thumbnail_url": image[:2048],
        "site_name": _clean_text(meta.get("og:site_name"), 60),
        "duration_s": duration,
    }


def _int_or_none(value: Any) -> Optional[int]:
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def preview_from_oembed(url: str, data: Dict[str, Any]) -> Dict[str, Any]:
    provider = provider_of(url)
    thumb = str(data.get("thumbnail_url") or "")
    if provider == "youtube":
        # Miniatura `hqdefault` istnieje zawsze; oEmbed oddaje ją także, ale
        # nie dla filmów z wyłączonym osadzaniem.
        thumb = youtube_thumb(youtube_id(url)) or thumb
    return {
        "url": url,
        "provider": provider,
        "title": _clean_text(data.get("title")),
        "author": _clean_text(data.get("author_name"), 80),
        "thumbnail_url": thumb if urlparse(thumb).scheme in {"http", "https"} else "",
        "site_name": "YouTube" if provider == "youtube" else "Vimeo" if provider == "vimeo" else _clean_text(data.get("provider_name"), 60),
        "duration_s": _int_or_none(data.get("duration")),
    }


def instant_preview(url: str) -> Dict[str, Any]:
    """To, co wiemy bez sieci - wynik zapasowy, gdy dostawca nie odpowie."""
    provider = provider_of(url)
    host = (urlparse(url).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return {
        "url": url,
        "provider": provider,
        "title": "",
        "author": "",
        "thumbnail_url": youtube_thumb(youtube_id(url)) if provider == "youtube" else "",
        "site_name": {"youtube": "YouTube", "vimeo": "Vimeo"}.get(provider, host),
        "duration_s": None,
    }


def merge_preview(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in (extra or {}).items():
        if value not in (None, ""):
            out[key] = value
    return out


def redirect_target(current: str, location: Optional[str]) -> str:
    """Następny adres po przekierowaniu - sprawdzany tymi samymi regułami."""
    if not location:
        raise UnsafeUrl("Strona przekierowuje donikąd.")
    return check_url_shape(urljoin(current, location.strip()))


class TtlCache:
    """Mała pamięć wyników (LRU + TTL) - jeden link nie męczy obcych serwerów."""

    def __init__(self, max_items: int = CACHE_MAX):
        self.max_items = max_items
        self._items: Dict[str, tuple[float, Dict[str, Any]]] = {}

    def get(self, key: str, now: float) -> Optional[Dict[str, Any]]:
        hit = self._items.get(key)
        if not hit:
            return None
        expires, value = hit
        if expires < now:
            self._items.pop(key, None)
            return None
        # Odświeżenie kolejności (LRU): słownik pamięta kolejność wstawiania.
        self._items.pop(key, None)
        self._items[key] = hit
        return value

    def put(self, key: str, value: Dict[str, Any], now: float, ttl: float) -> None:
        self._items.pop(key, None)
        self._items[key] = (now + ttl, value)
        while len(self._items) > self.max_items:
            self._items.pop(next(iter(self._items)))


# ─── Godzina startu transmisji (YouTube live) ──────────────────────────────
#
# Archiwum transmisji na żywo zaczyna się od chwili, w której YouTube zaczął
# odbierać obraz (`actualStartTime`). Ta godzina zamienia „o której padła
# akcja" na „która sekunda filmu" - bez ręcznego szukania pierwszego gwizdka.
# Źródła w kolejności zaufania:
#   1. YouTube Data API (`liveStreamingDetails.actualStartTime`), gdy jest klucz,
#   2. strona filmu: `liveBroadcastDetails.startTimestamp` w ytInitialPlayerResponse,
#   3. strona filmu: `<meta itemprop="startDate">` przy `isLiveBroadcast=True`.
# Zwykły film (nie transmisja) nie ma tej godziny - wtedy `None`, bez zgadywania
# z `uploadDate` (to data publikacji, nie sekunda 0:00 nagrania).

#: Strona filmu YouTube ma ~1,3 MB; godzina siedzi w okolicy 0,8 MB.
MAX_WATCH_HTML_BYTES = 1_800_000

_LIVE_DETAILS = re.compile(r'"liveBroadcastDetails"\s*:\s*\{([^{}]*)\}')
_START_TS = re.compile(r'"startTimestamp"\s*:\s*"([^"]+)"')
_META_START = re.compile(r'<meta\s+itemprop="startDate"\s+content="([^"]+)"', re.I)
_META_LIVE = re.compile(r'<meta\s+itemprop="isLiveBroadcast"\s+content="True"', re.I)


def iso_to_ms(value: Any) -> Optional[int]:
    """ISO 8601 ze strefą -> ms UTC. Bez strefy albo bez godziny -> None."""
    text = str(value or "").strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", text):
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        from datetime import datetime

        stamp = datetime.fromisoformat(text)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        return None
    return int(stamp.timestamp() * 1000)


def stream_start_from_html(text: str) -> Optional[int]:
    """Godzina startu transmisji ze strony filmu YouTube (ms UTC) albo None."""
    page = str(text or "")
    block = _LIVE_DETAILS.search(page)
    if block:
        ts = _START_TS.search(block.group(1))
        ms = iso_to_ms(ts.group(1)) if ts else None
        if ms:
            return ms
    if _META_LIVE.search(page):
        meta = _META_START.search(page)
        if meta:
            return iso_to_ms(meta.group(1))
    return None


def stream_start_from_api(data: Any) -> Optional[int]:
    """`videos?part=liveStreamingDetails` -> actualStartTime (ms UTC) albo None."""
    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list) or not items or not isinstance(items[0], dict):
        return None
    details = items[0].get("liveStreamingDetails")
    if not isinstance(details, dict):
        return None
    return iso_to_ms(details.get("actualStartTime"))


def youtube_watch_url(url: str) -> Optional[str]:
    """Kanoniczny adres strony filmu (`/live/ID`, `youtu.be/ID` -> `watch?v=ID`)."""
    vid = youtube_id(url)
    return f"https://www.youtube.com/watch?v={vid}" if vid else None

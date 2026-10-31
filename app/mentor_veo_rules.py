"""Nagrania Veo w Mentorze - reguły czyste (bez bazy i sieci), `docs/mentor-panel.md` sekcja 11.

Veo blokuje iframe, ale publiczne nagranie ma w nieoficjalnym API (`app.veo.co/api/app/matches/<slug>/` i `.../videos/`)
zwykły MP4 z `c.veocdn.com`. API może się zmienić bez uprzedzenia, więc parser jest obronny: każde pole bywa
puste, zły kształt kończy się statusem `unavailable`, nigdy wyjątkiem.

Bezpieczeństwo: slug ścisłym wzorcem, zapytania tylko do `app.veo.co` (https), plik tylko z `c.veocdn.com` (https).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlsplit

PROVIDER = "veo"
API_HOST = "app.veo.co"
CDN_HOST = "c.veocdn.com"
STATUSES = ("ok", "private", "gone", "unavailable", "processing")

#: Slug nagrania, np. `20261018-untitled-recording-2026-10-18_18-58-20-vbbdc38e`. Ścisły wzorzec: bez ukośników,
#: kropek i innych znaków, które pozwoliłyby zmienić ścieżkę zapytania.
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{5,119}$")
_PAGE_PATH = re.compile(r"^/matches/([^/]+)/?$")

#: Jak długo zapis stanu jest świeży (adres pliku bywa czasowy), i jak szybko wolno ponowić nieudaną próbę.
TTL = timedelta(hours=6)
RETRY_AFTER = timedelta(minutes=5)
#: Limity odpowiedzi JSON.
MAX_JSON_BYTES = 512 * 1024
REQUEST_TIMEOUT_S = 8.0
MAX_REDIRECTS = 3
#: Wariant docelowy: 1080p standard.
TARGET_HEIGHT = 1080

MESSAGES: Dict[str, str] = {
    "ok": "",
    "private": "To nagranie w Veo jest prywatne. Poproś właściciela o udostępnienie go przez link albo otwórz je w Veo.",
    "gone": "To nagranie zostało usunięte z Veo albo link jest nieprawidłowy.",
    "unavailable": "Veo chwilowo nie odpowiada. Spróbuj ponownie za chwilę.",
    "processing": "Veo jeszcze przetwarza to nagranie. Spróbuj ponownie za kilka minut.",
}


def parse_slug(url: Any) -> Optional[str]:
    """Slug z linku `https://app.veo.co/matches/<slug>/` (http też, z zapytaniem lub bez). Inny host/ścieżka: None."""
    try:
        parts = urlsplit(str(url or "").strip())
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or (parts.hostname or "").lower() != API_HOST or parts.port not in (None, 443, 80):
        return None
    if parts.username or parts.password:
        return None
    found = _PAGE_PATH.match(parts.path)
    slug = found.group(1) if found else None
    return slug if slug and SLUG_RE.match(slug) else None


def is_veo_url(url: Any) -> bool:
    return parse_slug(url) is not None


def canonical_url(slug: str) -> str:
    return f"https://{API_HOST}/matches/{slug}"


def match_api_url(slug: str) -> str:
    if not SLUG_RE.match(str(slug or "")):
        raise ValueError("bad slug")
    return f"https://{API_HOST}/api/app/matches/{slug}/"


def videos_api_url(slug: str) -> str:
    return match_api_url(slug) + "videos/"


def api_url_ok(url: Any) -> bool:
    """Wywołania API i ich przekierowania: tylko https na `app.veo.co`."""
    try:
        parts = urlsplit(str(url or ""))
    except ValueError:
        return False
    return parts.scheme == "https" and (parts.hostname or "").lower() == API_HOST and parts.port in (None, 443) and not parts.username


def cdn_url_ok(url: Any) -> bool:
    """Plik wideo (także po przekierowaniach): tylko https na `c.veocdn.com`."""
    try:
        parts = urlsplit(str(url or ""))
    except ValueError:
        return False
    return parts.scheme == "https" and (parts.hostname or "").lower() == CDN_HOST and parts.port in (None, 443) \
        and not parts.username and len(str(url)) <= 4096


# ─── Odczyt odpowiedzi ──────────────────────────────────────────────────────


def _text(value: Any, limit: int) -> Optional[str]:
    if not isinstance(value, str):
        return None
    out = re.sub(r"\s+", " ", value).strip().replace("—", "-").replace("–", "-")
    return out[:limit] or None


def _duration(value: Any) -> Optional[int]:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    return int(n) if n == n and 0 < n < 86400 else None


def _int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def parse_match(data: Any) -> Dict[str, Any]:
    """Pola nagrania z `.../matches/<slug>/`: title, thumbnail_url, duration_s, accessible (True/False/None), privacy."""
    src = data if isinstance(data, Mapping) else {}
    thumb = src.get("thumbnail")
    accessible = src.get("is_accessible")
    privacy = src.get("privacy")
    return {
        "title": _text(src.get("title"), 200),
        "thumbnail_url": thumb if isinstance(thumb, str) and thumb.startswith("https://") and len(thumb) <= 2048 else None,
        "duration_s": _duration(src.get("duration")),
        "accessible": accessible if isinstance(accessible, bool) else None,
        "privacy": privacy.strip().lower() if isinstance(privacy, str) else None,
    }


def _items(data: Any) -> List[Mapping[str, Any]]:
    if isinstance(data, Mapping):  # paginacja DRF: {"results": [...]}
        data = data.get("results")
    return [x for x in data if isinstance(x, Mapping)] if isinstance(data, list) else []


_PROCESSING_WORDS = ("process", "pending", "queue", "encod", "render", "transcod", "wait")


def parse_videos(data: Any) -> Dict[str, Any]:
    """Najlepszy wariant z `.../videos/`: {play_url, width, height, thumbnail_url, processing: bool, candidates: n}.

    Wariant docelowy: render_type standard, MP4, adres na `c.veocdn.com`, wysokość najbliższa 1080p od dołu
    (inaczej najniższa powyżej). Brak pola `render_type` nie dyskwalifikuje (API nieoficjalne).
    """
    best: Optional[Mapping[str, Any]] = None
    best_key = None
    processing = False
    seen = 0
    for item in _items(data):
        seen += 1
        availability = str(item.get("availability") or "").lower()
        if availability and any(word in availability for word in _PROCESSING_WORDS):
            processing = True
            continue
        if availability and availability not in ("available", "ready", "ok", "done", "complete", "completed", "public"):
            continue
        render = item.get("render_type")
        if isinstance(render, str) and render.lower() != "standard":
            continue
        mime = str(item.get("mime_type") or "").lower()
        url = item.get("url")
        if not cdn_url_ok(url):
            continue
        if mime and "mp4" not in mime:
            continue
        if not mime and not str(urlsplit(url).path).lower().endswith(".mp4"):
            continue
        height = _int(item.get("height"))
        # Klucz: najpierw warianty nie wyższe niż 1080p (większa wysokość lepsza), potem wyższe (mniejsza lepsza).
        key = (0, -height) if 0 < height <= TARGET_HEIGHT else (1, height) if height > TARGET_HEIGHT else (2, 0)
        if best_key is None or key < best_key:
            best, best_key = item, key
    if best is None:
        return {"play_url": None, "width": 0, "height": 0, "thumbnail_url": None, "processing": processing, "candidates": seen}
    thumb = best.get("thumbnail")
    return {"play_url": best["url"], "width": _int(best.get("width")), "height": _int(best.get("height")),
            "thumbnail_url": thumb if isinstance(thumb, str) and thumb.startswith("https://") else None,
            "processing": False, "candidates": seen}


# ─── Decyzja o stanie ───────────────────────────────────────────────────────


def status_for_http(code: int) -> Optional[str]:
    """404 -> gone; 401/403 -> private; 2xx -> None (czytamy treść); reszta (5xx, 429, 3xx, sieć) -> None i błąd tymczasowy."""
    if code == 404 or code == 410:
        return "gone"
    if code in (401, 403):
        return "private"
    return None


def classify(match_code: Optional[int], match_data: Any, videos_code: Optional[int], videos_data: Any) -> Dict[str, Any]:
    """Wynik odczytu: {kind: "state"|"error", status, play_url, title, thumbnail_url, duration_s, width, height}.

    `kind == "error"` = błąd sieci, 5xx albo nieczytelna odpowiedź: stan zapisany NIE zmienia się (dobry nie staje się `gone`).
    `match_code`/`videos_code` None = brak odpowiedzi (sieć, limit czasu, zbyt duża odpowiedź).
    """
    error = {"kind": "error", "status": "unavailable"}
    if match_code is None:
        return error
    fixed = status_for_http(match_code)
    if fixed:
        return {"kind": "state", "status": fixed}
    if not 200 <= match_code < 300 or not isinstance(match_data, Mapping):
        return error
    info = parse_match(match_data)
    base = {"kind": "state", "title": info["title"], "thumbnail_url": info["thumbnail_url"], "duration_s": info["duration_s"]}
    if info["accessible"] is False:
        return {**base, "status": "private"}
    if videos_code is None:
        return error
    fixed = status_for_http(videos_code)
    if fixed:
        return {**base, "status": fixed}
    if not 200 <= videos_code < 300:
        return error
    parsed = parse_videos(videos_data)
    if parsed["play_url"]:
        return {**base, "status": "ok", "play_url": parsed["play_url"], "width": parsed["width"], "height": parsed["height"],
                "thumbnail_url": base["thumbnail_url"] or parsed["thumbnail_url"]}
    if parsed["processing"]:
        return {**base, "status": "processing"}
    # Bez żadnego adresu: nagranie niepubliczne (prywatne) albo Veo zmieniło kształt API.
    if info["privacy"] and info["privacy"] not in ("public", "unlisted", "link", "anyone"):
        return {**base, "status": "private"}
    if parsed["candidates"] == 0 and info["accessible"] is True:
        return {**base, "status": "processing"}
    return {**base, "status": "unavailable"}


def merge_state(prev: Optional[Mapping[str, Any]], result: Mapping[str, Any], now: datetime, slug: str) -> Dict[str, Any]:
    """Nowy zapis `veo_json`. Błąd tymczasowy zachowuje poprzedni stan (zmienia tylko `attempt_at`)."""
    old = dict(prev) if isinstance(prev, Mapping) else {}
    stamp = now.astimezone(timezone.utc).isoformat()
    if result.get("kind") == "error":
        if old.get("status"):
            return {**old, "slug": slug, "attempt_at": stamp}
        return {"slug": slug, "status": "unavailable", "play_url": None, "checked_at": None, "attempt_at": stamp}
    status = result["status"]
    ok = status == "ok"
    return {
        "slug": slug, "status": status, "checked_at": stamp, "attempt_at": stamp,
        "play_url": result.get("play_url") if ok else None,
        "title": result.get("title") or old.get("title"),
        "thumbnail_url": result.get("thumbnail_url") or old.get("thumbnail_url"),
        "duration_s": result.get("duration_s") or old.get("duration_s"),
        "width": result.get("width") if ok else None, "height": result.get("height") if ok else None,
    }


def _when(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def needs_refresh(state: Optional[Mapping[str, Any]], now: datetime, ttl: timedelta = TTL) -> bool:
    """Nigdy niesprawdzone albo starsze niż TTL; po nieudanej próbie nie częściej niż co `RETRY_AFTER`."""
    if not isinstance(state, Mapping) or not state.get("status"):
        return True
    attempt = _when(state.get("attempt_at"))
    if attempt and now - attempt < RETRY_AFTER:
        return False
    checked = _when(state.get("checked_at"))
    return checked is None or now - checked >= ttl


def public_fields(state: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Pola obiektu Video dla providera veo (kontrakt: `play_url`, `playable`, `veo_status`, `veo_checked_at`, ...)."""
    st = state if isinstance(state, Mapping) else {}
    status = st.get("status") if st.get("status") in STATUSES else "unavailable"
    play = st.get("play_url") if status == "ok" and cdn_url_ok(st.get("play_url")) else None
    if status == "ok" and not play:
        status = "unavailable"
    return {"play_url": play, "playable": bool(play), "veo_status": status, "veo_checked_at": st.get("checked_at"),
            "veo_message": MESSAGES.get(status) or None,
            "title": st.get("title"), "thumbnail_url": st.get("thumbnail_url"), "duration_s": st.get("duration_s")}


def clip_error(status: str) -> str:
    """Kod i polski tekst dla klipu z nagrania, którego nie da się teraz przeczytać."""
    return MESSAGES.get(status) or MESSAGES["unavailable"]


def input_args(url: str) -> List[str]:
    """Opcje wejścia ffmpeg dla zdalnego MP4: tylko https, ponawianie, limit bezczynności (10 s). Idą PRZED `-ss`/`-i`."""
    return ["-protocol_whitelist", "https,tls,tcp,crypto", "-rw_timeout", "10000000", "-reconnect", "1",
            "-reconnect_streamed", "1", "-reconnect_delay_max", "5"]


def cut_args(base_args: List[str], url: str) -> List[str]:
    """Dokłada opcje wejścia do `mentor_panel_rules.cut_args` tuż przed `-ss` (czyli `-ss` przed `-i` zostaje: skok po Range)."""
    at = base_args.index("-ss")
    return [*base_args[:at], *input_args(url), *base_args[at:]]

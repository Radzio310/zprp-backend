"""Kopia filmu YouTube na serwerze (02.11.2026) - reguły czyste (bez bazy, sieci i yt-dlp).

Decyzja właściciela (02.11.2026, zastępuje wcześniejsze „YouTube przez yt-dlp: NIE”): film YouTube dodany do meczu
można na żądanie („Zrób kopię na serwer”) przegrać do R2 jako MP4 1080p. Kopia jest DRUGIM źródłem tego samego
nagrania (`mentor_match_videos.mirror_upload_id`), nie osobnym nagraniem: ten sam film, więc te same sekundy,
klipy, rysunki i synchronizacja. Odtwarzacz domyślnie gra kopię, YouTube zostaje w przełączniku.

Pobieranie: yt-dlp w wątku, najpierw prosto z serwera, a gdy YouTube odpowie blokadą („potwierdź, że nie jesteś
botem”, 429), drugi raz przez proxy z `MENTOR_YT_PROXY` (płatne proxy domowe - koszt tylko wtedy, gdy trzeba).
"""

from __future__ import annotations

import base64
import os
import re
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

#: Najwyżej 1080p. Najpierw H.264 + AAC (wtedy kopia to samo przepakowanie, bez kodowania), potem cokolwiek do 1080p
#: (VP9/AV1 przekodujemy), na końcu pojedynczy plik z obrazem i dźwiękiem.
FORMAT = ("bv*[vcodec^=avc1][height<=1080]+ba[acodec^=mp4a]/"
          "bv*[height<=1080]+ba/"
          "b[height<=1080]/b")

#: Granice zdrowego rozsądku: mecz z doliczonym czasem i przerwą to 2-3 h; więcej to raczej całodniowa transmisja.
MAX_DURATION_S = 5 * 3600
MAX_BYTES = 12 * 1024 ** 3

#: Udziały etapów w jednym pasku postępu (pobieranie trwa najdłużej).
PHASE_SPAN: Dict[str, Tuple[float, float]] = {
    "queued": (0.0, 0.0),
    "connecting": (0.0, 0.02),
    "downloading": (0.02, 0.86),
    "finishing": (0.86, 0.9),
    "converting": (0.86, 0.9),
    "uploading": (0.9, 1.0),
}
PHASES = tuple(PHASE_SPAN)


def enabled() -> bool:
    """Wyłącznik `MENTOR_YT_COPY=0`. Domyślnie włączone (o magazynie i yt-dlp decyduje osobne sprawdzenie)."""
    return os.getenv("MENTOR_YT_COPY", "1").strip().lower() not in ("0", "false", "no", "off")


def proxy_url() -> Optional[str]:
    value = (os.getenv("MENTOR_YT_PROXY") or "").strip()
    return value or None


def proxy_only() -> bool:
    """`MENTOR_YT_PROXY_ALWAYS=1`: od razu przez proxy (gdy prosto z serwera YouTube blokuje zawsze)."""
    return bool(proxy_url()) and os.getenv("MENTOR_YT_PROXY_ALWAYS", "").strip().lower() in ("1", "true", "yes", "on")


def attempts() -> Tuple[Optional[str], ...]:
    """Kolejne próby: None = prosto z serwera, napis = adres proxy."""
    proxy = proxy_url()
    if not proxy:
        return (None,)
    return (proxy,) if proxy_only() else (None, proxy)


def cookies_text(raw: Optional[str] = None) -> Optional[str]:
    """`MENTOR_YT_COOKIES`: plik ciasteczek w formacie Netscape, wprost albo w base64 (wygodniej w zmiennej Railway)."""
    value = (raw if raw is not None else os.getenv("MENTOR_YT_COOKIES") or "").strip()
    if not value:
        return None
    if "\t" in value or value.startswith("#"):
        return value + "\n"
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except Exception:  # noqa: BLE001 - zły zapis zmiennej = bez ciasteczek, nie awaria
        return None
    return decoded if "\t" in decoded else None


def youtube_video_id(url: Any) -> Optional[str]:
    text = str(url or "").strip()
    for pattern in (r"(?:v=|/shorts/|/live/|/embed/|youtu\.be/)([A-Za-z0-9_-]{11})",):
        found = re.search(pattern, text)
        if found:
            return found.group(1)
    return None


def watch_url(url: Any) -> Optional[str]:
    vid = youtube_video_id(url)
    return f"https://www.youtube.com/watch?v={vid}" if vid else None


# ─── Przed pobraniem ────────────────────────────────────────────────────────


class CopyError(Exception):
    """Błąd z kodem i polskim komunikatem, który wolno pokazać użytkownikowi."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


MESSAGES: Dict[str, str] = {
    "BLOCKED": "YouTube zablokował pobieranie z naszego serwera. Spróbuj ponownie za jakiś czas.",
    "BLOCKED_PROXY": "YouTube zablokował pobieranie z serwera i przez proxy. Spróbuj ponownie za jakiś czas.",
    "PRIVATE": "Ten film jest prywatny - YouTube nie pozwala go pobrać.",
    "GONE": "Tego filmu nie ma już na YouTube albo link jest nieprawidłowy.",
    "AGE": "Film ma ograniczenie wiekowe. Pobranie wymaga ciasteczek konta YouTube na serwerze (MENTOR_YT_COOKIES).",
    "MEMBERS": "Film jest tylko dla członków kanału - nie da się go pobrać.",
    "LIVE": "Transmisja jeszcze trwa. Kopię zrobisz po jej zakończeniu.",
    "UPCOMING": "Transmisja jeszcze się nie zaczęła.",
    "POST_LIVE": "YouTube jeszcze przetwarza zapis tej transmisji. Spróbuj ponownie za godzinę.",
    "TOO_LONG": "Film trwa ponad 5 godzin - to raczej całodniowa transmisja niż mecz.",
    "TOO_BIG": "Film jest za duży, żeby zrobić z niego kopię.",
    "NOT_YOUTUBE": "Kopię na serwer można zrobić tylko z filmu YouTube.",
    "NO_TOOL": "Serwer nie ma narzędzia do pobierania z YouTube (yt-dlp).",
    "CANCELLED": "Kopię anulowano.",
    "FAILED": "Nie udało się pobrać filmu z YouTube. Spróbuj ponownie.",
}


def check_info(info: Mapping[str, Any]) -> None:
    """Odrzuca, zanim zaczniemy ściągać gigabajty: transmisja na żywo/zapowiedź/świeży zapis, za długi, za duży."""
    live = str(info.get("live_status") or "")
    if info.get("is_live") or live == "is_live":
        raise CopyError("LIVE", MESSAGES["LIVE"])
    if live == "is_upcoming":
        raise CopyError("UPCOMING", MESSAGES["UPCOMING"])
    if live == "post_live":
        raise CopyError("POST_LIVE", MESSAGES["POST_LIVE"])
    duration = float(info.get("duration") or 0)
    if duration > MAX_DURATION_S:
        raise CopyError("TOO_LONG", MESSAGES["TOO_LONG"])
    size = expected_bytes(info)
    if size and size > MAX_BYTES:
        raise CopyError("TOO_BIG", MESSAGES["TOO_BIG"])


def chosen_formats(info: Mapping[str, Any]) -> list:
    formats = info.get("requested_formats")
    if formats:
        return list(formats)
    return [info] if info.get("format_id") else []


def expected_bytes(info: Mapping[str, Any]) -> int:
    return int(sum(int(f.get("filesize") or f.get("filesize_approx") or 0) for f in chosen_formats(info)))


def chosen_height(info: Mapping[str, Any]) -> Optional[int]:
    heights = [int(f.get("height") or 0) for f in chosen_formats(info)] + [int(info.get("height") or 0)]
    best = max(heights) if heights else 0
    return best or None


#: Ślady blokady serwera przez YouTube (adres IP centrum danych, brak tokenu PO, limit zapytań).
BLOCK_SIGNS = ("not a bot", "sign in to confirm", "http error 429", "too many requests", "http error 403", "po token")


def classify(message: Any, *, via_proxy: bool = False) -> Tuple[str, str]:
    """Komunikat yt-dlp -> (kod, polski komunikat). Kolejność ma znaczenie: wiek przed „sign in”."""
    text = str(message or "").lower()
    if "confirm your age" in text or "age-restricted" in text or "inappropriate for some users" in text:
        code = "AGE"
    elif "members-only" in text or "join this channel" in text or "available to this channel's members" in text:
        code = "MEMBERS"
    elif "private video" in text or "video is private" in text:
        code = "PRIVATE"
    elif any(sign in text for sign in BLOCK_SIGNS):
        code = "BLOCKED_PROXY" if via_proxy else "BLOCKED"
    elif "live event will begin" in text or "premieres in" in text or "is_upcoming" in text:
        code = "UPCOMING"
    elif "video unavailable" in text or "has been removed" in text or "does not exist" in text or "account associated" in text \
            or "incomplete youtube id" in text or "no longer available" in text:
        code = "GONE"
    else:
        code = "FAILED"
    return code, MESSAGES[code]


def retry_through_proxy(code: str) -> bool:
    """Po której porażce prosto z serwera warto spróbować przez proxy."""
    return code in ("BLOCKED", "FAILED")


# ─── Postęp ─────────────────────────────────────────────────────────────────


def download_fraction(parts: Mapping[str, Tuple[float, float]], expected: Iterable[Tuple[str, float]] = ()) -> Optional[float]:
    """Postęp pobierania kilku strumieni (obraz, potem dźwięk): {format_id: (pobrane, całość)}.
    `expected` = rozmiary znane z góry (format_id, bajty), żeby dźwięk ściągany po obrazie nie cofał paska."""
    totals: Dict[str, float] = {fid: float(size) for fid, size in expected if size}
    done: Dict[str, float] = {}
    for fid, (got, total) in parts.items():
        done[fid] = float(got or 0)
        if total:
            totals[fid] = float(total)
    whole = sum(totals.values())
    if whole <= 0:
        return None
    got = sum(min(done.get(fid, 0.0), size) for fid, size in totals.items())
    return max(0.0, min(1.0, got / whole))


def overall(phase: str, fraction: Optional[float]) -> float:
    lo, hi = PHASE_SPAN.get(phase, (0.0, 0.0))
    if fraction is None:
        return round(lo, 4)
    return round(lo + (hi - lo) * max(0.0, min(1.0, float(fraction))), 4)


def mirror_shape(upload: Optional[Mapping[str, Any]], live: Optional[Mapping[str, Any]], play_url: Optional[str],
                 poster_url: Optional[str]) -> Optional[Dict[str, Any]]:
    """Pole `mirror` nagrania. `live` = stan z pamięci workera (etap, postęp, prędkość) - po restarcie go nie ma,
    wtedy kopia w toku jest „w kolejce”, dopóki worker jej nie podejmie."""
    if not upload:
        return None
    status = str(upload.get("status") or "failed")
    live = live or {}
    if status == "ready" and play_url:
        state = "ready"
    elif status in ("downloading", "queued"):
        state = "working"
    elif status == "expired":
        state = "expired"
    else:
        state = "failed"
    phase = (live.get("phase") or "queued") if state == "working" else None
    return {
        "id": upload.get("id"), "status": state, "phase": phase,
        "progress": 1.0 if state == "ready" else (live.get("progress") if state == "working" else None),
        "speed_bps": live.get("speed_bps") if state == "working" else None,
        "eta_s": live.get("eta_s") if state == "working" else None,
        "downloaded_bytes": live.get("downloaded_bytes") if state == "working" else None,
        "total_bytes": live.get("total_bytes") if state == "working" else None,
        "via_proxy": bool(live.get("via_proxy")) if state == "working" else None,
        "size": int(upload.get("size") or 0) or None,
        "height": int(upload.get("height") or 0) or None,
        "duration_s": upload.get("duration_s"),
        "error": upload.get("error") if state in ("failed", "expired") else None,
        "play_url": play_url if state == "ready" else None,
        "poster_url": poster_url if state == "ready" else None,
        "requested_by": upload.get("uploader_id"),
        "created_at": upload.get("created_at"),
        #: 03.11.2026: gotowa kopia to osobne nagranie meczu (`Video.copy_of` = ten film); tu jego id (może leżeć w koszu).
        "video_id": upload.get("video_id") if state == "ready" else None,
    }


def copy_title(title: Any, filename: Any = None, height: Any = None) -> str:
    """Nazwa nagrania-kopii: „<nazwa filmu> · kopia 1080p”. Bez długich myślników, do 200 znaków."""
    base = re.sub(r"\s+", " ", str(title or "")).strip()
    if not base:
        base = re.sub(r"\.mp4$", "", str(filename or ""), flags=re.I).strip() or "YouTube"
    try:
        h = int(height or 0)
    except (TypeError, ValueError):
        h = 0
    tail = f" · kopia {h}p" if h > 0 else " · kopia"
    return base[: 200 - len(tail)].rstrip() + tail


def safe_filename(title: Any) -> str:
    base = re.sub(r"[\\/\x00-\x1f:*?\"<>|]+", " ", str(title or "")).strip()
    base = re.sub(r"\s+", " ", base)[:120].strip(" .")
    return f"{base or 'YouTube'}.mp4"

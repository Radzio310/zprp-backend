"""Pobranie i kontrola pliku klipu z Bastionu (etap 4) - bez bazy, bez connectora.

Podpisany adres Bunny dostajemy od connectora (już po walidacji hosta), ale BAZA sprawdza go jeszcze raz i pobiera
OSOBNYM klientem: zero ciasteczek, zero nagłówków autoryzacji, `trust_env=False`, https bez userinfo i portu, host z listy
sufiksów, literały IP odrzucone, KAŻDY adres hosta musi być publiczny (łączymy na ten sam rozwiązany adres, więc DNS
rebinding nic nie zmieni), przekierowania (maks. 3) przechodzą te same kontrole. Strumień do pliku z twardym limitem.
Adres jest sekretem: nie trafia do logów ani do komunikatów błędów (tylko host).
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional
from urllib.parse import urljoin, urlsplit

DEFAULT_SUFFIXES = ["b-cdn.net", "mediadelivery.net", "bunnycdn.com"]
MAX_REDIRECTS = 3
DEFAULT_MAX_MB = 400


class MediaError(Exception):
    """`code` jak w kolejce (np. DOWNLOAD_TOO_LARGE); `retryable` mówi, czy ma sens kolejna próba."""

    def __init__(self, code: str, retryable: bool = False, detail: str = ""):
        super().__init__(code)
        self.code, self.retryable, self.detail = code, retryable, detail


def download_suffixes() -> List[str]:
    raw = os.getenv("BASTION_DOWNLOAD_HOST_SUFFIXES", "")
    found = [x.strip().lower().lstrip(".") for x in raw.split(",") if x.strip()]
    return found or list(DEFAULT_SUFFIXES)


def max_download_bytes() -> int:
    try:
        mb = int(os.getenv("BASTION_MAX_DOWNLOAD_MB", "") or DEFAULT_MAX_MB)
    except ValueError:
        mb = DEFAULT_MAX_MB
    return max(1, min(2048, mb)) * 1024 * 1024


def host_ok(url: str, suffixes: List[str]) -> bool:
    try:
        u = urlsplit(url)
        host = (u.hostname or "").lower()
        if u.scheme != "https" or u.username or u.password or u.port not in (None, 443) or not host:
            return False
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            pass
        return any(host == s or host.endswith("." + s) for s in suffixes)
    except ValueError:
        return False


def ip_is_public(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


async def resolve_public_ips(host: str) -> List[str]:
    """Adresy hosta, ale tylko gdy KAŻDY jest publiczny (inaczej pusta lista)."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        return []
    addrs = list(dict.fromkeys(i[4][0].split("%")[0] for i in infos))
    return addrs if addrs and all(ip_is_public(a) for a in addrs) else []


def pin_url(url: str, ip: str) -> str:
    u = urlsplit(url)
    return u._replace(netloc=f"[{ip}]" if ":" in ip else ip).geturl()


@dataclass
class Downloaded:
    path: str
    size: int
    sha256: str
    content_type: Optional[str]
    host: str
    hops: int


async def download_signed(url: str, dest_dir: str, *, max_bytes: Optional[int] = None, suffixes: Optional[List[str]] = None,
                          timeout_s: float = 300.0, transport: Any = None,
                          resolver: Callable[[str], Awaitable[List[str]]] = resolve_public_ips) -> Downloaded:
    import httpx

    suffixes = suffixes or download_suffixes()
    limit = max_bytes or max_download_bytes()
    cur = url
    try:
        async with httpx.AsyncClient(follow_redirects=False, trust_env=False, cookies=None, transport=transport,
                                     timeout=httpx.Timeout(timeout_s, connect=15.0),
                                     headers={"User-Agent": "BAZA-Mentor"}) as client:
            for hop in range(MAX_REDIRECTS + 1):
                host = (urlsplit(cur).hostname or "").lower()
                if not host_ok(cur, suffixes):
                    raise MediaError("DOWNLOAD_HOST_NOT_ALLOWED", False, host or "?")
                ips = await resolver(host)
                if not ips:
                    raise MediaError("DOWNLOAD_ADDRESS_NOT_PUBLIC", False, host)
                async with client.stream("GET", pin_url(cur, ips[0]), headers={"Host": host},
                                         extensions={"sni_hostname": host}) as res:
                    if res.status_code in (301, 302, 303, 307, 308):
                        loc = res.headers.get("location")
                        if not loc:
                            raise MediaError("DOWNLOAD_BAD_REDIRECT", False, host)
                        cur = urljoin(cur, loc)
                        continue
                    if res.status_code != 200:
                        # 4xx z CDN (np. wygasły podpis) bywa przejściowy: kolejna próba prosi o nowy adres.
                        raise MediaError("DOWNLOAD_HTTP_ERROR", True, f"{host} HTTP {res.status_code}")
                    declared = res.headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > limit:
                        raise MediaError("DOWNLOAD_TOO_LARGE", False, f"{declared} > {limit}")
                    fd, path = tempfile.mkstemp(dir=dest_dir, suffix=".mp4")
                    digest, size = hashlib.sha256(), 0
                    try:
                        with os.fdopen(fd, "wb") as handle:
                            async for chunk in res.aiter_bytes(65536):
                                size += len(chunk)
                                if size > limit:
                                    raise MediaError("DOWNLOAD_TOO_LARGE", False, f"> {limit}")
                                digest.update(chunk)
                                handle.write(chunk)
                    except BaseException:
                        try:
                            os.unlink(path)
                        except OSError:
                            pass
                        raise
                    return Downloaded(path, size, digest.hexdigest(), res.headers.get("content-type"), host, hop)
    except MediaError:
        raise
    except httpx.HTTPError as exc:
        raise MediaError("DOWNLOAD_NETWORK", True, type(exc).__name__) from exc
    raise MediaError("DOWNLOAD_TOO_MANY_REDIRECTS", False, "")


def parse_ffprobe(data: Any) -> Dict[str, Any]:
    d = data if isinstance(data, dict) else {}
    streams = d.get("streams") if isinstance(d.get("streams"), list) else []
    fmt = d.get("format") if isinstance(d.get("format"), dict) else {}
    video = next((s for s in streams if isinstance(s, dict) and s.get("codec_type") == "video"), None)
    audio = next((s for s in streams if isinstance(s, dict) and s.get("codec_type") == "audio"), None)

    def num(v: Any) -> Optional[float]:
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    dur = num(fmt.get("duration"))
    if dur is None and video:
        dur = num(video.get("duration"))
    return {"format": fmt.get("format_name"), "duration_s": round(dur, 2) if dur is not None else None,
            "has_video": video is not None, "has_audio": audio is not None,
            "video_codec": video.get("codec_name") if video else None,
            "width": int(video.get("width") or 0) or None if video else None,
            "height": int(video.get("height") or 0) or None if video else None,
            "audio_codec": audio.get("codec_name") if audio else None}


def ffprobe_file(path: str, timeout_s: float = 60.0) -> Dict[str, Any]:
    """Synchronicznie (wołać w wątku). Brak ffprobe albo uszkodzony plik = MediaError."""
    try:
        done = subprocess.run(["ffprobe", "-v", "error", "-print_format", "json", "-show_format", "-show_streams", path],
                              capture_output=True, text=True, timeout=timeout_s, check=False)
    except FileNotFoundError as exc:
        raise MediaError("FFPROBE_MISSING", True, "brak ffprobe") from exc
    except subprocess.TimeoutExpired as exc:
        raise MediaError("FFPROBE_TIMEOUT", True, "") from exc
    if done.returncode != 0:
        raise MediaError("BASTION_FILE_INVALID", False, (done.stderr or "")[-200:])
    try:
        return parse_ffprobe(json.loads(done.stdout or "{}"))
    except ValueError as exc:
        raise MediaError("BASTION_FILE_INVALID", False, "json") from exc


def make_thumbnail(path: str, target: str, duration: Optional[float]) -> bool:
    """Klatka z klipu (360 px wysokości). Brak miniatury nie blokuje klipu."""
    at = max(0.0, min(2.0, (duration or 4) / 3))
    try:
        done = subprocess.run(["ffmpeg", "-hide_banner", "-nostdin", "-y", "-ss", f"{at:.1f}", "-i", path, "-frames:v", "1",
                               "-vf", "scale=-2:360", "-q:v", "4", target], capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0 and os.path.exists(target) and os.path.getsize(target) > 0

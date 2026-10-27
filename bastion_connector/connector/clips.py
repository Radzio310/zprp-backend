"""P8: ciecie klipu w Bastionie i pobranie MP4 (wewnetrzne API portalu, nie publiczna umowa).

Kontrakt (z publicznego /static/game.js i /static/clip.js, 27.10.2026; serwer nie potwierdzony):
  POST /api/game-submit  {bunny_item_id, clips:[{clipNumber, startTime "m:ss"|"h:mm:ss", endTime, privateId|null,
                          audience_group_id|null (null = tylko ja), comment 1..300, situationType, videoTags 1..5}]}
                         -> {clip_codes:[...], clip_ids:[...], addressees:[...]}
  GET  /api/clip-context?clip_id=  -> {clip:{clip_code,time_start_sec,time_end_sec,situation_type,video_tags,...}, download_available, ...}
  GET  /api/clip/{id}/download     -> 302 do podpisanego adresu Bunny (wymuszone pobranie)
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import socket
import tempfile
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin, urlsplit

MIN_CLIP_S = 2
MAX_CLIP_S = 300
MAX_START_S = 86_400  # rozsadna gorna granica pozycji w filmie (24 h)
PROBE_COMMENT = "BAZA test P8"
PROBE_SITUATION = "NORMAL"  # z SITUATION_TYPES skryptu: NORMAL | TRAINING | CURIOSITY | NEEDS_ANALYSIS
PROBE_TAGS = ["PLAY_ON"]  # z VIDEO_TAGS skryptu; neutralny znacznik "gra trwa"
DEFAULT_DOWNLOAD_SUFFIXES = ["b-cdn.net", "mediadelivery.net", "bunnycdn.com"]
MAX_REDIRECTS = 3


class ClipError(Exception):
    def __init__(self, code: str, status: int = 400, detail: str | None = None) -> None:
        super().__init__(code)
        self.code, self.status, self.detail = code, status, detail


# ---------- zakres i tresc zgloszenia ----------
def validate_range(start_s: Any, end_s: Any) -> tuple[int, int]:
    """Calkowite sekundy, bez zaokraglen: ulamek lub nie-liczba = blad (nic nie przesuwamy po cichu)."""
    for name, v in (("start_s", start_s), ("end_s", end_s)):
        if isinstance(v, bool) or not isinstance(v, int):
            raise ClipError("BAD_RANGE", 400, f"{name} musi byc liczba calkowita sekund (bez ulamkow)")
        if v < 0 or v > MAX_START_S:
            raise ClipError("BAD_RANGE", 400, f"{name} poza zakresem 0..{MAX_START_S}")
    d = end_s - start_s
    if d < MIN_CLIP_S:
        raise ClipError("BAD_RANGE", 400, f"klip krotszy niz {MIN_CLIP_S} s (jest {d} s); koniec musi byc pozniej niz poczatek")
    if d > MAX_CLIP_S:
        raise ClipError("BAD_RANGE", 400, f"klip dluzszy niz {MAX_CLIP_S} s (jest {d} s); portal Bastionu przyjmuje {MIN_CLIP_S}-{MAX_CLIP_S} s")
    return start_s, end_s


def clock(total: int) -> str:
    """Jak PortalFormat.clock portalu: m:ss albo h:mm:ss od godziny."""
    s = max(0, int(total))
    h, m, r = s // 3600, (s % 3600) // 60, s % 60
    return f"{h}:{m:02d}:{r:02d}" if h else f"{m}:{r:02d}"


def build_submit_body(bunny_item_id: int, start_s: int, end_s: int) -> dict:
    """Jeden prywatny klip, neutralna tresc. Nic z ocen ani komentarzy BAZY."""
    return {"bunny_item_id": bunny_item_id, "clips": [{
        "clipNumber": 1, "startTime": clock(start_s), "endTime": clock(end_s), "privateId": None,
        "audience_group_id": None,  # ONLY_ME
        "comment": PROBE_COMMENT, "situationType": PROBE_SITUATION, "videoTags": list(PROBE_TAGS)}]}


def sent_summary(start_s: int, end_s: int) -> dict:
    return {"start_s": start_s, "end_s": end_s, "duration_s": end_s - start_s, "startTime": clock(start_s),
            "endTime": clock(end_s), "title": PROBE_COMMENT, "situation_type": PROBE_SITUATION,
            "video_tags": list(PROBE_TAGS), "audience": "ONLY_ME (prywatny)"}


# ---------- klasyfikacja odpowiedzi ----------
@dataclass
class SubmitResult:
    state: str  # submitted | failed | needs_reconciliation
    code: str
    http_status: int | None = None
    remote_id: str | None = None
    clip_code: str | None = None
    detail: str | None = None


def classify_submit(http_status: int | None, body: Any) -> SubmitResult:
    """Brak odpowiedzi (timeout/siec) i 5xx = NIEROZSTRZYGNIETE: zlecenie moglo powstac, wiec zero ponowien."""
    if http_status is None:
        return SubmitResult("needs_reconciliation", "BASTION_SUBMIT_NO_RESPONSE", None)
    if http_status == 401:
        return SubmitResult("failed", "BASTION_AUTH_REQUIRED", 401)
    if http_status == 403:
        return SubmitResult("failed", "BASTION_RESOURCE_FORBIDDEN", 403)
    if http_status == 429:
        return SubmitResult("failed", "BASTION_RATE_LIMITED", 429)
    if http_status in (400, 404, 409, 413, 422):
        d = body.get("message") if isinstance(body, dict) and isinstance(body.get("message"), str) else None
        return SubmitResult("failed", "BASTION_SUBMIT_REJECTED", http_status, detail=d)
    if http_status >= 500 or http_status in (408,):
        return SubmitResult("needs_reconciliation", "BASTION_SUBMIT_UNCERTAIN", http_status)
    if http_status in (200, 201):
        ids = body.get("clip_ids") if isinstance(body, dict) else None
        codes = body.get("clip_codes") if isinstance(body, dict) else None
        if isinstance(ids, list) and len(ids) == 1 and isinstance(ids[0], (int, str)) and not isinstance(ids[0], bool):
            code = codes[0] if isinstance(codes, list) and codes and isinstance(codes[0], str) else None
            return SubmitResult("submitted", "OK", http_status, remote_id=str(ids[0]), clip_code=code)
        return SubmitResult("needs_reconciliation", "BASTION_SUBMIT_BAD_RESPONSE", http_status,
                            detail="sukces HTTP bez dokladnie jednego clip_ids")
    return SubmitResult("needs_reconciliation", "BASTION_SUBMIT_UNCERTAIN", http_status)


def summarize_context(body: Any) -> dict:
    """Z clip-context bierzemy tylko to, co potrzebne (bez opisow, komentarzy, osob)."""
    b = body if isinstance(body, dict) else {}
    c = b.get("clip") if isinstance(b.get("clip"), dict) else {}
    return {"download_available": bool(b.get("download_available")), "clip_code": c.get("clip_code"),
            "time_start_sec": c.get("time_start_sec"), "time_end_sec": c.get("time_end_sec"),
            "situation_type": c.get("situation_type"), "video_tags": c.get("video_tags"),
            "top_keys": sorted(b.keys())[:30]}


# ---------- dozwolone hosty pobrania ----------
def download_host_ok(url: str, suffixes: list[str]) -> bool:
    """https, bez userinfo/portu, host z listy sufiksow, nie literal IP."""
    try:
        u = urlsplit(url)
        host = (u.hostname or "").lower()
        if u.scheme != "https" or u.username or u.password or u.port not in (None, 443) or not host:
            return False
        try:
            ipaddress.ip_address(host)
            return False  # literaly IP odrzucamy zawsze
        except ValueError:
            pass
        sfx = [s.lower().lstrip(".") for s in suffixes if s.strip()]
        return any(host == s or host.endswith("." + s) for s in sfx)
    except ValueError:
        return False


def ip_is_public(ip_text: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_text.split("%")[0])
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
                or ip.is_unspecified)


async def resolve_public_ips(host: str) -> list[str]:
    """Rozwiazuje host RAZ i zwraca liste adresow, ale tylko gdy KAZDY jest publiczny (inaczej pusta lista).
    Polaczenie idzie potem na jeden z tych adresow, wiec ponowne zapytanie DNS (rebinding) nic nie zmieni."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        return []
    addrs = list(dict.fromkeys(i[4][0].split("%")[0] for i in infos))
    return addrs if addrs and all(ip_is_public(a) for a in addrs) else []


async def resolve_public(host: str) -> bool:
    return bool(await resolve_public_ips(host))


def pin_url(url: str, ip: str) -> str:
    """Ten sam adres, ale z literalem IP zamiast nazwy (host/SNI idzie osobno: naglowek Host i extensions)."""
    u = urlsplit(url)
    ip_host = f"[{ip}]" if ":" in ip else ip
    return u._replace(netloc=ip_host).geturl()


# ---------- pobranie podpisanego adresu osobnym klientem ----------
@dataclass
class Downloaded:
    path: str
    size: int
    sha256: str
    content_type: str | None
    final_host: str
    hops: int


async def safe_download(url: str, *, suffixes: list[str], max_bytes: int, dest_dir: str, timeout_s: float = 120.0,
                        transport: Any = None,
                        resolver: Callable[[str], Awaitable[list[str]]] = resolve_public_ips) -> Downloaded:
    """Osobny klient httpx: ZERO ciasteczek Bastionu i zadnych naglowkow autoryzacji. Kazdy hop (takze po
    przekierowaniu) przechodzi te sama kontrole hosta i adresow.
    Anty-rebinding: host rozwiazywany raz na hop, wszystkie adresy musza byc publiczne, laczymy na ten adres
    (URL z IP, Host i SNI = nazwa hosta, wiec certyfikat nadal jest sprawdzany dla nazwy). Strumien do pliku z limitem rozmiaru."""
    import httpx

    cur = url
    async with httpx.AsyncClient(follow_redirects=False, trust_env=False,
                                 timeout=httpx.Timeout(timeout_s, connect=15.0), transport=transport,
                                 headers={"User-Agent": "BAZA-Mentor-connector"}) as cl:
        for hop in range(MAX_REDIRECTS + 1):
            host = (urlsplit(cur).hostname or "").lower()
            if not download_host_ok(cur, suffixes):
                raise ClipError("DOWNLOAD_HOST_NOT_ALLOWED", 502, f"host pobrania: {host or '?'} (poza lista dozwolonych sufiksow)")
            ips = await resolver(host)
            if not ips:
                raise ClipError("DOWNLOAD_ADDRESS_NOT_PUBLIC", 502, f"host {host} wskazuje na adres nie-publiczny albo sie nie rozwiazuje")
            async with cl.stream("GET", pin_url(cur, ips[0]), headers={"Host": host},
                                 extensions={"sni_hostname": host}) as r:
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("location")
                    if not loc:
                        raise ClipError("DOWNLOAD_BAD_REDIRECT", 502, "przekierowanie bez Location")
                    cur = urljoin(cur, loc)
                    continue
                if r.status_code != 200:
                    raise ClipError("DOWNLOAD_HTTP_ERROR", 502, f"host {host} odpowiedzial HTTP {r.status_code}")
                declared = r.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > max_bytes:
                    raise ClipError("DOWNLOAD_TOO_LARGE", 413, f"Content-Length {declared} > limit {max_bytes} B")
                fd, path = tempfile.mkstemp(dir=dest_dir, suffix=".mp4")
                h, size = hashlib.sha256(), 0
                try:
                    with os.fdopen(fd, "wb") as f:
                        async for chunk in r.aiter_bytes(65536):
                            size += len(chunk)
                            if size > max_bytes:
                                raise ClipError("DOWNLOAD_TOO_LARGE", 413, f"plik przekroczyl limit {max_bytes} B")
                            h.update(chunk)
                            f.write(chunk)
                except BaseException:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                    raise
                return Downloaded(path, size, h.hexdigest(), r.headers.get("content-type"), host, hop)
    raise ClipError("DOWNLOAD_TOO_MANY_REDIRECTS", 502, f"wiecej niz {MAX_REDIRECTS} przekierowan")


# ---------- ffprobe ----------
def parse_ffprobe(data: Any, expected_s: int | None = None) -> dict:
    d = data if isinstance(data, dict) else {}
    streams = d.get("streams") if isinstance(d.get("streams"), list) else []
    fmt = d.get("format") if isinstance(d.get("format"), dict) else {}
    video = next((s for s in streams if isinstance(s, dict) and s.get("codec_type") == "video"), None)
    audio = next((s for s in streams if isinstance(s, dict) and s.get("codec_type") == "audio"), None)

    def num(v: Any) -> float | None:
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    dur = num(fmt.get("duration"))
    if dur is None and video:
        dur = num(video.get("duration"))
    out: dict = {"format": fmt.get("format_name"), "duration_s": round(dur, 2) if dur is not None else None,
                 "has_video": video is not None, "has_audio": audio is not None,
                 "video_codec": video.get("codec_name") if video else None,
                 "width": video.get("width") if video else None, "height": video.get("height") if video else None,
                 "audio_codec": audio.get("codec_name") if audio else None}
    if expected_s is not None and dur is not None:
        out["expected_s"] = expected_s
        out["delta_s"] = round(dur - expected_s, 2)
    return out


async def ffprobe_file(path: str, expected_s: int | None = None, timeout_s: float = 30.0) -> dict:
    try:
        p = await asyncio.create_subprocess_exec(
            "ffprobe", "-v", "error", "-print_format", "json", "-show_format", "-show_streams", path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError as e:
        raise ClipError("FFPROBE_MISSING", 500, "brak ffprobe w obrazie (ffmpeg)") from e
    try:
        out, err = await asyncio.wait_for(p.communicate(), timeout_s)
    except asyncio.TimeoutError:
        p.kill()
        raise ClipError("FFPROBE_TIMEOUT", 502, f"ffprobe > {timeout_s:.0f} s") from None
    if p.returncode != 0:
        raise ClipError("FFPROBE_FAILED", 502, (err.decode("utf-8", "replace") or "")[:300])
    try:
        return parse_ffprobe(json.loads(out), expected_s)
    except ValueError as e:
        raise ClipError("FFPROBE_FAILED", 502, "niepoprawny JSON z ffprobe") from e


# ---------- ksiega zlecen (przezywa restart; unikamy dubli) ----------
class ClipLedger:
    """Maly plik JSON w data_dir. Wpis powstaje PRZED POST-em (state=submitting), wiec restart w trakcie
    nie pozwoli na ponowne zlecenie: stan nierozstrzygniety wymaga recznej oceny."""

    def __init__(self, data_dir: str) -> None:
        self.path = os.path.join(data_dir, "clip_jobs.json")
        self.jobs: dict[str, dict] = {}
        try:
            with open(self.path, encoding="utf-8") as f:
                self.jobs = json.load(f)
        except (OSError, ValueError):
            self.jobs = {}
        for j in self.jobs.values():  # proces padl w trakcie POST: nie wiemy, czy powstalo
            if j.get("state") == "submitting":
                j["state"] = "needs_reconciliation"
                j["code"] = "RESTART_DURING_SUBMIT"

    @staticmethod
    def fingerprint(conn_key: str, item: int, start_s: int, end_s: int) -> str:
        return f"{conn_key}|{item}|{start_s}|{end_s}"

    def get(self, fp: str) -> dict | None:
        return self.jobs.get(fp)

    def by_remote_id(self, remote_id: str) -> dict | None:
        return next((j for j in self.jobs.values() if j.get("remote_id") == remote_id), None)

    def put(self, fp: str, job: dict) -> None:
        self.jobs[fp] = job
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.jobs, f)
        os.replace(tmp, self.path)

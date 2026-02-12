# app/utils.py

from __future__ import annotations

import re
import httpx
import chardet
from typing import Optional, Tuple, Dict, Any

# =========================
# Encoding helpers
# =========================

_RE_CHARSET = re.compile(r'charset\s*=\s*["\']?\s*([a-zA-Z0-9_\-]+)', re.I)

def _normalize_charset(enc: str) -> str:
    e = (enc or "").strip().lower()
    if not e:
        return ""
    # popular aliases
    if e in ("iso8859-2", "iso_8859-2", "latin2", "latin-2", "l2"):
        return "iso-8859-2"
    if e in ("windows-1250", "win1250", "cp1250"):
        return "cp1250"
    if e in ("windows-1252", "win1252", "cp1252", "latin-1", "iso-8859-1"):
        return "cp1252"
    if e in ("utf8", "utf-8"):
        return "utf-8"
    return e

def _charset_from_headers(resp: httpx.Response) -> str:
    ct = resp.headers.get("content-type", "") or ""
    m = _RE_CHARSET.search(ct)
    return _normalize_charset(m.group(1)) if m else ""

def _charset_from_html_bytes(raw: bytes) -> str:
    # look only in the beginning of the HTML
    head = raw[:4096].decode("ascii", errors="ignore")
    m = _RE_CHARSET.search(head)
    return _normalize_charset(m.group(1)) if m else ""

def _decode_with_fallback(raw: bytes, enc: str) -> str:
    enc = _normalize_charset(enc)
    if not enc:
        enc = "iso-8859-2"
    try:
        return raw.decode(enc, errors="replace")
    except LookupError:
        return raw.decode("iso-8859-2", errors="replace")
    except Exception:
        return raw.decode("iso-8859-2", errors="replace")

# =========================
# Main fetch
# =========================

async def fetch_with_correct_encoding(
    client: httpx.AsyncClient,
    url: str,
    method: str = "GET",
    params: Optional[dict] = None,
    data: Optional[dict] = None,
    json: Optional[dict] = None,
    cookies: Optional[dict] = None,
) -> Tuple[httpx.Response, str]:
    """
    Wysyła żądanie i zwraca (response, text) z poprawnym dekodowaniem.

    Priorytet:
    1) charset z nagłówka Content-Type
    2) charset z <meta charset=...> w HTML
    3) twardy fallback dla ZPRP: iso-8859-2 (najczęstszy)
    4) chardet jako ostatnia deska ratunku (jeśli wszystko powyżej zawiedzie)
    """
    resp = await client.request(
        method,
        url,
        params=params,
        data=data,
        json=json,
        cookies=cookies,
        follow_redirects=True,
    )

    raw = resp.content

    # 1) headers
    enc = _charset_from_headers(resp)

    # 2) meta in HTML
    if not enc:
        enc = _charset_from_html_bytes(raw)

    # 3) hard fallback for ZPRP pages (iso-8859-2 is typical)
    if not enc:
        enc = "iso-8859-2"

    text = _decode_with_fallback(raw, enc)

    # 4) if still looks like mojibake typical for PL (e.g. £/¡/ñ),
    # try chardet once as a rescue (but keep PL-friendly defaults)
    if re.search(r"[£¡ñ¦±³¬¯¿½]", text):
        detected = chardet.detect(raw)
        det_enc = _normalize_charset((detected or {}).get("encoding") or "")
        # only switch if chardet is confident-ish and suggests something meaningful
        conf = float((detected or {}).get("confidence") or 0.0)
        if det_enc and det_enc != _normalize_charset(enc) and conf >= 0.55:
            text2 = _decode_with_fallback(raw, det_enc)
            # choose the one with fewer mojibake markers
            bad1 = len(re.findall(r"[£¡ñ¦±³¬¯¿½]", text))
            bad2 = len(re.findall(r"[£¡ñ¦±³¬¯¿½]", text2))
            if bad2 < bad1:
                text = text2

    return resp, text

# =========================
# Dodano klasę Utils do logowania
# =========================

import logging
from datetime import datetime

class Utils:
    def __init__(self, logfile_roller: Optional[str] = None, logfile_main_dirs: Optional[list] = None):
        self.logger = logging.getLogger("zprp")
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        if not self.logger.handlers:
            self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        self.logger_max_level = logging.INFO

    def log_this(self, line: str, level: str = 'debug', exc_info=None, pure_print: bool = False):
        """
        Loguje wiadomość lub wypisuje ją bezpośrednio.
        """
        if pure_print:
            print(line)
        else:
            log_level = getattr(logging, level.upper(), logging.DEBUG)
            self.logger.log(log_level, line, exc_info=exc_info)
            self.logger_max_level = max(self.logger_max_level, log_level)

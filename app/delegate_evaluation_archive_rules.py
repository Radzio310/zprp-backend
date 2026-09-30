"""Reguły archiwum ocen delegatów - moduł-liść, bez `app.db`.

Telefon podaje tylko linki z komórki „Ocena" swojej listy meczów. Serwer
przyjmuje wyłącznie ścieżki arkuszy ZPRP (stary PDF albo nowa ocena HTML),
żeby tym kanałem nie dało się kazać mu pobrać czegokolwiek innego.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlparse

ZPRP_HOSTS = {"baza.zprp.pl", "www.baza.zprp.pl"}
LEGACY_PDF_PATH = "/statystyki_sedzia_oc_pdf.php"


def _text(value: Any, limit: int = 240) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def normalize_document_path(url: str) -> tuple[str, str]:
    """(ścieżka z zapytaniem, rodzaj) albo ValueError dla obcego adresu."""
    raw = str(url or "").strip()
    if not raw or len(raw) > 600:
        raise ValueError("Pusty albo zbyt długi adres arkusza")
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"", "http", "https"} or (host and host not in ZPRP_HOSTS):
        raise ValueError("Adres spoza bazy ZPRP")
    path = parsed.path or ""
    if path.startswith("./"):
        path = path[1:]
    if not path.startswith("/"):
        path = "/" + path
    if ".." in path or not path.lower().endswith(".php"):
        raise ValueError("Nieobsługiwana ścieżka arkusza")
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    low = f"{path}?{query}".lower()
    if path.lower() == LEGACY_PDF_PATH:
        kind = "legacy_pdf"
    elif "ocena2" in low:
        kind = "html"
    else:
        raise ValueError("To nie jest arkusz oceny delegata")
    return (f"{path}?{query}" if query else path), kind


def source_key(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8")).hexdigest()[:40]


def validated_candidate(item: dict[str, Any]) -> dict[str, Any]:
    path, kind = normalize_document_path(item.get("url") or "")
    match_id = _text(item.get("match_id"), 40)
    if not match_id.isdigit():
        raise ValueError("Brak poprawnego IdZawody")
    ids = [_text(x, 20) for x in (item.get("referee_ids") or [])][:4]
    names = [_text(x, 120) for x in (item.get("referee_names") or [])][:4]
    return {
        "source_key": source_key(path),
        "path": path,
        "kind": kind,
        "match_id": match_id,
        "match_code": _text(item.get("match_code"), 80),
        "season": _text(item.get("season"), 24),
        "match_date": _text(item.get("match_date"), 40),
        "referee_ids": [x for x in ids if x.isdigit()],
        "referee_names": [x for x in names if x],
        "delegate_name": _text(item.get("delegate_name"), 160),
    }


def looks_like_login_page(html: str) -> bool:
    low = (html or "").lower()
    return 'name="haslo"' in low or "name='haslo'" in low


def document_kind(data: bytes, expected: str) -> str:
    """Rodzaj odpowiedzi po TREŚCI - ZPRP bywa, że odda stronę zamiast PDF-u."""
    if data[:5] == b"%PDF-":
        return "legacy_pdf"
    if expected == "legacy_pdf":
        raise ValueError("ZPRP nie zwrócił pliku PDF")
    return "html"


def content_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def judge_on_sheet(judge_id: str, referee_ids: Iterable[str]) -> bool:
    return str(judge_id or "").strip() in {str(x).strip() for x in referee_ids}

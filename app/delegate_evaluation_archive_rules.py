"""Reguły archiwum ocen delegatów - moduł-liść, bez `app.db`.

Telefon podaje tylko linki z komórki „Ocena" swojej listy meczów. Serwer
przyjmuje wyłącznie formularz ocen ZPRP (`ocena2`) z sezonów liczonych w
statystyce - stare arkusze PDF świadomie pomijamy (decyzja z 30.09.2026).
Tym kanałem nie da się kazać serwerowi pobrać niczego innego.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlparse

from app.delegate_evaluation_utils import allowed_season

ZPRP_HOSTS = {"baza.zprp.pl", "www.baza.zprp.pl"}


def _text(value: Any, limit: int = 240) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def normalize_document_path(url: str) -> str:
    """Ścieżka formularza oceny z uporządkowanym zapytaniem albo ValueError."""
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
    if "ocena2" not in f"{path}?{query}".lower():
        raise ValueError("To nie jest formularz oceny delegata")
    return f"{path}?{query}" if query else path


def source_key(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8")).hexdigest()[:40]


def validated_candidate(item: dict[str, Any]) -> dict[str, Any]:
    path = normalize_document_path(item.get("url") or "")
    match_id = _text(item.get("match_id"), 40)
    if not match_id.isdigit():
        raise ValueError("Brak poprawnego IdZawody")
    season = _text(item.get("season"), 24)
    if not allowed_season(season):
        raise ValueError("Sezon spoza statystyki ocen")
    ids = [_text(x, 20) for x in (item.get("referee_ids") or [])][:4]
    names = [_text(x, 120) for x in (item.get("referee_names") or [])][:4]
    return {
        "source_key": source_key(path),
        "path": path,
        "match_id": match_id,
        "match_code": _text(item.get("match_code"), 80),
        "season": season,
        "match_date": _text(item.get("match_date"), 40),
        "referee_ids": [x for x in ids if x.isdigit()],
        "referee_names": [x for x in names if x],
        "delegate_name": _text(item.get("delegate_name"), 160),
    }


def looks_like_login_page(html: str) -> bool:
    low = (html or "").lower()
    return 'name="haslo"' in low or "name='haslo'" in low


def content_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def has_grades(evaluation: dict[str, Any]) -> bool:
    """Arkusz bez żadnej sekcji to pusty formularz (delegat jeszcze nie wypełnił)."""
    return bool(evaluation.get("sections"))


def judge_on_sheet(judge_id: str, referee_ids: Iterable[str]) -> bool:
    return str(judge_id or "").strip() in {str(x).strip() for x in referee_ids}

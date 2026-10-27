"""Zgłoszenia błędów rysowania z przeglądarki - czyste reguły (bez bazy, bez FastAPI).

Treść zgłoszenia -> pola wiersza `client_error_reports`: bez danych osobowych (adresy URL
wycięte, trasa bez zapytania, długie identyfikatory w trasie sklejone do `:id`), każde pole
przycięte. Odcisk = rodzaj, trasa, część, komunikat, build - ten sam błąd z wielu telefonów
to jeden wiersz z licznikiem. Trasy w `app/client_errors.py`.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Optional

#: Największa treść zgłoszenia (bajty).
MAX_BODY = 4096
#: Zgłoszeń na minutę z jednego adresu.
RATE_LIMIT = 30
#: Najwięcej różnych błędów w tabeli - najdawniej widziane wypadają.
MAX_ROWS = 2000
KINDS = ("stats", "screen")
FIELDS = {"route": 120, "part": 80, "message": 300, "stack": 900, "ua": 240, "build": 40}

_URL = re.compile(r"https?://\S+")
_QUERY = re.compile(r"[?#].*$")
_DIGITS = re.compile(r"\d{6,}")


class ReportError(ValueError):
    """Zgłoszenie nie do przyjęcia (kod HTTP, komunikat)."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _text(value: Any, limit: int) -> Optional[str]:
    if value is None:
        return None
    text = str(value).replace("\x00", "").strip()
    text = _URL.sub("<url>", text)
    return text[:limit] or None


def clean_report(raw: bytes) -> Dict[str, Any]:
    """Treść żądania -> pola wiersza (bez danych osobowych) albo ReportError."""
    if len(raw) > MAX_BODY:
        raise ReportError(413, "Zgłoszenie jest za duże.")
    try:
        data = json.loads(raw.decode("utf-8", errors="replace") or "null")
    except ValueError as exc:
        raise ReportError(422, "Zgłoszenie nie jest poprawnym JSON-em.") from exc
    if not isinstance(data, dict):
        raise ReportError(422, "Zgłoszenie musi być obiektem JSON.")
    message = _text(data.get("message"), FIELDS["message"])
    part = _text(data.get("part"), FIELDS["part"])
    if not message or not part:
        raise ReportError(422, "Brak komunikatu błędu albo nazwy części.")
    kind = str(data.get("kind") or "").strip()
    route = _QUERY.sub("", _text(data.get("route"), FIELDS["route"]) or "/")
    # Długie liczby w trasie (identyfikatory meczów, zawodników) - odcisk wspólny dla wszystkich.
    route = _DIGITS.sub(":id", route) or "/"
    width = data.get("width")
    return {
        "kind": kind if kind in KINDS else "other",
        "route": route[: FIELDS["route"]],
        "part": part,
        "message": message,
        "stack": _text(data.get("stack"), FIELDS["stack"]),
        "ua": _text(data.get("ua"), FIELDS["ua"]),
        "build": _text(data.get("build"), FIELDS["build"]),
        "lite": data.get("lite") if isinstance(data.get("lite"), bool) else None,
        "standalone": data.get("standalone") if isinstance(data.get("standalone"), bool) else None,
        "width": int(width) if isinstance(width, (int, float)) and 0 < width < 10_000 else None,
    }


def fingerprint(row: Dict[str, Any]) -> str:
    """Odcisk błędu: ten sam błąd w tym samym buildzie = jeden wiersz z licznikiem."""
    key = "|".join(str(row.get(k) or "") for k in ("kind", "route", "part", "message", "build"))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:40]

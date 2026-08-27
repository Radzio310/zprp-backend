"""Tekst nagłówków używany wyłącznie przez tor szkoleniowy."""

from __future__ import annotations

from typing import Any

from app.proel_auth import header_text


def actor_text(v: Any, limit: int = 120) -> str:
    """Naprawia latin-1 i Windows-1252, nie zmieniając poprawnego UTF-8."""
    value = header_text(v)
    if not value or value.isascii():
        return str(value or "").strip()[:limit]
    try:
        # Część stosów HTTP mapuje bajty 0x80-0x9f na znaki cp1252 zamiast
        # pozostawić je jako kontrolne latin-1. Przykład: C5 82 -> ``Å‚``.
        repaired = value.encode("cp1252").decode("utf-8")
        markers = ("Ã", "Å", "Ä", "Â")
        if sum(value.count(x) for x in markers) > sum(
            repaired.count(x) for x in markers
        ):
            value = repaired
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass
    return str(value or "").strip()[:limit]


__all__ = ["actor_text"]

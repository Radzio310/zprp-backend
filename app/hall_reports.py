from __future__ import annotations

import unicodedata
from typing import Any, Iterable


def _strip_diacritics(value: str) -> str:
    return "".join(
        char
        for char in unicodedata.normalize("NFKD", value or "")
        if not unicodedata.combining(char)
    )


def _norm_text(value: str) -> str:
    plain = _strip_diacritics(value or "").lower()
    spaced = " ".join(plain.strip().split())
    return "".join(char for char in spaced if char.isalnum() or char.isspace())


def hall_norm_key(name: str, city: str, street: str, number: str) -> str:
    return "|".join(
        [_norm_text(name), _norm_text(city), _norm_text(street), _norm_text(number)]
    )


def hall_dict_key(value: dict[str, Any]) -> str:
    return hall_norm_key(
        str(value.get("Hala_nazwa") or ""),
        str(value.get("Hala_miasto") or ""),
        str(value.get("Hala_ulica") or ""),
        str(value.get("Hala_numer") or ""),
    )


def _teams(value: Any) -> list[str]:
    return list(
        dict.fromkeys(
            str(team).strip() for team in (value or []) if str(team).strip()
        )
    )


def merge_halls(
    current: Iterable[dict[str, Any]],
    accepted: Iterable[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int, int]:
    """Dodaje zatwierdzone hale, a przy identycznym wpisie scala drużyny."""
    halls = [dict(value) for value in current if isinstance(value, dict)]
    hall_index = {hall_dict_key(hall): index for index, hall in enumerate(halls)}
    added = 0
    merged = 0

    for raw_candidate in accepted:
        candidate = dict(raw_candidate)
        candidate["Druzyny"] = _teams(candidate.get("Druzyny"))
        key = hall_dict_key(candidate)
        existing_index = hall_index.get(key)
        if existing_index is None:
            halls.append(candidate)
            hall_index[key] = len(halls) - 1
            added += 1
            continue
        existing = halls[existing_index]
        existing["Druzyny"] = _teams(
            [*(existing.get("Druzyny") or []), *candidate["Druzyny"]]
        )
        merged += 1

    return halls, added, merged


# ---------------------------------------------------------------------------
# Szybkie wczytywanie pliku hal i zbiorcze odrzucanie zgłoszeń
# ---------------------------------------------------------------------------

#: Ile zgłoszeń wolno odrzucić jednym żądaniem.
MAX_BULK_REJECT = 500


def json_file_etag(key: str, updated_at: Any) -> str:
    """Słaby ETag pliku JSON z klucza i chwili ostatniej zmiany.

    `updated_at` ustawia każdy zapis pliku (PUT i zatwierdzenie hal), więc
    nowa treść zawsze daje nowy znacznik. Telefon trzyma kopię pliku i pyta
    `If-None-Match` - bez zmian dostaje krótkie 304 zamiast całej bazy hal.
    """
    stamp = updated_at.isoformat() if hasattr(updated_at, "isoformat") else str(updated_at or "")
    return f'W/"{key}-{stamp}"'


def etag_matches(if_none_match: str | None, etag: str) -> bool:
    """Czy nagłówek `If-None-Match` wskazuje ten sam znacznik (także w liście)."""
    if not if_none_match:
        return False
    wanted = etag.removeprefix("W/")
    for part in if_none_match.split(","):
        candidate = part.strip()
        if candidate == "*" or candidate.removeprefix("W/") == wanted:
            return True
    return False


def clean_report_ids(raw: Iterable[Any]) -> list[int]:
    """Identyfikatory zgłoszeń do odrzucenia: dodatnie, bez powtórzeń, w kolejności."""
    out: list[int] = []
    for value in raw or []:
        try:
            number = int(value)
        except (TypeError, ValueError):
            continue
        if number > 0 and number not in out:
            out.append(number)
    return out[:MAX_BULK_REJECT]

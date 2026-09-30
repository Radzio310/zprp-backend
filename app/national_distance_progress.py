"""Reguły postępu czytania ryczałtów - liść bez importów bazy.

Trasa `/national-distances/progress` tylko pobiera wiersze; co z nich wynika,
rozstrzyga ten moduł, żeby dało się to sprawdzić testem bez łączenia z bazą
(`app.db` łączy się już przy imporcie).
"""

from __future__ import annotations

from typing import Any, Iterable

MAX_ATTEMPTS = 3


def summarize_sources(rows: Iterable[tuple[Any, Any, Any]]) -> dict[str, int]:
    """Wiersze (status, attempts, liczba) -> liczniki dla overlaya.

    Porażka po ostatniej próbie to koniec - serwer już po ten dokument nie
    sięgnie. Porażka przed nią jeszcze czeka na ponowienie, więc jest „w toku".
    """
    counts = {"total": 0, "done": 0, "failed": 0, "pending": 0}
    for state, attempts, n in rows:
        n = int(n or 0)
        counts["total"] += n
        if str(state or "") == "done":
            counts["done"] += n
        elif str(state or "") == "failed" and int(attempts or 0) >= MAX_ATTEMPTS:
            counts["failed"] += n
        else:
            counts["pending"] += n
    return counts


def routes_from_home(rows: Iterable[Any], home_key: str) -> list[dict[str, Any]]:
    """Połączenia zapisane jako para A-B (alfabetycznie) -> „dokąd z domu"."""
    out: list[dict[str, Any]] = []
    for row in rows:
        other_is_b = row["city_a_key"] == home_key
        out.append(
            {
                "key": row["city_b_key"] if other_is_b else row["city_a_key"],
                "name": row["city_b_name"] if other_is_b else row["city_a_name"],
                "km": int(row["distance_km"]),
            }
        )
    return out

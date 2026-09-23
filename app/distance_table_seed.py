"""Publikacja oficjalnych, wersjonowanych tabel odległości wraz z wdrożeniem.

Plik w repozytorium jest bezpiecznikiem wdrożeniowym, a nie drugim panelem
administracyjnym. Przy starcie podnosimy tabelę wyłącznie do nowszego
``validFrom``. Późniejszej wersji wgranej przez administratora nigdy nie
cofamy.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


SILESIA = "ŚLĄSKIE"
SILESIA_2026_PATH = Path(__file__).with_name("data") / "slaskie_distances_2026_09.json"


def load_silesia_2026_table() -> dict[str, Any]:
    with SILESIA_2026_PATH.open(encoding="utf-8") as handle:
        content = json.load(handle)
    if content.get("validFrom") != "2026-09-01":
        raise ValueError("Nieprawidłowa data początku śląskiej tabeli odległości")
    if len(content.get("cities") or []) != 42 or len(content.get("edges") or []) != 861:
        raise ValueError("Niekompletna śląska tabela odległości 2026/2027")
    return content


def should_promote(current: Mapping[str, Any] | None, bundled: Mapping[str, Any]) -> bool:
    """Czy wdrożenie ma podnieść tabelę bez ryzyka cofnięcia nowszej wersji."""

    current_from = str((current or {}).get("validFrom") or "")
    bundled_from = str(bundled.get("validFrom") or "")
    return bool(bundled_from) and current_from < bundled_from


async def promote_official_distance_tables() -> bool:
    """Wstaw oficjalną tabelę Śląska 2026/27, jeśli serwer ma starszą."""

    # Leniwy import nie uruchamia inicjalizacji bazy podczas testów funkcji
    # porównującej wersje.
    from app.db import database, okreg_distances

    bundled = load_silesia_2026_table()
    row = await database.fetch_one(
        okreg_distances.select().where(okreg_distances.c.province == SILESIA)
    )
    current: dict[str, Any] | None = None
    if row:
        raw = row["content"]
        if isinstance(raw, (str, bytes, bytearray)):
            raw = json.loads(raw)
        if isinstance(raw, Mapping):
            current = dict(raw)
    if not should_promote(current, bundled):
        return False

    values = {
        "content": bundled,
        "enabled": True,
        "updated_at": datetime.now(timezone.utc),
    }
    if row:
        await database.execute(
            okreg_distances.update()
            .where(okreg_distances.c.province == SILESIA)
            .values(**values)
        )
    else:
        await database.execute(
            okreg_distances.insert().values(province=SILESIA, **values)
        )
    return True

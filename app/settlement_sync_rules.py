"""
Reguly synca rozliczen okregu bez dotykania bazy: pamiec porazek pomiaru Google,
odswiezanie pustych hal i zapis wierszy paczkami. Osobny modul, zeby dalo sie go
testowac bez Postgresa (`app.db` wymaga go przy imporcie).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy.dialects.postgresql import insert as pg_insert

STORE_BATCH = 400

#: Jak dlugo pamietamy porazke pomiaru Google. Brak wyniku moze byc chwilowy
#: (limit, siec), wiec wraca szybciej; brak samej geometrii przy znanych km nic
#: nie psuje (mapa rysuje luk), wiec wraca rzadko.
FAILURE_TTL = {"nokm": timedelta(days=7), "noshape": timedelta(days=30)}

VENUE_TTL_DAYS = 14
#: Po meczu API wciaz bez miasta hali: pytamy ponownie dopiero po tylu dniach.
VENUE_EMPTY_RETRY_DAYS = 5


def failure_alive(kind: str, checked_at: Optional[datetime], now: datetime) -> bool:
    ttl = FAILURE_TTL.get(kind)
    return bool(ttl and checked_at is not None and (now - checked_at) <= ttl)


def classify_failures(
    cache: dict, before: set, shapes: dict, *, google_on: bool, no_route: Optional[set] = None
) -> tuple[dict, set]:
    """
    Z wyniku pomiaru: ({klucz: rodzaj porazki}, {klucze w pelni zmierzone}).
    "nokm" tylko dla par z `no_route` (Google jednoznacznie: trasy nie ma);
    wyjatek, timeout, limit czy odmowa klucza to "nie wiemy" i nie sa pamietane.
    """
    failed: dict = {}
    healed: set = set()
    for key, value in cache.items():
        if key in before:
            continue
        if value is None:
            if google_on and no_route is not None and key in no_route:
                failed[key] = "nokm"
        elif key in shapes:
            healed.add(key)
        else:
            failed[key] = "noshape"
    return failed, healed


def venue_needs_refresh(hit: Optional[dict], match_at: Optional[datetime], now: datetime) -> bool:
    """Czy pytac API o hale meczu, majac (albo nie) wpis w pamieci."""
    if not hit:
        return True
    fetched_at = hit.get("fetched_at")
    if not str(hit.get("city") or "").strip():
        # Wpis bez miasta pytamy ponownie tylko wtedy, gdy zapisano go PRZED
        # meczem (API moglo jeszcze nie znac hali). Rozegranego meczu, o ktory
        # pytalismy juz po fakcie, pytamy najwyzej raz na VENUE_EMPTY_RETRY_DAYS.
        if fetched_at is None or match_at is None or fetched_at < match_at:
            return True
        return (now - fetched_at) > timedelta(days=VENUE_EMPTY_RETRY_DAYS)
    upcoming = match_at is None or match_at >= now - timedelta(days=1)
    return upcoming and (fetched_at is None or (now - fetched_at) > timedelta(days=VENUE_TTL_DAYS))


async def upsert_batches(
    db: Any, table: Any, rows: list[dict], conflict_cols: list[str], batch: int = STORE_BATCH
) -> int:
    """
    INSERT ... ON CONFLICT DO UPDATE z wieloma wierszami w jednym zapytaniu.
    Wiersze z tym samym kluczem sklada w jeden (ostatni wygrywa) - Postgres nie
    pozwala trafic dwa razy w ten sam wiersz jednym poleceniem. Zwraca liczbe zapytan.
    """
    merged: dict[tuple, dict] = {}
    for row in rows:
        merged[tuple(row[c] for c in conflict_cols)] = row
    values = list(merged.values())
    queries = 0
    for start in range(0, len(values), batch):
        chunk = values[start : start + batch]
        statement = pg_insert(table).values(chunk)
        updatable = [c for c in chunk[0] if c not in conflict_cols]
        await db.execute(
            statement.on_conflict_do_update(
                index_elements=[table.c[c] for c in conflict_cols],
                set_={c: statement.excluded[c] for c in updatable},
            )
        )
        queries += 1
    return queries

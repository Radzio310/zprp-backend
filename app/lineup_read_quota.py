"""Dobowy limit odczytów składów na konto - trwały w bazie („Wczytaj składy", 02.11.2026).

Funkcje dostają `database` i tabelę jako argumenty (bez importu `app.db`), więc dają się sprawdzić na małym SQLite.
Zajęcie miejsca jest jednym warunkowym UPDATE (`count < limit`), więc dwa równoległe żądania nie przekroczą limitu.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Tuple
from zoneinfo import ZoneInfo

from sqlalchemy import delete, insert, select, update

WARSAW = ZoneInfo("Europe/Warsaw")
KEEP_DAYS = 14


def today(now: Optional[datetime] = None) -> str:
    return (now or datetime.now(timezone.utc)).astimezone(WARSAW).date().isoformat()


async def take(database: Any, table: Any, judge_id: str, kind: str, limit: int, *, now: Optional[datetime] = None) -> Tuple[bool, int]:
    """(zajęto, ile już zużyto po tej operacji). Zajęto=False przy wyczerpanym limicie (licznik bez zmiany)."""
    day = today(now)
    where = (table.c.judge_id == judge_id, table.c.day == day, table.c.kind == kind)
    for _ in range(2):
        bumped = await database.fetch_one(update(table).where(*where, table.c.count < limit).values(count=table.c.count + 1).returning(table.c.count))
        if bumped is not None:
            return True, int(bumped["count"])
        row = await database.fetch_one(select(table.c.count).where(*where))
        if row is not None:
            return False, int(row["count"])
        try:
            await database.execute(insert(table).values(judge_id=judge_id, day=day, kind=kind, count=1))
        except Exception:  # noqa: BLE001 - wyścig o pierwszy wpis dnia: drugi proces był szybszy, próbujemy UPDATE
            continue
        cutoff = today((now or datetime.now(timezone.utc)) - timedelta(days=KEEP_DAYS))
        try:
            await database.execute(delete(table).where(table.c.day < cutoff))
        except Exception:  # noqa: BLE001 - sprzątanie nigdy nie psuje odczytu
            pass
        return True, 1
    return False, limit


async def release(database: Any, table: Any, judge_id: str, kind: str, *, now: Optional[datetime] = None) -> None:
    """Oddaje miejsce, gdy odczyt nie doszedł do skutku z winy serwera lub dostawcy (nie z winy użytkownika)."""
    await database.execute(update(table).where(table.c.judge_id == judge_id, table.c.day == today(now), table.c.kind == kind,
                                               table.c.count > 0).values(count=table.c.count - 1))


async def used(database: Any, table: Any, judge_id: str, kind: str, *, now: Optional[datetime] = None) -> int:
    row = await database.fetch_one(select(table.c.count).where(table.c.judge_id == judge_id, table.c.day == today(now), table.c.kind == kind))
    return int(row["count"]) if row is not None else 0

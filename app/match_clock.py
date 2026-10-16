"""Ślad zegara meczu - punkty (godzina, czas meczu) z migawek i ich pamięć.

Reguły (jak z punktów policzyć godzinę zdarzenia) mieszkają w liściu
`app/match_clock_rules.py` z testami bez bazy. Tutaj tylko baza:

  * `clock_points(match_number)` - ślad zapamiętany + migawki dołożone od
    ostatniego razu (przyrostowo po `id`), z zapisem nowego śladu;
  * `remember_from_ids(ids)` - wołane przez sprzątanie migawek PRZED ich
    skasowaniem, żeby ślad przeżył 7-dniową retencję zwykłych migawek.

Jak migawki: NIGDY nie rzuca. Brak śladu to brak godzin przy znacznikach,
nie błąd ekranu.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import select

from app.match_clock_rules import Point, merge_points, point_from_blob, skew_by_writer
from app.snapshot_rules import unpack

logger = logging.getLogger(__name__)


def _ms(value: Any) -> Optional[int]:
    if isinstance(value, datetime):
        stamp = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return int(stamp.timestamp() * 1000)
    return None


def points_from_rows(rows: Sequence[Any]) -> List[Point]:
    """Punkty z wierszy migawek (z treścią). Poprawia przestawiony zegar telefonu."""
    raw: List[Tuple[str, Optional[Point], Optional[int], str]] = []
    samples: List[Tuple[str, int, int]] = []
    for row in rows:
        blob = unpack(row["payload"])
        created = _ms(row["created_at"])
        writer = str(row["writer_install"] or "")
        point = point_from_blob(blob, fallback_wall_ms=created)
        if point is None and blob is None and row["main_time_ms"] is not None and created:
            # Treść za duża albo jej brak - zostają kolumny listy.
            half = 0 if row["first_half"] is None else (1 if row["first_half"] else 2)
            point = (created, int(row["main_time_ms"]), half, 0)
        source = str(row["source"] or "server")
        if point and created and source == "server" and isinstance(blob, dict) and blob.get("savedAtMs"):
            samples.append((writer, created, point[0]))
        raw.append((writer, point, created, source))
    skew = skew_by_writer(samples)
    out: List[Point] = []
    for writer, point, _created, _source in raw:
        if not point:
            continue
        fix = skew.get(writer, 0)
        out.append((point[0] + fix, point[1], point[2], point[3]))
    return out


def _cols(T):
    return (
        T.c.id,
        T.c.payload,
        T.c.created_at,
        T.c.writer_install,
        T.c.source,
        T.c.main_time_ms,
        T.c.first_half,
    )


async def _stored(match_number: str) -> Tuple[List[Point], int]:
    from app.db import database, proel_match_clock_trace as C

    row = await database.fetch_one(select(C).where(C.c.match_number == match_number))
    if not row:
        return [], 0
    try:
        points = merge_points(json.loads(row["points_json"] or "[]"))
    except ValueError:
        points = []
    return points, int(row["last_snapshot_id"] or 0)


async def _save(match_number: str, points: List[Point], last_id: int) -> None:
    from app.db import database, proel_match_clock_trace as C

    values = {
        "match_number": match_number,
        "points_json": json.dumps([list(p) for p in points], separators=(",", ":")),
        "last_snapshot_id": last_id,
        "updated_at": datetime.now(timezone.utc),
    }
    exists = await database.fetch_one(select(C.c.match_number).where(C.c.match_number == match_number))
    if exists:
        await database.execute(C.update().where(C.c.match_number == match_number).values(**values))
    else:
        try:
            await database.execute(C.insert().values(**values))
        except Exception:  # noqa: BLE001 - wyścig dwóch odczytów: wygrywa ten, który był pierwszy
            await database.execute(C.update().where(C.c.match_number == match_number).values(**values))


async def clock_points(match_number: str) -> List[Point]:
    """Pełny ślad zegara meczu - pamięć + nowe migawki. Nigdy nie rzuca."""
    key = str(match_number or "").strip()
    if not key:
        return []
    try:
        from app.db import database, proel_match_snapshots as T

        stored, last_id = await _stored(key)
        rows = await database.fetch_all(
            select(*_cols(T)).where(T.c.match_number == key, T.c.id > last_id).order_by(T.c.id.asc()).limit(3000)
        )
        if not rows:
            return stored
        fresh = points_from_rows(rows)
        merged = merge_points(stored, fresh)
        await _save(key, merged, max(int(r["id"]) for r in rows))
        return merged
    except Exception:  # noqa: BLE001
        logger.warning("slad zegara meczu nieudany (%s)", match_number, exc_info=True)
        return []


async def remember_from_ids(ids: Iterable[int]) -> int:
    """Dopisz do śladów punkty z migawek, które za chwilę znikną. Nigdy nie rzuca."""
    wanted = [int(i) for i in ids]
    if not wanted:
        return 0
    try:
        from app.db import database, proel_match_snapshots as T

        rows = await database.fetch_all(select(T.c.match_number, *_cols(T)).where(T.c.id.in_(wanted)))
        by_match: Dict[str, List[Any]] = {}
        for row in rows:
            by_match.setdefault(str(row["match_number"]), []).append(row)
        for key, group in by_match.items():
            stored, last_id = await _stored(key)
            merged = merge_points(stored, points_from_rows(group))
            await _save(key, merged, last_id)
        return len(by_match)
    except Exception:  # noqa: BLE001 - sprzątanie ma iść dalej
        logger.warning("zapamietanie sladu zegara nieudane", exc_info=True)
        return 0


async def drop_trace(match_number: str) -> None:
    """Usunięcie meczu zabiera jego ślad (jak migawki)."""
    try:
        from app.db import database, proel_match_clock_trace as C

        await database.execute(C.delete().where(C.c.match_number == str(match_number)))
    except Exception:  # noqa: BLE001
        logger.warning("usuniecie sladu zegara nieudane (%s)", match_number, exc_info=True)

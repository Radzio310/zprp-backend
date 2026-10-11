"""Skaner alarmów meczu - w tle przelicza mecze, które dostały nowe wersje.

Co `SCAN_INTERVAL_S` bierze mecze z migawkami z ostatnich `WINDOW_DAYS` dni,
których ostatnia migawka jest nowsza niż ta, do której liczono, i przelicza
alarmy (`app/raport_dowodowy/alarmy.py`). Wynik ląduje w `proel_match_alarms`
- stąd plakietka na liście Dziennika.

PUSH TYLKO PRZY PODEJRZANYM (decyzja 09.10.2026: „nie każde usunięcie kary
jest podejrzane"), tylko gdy pojawiło się NOWE podejrzane znalezisko (odcisk
zbioru) i tylko świeże (`PUSH_FRESH_H`) - pierwsze uruchomienie po wdrożeniu
nie może zasypać adminów powiadomieniami o meczach sprzed tygodnia.

Partie po `PER_CYCLE` meczów z oddechem między nimi: rozpakowanie historii
meczu to ~100 ms pracy procesora, a w tym samym procesie lecą autozapisy.
Nic tu nie ma prawa wywrócić pętli - błąd jednego meczu jest logowany,
a mecz dostaje wiersz z numerem migawki, żeby nie wracał co cykl.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy import func, select

logger = logging.getLogger(__name__)

SCAN_INTERVAL_S = 120
WINDOW_DAYS = 8
PER_CYCLE = 25
PUSH_FRESH_H = 24


def _now() -> datetime:
    return datetime.now(timezone.utc)


def should_push(alarmy: Dict[str, Any], pushed_fingerprint: Optional[str], now: datetime) -> bool:
    """Czy wysłać push - reguła w jednym miejscu, z testem."""
    from app.raport_dowodowy.analiza import czas_utc

    if alarmy.get("poziom") != "podejrzane" or not alarmy.get("odcisk"):
        return False
    if alarmy["odcisk"] == (pushed_fingerprint or ""):
        return False
    kiedy = czas_utc(alarmy.get("ostatnie_podejrzane"))
    return bool(kiedy and kiedy >= now - timedelta(hours=PUSH_FRESH_H))


async def _zapisz(key: str, values: Dict[str, Any]) -> None:
    from app.db import database, proel_match_alarms as T

    istnieje = await database.fetch_one(select(T.c.match_number).where(T.c.match_number == key))
    if istnieje is None:
        await database.execute(T.insert().values(match_number=key, **values))
    else:
        await database.execute(T.update().where(T.c.match_number == key).values(**values))


async def przelicz(key: str, last_snapshot_id: Optional[int], poprzedni: Optional[Dict[str, Any]]) -> None:
    from app.proel_match_history import analiza_meczu

    now = _now()
    try:
        _zrzut, alarmy = await analiza_meczu(key)
    except Exception:  # noqa: BLE001 - mecz bez zapisu, uszkodzona migawka
        logger.warning("alarmy: nie przeliczono %s", key, exc_info=True)
        await _zapisz(key, {"last_snapshot_id": last_snapshot_id, "computed_at": now})
        return
    values: Dict[str, Any] = {
        "level": alarmy.get("poziom"),
        "headline": alarmy.get("naglowek") or None,
        "findings_json": alarmy.get("osoby") or [],
        "findings_count": int(alarmy.get("liczba") or 0),
        "last_snapshot_id": last_snapshot_id,
        "computed_at": now,
    }
    stary_odcisk = (poprzedni or {}).get("pushed_fingerprint")
    if alarmy.get("poziom") == "podejrzane" and alarmy.get("odcisk") and alarmy["odcisk"] != (stary_odcisk or ""):
        if should_push(alarmy, stary_odcisk, now):
            from app.admin_alerts import notify_admins

            await notify_admins(
                "proel_suspicious", key, alarmy.get("naglowek") or "Podejrzana zmiana w protokole",
                reference=key,
            )
            values["pushed_at"] = now
        # Odcisk zapisujemy także bez pushu (stare znalezisko) - inaczej każde
        # następne przeliczenie pytałoby o to samo od nowa.
        values["pushed_fingerprint"] = alarmy["odcisk"]
    await _zapisz(key, values)


async def scan_once(limit: int = PER_CYCLE) -> int:
    from app.db import database, proel_match_alarms as T, proel_match_snapshots as S

    since = _now() - timedelta(days=WINDOW_DAYS)
    ostatnie = await database.fetch_all(
        select(S.c.match_number, func.max(S.c.id).label("last"))
        .where(S.c.received_at >= since)
        .group_by(S.c.match_number)
        .order_by(func.max(S.c.id).desc())
    )
    znane = {r["match_number"]: dict(r) for r in await database.fetch_all(
        select(T.c.match_number, T.c.last_snapshot_id, T.c.pushed_fingerprint)
    )}
    do_zrobienia = [r for r in ostatnie
                    if (znane.get(r["match_number"]) or {}).get("last_snapshot_id") != r["last"]][:limit]
    for r in do_zrobienia:
        await przelicz(r["match_number"], r["last"], znane.get(r["match_number"]))
        await asyncio.sleep(0.2)  # oddech dla autozapisów meczów w toku
    return len(do_zrobienia)


async def run_alarm_scan() -> None:
    """Pętla skanera. Jedna porażka nie kończy pętli."""
    await asyncio.sleep(30)  # po starcie najpierw niech wstanie reszta
    while True:
        try:
            await scan_once()
        except Exception:  # noqa: BLE001
            logger.warning("skaner alarmów meczu: cykl nieudany", exc_info=True)
        await asyncio.sleep(SCAN_INTERVAL_S)

"""Cykliczne pobieranie kalendarzy sędziów (iCal) i odświeżanie snapshotu.

Sędzia podaje link raz, a serwer czyta go co kilka godzin - także wtedy, gdy
nikt nie otwiera aplikacji. To jest cała różnica wobec dzisiejszego importu z
Google, który dzieje się na telefonie, przy wejściu na ekran niedyspozycji.

GDZIE LĄDUJĄ WPISY. W osobnej tabeli (``judge_feed_offtimes``), dokładnie tak
jak niedyspozycje centralne z baza.zprp.pl. Endpointy ``/silesia/offtimes/*``
składają oba źródła razem z kalendarzem okręgowym dopiero PRZY ODCZYCIE, więc:

  * zapis z telefonu nie może skasować planu zajęć,
  * plan zajęć nie może skasować wpisów zrobionych ręcznie.

NIEUDANE POBRANIE NIE KASUJE PLANU. Gdy uczelnia nie odpowiada, zostawiamy
poprzedni snapshot i zapisujemy powód przy kalendarzu. Pusta odpowiedź po
awarii wyglądałaby jak „jestem wolny w każdy termin", a to nieprawda i nikt by
tego nie zauważył.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.calendar_feed_rules import (
    DEFAULT_INTERVAL_SECONDS,
    feed_due,
    sync_window,
)
from app.db import database, judge_calendar_feeds, judge_feed_offtimes
from app.ical_feed import feed_entries

logger = logging.getLogger("app.calendar_feed_sync")

WARSAW = ZoneInfo("Europe/Warsaw")

#: Plik kalendarza to tekst. Pięć megabajtów to już nie plan zajęć, tylko
#: pomyłka albo próba zapchania nam pamięci.
MAX_BYTES = 5_000_000
TIMEOUT_SECONDS = 25.0

#: Co ile sprawdzamy, czy któryś kalendarz ma termin odświeżenia. Samo
#: odświeżenie jest rzadsze (`DEFAULT_INTERVAL_SECONDS`).
TICK_SECONDS = 600


def sync_enabled() -> bool:
    return os.getenv("CALENDAR_FEED_SYNC_ENABLED", "true").strip().lower() in (
        "1",
        "true",
        "tak",
        "yes",
        "on",
    )


def interval_seconds() -> int:
    try:
        return max(900, int(os.getenv("CALENDAR_FEED_SYNC_SECONDS", "")))
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL_SECONDS


def _short_error(exc: BaseException) -> str:
    """Powód bez adresu - w linku siedzi klucz, a błędy trafiają do aplikacji."""
    if isinstance(exc, httpx.TimeoutException):
        return "Serwer kalendarza nie odpowiedział na czas."
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code in (401, 403):
            return "Serwer kalendarza odmówił dostępu - link mógł stracić ważność."
        if code == 404:
            return "Pod tym adresem nie ma kalendarza."
        return f"Serwer kalendarza odpowiedział błędem {code}."
    if isinstance(exc, httpx.HTTPError):
        return "Nie udało się połączyć z serwerem kalendarza."
    text = str(exc).strip()
    return text[:200] if text else "Nie udało się odczytać kalendarza."


async def fetch_ics(url: str) -> str:
    """Treść pliku iCal. Rzuca wyjątkiem, którego powód pokażemy sędziemu."""
    async with httpx.AsyncClient(
        timeout=TIMEOUT_SECONDS,
        follow_redirects=True,
        headers={"User-Agent": "BAZA-kalendarz/1.0", "Accept": "text/calendar, */*"},
    ) as client:
        response = await client.get(url)
        response.raise_for_status()
        content = response.content[: MAX_BYTES + 1]
        if len(content) > MAX_BYTES:
            raise ValueError("Plik kalendarza jest zbyt duży.")
        try:
            return content.decode(response.encoding or "utf-8", errors="replace")
        except (LookupError, UnicodeDecodeError):
            return content.decode("utf-8", errors="replace")


async def _mark(
    feed_id: str,
    *,
    status: str,
    error: Optional[str],
    count: Optional[int],
    synced: bool,
) -> None:
    values: Dict[str, Any] = {"last_status": status, "last_error": error}
    if synced:
        values["last_sync_at"] = datetime.now(timezone.utc)
    if count is not None:
        values["entry_count"] = count
    await database.execute(
        judge_calendar_feeds.update()
        .where(judge_calendar_feeds.c.id == feed_id)
        .values(**values)
    )


async def sync_feed(feed: Any, *, today: Optional[date] = None) -> Dict[str, Any]:
    """Jeden kalendarz: pobierz, przeczytaj, odśwież snapshot. Nigdy nie rzuca."""
    feed_id = str(feed["id"])
    judge_id = str(feed["judge_id"])
    name = str(feed["name"] or "Kalendarz")
    day = today or datetime.now(WARSAW).date()
    window_start, window_end = sync_window(day)

    try:
        text = await fetch_ics(str(feed["url"]))
        entries = feed_entries(
            text,
            feed_id=feed_id,
            feed_name=name,
            color=feed["color"],
            window_start=window_start,
            window_end=window_end,
            synced_at=datetime.now(timezone.utc),
        )
    except Exception as exc:  # noqa: BLE001 - powód pokazujemy, snapshot zostaje
        reason = _short_error(exc)
        logger.warning("kalendarz %s: %s", feed_id, reason)
        # Świadomie BEZ `last_sync_at`: nieudana próba nie jest synchronizacją,
        # więc kolejny przebieg spróbuje ponownie.
        await _mark(feed_id, status="error", error=reason, count=None, synced=False)
        return {"feed_id": feed_id, "status": "error", "error": reason}

    stmt = pg_insert(judge_feed_offtimes).values(
        feed_id=feed_id,
        judge_id=judge_id,
        data_json=entries,
        synced_at=datetime.now(timezone.utc),
    ).on_conflict_do_update(
        index_elements=[judge_feed_offtimes.c.feed_id],
        set_={
            "judge_id": judge_id,
            "data_json": entries,
            "synced_at": datetime.now(timezone.utc),
        },
    )
    await database.execute(stmt)
    await _mark(feed_id, status="ok", error=None, count=len(entries), synced=True)
    logger.info("kalendarz %s: %s wpisów", feed_id, len(entries))
    return {"feed_id": feed_id, "status": "ok", "entries": len(entries)}


async def sync_judge_feeds(judge_id: str) -> List[Dict[str, Any]]:
    """Wszystkie włączone kalendarze jednego sędziego - na żądanie z aplikacji."""
    rows = await database.fetch_all(
        select(judge_calendar_feeds).where(
            (judge_calendar_feeds.c.judge_id == str(judge_id))
            & (judge_calendar_feeds.c.enabled.is_(True))
        )
    )
    return [await sync_feed(row) for row in rows]


async def _cycle() -> int:
    rows = await database.fetch_all(
        select(judge_calendar_feeds).where(judge_calendar_feeds.c.enabled.is_(True))
    )
    now = datetime.now(timezone.utc)
    interval = interval_seconds()
    done = 0
    for row in rows:
        if not feed_due(row["last_sync_at"], now=now, interval_seconds=interval):
            continue
        await sync_feed(row)
        done += 1
        # Cudze serwery odpytujemy spokojnie, jeden po drugim.
        await asyncio.sleep(1.5)
    return done


async def run_calendar_feed_sync() -> None:
    """Pętla w tle. Jak pozostałe: sama się podnosi po każdym błędzie."""
    if not sync_enabled():
        logger.info("Synchronizacja kalendarzy sędziów wyłączona zmienną środowiskową")
        return
    # Start po chwili, żeby nie konkurować z resztą rozruchu.
    await asyncio.sleep(40)
    while True:
        try:
            done = await _cycle()
            if done:
                logger.info("Kalendarze sędziów: odświeżono %s", done)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("Przebieg synchronizacji kalendarzy nieudany")
        await asyncio.sleep(TICK_SECONDS)

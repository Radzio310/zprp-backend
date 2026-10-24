"""Czas polski: jedno źródło „teraz", „dziś" i granic doby (Europe/Warsaw, z DST).

Serwer (Railway) chodzi w UTC, a `zprp_public_matches.scheduled_at`/`played_at`
to NAIWNY czas warszawski (ZPRP podaje „2026-10-24 18:00:00" bez strefy).
Porównania z gołym `datetime.now()` (UTC) przesuwały dobę o 1-2 h: po północy
„Dziś" pokazywało wczoraj. Każde „teraz/dziś" portalu idzie przez ten moduł.

Testy podmieniają zegar: ``monkeypatch.setattr(time_pl, "utc_now", lambda: ...)``.
Python 3.10 (produkcja): tylko `zoneinfo`, bez nowszych API.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Optional, Tuple
from zoneinfo import ZoneInfo

WARSAW = ZoneInfo("Europe/Warsaw")


def utc_now() -> datetime:
    """Jedyny odczyt zegara (aware UTC) - podmieniany w testach."""
    return datetime.now(timezone.utc)


def to_warsaw_naive(value: Optional[datetime]) -> Optional[datetime]:
    """Aware → naiwny czas warszawski; naiwny zostaje (umowa: naiwny = już Warszawa)."""
    if value is None or value.tzinfo is None:
        return value
    return value.astimezone(WARSAW).replace(tzinfo=None)


def warsaw_now(now: Optional[datetime] = None) -> datetime:
    """„Teraz" jako naiwny czas warszawski - porównywalny ze `scheduled_at`.

    `now` (aware) pozwala wstrzyknąć zegar; naiwny `now` traktujemy jako UTC.
    """
    current = utc_now() if now is None else now
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(WARSAW).replace(tzinfo=None)


def warsaw_today(now: Optional[datetime] = None) -> date:
    """Dzisiejsza data kalendarza polskiego."""
    return warsaw_now(now).date()


def day_bounds(day: date) -> Tuple[datetime, datetime]:
    """[początek, koniec) doby `day` jako naiwny czas warszawski (do zapytań po `scheduled_at`)."""
    start = datetime.combine(day, time(0, 0))
    return start, start + timedelta(days=1)


def today_bounds(now: Optional[datetime] = None) -> Tuple[datetime, datetime]:
    return day_bounds(warsaw_today(now))


def warsaw_to_utc(local: Optional[datetime]) -> Optional[datetime]:
    """Naiwny czas warszawski → aware UTC (aware przechodzi bez zmian, tylko do UTC)."""
    if not isinstance(local, datetime):
        return None
    if local.tzinfo is not None:
        return local.astimezone(timezone.utc)
    return local.replace(tzinfo=WARSAW).astimezone(timezone.utc)


def has_kickoff_time(value: Any) -> bool:
    """Czy termin meczu niesie godzinę.

    ZPRP dla meczu bez ustalonej godziny (np. Superliga czekająca na TV) podaje
    sam dzień albo „RRRR-MM-DD 00:00:00". Piłka ręczna nie startuje o północy,
    więc 00:00 = „godzina do ustalenia" (brak godziny, nie start o 0:00).
    """
    if not isinstance(value, datetime):
        return False
    return (value.hour, value.minute, value.second, value.microsecond) != (0, 0, 0, 0)


def kickoff_sort_key(value: Any) -> Tuple[int, date, int, datetime]:
    """Klucz sortowania terminów: dzień, w dniu mecze z godziną przed „do ustalenia"; brak daty na końcu."""
    if not isinstance(value, datetime):
        return (1, date.max, 1, datetime.max)
    naive = to_warsaw_naive(value)
    return (0, naive.date(), 0 if has_kickoff_time(naive) else 1, naive)


def is_upcoming_at(value: Any, now_local: datetime, grace: timedelta) -> bool:
    """Termin „przed nami" względem naiwnego `now_local` (Warszawa).

    Z godziną: nie starszy niż `grace` (mecz w toku też). Bez godziny: do końca
    swojej doby - mecz „do ustalenia" na dziś nie znika o 3:00 w nocy.
    Brak daty = przed nami (nie wiemy, że minął).
    """
    if not isinstance(value, datetime):
        return True
    at = to_warsaw_naive(value)
    if not has_kickoff_time(at):
        return at.date() >= now_local.date()
    return at >= now_local - grace

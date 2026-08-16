# app/proel_users/rate_limit.py
#
# Limiter oparty o BAZĘ, nie o pamięć procesu.
#
# Dlaczego nie slowapi z main.py: tamten limiter liczy w pamięci jednego
# procesu i wymagałby importu z main (cykl). Tu chodzi o twardą ochronę
# 5-znakowego tokenu meczu (36^5 ≈ 60 mln kombinacji) — licznik musi przeżyć
# restart i działać także przy kilku instancjach, więc zapisujemy zdarzenia
# do istniejącej, generycznej tabeli `email_rate_events` (scope/ref/created_at)
# pod scope'ami z prefiksem `proel_`. Wzorzec 1:1 z
# app/beach/email_verification.py:130-165 — sprawdzony w produkcji.

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import and_, func, select

logger = logging.getLogger(__name__)


def _db():
    """Import bazy DOPIERO przy użyciu — wzorzec z app/results.py.

    `app/db.py` odpala `metadata.create_all()` już przy imporcie, a to wywraca
    się na SQLite (kolumny ARRAY), na którym chodzą testy jednostkowe. Import
    na poziomie modułu uwalałby więc KOLEKCJĘ testów każdego pliku, który
    przez łańcuch importów dotknie tego modułu.
    """
    from app.db import beach_email_rate_events as rate_t, database

    return database, rate_t


async def count_recent(scope: str, ref: str, window_seconds: int) -> int:
    database, rate_t = _db()
    since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    row = await database.fetch_one(
        select(func.count())
        .select_from(rate_t)
        .where(
            and_(
                rate_t.c.scope == scope,
                rate_t.c.ref == ref,
                rate_t.c.created_at >= since,
            )
        )
    )
    return int(row[0]) if row else 0


async def record(scope: str, ref: str) -> None:
    if not ref:
        return
    database, rate_t = _db()
    await database.execute(
        rate_t.insert().values(
            scope=scope, ref=ref, created_at=datetime.now(timezone.utc)
        )
    )


async def _retry_after_seconds(scope: str, ref: str, window_seconds: int) -> int:
    """Za ile sekund najstarsze zdarzenie wypadnie z okna — uczciwsze niż
    zwracanie całego okna, bo klient pokazuje użytkownikowi odliczanie."""
    database, rate_t = _db()
    since = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    row = await database.fetch_one(
        select(func.min(rate_t.c.created_at)).where(
            and_(
                rate_t.c.scope == scope,
                rate_t.c.ref == ref,
                rate_t.c.created_at >= since,
            )
        )
    )
    oldest = row[0] if row else None
    if oldest is None:
        return window_seconds
    if oldest.tzinfo is None:
        oldest = oldest.replace(tzinfo=timezone.utc)
    elapsed = (datetime.now(timezone.utc) - oldest).total_seconds()
    return max(1, int(window_seconds - elapsed) + 1)


async def enforce(scope: str, ref: str, limit: int, window_seconds: int) -> None:
    """Rzuca 429 z `retry_after_s`, gdy limit w oknie jest wyczerpany.

    `ref` (zwykle IP) nigdy nie jest tokenem ani hasłem — logujemy go wprost.
    """
    if not ref:
        return
    count = await count_recent(scope, ref, window_seconds)
    if count >= limit:
        retry = await _retry_after_seconds(scope, ref, window_seconds)
        logger.warning(
            "proel rate limit hit scope=%s ref=%s count=%s retry=%ss",
            scope, ref, count, retry,
        )
        raise HTTPException(
            status_code=429,
            detail={
                "code": "RATE_LIMITED",
                "message": "Zbyt wiele prób. Spróbuj ponownie później.",
                "retry_after_s": retry,
            },
        )

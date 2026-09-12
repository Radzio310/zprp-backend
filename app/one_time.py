"""
Czynnosci, ktore maja sie wydarzyc RAZ - nawet gdy Railway wstanie dziesiec razy.

Slad zostaje w `app_migrations`. Bez niego kazdy restart serwera powtarzalby
poprawke danych, a poprawki bywaja kosztowne: jedna kasuje rejestr sezonow
(czyli konczy sie pobraniem calej historii z ZPRP), inna chodzi po formularzach
obsady. Dwie repliki na Railway prosza o to samo w tej samej sekundzie, wiec
o pierwszenstwie rozstrzyga BAZA, a nie kolejnosc wywolan: klucz glowny na
`name` sprawia, ze drugi wpis po prostu nie powstaje.

⚠ `app.db` laczy sie z Postgresem juz przy imporcie, wiec import siedzi
w srodku funkcji - dzieki temu modul da sie wczytac bez bazy.
"""

from __future__ import annotations

from datetime import datetime, timezone


async def claim_once(name: str) -> bool:
    """
    Pierwsze wolanie oddaje True i zostawia slad; kazde nastepne oddaje False.

    Nazwa jest kluczem, wiec ma byc konkretna („assignment-grades-SLASKIE"),
    a nie ogolna („backfill") - inaczej poprawka dla jednego okregu zablokuje
    ja wszystkim pozostalym.
    """
    from sqlalchemy import select
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.db import app_migrations, database

    row = await database.fetch_one(
        select(app_migrations.c.name).where(app_migrations.c.name == name)
    )
    if row is not None:
        return False
    await database.execute(
        pg_insert(app_migrations)
        .values(name=name, ran_at=datetime.now(timezone.utc))
        .on_conflict_do_nothing(index_elements=[app_migrations.c.name])
    )
    return True


async def was_claimed(name: str) -> bool:
    """Czy ta czynnosc juz sie odbyla - do pokazania w panelu, bez zajmowania sladu."""
    from sqlalchemy import select

    from app.db import app_migrations, database

    row = await database.fetch_one(
        select(app_migrations.c.name).where(app_migrations.c.name == name)
    )
    return row is not None

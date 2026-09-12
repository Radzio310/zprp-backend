"""
Czynności, które mają się wydarzyć RAZ - nawet gdy Railway wstanie dziesięć razy.

Ślad zostaje w `app_migrations`. Bez niego każdy restart serwera powtarzałby
poprawkę danych, a poprawki bywają kosztowne: jedna kasuje rejestr sezonów
(czyli kończy się pobraniem całej historii z ZPRP), inna chodzi po formularzach
obsady. Dwie repliki na Railway proszą o to samo w tej samej sekundzie, więc
o pierwszeństwie rozstrzyga BAZA, a nie kolejność wywołań: klucz główny na
`name` sprawia, że drugi wpis po prostu nie powstaje.

⚠ `app.db` łączy się z Postgresem już przy imporcie, więc import siedzi
w środku funkcji - dzięki temu moduł da się wczytać bez bazy.
"""

from __future__ import annotations

from datetime import datetime, timezone


async def claim_once(name: str) -> bool:
    """
    Pierwsze wołanie oddaje True i zostawia ślad; każde następne oddaje False.

    Nazwa jest kluczem, więc ma być konkretna („assignment-grades-SLASKIE"),
    a nie ogólna („backfill") - inaczej poprawka dla jednego okręgu zablokuje
    ją wszystkim pozostałym.
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
    """Czy ta czynność już się odbyła - do pokazania w panelu, bez zajmowania śladu."""
    from sqlalchemy import select

    from app.db import app_migrations, database

    row = await database.fetch_one(
        select(app_migrations.c.name).where(app_migrations.c.name == name)
    )
    return row is not None

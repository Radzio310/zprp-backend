"""Kalendarze drugorzędne Google: dostęp do bazy (port `store` silnika).

`app.db` łączy się z bazą już przy imporcie, więc importujemy go DOPIERO we
wnętrzu funkcji (`_t()`), a nie w nagłówku pliku.
"""

from __future__ import annotations

import datetime
from typing import Any

from sqlalchemy import and_, delete, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

_JOB_FIELDS = (
    "job_kind",
    "job_state",
    "job_total",
    "job_done",
    "job_skipped",
    "job_failed",
    "job_error",
    "job_kept",
    "job_note",
    "job_heartbeat",
)


def _t():
    from app import db  # noqa: PLC0415 - import odroczony celowo

    return db


class SecondaryStore:
    # ── ustawienia ─────────────────────────────────────────────────────────
    async def get_setup(self, user: str) -> dict | None:
        db = _t()
        row = await db.database.fetch_one(
            select(db.calendar_secondary).where(db.calendar_secondary.c.user_login == user)
        )
        return dict(row._mapping) if row else None

    async def upsert_setup(self, user: str, **fields: Any) -> None:
        db = _t()
        t = db.calendar_secondary
        stmt = pg_insert(t).values(user_login=user, **fields)
        if fields:
            stmt = stmt.on_conflict_do_update(
                index_elements=[t.c.user_login], set_=dict(fields)
            )
        else:
            stmt = stmt.on_conflict_do_nothing(index_elements=[t.c.user_login])
        await db.database.execute(stmt)

    async def set_calendar_id(
        self, user: str, kind: str, new_id: str | None, expect_old: str | None
    ) -> bool:
        """Zapis warunkowy: zmienia id tylko, gdy nadal jest równe `expect_old`."""
        db = _t()
        t = db.calendar_secondary
        column = getattr(t.c, f"{kind}_id")
        await self.upsert_setup(user)  # wiersz musi istnieć
        cond = column.is_(None) if expect_old is None else column == expect_old
        result = await db.database.execute(
            update(t)
            .where(and_(t.c.user_login == user, cond))
            .values({f"{kind}_id": new_id})
            .returning(t.c.user_login)
        )
        return result is not None

    # ── tokeny ─────────────────────────────────────────────────────────────
    async def get_tokens(self, user: str) -> dict | None:
        db = _t()
        row = await db.database.fetch_one(
            select(db.calendar_tokens).where(db.calendar_tokens.c.user_login == user)
        )
        return dict(row._mapping) if row else None

    async def save_tokens(
        self, user: str, access: str, refresh: str, expires_at: str, scope: str | None
    ) -> None:
        from app.calendar_storage import save_calendar_tokens  # noqa: PLC0415

        await save_calendar_tokens(user, access, refresh, expires_at, scope)

    async def delete_tokens(self, user: str) -> None:
        from app.calendar_storage import delete_calendar_tokens  # noqa: PLC0415

        await delete_calendar_tokens(user)

    async def park_tokens(
        self, user: str, *, access: str, refresh: str, expires_at: str, scope: str | None
    ) -> None:
        await self.upsert_setup(
            user,
            park_access=access,
            park_refresh=refresh,
            park_expires=expires_at,
            park_scope=scope,
        )

    async def clear_park(self, user: str) -> None:
        await self.upsert_setup(
            user, park_access=None, park_refresh=None, park_expires=None, park_scope=None
        )

    # ── mapowania ──────────────────────────────────────────────────────────
    async def list_mappings(self, user: str) -> list[dict]:
        db = _t()
        rows = await db.database.fetch_all(
            select(db.event_mappings).where(db.event_mappings.c.user_login == user)
        )
        return [dict(r._mapping) for r in rows]

    async def get_mapping(self, user: str, match_id: str) -> dict | None:
        db = _t()
        t = db.event_mappings
        row = await db.database.fetch_one(
            select(t).where((t.c.user_login == user) & (t.c.match_id == match_id))
        )
        return dict(row._mapping) if row else None

    async def save_mapping(
        self, user: str, match_id: str, event_id: str, calendar_id: str | None
    ) -> None:
        from app.calendar_storage import save_event_mapping  # noqa: PLC0415

        await save_event_mapping(user, match_id, event_id, calendar_id)

    async def delete_mapping(self, user: str, match_id: str) -> None:
        from app.calendar_storage import delete_event_mapping  # noqa: PLC0415

        await delete_event_mapping(user, match_id)

    async def delete_mappings_for_calendar(self, user: str, calendar_id: str) -> None:
        db = _t()
        t = db.event_mappings
        await db.database.execute(
            delete(t).where((t.c.user_login == user) & (t.c.calendar_id == calendar_id))
        )

    # ── zadanie w tle ──────────────────────────────────────────────────────
    async def try_start_job(
        self, user: str, kind: str, now: datetime.datetime, stale_seconds: int, carry_done: int
    ) -> bool:
        """Warunkowy start: tylko gdy nic nie biegnie albo bieg jest porzucony."""
        db = _t()
        t = db.calendar_secondary
        await self.upsert_setup(user)
        stale_before = now - datetime.timedelta(seconds=stale_seconds)
        result = await db.database.execute(
            update(t)
            .where(
                and_(
                    t.c.user_login == user,
                    or_(
                        t.c.job_state.is_(None),
                        t.c.job_state != "running",
                        t.c.job_heartbeat.is_(None),
                        t.c.job_heartbeat < stale_before,
                    ),
                )
            )
            .values(
                job_kind=kind,
                job_state="running",
                job_done=carry_done,
                job_skipped=0,
                job_failed=0,
                job_error=None,
                job_kept=[],
                job_note=None,
                job_heartbeat=now,
            )
            .returning(t.c.user_login)
        )
        return result is not None

    async def update_job(self, user: str, **fields: Any) -> None:
        unknown = set(fields) - set(_JOB_FIELDS)
        if unknown:
            raise ValueError(f"Nieznane pola zadania: {sorted(unknown)}")
        await self.upsert_setup(user, **fields)

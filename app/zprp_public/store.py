"""Wspólne zapisy, historia zmian i migawki dla publicznej hurtowni ZPRP."""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import and_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.db import (
    DATABASE_URL,
    database,
    zprp_public_changes,
    zprp_public_raw_snapshots,
)
from app.zprp_public.client import canonical_json, sanitize


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _insert(table, values: dict[str, Any]):
    return sqlite_insert(table).values(**values) if DATABASE_URL.startswith("sqlite") else pg_insert(table).values(**values)


async def upsert_values(
    table,
    values: dict[str, Any],
    *,
    key_columns: Iterable[str],
    update_columns: Iterable[str] | None = None,
) -> None:
    keys = list(key_columns)
    updates = list(update_columns or [key for key in values if key not in keys])
    statement = _insert(table, values)
    await database.execute(
        statement.on_conflict_do_update(
            index_elements=[table.c[key] for key in keys],
            set_={key: getattr(statement.excluded, key) for key in updates},
        )
    )


async def insert_ignore(table, values: dict[str, Any], *, key_columns: Iterable[str]) -> None:
    statement = _insert(table, values)
    await database.execute(
        statement.on_conflict_do_nothing(index_elements=[table.c[key] for key in key_columns])
    )


def changed_fields(before: Any, after: Any) -> list[str]:
    if not isinstance(before, dict) or not isinstance(after, dict):
        return ["payload"]
    keys = sorted(set(before) | set(after))
    return [key for key in keys if before.get(key) != after.get(key)]


def _prepare(source: Any, *, compress: bool) -> tuple[Any, str, bytes | None]:
    """Czysty CPU (sanitize, kanoniczny JSON, sha256, gzip) - do wątku, nie na pętlę."""
    clean = sanitize(source)
    blob = canonical_json(clean)
    digest = hashlib.sha256(blob).hexdigest()
    return clean, digest, (gzip.compress(blob, compresslevel=6) if compress else None)


async def save_snapshot(resource_type: str, resource_key: str, source: Any, *, fetched_at: datetime | None = None) -> str:
    clean, digest, packed = await asyncio.to_thread(_prepare, source, compress=True)
    await _insert_snapshot(resource_type, resource_key, digest, packed, fetched_at)
    return digest


async def _insert_snapshot(resource_type: str, resource_key: str, digest: str, packed: bytes | None, fetched_at: datetime | None) -> None:
    await insert_ignore(
        zprp_public_raw_snapshots,
        {
            "resource_type": resource_type,
            "resource_key": resource_key,
            "checksum": digest,
            "payload_gzip": packed,
            "fetched_at": fetched_at or now_utc(),
        },
        key_columns=("resource_type", "resource_key", "checksum"),
    )


async def store_entity(
    table,
    values: dict[str, Any],
    *,
    key_columns: Iterable[str],
    resource_type: str,
    resource_key: str,
    source: Any,
    keep_snapshot: bool = True,
) -> bool:
    """Upsert encji. Zwraca ``True`` tylko przy rzeczywistej zmianie źródła."""
    keys = list(key_columns)
    where = and_(*(table.c[key] == values[key] for key in keys))
    previous = await database.fetch_one(
        select(table.c.source_hash, table.c.source_json).where(where).limit(1)
    )
    clean, digest, packed = await asyncio.to_thread(_prepare, source, compress=keep_snapshot)
    now = now_utc()
    old_hash = str(previous["source_hash"]) if previous else None
    old_json = previous["source_json"] if previous else None
    if isinstance(old_json, str):
        try:
            old_json = await asyncio.to_thread(json.loads, old_json) if len(old_json) > 20000 else json.loads(old_json)
        except Exception:
            old_json = None

    payload = {
        **values,
        "source_hash": digest,
        "source_json": clean,
        "fetched_at": now,
    }
    if "updated_at" in table.c:
        payload["updated_at"] = now
    await upsert_values(table, payload, key_columns=keys)

    if keep_snapshot:
        await _insert_snapshot(resource_type, resource_key, digest, packed, now)

    if old_hash == digest:
        return False
    await database.execute(
        zprp_public_changes.insert().values(
            resource_type=resource_type,
            resource_key=resource_key,
            old_hash=old_hash,
            new_hash=digest,
            changed_fields=changed_fields(old_json, clean),
            changed_at=now,
        )
    )
    return True


"""Tabele Rejestru prób ProEla (`app/proel_attempts.py`).

Własny `MetaData`, a nie `app.db.metadata`: tabele zakłada `ensure_tables()` przy
pierwszym użyciu (`create_all` tylko dla nich, `checkfirst`), więc nie ma zmian
w `app/db.py`. Jeśli kiedyś trafią do `db.py`, wystarczy zawołać `define_tables`
na jego `metadata` - wtedy `ensure_tables` nic nie zrobi.

* `proel_attempt_log` - jeden wiersz na próbę albo epizod (z licznikiem).
* `proel_attempt_alert_prefs` - alert push na admina, domyślnie WYŁĄCZONY
  (brak wiersza = wyłączony).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Tuple

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    func,
)

logger = logging.getLogger(__name__)

_metadata = MetaData()


def define_tables(metadata: MetaData) -> Tuple[Table, Table]:
    log = Table(
        "proel_attempt_log",
        metadata,
        Column("id", BigInteger, primary_key=True, autoincrement=True),
        Column("event_key", String(80), nullable=False, unique=True),
        Column("kind", String(8), nullable=False),
        Column("outcome", String(12), nullable=False),
        Column("reason", String(40), nullable=True),
        Column("reason_text", Text, nullable=True),
        Column("blocker", String(16), nullable=True),
        Column("path", String(20), nullable=True),
        Column("match_number", String(64), nullable=True),
        Column("zprp_match_id", String(40), nullable=True),
        Column("official", Boolean, nullable=True),
        Column("actor_judge_id", String(40), nullable=True),
        Column("actor_name", String(120), nullable=True),
        Column("actor_login", String(120), nullable=True),
        Column("actor_install", String(80), nullable=True),
        Column("actor_verified", Boolean, nullable=False, server_default="false"),
        Column("holder_name", String(120), nullable=True),
        Column("holder_install", String(80), nullable=True),
        Column("steps", JSON, nullable=True),
        Column("duration_ms", Integer, nullable=True),
        Column("count", Integer, nullable=False, server_default="1"),
        Column("first_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("last_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("client_at", DateTime(timezone=True), nullable=True),
        Column("queued", Boolean, nullable=False, server_default="false"),
        Column("net", String(8), nullable=True),
        Column("device", JSON, nullable=True),
        Column("app_version", String(32), nullable=True),
        Column("client_ip", String(64), nullable=True),
        Column("source", String(8), nullable=False, server_default="client"),
        # Klucz klienta, gdy jego wpis scalił się z epizodem serwera (`should_merge_into_server`).
        Column("client_event_key", String(80), nullable=True, index=True),
        Column("escalated_at", DateTime(timezone=True), nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Index("ix_proel_attempt_log_created_at", "created_at"),
        Index("ix_proel_attempt_log_kind_outcome", "kind", "outcome"),
        Index("ix_proel_attempt_log_match_number", "match_number"),
        Index("ix_proel_attempt_log_actor_judge_id", "actor_judge_id"),
    )
    prefs = Table(
        "proel_attempt_alert_prefs",
        metadata,
        Column("judge_id", String(40), primary_key=True),
        Column("enabled", Boolean, nullable=False, server_default="false"),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    return log, prefs


attempt_log, attempt_alert_prefs = define_tables(_metadata)

_ready = False
_lock: "asyncio.Lock | None" = None


def _create_sync() -> None:
    from app.db import engine

    _metadata.create_all(engine, checkfirst=True)
    # Tabela z wcześniejszego wdrożenia nie dostaje nowej kolumny z `create_all`.
    from sqlalchemy import text

    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE proel_attempt_log ADD COLUMN IF NOT EXISTS client_event_key VARCHAR(80)"))
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_proel_attempt_log_client_event_key "
            "ON proel_attempt_log (client_event_key)"))


async def ensure_tables() -> None:
    """Zakłada tabele raz na proces. Rzuca przy awarii bazy (wołający łapie)."""
    global _ready, _lock
    if _ready:
        return
    if _lock is None:
        _lock = asyncio.Lock()
    async with _lock:
        if _ready:
            return
        await asyncio.to_thread(_create_sync)
        _ready = True

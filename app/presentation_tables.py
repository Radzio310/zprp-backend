"""Tryb prezentacji (`app/presentation.py`, `docs/presentation-mode.md`) - tabele.

* `presentation_state` - jeden wiersz (id=1): czy tryb działa, które konta i obszary
  obejmuje, do kiedy, kto go włączył i jakie loginy ZPRP poznaliśmy dla kont
  podanych numerem sędziego (`learned_logins_json`).
* `presentation_ops` - dziennik udawanych operacji (co kliknięto, bez haseł).
* `presentation_overlay` - nakładka: udawane oferty, zgłoszenia, szkic kolejki,
  niedyspozycje, ogłoszenia. Widzą ją WYŁĄCZNIE konta objęte trybem; nikt inny
  nie czyta tej tabeli. Czyszczona przy wyłączeniu trybu i przy DELETE /ops.

JSON trzymamy jako tekst (Text), żeby tabele działały tak samo w Postgresie i w
SQLite testów. Nowe tabele (create_all), bez zmian w istniejących.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Integer, MetaData, String, Table, Text, func


def define_tables(metadata: MetaData):
    state = Table(
        "presentation_state",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("enabled", Boolean, nullable=False, server_default="0"),
        Column("accounts_json", Text, nullable=True),
        Column("areas_json", Text, nullable=True),
        Column("expires_at", DateTime(timezone=True), nullable=True),
        Column("enabled_by", String(120), nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=True, server_default=func.now()),
        Column("learned_logins_json", Text, nullable=True),
    )
    ops = Table(
        "presentation_ops",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("at", DateTime(timezone=True), nullable=False, server_default=func.now(), index=True),
        Column("account", String(160), nullable=False),
        Column("area", String(40), nullable=False),
        Column("method", String(10), nullable=False),
        Column("path", String(400), nullable=False),
        Column("summary_json", Text, nullable=True),
        Column("payload_json", Text, nullable=True),
    )
    overlay = Table(
        "presentation_overlay",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("kind", String(40), nullable=False, index=True),
        Column("key", String(200), nullable=False, index=True),
        Column("data_json", Text, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    return state, ops, overlay

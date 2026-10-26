"""Trwala pamiec ekranu Statystyki (`app/zprp_public/stats.py`).

`zprp_public_stats_snapshots`: maly magazyn klucz -> JSON. Dzis trzyma
streszczenia publicznych protokolow ProEl (`kind = 'proel'`, klucz
`proel:<numer meczu>`, `source_at` = `proel_matches.updated_at`), zeby restart
nie czytal wszystkich blobow od nowa. Same liczniki i czasy - bez numerow
i nazwisk. Nowa tabela (create_all), bez zmian w istniejacych.
"""

from __future__ import annotations

from sqlalchemy import JSON, Column, DateTime, MetaData, String, Table, func
from sqlalchemy.dialects.postgresql import JSONB


def define_tables(metadata: MetaData) -> Table:
    json_type = JSON().with_variant(JSONB, "postgresql")
    return Table(
        "zprp_public_stats_snapshots",
        metadata,
        Column("key", String, primary_key=True),
        Column("kind", String, nullable=False, index=True),
        Column("source_at", String, nullable=True),
        Column("value_json", json_type, nullable=False),
        Column("built_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

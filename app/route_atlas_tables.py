"""Atlas tras: jedno trwale zrodlo odleglosci drogowych (`app/route_atlas.py`).

`route_atlas`: jeden wiersz na pare miejsc (klucz kanoniczny z `route_atlas_rules`),
km + zakodowana polilinia + zrodlo + data pomiaru + licznik uzyc.
`route_atlas_failures`: pamiec porazek pomiaru z terminem ponowienia.
Nowe tabele (create_all), bez zmian w istniejacych - `city_distances`,
`city_route_shapes` i `settlement_pair_failures` zostaja jako archiwum.
"""

from __future__ import annotations

from sqlalchemy import Column, DateTime, Float, Integer, MetaData, String, Table, Text, func


def define_tables(metadata: MetaData) -> tuple[Table, Table]:
    atlas = Table(
        "route_atlas",
        metadata,
        Column("pair_key", String, primary_key=True),
        Column("from_label", String, nullable=False, server_default=""),
        Column("to_label", String, nullable=False, server_default=""),
        Column("km", Float, nullable=False),
        Column("encoded", Text, nullable=True),
        Column("source", String, nullable=False),
        Column("measured_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("uses", Integer, nullable=False, server_default="0"),
        Column("last_used_at", DateTime(timezone=True), nullable=True),
    )
    failures = Table(
        "route_atlas_failures",
        metadata,
        Column("pair_key", String, primary_key=True),
        Column("kind", String, nullable=False),  # "transient" | "no_route" | "noshape"
        Column("attempts", Integer, nullable=False, server_default="1"),
        Column("checked_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("retry_after", DateTime(timezone=True), nullable=False),
    )
    return atlas, failures

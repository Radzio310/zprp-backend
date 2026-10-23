"""Trwała pamięć geokodera miejscowości portalu (Nominatim / OpenStreetMap).

Jeden wiersz na znormalizowaną nazwę miasta (`city_norm`, klucz
`normalize_city_key`). Udane trafienie zostaje na zawsze; nieudane
(`failed`) wraca do kolejki po 30 dniach (`app/zprp_public/geocode_rules.py`).
Tabela powstaje przez `metadata.create_all()` w `app/db.py`.

Druga tabela, `zprp_public_venue_geocode_cache`: adresy hal (ulica z numerem)
- pinezka na hali zamiast w środku miasta. Klucz `addr_norm` =
`geocode_rules.venue_addr_key(miasto, ulica, numer)`. Nowa tabela (create_all),
bez zmiany istniejących - nic do migrowania.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, MetaData, String, Table, text


def define_tables(metadata: MetaData) -> Table:
    return Table(
        "zprp_public_geocode_cache",
        metadata,
        Column("city_norm", String, primary_key=True),
        Column("city", String, nullable=False),
        Column("query", String, nullable=True),
        Column("lat", Float, nullable=True),
        Column("lon", Float, nullable=True),
        Column("province", String, nullable=True),
        Column("display_name", String, nullable=True),
        Column("place_type", String, nullable=True),
        Column("source", String, nullable=False, server_default=text("'nominatim'")),
        Column("looked_up_at", DateTime(timezone=True), nullable=False),
        Column("failed", Boolean, nullable=False, server_default=text("false")),
        Column("attempts", Integer, nullable=False, server_default=text("0")),
    )


def define_venue_table(metadata: MetaData) -> Table:
    return Table(
        "zprp_public_venue_geocode_cache",
        metadata,
        Column("addr_norm", String, primary_key=True),
        Column("city", String, nullable=False),
        Column("street", String, nullable=False),
        Column("query", String, nullable=True),
        Column("lat", Float, nullable=True),
        Column("lon", Float, nullable=True),
        Column("display_name", String, nullable=True),
        Column("place_class", String, nullable=True),
        Column("place_type", String, nullable=True),
        Column("km_from_city", Float, nullable=True),
        Column("source", String, nullable=False, server_default=text("'nominatim'")),
        Column("looked_up_at", DateTime(timezone=True), nullable=False),
        Column("failed", Boolean, nullable=False, server_default=text("false")),
        Column("attempts", Integer, nullable=False, server_default=text("0")),
    )

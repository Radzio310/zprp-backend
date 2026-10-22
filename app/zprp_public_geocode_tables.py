"""Trwała pamięć geokodera miejscowości portalu (Nominatim / OpenStreetMap).

Jeden wiersz na znormalizowaną nazwę miasta (`city_norm`, klucz
`normalize_city_key`). Udane trafienie zostaje na zawsze; nieudane
(`failed`) wraca do kolejki po 30 dniach (`app/zprp_public/geocode_rules.py`).
Tabela powstaje przez `metadata.create_all()` w `app/db.py`.
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

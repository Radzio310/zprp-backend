"""Tabele ogólnopolskiej mapy odległości budowanej z ryczałtów ZPRP."""

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)


def define_tables(metadata):
    sources = Table(
        "national_distance_sources",
        metadata,
        Column("source_key", String, primary_key=True),
        Column("settlement_id", String, nullable=False, index=True),
        Column("match_id", String, nullable=False, index=True),
        Column("match_code", String, nullable=True),
        Column("status", String, nullable=False, server_default=text("'queued'")),
        Column("attempts", Integer, nullable=False, server_default=text("0")),
        Column("error", Text, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("processed_at", DateTime(timezone=True), nullable=True),
        UniqueConstraint("settlement_id", "match_id", name="uq_national_distance_source"),
    )

    cities = Table(
        "national_distance_cities",
        metadata,
        Column("city_key", String, primary_key=True),
        Column("name", String, nullable=False),
        Column("latitude", Float, nullable=True),
        Column("longitude", Float, nullable=True),
        Column("observations", Integer, nullable=False, server_default=text("0")),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    connections = Table(
        "national_distance_connections",
        metadata,
        Column("city_a_key", String, primary_key=True),
        Column("city_b_key", String, primary_key=True),
        Column("city_a_name", String, nullable=False),
        Column("city_b_name", String, nullable=False),
        # Odległość zawsze w jedną stronę. Kierunek jest kanoniczny i umowny.
        Column("distance_km", Integer, nullable=False),
        Column("observations", Integer, nullable=False, server_default=text("1")),
        Column("distance_sum", Integer, nullable=False),
        # GeoJSON-owa kolejność punktów OSRM: [longitude, latitude].
        Column("route_geometry", JSON, nullable=True),
        Column("last_match_id", String, nullable=True),
        Column("last_source_key", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

    return sources, cities, connections


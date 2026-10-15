"""Tabele ogólnopolskiej mapy odległości budowanej z ryczałtów ZPRP."""

from sqlalchemy import (
    Boolean,
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
        # Szczegóły jednego dokumentu (od 15.10.2026). Dzięki nim połączenie
        # da się później rozłożyć na dokumenty, a nie tylko na średnią.
        Column("judge_city", String, nullable=True),
        Column("venue_city", String, nullable=True),
        Column("one_way_km", Integer, nullable=True),
        # Węzły (klucze miast), do których dokument został doliczony.
        Column("judge_node", String, nullable=True),
        Column("venue_node", String, nullable=True),
        # Wskazówki z telefonu - tylko priorytet przy rozpoznaniu miejscowości.
        Column("hint_judge_city", String, nullable=True),
        Column("hint_venue_city", String, nullable=True),
        Column("judge_province", String, nullable=True),
        Column("judge_postal_code", String, nullable=True),
        Column("match_province", String, nullable=True),
        Column("venue_street", String, nullable=True),
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
        # Węzeł = nazwa + rozpoznane miejsce (15.10.2026). `city_key` to goła
        # nazwa dla pierwszego węzła nazwy (tak jak dotąd) albo
        # `nazwa|województwo` dla kolejnej miejscowości o tej samej nazwie.
        Column("name_key", String, nullable=True, index=True),
        Column("province", String, nullable=True),
        # Identyfikator GeoNames („fit:..." = punkt z tras, „node:..." = geokoder).
        Column("gid", String, nullable=True),
        Column("approximate", Boolean, nullable=False, server_default=text("false")),
        # Przypięte przez admina - automat nigdy tego punktu nie rusza.
        Column("pinned", Boolean, nullable=False, server_default=text("false")),
        Column("pinned_by", String, nullable=True),
        Column("pinned_at", DateTime(timezone=True), nullable=True),
        Column("fit_error", Float, nullable=True),
        Column("candidates", JSON, nullable=True),
        # Ostatnie przeniesienie: skąd i o ile km (widok admina).
        Column("previous_latitude", Float, nullable=True),
        Column("previous_longitude", Float, nullable=True),
        Column("moved_km", Float, nullable=True),
        Column("resolved_at", DateTime(timezone=True), nullable=True),
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

    # Sędziowie, którzy zbudowali tabelę pełnym pobraniem ryczałtów. Wpis
    # powstaje po udanym odszyfrowaniu także wtedy, gdy sędzia nie ma żadnego
    # nowego ryczałtu - aplikacja wie wtedy, że nie musi go już zachęcać.
    judges = Table(
        "national_distance_judges",
        metadata,
        Column("judge_id", String, primary_key=True),
        Column("first_full_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("last_full_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("links", Integer, nullable=False, server_default=text("0")),
    )

    return sources, cities, connections, judges



#: Kolumny dołożone 15.10.2026 do tabel, które na produkcji już istnieją
#: (`create_all` ich nie doda). Wołane z bloku migracji w `app/db.py`.
MIGRATIONS = (
    "ALTER TABLE national_distance_sources ADD COLUMN IF NOT EXISTS judge_city varchar",
    "ALTER TABLE national_distance_sources ADD COLUMN IF NOT EXISTS venue_city varchar",
    "ALTER TABLE national_distance_sources ADD COLUMN IF NOT EXISTS one_way_km integer",
    "ALTER TABLE national_distance_sources ADD COLUMN IF NOT EXISTS judge_node varchar",
    "ALTER TABLE national_distance_sources ADD COLUMN IF NOT EXISTS venue_node varchar",
    "ALTER TABLE national_distance_sources ADD COLUMN IF NOT EXISTS hint_judge_city varchar",
    "ALTER TABLE national_distance_sources ADD COLUMN IF NOT EXISTS hint_venue_city varchar",
    "ALTER TABLE national_distance_sources ADD COLUMN IF NOT EXISTS judge_province varchar",
    "ALTER TABLE national_distance_sources ADD COLUMN IF NOT EXISTS judge_postal_code varchar",
    "ALTER TABLE national_distance_sources ADD COLUMN IF NOT EXISTS match_province varchar",
    "ALTER TABLE national_distance_sources ADD COLUMN IF NOT EXISTS venue_street varchar",
    "ALTER TABLE national_distance_cities ADD COLUMN IF NOT EXISTS name_key varchar",
    "ALTER TABLE national_distance_cities ADD COLUMN IF NOT EXISTS province varchar",
    "ALTER TABLE national_distance_cities ADD COLUMN IF NOT EXISTS gid varchar",
    "ALTER TABLE national_distance_cities ADD COLUMN IF NOT EXISTS approximate boolean NOT NULL DEFAULT false",
    "ALTER TABLE national_distance_cities ADD COLUMN IF NOT EXISTS pinned boolean NOT NULL DEFAULT false",
    "ALTER TABLE national_distance_cities ADD COLUMN IF NOT EXISTS pinned_by varchar",
    "ALTER TABLE national_distance_cities ADD COLUMN IF NOT EXISTS pinned_at timestamptz",
    "ALTER TABLE national_distance_cities ADD COLUMN IF NOT EXISTS fit_error double precision",
    "ALTER TABLE national_distance_cities ADD COLUMN IF NOT EXISTS candidates json",
    "ALTER TABLE national_distance_cities ADD COLUMN IF NOT EXISTS previous_latitude double precision",
    "ALTER TABLE national_distance_cities ADD COLUMN IF NOT EXISTS previous_longitude double precision",
    "ALTER TABLE national_distance_cities ADD COLUMN IF NOT EXISTS moved_km double precision",
    "ALTER TABLE national_distance_cities ADD COLUMN IF NOT EXISTS resolved_at timestamptz",
    # Dotychczasowe miasta: klucz nazwy = klucz miasta (wszystkie były gołymi nazwami).
    "UPDATE national_distance_cities SET name_key = city_key WHERE name_key IS NULL",
    "CREATE INDEX IF NOT EXISTS ix_national_distance_cities_name_key ON national_distance_cities (name_key)",
)

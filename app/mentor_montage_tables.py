"""Montaż zestawienia w jeden film (12.11.2026) - schemat. Kontrakt: `docs/mentor-panel.md`, sekcja 15.

  - `mentor_montages`: zamówienie filmu (z zestawienia albo z zaznaczenia), stan, postęp, gotowy plik w magazynie R2,
  - `mentor_montage_assets`: księga odcinków i okładek w R2 po odcisku treści (ten sam odcinek nie renderuje się drugi raz;
    retencja usuwa nieużywane od 30 dni).
Tabele powstają z `metadata.create_all`; `MIGRATIONS` tylko domykają je idempotentnie.
"""

from sqlalchemy import BigInteger, Boolean, Column, DateTime, Float, Index, Integer, String, Table, Text, func, text


def define_tables(metadata):
    montages = Table(
        "mentor_montages",
        metadata,
        Column("id", String, primary_key=True),
        Column("pair_id", String, nullable=False),
        #: NULL = szybki montaż z zaznaczenia (Biblioteka, pokój meczu).
        Column("compilation_id", String, nullable=True),
        Column("name", String, nullable=False),
        Column("description", Text, nullable=True),
        #: [{clip_id, label, note}] w kolejności filmu (migawka z chwili zamówienia).
        Column("items_json", Text, nullable=False, server_default=text("'[]'")),
        #: Stan pozycji z ostatniego przeglądu gotowości: {clip_id: {state, reason, hint, action, ...}}.
        Column("states_json", Text, nullable=False, server_default=text("'{}'")),
        Column("skip_missing", Boolean, nullable=False, server_default=text("false")),
        #: preparing | queued | rendering | ready | failed | expired | cancelled.
        Column("status", String, nullable=False, server_default=text("'preparing'")),
        Column("stage", String, nullable=True),
        Column("progress", Float, nullable=False, server_default=text("0")),
        Column("message", String, nullable=True),
        Column("request_sig", String, nullable=True),
        Column("film_key", String, nullable=True),
        Column("poster_key", String, nullable=True),
        Column("size", BigInteger, nullable=True),
        Column("duration_s", Float, nullable=True),
        Column("width", Integer, nullable=True),
        Column("height", Integer, nullable=True),
        #: Rozdziały gotowego filmu: [{kind, clip_id, title, start_s, end_s, clip_start_s}].
        Column("chapters_json", Text, nullable=True),
        #: Pozycje, które weszły do filmu (przy pominięciu brakujących to podzbiór `items_json`).
        Column("rendered_json", Text, nullable=True),
        Column("estimate_s", Integer, nullable=True),
        Column("attempts", Integer, nullable=False, server_default=text("0")),
        Column("created_by", String, nullable=False),
        Column("acted_by", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("started_at", DateTime(timezone=True), nullable=True),
        #: Od kiedy film czeka na klipy (limit przygotowania liczy się od zamówienia albo od ostatniego ponowienia).
        Column("waiting_since", DateTime(timezone=True), nullable=True),
        Column("ready_at", DateTime(timezone=True), nullable=True),
        Column("expires_at", DateTime(timezone=True), nullable=True),
    )
    Index("ix_mentor_montages_pair", montages.c.pair_id, montages.c.updated_at)
    Index("ix_mentor_montages_compilation", montages.c.compilation_id)
    Index("ix_mentor_montages_status", montages.c.status)
    assets = Table(
        "mentor_montage_assets",
        metadata,
        Column("sig", String, primary_key=True),
        Column("pair_id", String, nullable=False),
        #: segment | cover
        Column("kind", String, nullable=False),
        Column("key", String, nullable=False),
        Column("size", BigInteger, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("used_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    Index("ix_mentor_montage_assets_used", assets.c.used_at)
    return (montages, assets)


#: Wykonywane przy starcie przez `app/db.py` (PostgreSQL), każde osobno i idempotentnie.
MIGRATIONS = (
    "ALTER TABLE mentor_montages ADD COLUMN IF NOT EXISTS waiting_since TIMESTAMPTZ",
    "CREATE INDEX IF NOT EXISTS ix_mentor_montages_pair ON mentor_montages (pair_id, updated_at)",
    "CREATE INDEX IF NOT EXISTS ix_mentor_montages_compilation ON mentor_montages (compilation_id)",
    "CREATE INDEX IF NOT EXISTS ix_mentor_montages_status ON mentor_montages (status)",
    "CREATE INDEX IF NOT EXISTS ix_mentor_montage_assets_used ON mentor_montage_assets (used_at)",
)

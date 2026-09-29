"""
Tabele ocen mentora (29.09.2026) - same schematy, bez połączenia z bazą.

  - `mentor_evaluations`          jedna ocena na mecz i autora (albo wspólna
                                  z drugim mentorem pary). Dwie kopie arkusza:
                                  `sheet_json` to wersja robocza autorów,
                                  `published_json` to to, co widzi para -
                                  poprawki po publikacji nie wyciekają, zanim
                                  autor ich nie zapisze.
  - `mentor_evaluation_versions`  migawka KAŻDEJ publikacji (historia wersji).

JSON jako Text (nie JSONB): sterownik `databases` oddaje JSONB napisem, więc
każdy odczyt i tak musiałby go rozbierać.
"""

from sqlalchemy import Column, DateTime, Float, Index, Integer, String, Table, Text, func


def define_tables(metadata):
    evaluations = Table(
        "mentor_evaluations",
        metadata,
        Column("id", String, primary_key=True),
        Column("match_id", String, nullable=False, index=True),
        Column("province", String, nullable=False, index=True),
        Column("season", String, nullable=True, index=True),
        Column("match_number", String, nullable=True),
        Column("match_at", DateTime(timezone=True), nullable=True),
        #: Posortowane numery ocenianej pary złączone „|".
        Column("pair_key", String, nullable=False, index=True),
        Column("author_id", String, nullable=False, index=True),
        #: Lista numerów współautorów (ocena wspólna) jako napis JSON.
        Column("co_author_ids", Text, nullable=False, default="[]"),
        #: Skąd autor jest mentorem pary: „mentoring" albo „obsada".
        Column("source", String, nullable=False),
        Column("status", String, nullable=False, default="draft"),
        Column("sheet_json", Text, nullable=False, default="{}"),
        Column("published_json", Text, nullable=True),
        Column("points", Float, nullable=True),
        Column("letter", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("published_at", DateTime(timezone=True), nullable=True),
        Index("ux_mentor_evaluations_match_author", "match_id", "author_id", unique=True),
    )
    versions = Table(
        "mentor_evaluation_versions",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("evaluation_id", String, nullable=False, index=True),
        Column("saved_by", String, nullable=False),
        Column("sheet_json", Text, nullable=False),
        Column("points", Float, nullable=True),
        Column("letter", String, nullable=True),
        Column("saved_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    return evaluations, versions

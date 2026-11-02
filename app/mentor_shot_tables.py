"""Zrzuty klatek Mentora (02.11.2026) - schemat. Kontrakt: `docs/mentor-panel.md`, sekcja 13.

Jedna tabela `mentor_shots`: moment nagrania meczu pary z rysunkiem (kształty w JSON, współrzędne 0..1 względem kadru),
opcjonalnie z obrazem w magazynie nagrań (R2) i z (opcjonalnym) powiązaniem z klipem. Kosz jak przy klipach: `deleted_at`.
Tabela powstaje z `metadata.create_all`; `MIGRATIONS` tylko domykają ją idempotentnie (IF NOT EXISTS).
"""

from sqlalchemy import BigInteger, Column, DateTime, Float, Index, Integer, String, Table, Text, func, text


def define_tables(metadata):
    shots = Table(
        "mentor_shots",
        metadata,
        Column("id", String, primary_key=True),
        Column("pair_id", String, nullable=False),
        Column("match_id", String, nullable=False),
        Column("video_id", String, nullable=False),
        #: Sekunda nagrania z ułamkiem (milisekundy).
        Column("at_s", Float, nullable=False),
        Column("title", String, nullable=True),
        Column("note", Text, nullable=True),
        Column("category_ids", Text, nullable=False, server_default=text("'[]'")),
        #: Kształty (JSON, lista); walidacja i limity w `mentor_shot_rules.clean_shapes`.
        Column("shapes_json", Text, nullable=False, server_default=text("'[]'")),
        Column("clip_id", String, nullable=True),
        #: Kadr zrzutu zrobionego w zoomie (JSON `{cx,cy,zoom}`, `mentor_shot_rules.clean_view`); NULL = cała klatka.
        Column("view_json", Text, nullable=True),
        #: `auto` | `manual` | `detached`.
        Column("attach_mode", String, nullable=False, server_default=text("'auto'")),
        #: `none` | `processing` | `ready` | `failed`.
        Column("image_status", String, nullable=False, server_default=text("'none'")),
        #: Kod powodu przy `none`/`failed` (np. YOUTUBE_NO_IMAGE), bez adresów.
        Column("image_reason", String, nullable=True),
        #: `browser` (wgrane z przeglądarki) | `server` (klatka z serwera) | NULL.
        Column("image_source", String, nullable=True),
        Column("image_key", String, nullable=True),
        Column("thumb_key", String, nullable=True),
        Column("image_size", BigInteger, nullable=True),
        Column("width", Integer, nullable=True),
        Column("height", Integer, nullable=True),
        Column("image_updated_at", DateTime(timezone=True), nullable=True),
        Column("author_id", String, nullable=False),
        Column("acted_by", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("deleted_at", DateTime(timezone=True), nullable=True),
    )
    Index("ix_mentor_shots_pair_match", shots.c.pair_id, shots.c.match_id)
    Index("ix_mentor_shots_video", shots.c.video_id)
    Index("ix_mentor_shots_clip", shots.c.clip_id)
    return (shots,)


#: Wykonywane przy starcie przez `app/db.py` (PostgreSQL), każde osobno i idempotentnie.
MIGRATIONS = (
    "ALTER TABLE mentor_shots ADD COLUMN IF NOT EXISTS view_json TEXT",
    "CREATE INDEX IF NOT EXISTS ix_mentor_shots_pair_match ON mentor_shots (pair_id, match_id)",
    "CREATE INDEX IF NOT EXISTS ix_mentor_shots_video ON mentor_shots (video_id)",
    "CREATE INDEX IF NOT EXISTS ix_mentor_shots_clip ON mentor_shots (clip_id)",
)

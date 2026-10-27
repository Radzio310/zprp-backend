"""
Tabele ocen mentora (29.09.2026) - same schematy, bez połączenia z bazą.

  - `mentor_evaluations`          jedna ocena na mecz i autora (albo wspólna
                                  z drugim mentorem pary). Dwie kopie arkusza:
                                  `sheet_json` to wersja robocza autorów,
                                  `published_json` to to, co widzi para -
                                  poprawki po publikacji nie wyciekają, zanim
                                  autor ich nie zapisze.
  - `mentor_evaluation_versions`  migawka KAŻDEJ publikacji (historia wersji).
  - `mentor_evaluation_requests`  prośby pary o ocenę (wysłano / przeczytane / ocenił).
  - `mentor_match_videos`         wspólna galeria nagrań meczu ze znacznikami akcji.

JSON jako Text (nie JSONB): sterownik `databases` oddaje JSONB napisem, więc
każdy odczyt i tak musiałby go rozbierać.
"""

from sqlalchemy import Column, DateTime, Float, Index, Integer, String, Table, Text, UniqueConstraint, func


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
        Column("acted_by", String, nullable=True),  # admin wystawiający ocenę okiem mentora (`act_as`)
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
    requests = Table(
        "mentor_evaluation_requests",
        metadata,
        Column("id", String, primary_key=True),
        Column("match_id", String, nullable=False, index=True),
        Column("province", String, nullable=False, index=True),
        Column("pair_key", String, nullable=False, index=True),
        Column("mentor_id", String, nullable=False, index=True),
        Column("requested_by", String, nullable=False),
        Column("video_url", Text, nullable=True),
        Column("channels_json", Text, nullable=False, default="[]"),
        Column("delivery_json", Text, nullable=False, default="{}"),
        Column("send_count", Integer, nullable=False, default=1),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("last_sent_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("fulfilled_at", DateTime(timezone=True), nullable=True),
        #: Mentor otworzył szczegóły meczu po prośbie (15.10.2026) - status „przeczytane".
        Column("read_at", DateTime(timezone=True), nullable=True),
        UniqueConstraint("match_id", "mentor_id", name="uq_mentor_evaluation_request_match_mentor"),
    )
    videos = Table(
        "mentor_match_videos",
        metadata,
        Column("id", String, primary_key=True),
        Column("match_id", String, nullable=False, index=True),
        Column("pair_key", String, nullable=False, index=True),
        Column("url", Text, nullable=False),
        Column("normalized_url", Text, nullable=False),
        Column("provider", String, nullable=False),
        Column("added_by", String, nullable=False, index=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        # Podgląd linku (15.10.2026): tytuł, miniatura i długość z oEmbed/og:*.
        Column("title", Text, nullable=True),
        Column("thumbnail_url", Text, nullable=True),
        Column("site_name", String, nullable=True),
        Column("duration_s", Integer, nullable=True),
        #: Synchronizacja z zegarem meczu i znaczniki akcji - `app/mentor_video_rules.py`.
        Column("sync_json", Text, nullable=True),
        Column("markers_json", Text, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=True),
        #: Panel „Mentor" (21.10.2026): `link` (YouTube/Vimeo/inne) albo `upload`
        #: (własne nagranie w R2, `mentor_uploads.id` w `upload_id`).
        Column("kind", String, nullable=True),
        Column("upload_id", String, nullable=True),
        #: Identyfikator źródła u dostawcy (Bastion: `bunny_item_id`); migracja w `mentor_bastion_tables`.
        Column("external_id", String, nullable=True),
        UniqueConstraint("match_id", "normalized_url", name="uq_mentor_match_video_url"),
    )
    return evaluations, versions, requests, videos


#: Kolumny dołożone po pierwszym wdrożeniu - tabele istnieją na produkcji,
#: więc `create_all` ich nie doda. Wykonuje je `app/db.py` przy starcie.
MIGRATIONS = (
    "ALTER TABLE mentor_evaluations ADD COLUMN IF NOT EXISTS acted_by varchar",
    "ALTER TABLE mentor_evaluation_requests ADD COLUMN IF NOT EXISTS read_at timestamptz",
    "ALTER TABLE mentor_match_videos ADD COLUMN IF NOT EXISTS title text",
    "ALTER TABLE mentor_match_videos ADD COLUMN IF NOT EXISTS thumbnail_url text",
    "ALTER TABLE mentor_match_videos ADD COLUMN IF NOT EXISTS site_name varchar",
    "ALTER TABLE mentor_match_videos ADD COLUMN IF NOT EXISTS duration_s integer",
    "ALTER TABLE mentor_match_videos ADD COLUMN IF NOT EXISTS sync_json text",
    "ALTER TABLE mentor_match_videos ADD COLUMN IF NOT EXISTS markers_json text",
    "ALTER TABLE mentor_match_videos ADD COLUMN IF NOT EXISTS updated_at timestamptz",
    "ALTER TABLE mentor_match_videos ADD COLUMN IF NOT EXISTS kind varchar",
    "ALTER TABLE mentor_match_videos ADD COLUMN IF NOT EXISTS upload_id varchar",
)

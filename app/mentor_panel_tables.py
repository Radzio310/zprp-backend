"""
Tabele panelu „Mentor" (21.10.2026) - same schematy, bez połączenia z bazą.

Kontrakt: `docs/mentor-panel.md`, sekcja 2. Identyfikatory tekstowe (uuid4 hex).
JSON jako Text (jak `mentor_evaluation_tables`): sterownik `databases` oddaje
JSONB napisem, więc każdy odczyt i tak rozbiera go `json_value`.

Do kontraktu dołożone (tylko wewnętrznie, bez zmiany kształtu odpowiedzi):
  - `mentor_audit.rev/scope/match_id` - z nich `GET /changes` wie, CO się
    zmieniło od numeru `since`,
  - `mentor_qr_logins.user_agent` - podpowiedź „Chrome na Windows" przy
    zatwierdzaniu logowania w aplikacji.
"""

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    func,
    text,
)


def define_tables(metadata):
    panels = Table(
        "mentor_panels",
        metadata,
        Column("pair_id", String, ForeignKey("mentoring_pairs.id"), primary_key=True),
        Column("enabled", Boolean, nullable=False, server_default=text("false")),
        Column("enabled_by", String, nullable=True),
        Column("enabled_at", DateTime(timezone=True), nullable=True),
        Column("rev", BigInteger, nullable=False, server_default=text("0")),
        Column("settings_json", Text, nullable=False, server_default=text("'{}'")),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    flags = Table(
        "mentor_match_flags",
        metadata,
        Column("pair_id", String, primary_key=True),
        Column("match_id", String, primary_key=True),
        Column("starred", Boolean, nullable=False, server_default=text("false")),
        Column("star_reason", String, nullable=True),
        Column("starred_by", String, nullable=True),
        Column("submitted", Boolean, nullable=False, server_default=text("false")),
        Column("submitted_by", String, nullable=True),
        Column("submitted_at", DateTime(timezone=True), nullable=True),
        Column("due_at", DateTime(timezone=True), nullable=True),
        Column("review_status", String, nullable=True),
        Column("note", String, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    categories = Table(
        "mentor_categories",
        metadata,
        Column("id", String, primary_key=True),
        #: NULL = kategoria globalna administratora (widzą ją wszystkie pary).
        Column("pair_id", String, nullable=True, index=True),
        Column("key", String, nullable=True),
        Column("name", String, nullable=False),
        Column("color", String, nullable=False),
        Column("icon", String, nullable=False),
        Column("description", String, nullable=True),
        Column("sort", Integer, nullable=False, server_default=text("0")),
        Column("archived", Boolean, nullable=False, server_default=text("false")),
        Column("created_by", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    clips = Table(
        "mentor_clips",
        metadata,
        Column("id", String, primary_key=True),
        Column("pair_id", String, nullable=False),
        Column("match_id", String, nullable=False),
        Column("video_id", String, nullable=False, index=True),
        Column("start_s", Float, nullable=False),
        Column("end_s", Float, nullable=False),
        Column("title", String, nullable=True),
        Column("note", Text, nullable=True),
        Column("category_ids", Text, nullable=False, server_default=text("'[]'")),
        Column("source", String, nullable=False, server_default=text("'manual'")),
        Column("source_key", String, nullable=True),
        Column("match_ms", BigInteger, nullable=True),
        Column("half", Integer, nullable=True),
        Column("author_id", String, nullable=False),
        Column("acted_by", String, nullable=True),  # admin działający okiem mentora
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("deleted_at", DateTime(timezone=True), nullable=True),
        Column("mp4_status", String, nullable=False, server_default=text("'none'")),
        Column("mp4_key", String, nullable=True),
        Column("mp4_size", BigInteger, nullable=True),
        Column("public_token", String, nullable=True, unique=True),
        Column("published_at", DateTime(timezone=True), nullable=True),
        # Znaki klipu (26.10.2026), jak „Istotny” i „Do omówienia” na meczu; NULL = false.
        Column("important", Boolean, nullable=True, server_default=text("false")),
        Column("to_discuss", Boolean, nullable=True, server_default=text("false")),
    )
    Index("ix_mentor_clips_pair_match", clips.c.pair_id, clips.c.match_id)
    Index("ix_mentor_clips_pair_created", clips.c.pair_id, clips.c.created_at)
    compilations = Table(
        "mentor_compilations",
        metadata,
        Column("id", String, primary_key=True),
        Column("pair_id", String, nullable=False, index=True),
        Column("name", String, nullable=False),
        Column("description", Text, nullable=True),
        Column("mode", String, nullable=False, server_default=text("'free'")),
        Column("created_by", String, nullable=False),
        Column("acted_by", String, nullable=True),  # admin działający okiem mentora
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("public_token", String, nullable=True, unique=True),
        Column("published_at", DateTime(timezone=True), nullable=True),
    )
    compilation_items = Table(
        "mentor_compilation_items",
        metadata,
        Column("compilation_id", String, primary_key=True),
        Column("clip_id", String, primary_key=True),
        Column("position", Integer, nullable=False, server_default=text("0")),
        Column("column", String, nullable=True),
        Column("note", String, nullable=True),
        # Etykieta klipu w playliście (24.10.2026): „Dobra decyzja”, „Balans”
        # albo dowolny tekst. Stare zestawienia „kontrast” mają ją pustą - A/B
        # zamienia na etykiety klient (`legacy_label`).
        Column("label", String, nullable=True),
    )
    threads = Table(
        "mentor_threads",
        metadata,
        Column("id", String, primary_key=True),
        Column("pair_id", String, nullable=False),
        Column("target_kind", String, nullable=False),
        Column("target_id", String, nullable=False),
        Column("match_id", String, nullable=True),
        Column("title", String, nullable=True),
        Column("kind", String, nullable=False, server_default=text("'question'")),
        Column("status", String, nullable=False, server_default=text("'open'")),
        Column("created_by", String, nullable=False),
        Column("acted_by", String, nullable=True),  # admin działający okiem mentora
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("last_comment_at", DateTime(timezone=True), nullable=True),
    )
    Index("ix_mentor_threads_target", threads.c.pair_id, threads.c.target_kind, threads.c.target_id)
    comments = Table(
        "mentor_comments",
        metadata,
        Column("id", String, primary_key=True),
        Column("thread_id", String, nullable=False, index=True),
        Column("author_id", String, nullable=False),
        Column("acted_by", String, nullable=True),  # admin działający okiem mentora
        Column("body", Text, nullable=False),
        Column("video_id", String, nullable=True),
        Column("video_s", Float, nullable=True),
        Column("drawing_json", Text, nullable=True),
        Column("mentions", Text, nullable=False, server_default=text("'[]'")),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("edited_at", DateTime(timezone=True), nullable=True),
        Column("deleted_at", DateTime(timezone=True), nullable=True),
    )
    reads = Table(
        "mentor_reads",
        metadata,
        Column("pair_id", String, primary_key=True),
        Column("judge_id", String, primary_key=True),
        Column("seen_rev", BigInteger, nullable=False, server_default=text("0")),
        Column("seen_at", DateTime(timezone=True), nullable=True),
    )
    uploads = Table(
        "mentor_uploads",
        metadata,
        Column("id", String, primary_key=True),
        Column("pair_id", String, nullable=False, index=True),
        Column("match_id", String, nullable=False),
        Column("video_id", String, nullable=True),
        Column("uploader_id", String, nullable=False),
        Column("filename", String, nullable=False),
        Column("size", BigInteger, nullable=False),
        Column("content_type", String, nullable=True),
        Column("r2_key", String, nullable=True),
        Column("upload_id", String, nullable=True),
        Column("status", String, nullable=False, server_default=text("'uploading'"), index=True),
        Column("duration_s", Float, nullable=True),
        Column("width", Integer, nullable=True),
        Column("height", Integer, nullable=True),
        Column("play_key", String, nullable=True),
        Column("poster_key", String, nullable=True),
        Column("error", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("expires_at", DateTime(timezone=True), nullable=True),
    )
    reports = Table(
        "mentor_reports",
        metadata,
        Column("id", String, primary_key=True),
        Column("pair_id", String, nullable=False, index=True),
        Column("title", String, nullable=False),
        Column("config_json", Text, nullable=False, server_default=text("'{}'")),
        Column("snapshot_json", Text, nullable=False, server_default=text("'{}'")),
        Column("created_by", String, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("public_token", String, nullable=True, unique=True),
        Column("published_at", DateTime(timezone=True), nullable=True),
        Column("pdf_key", String, nullable=True),
    )
    web_sessions = Table(
        "mentor_web_sessions",
        metadata,
        Column("id", String, primary_key=True),
        Column("judge_id", String, nullable=False, index=True),
        Column("session_hash", String, nullable=False, unique=True),
        Column("csrf_hash", String, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("expires_at", DateTime(timezone=True), nullable=False),
        Column("last_seen_at", DateTime(timezone=True), nullable=True),
        Column("revoked_at", DateTime(timezone=True), nullable=True),
        Column("user_agent", String, nullable=True),
    )
    qr_logins = Table(
        "mentor_qr_logins",
        metadata,
        Column("code", String, primary_key=True),
        Column("poll_hash", String, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("expires_at", DateTime(timezone=True), nullable=False),
        Column("approved_by", String, nullable=True),
        Column("approved_at", DateTime(timezone=True), nullable=True),
        Column("consumed_at", DateTime(timezone=True), nullable=True),
        Column("user_agent", String, nullable=True),
    )
    # Krótki adres „bazapodreka.app/m/7K2Q" z ekranu telefonu (przepisanie na
    # komputerze). Kod = klucz, ścieżka panelu, ważność 24 h (`mentor_handoff_rules`).
    short_links = Table(
        "mentor_short_links",
        metadata,
        Column("code", String, primary_key=True),
        Column("path", String, nullable=False),
        Column("created_by", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("expires_at", DateTime(timezone=True), nullable=False, index=True),
        Column("hits", Integer, nullable=False, server_default=text("0")),
    )
    audit = Table(
        "mentor_audit",
        metadata,
        Column("id", String, primary_key=True),
        Column("pair_id", String, nullable=True),
        Column("actor_id", String, nullable=True),
        Column("action", String, nullable=False),
        Column("data", Text, nullable=False, server_default=text("'{}'")),
        Column("rev", BigInteger, nullable=True),
        Column("scope", String, nullable=True),
        Column("match_id", String, nullable=True),
        Column("acted_by", String, nullable=True),  # admin działający okiem mentora (`actor_id` = mentor)
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    Index("ix_mentor_audit_pair_rev", audit.c.pair_id, audit.c.rev)
    # Powiadomienia i kropki nowości (24.10.2026): stan per osoba, tylko dopisywany.
    thread_prefs = Table(
        "mentor_thread_prefs",
        metadata,
        Column("thread_id", String, primary_key=True),
        Column("judge_id", String, primary_key=True),
        Column("mode", String, nullable=False),  # follow | mute (brak wiersza = auto)
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    thread_reads = Table(
        "mentor_thread_reads",
        metadata,
        Column("thread_id", String, primary_key=True),
        Column("judge_id", String, primary_key=True),
        Column("seen_at", DateTime(timezone=True), nullable=False),
    )
    sheet_seen = Table(
        "mentor_sheet_seen",
        metadata,
        Column("evaluation_id", String, primary_key=True),
        Column("judge_id", String, primary_key=True),
        Column("seen_at", DateTime(timezone=True), nullable=False),
    )
    # Wyszukiwanie nagrania meczu na YouTube na żądanie pary (24.10.2026,
    # `app/mentor_panel_streams.py`): licznik dobowy (doba warszawska), ostatni
    # wynik (wspólny dla sędziów i mentorów) i odrzucone filmy („Nie ten").
    stream_searches = Table(
        "mentor_stream_searches",
        metadata,
        Column("pair_id", String, primary_key=True),
        Column("match_id", String, primary_key=True),
        Column("day", String, nullable=True),
        Column("day_count", Integer, nullable=False, server_default=text("0")),
        Column("searched_at", DateTime(timezone=True), nullable=True),
        Column("searched_by", String, nullable=True),
        Column("last_count", Integer, nullable=True),
        Column("found_json", Text, nullable=False, server_default=text("'[]'")),
        Column("rejected_json", Text, nullable=False, server_default=text("'[]'")),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    return (
        panels,
        flags,
        categories,
        clips,
        compilations,
        compilation_items,
        threads,
        comments,
        reads,
        uploads,
        reports,
        web_sessions,
        qr_logins,
        audit,
        short_links,
        stream_searches,
        thread_prefs,
        thread_reads,
        sheet_seen,
    )


#: Wykonywane przy starcie przez `app/db.py` (PostgreSQL). Indeksy na numerach
#: sędziów - lista meczów pary pyta hurtownię i archiwum po obu numerach.
MIGRATIONS = (
    "ALTER TABLE mentor_clips ADD COLUMN IF NOT EXISTS acted_by VARCHAR",
    "ALTER TABLE mentor_clips ADD COLUMN IF NOT EXISTS important BOOLEAN DEFAULT false",
    "ALTER TABLE mentor_clips ADD COLUMN IF NOT EXISTS to_discuss BOOLEAN DEFAULT false",
    "ALTER TABLE mentor_compilations ADD COLUMN IF NOT EXISTS acted_by VARCHAR",
    "ALTER TABLE mentor_threads ADD COLUMN IF NOT EXISTS acted_by VARCHAR",
    "ALTER TABLE mentor_comments ADD COLUMN IF NOT EXISTS acted_by VARCHAR",
    "ALTER TABLE mentor_audit ADD COLUMN IF NOT EXISTS acted_by VARCHAR",
    "ALTER TABLE mentor_compilation_items ADD COLUMN IF NOT EXISTS label VARCHAR",
    # Wątki przy klipie (26.10.2026): dawny jedyny, płaski wątek klipu (bez tytułu)
    # staje się pierwszym wątkiem „Rozmowa”. Nowe wątki klipu tytuł mają zawsze.
    "UPDATE mentor_threads SET title = 'Rozmowa' WHERE target_kind = 'clip' AND (title IS NULL OR title = '')",
    # Wątki klipów na ścianie Biblioteki: zbiorczo po target_id.
    "CREATE INDEX IF NOT EXISTS ix_mentor_comments_thread_created ON mentor_comments (thread_id, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_zprp_public_matches_referee_1 ON zprp_public_matches (referee_1_id)",
    "CREATE INDEX IF NOT EXISTS ix_zprp_public_matches_referee_2 ON zprp_public_matches (referee_2_id)",
    "CREATE INDEX IF NOT EXISTS ix_zprp_archive_matches_ref_first ON zprp_archive_matches ((slim_json->'refs'->>'first'))",
    "CREATE INDEX IF NOT EXISTS ix_zprp_archive_matches_ref_second ON zprp_archive_matches ((slim_json->'refs'->>'second'))",
    # Arkusze delegatów pary pytają `referee_ids @> [a] AND referee_ids @> [b]` - bez GIN to skan całej tabeli.
    "CREATE INDEX IF NOT EXISTS ix_delegate_evaluations_referee_ids ON delegate_evaluations USING gin (referee_ids jsonb_path_ops)",
)

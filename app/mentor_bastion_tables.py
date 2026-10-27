"""Tabele integracji Handball Bastion w Mentorze (etap 1) - same schematy, bez połączenia z bazą.

Kontrakt: `docs/mentor-panel.md`, sekcja „Bastion". Sesja Bastionu (cookie, stan przeglądarki) żyje WYŁĄCZNIE
w connectorze (`bastion_connector/`); tu są metadane połączeń, próby logowania, zadania klipów i assety.
Nigdy nie zapisujemy tu adresu embed Bunny, cookie ani biletów logowania.
"""

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)


def define_tables(metadata):
    connections = Table(
        "mentor_bastion_connections",
        metadata,
        Column("id", String, primary_key=True),
        #: `default` albo `personal-<judge_id>`: unikalne w bazie również dla połączenia domyślnego (bez NULL-i).
        Column("connection_key", String, nullable=False, unique=True),
        Column("scope", String, nullable=False),
        #: NULL tylko dla `default`.
        Column("owner_judge_id", String, nullable=True, index=True),
        Column("status", String, nullable=False, server_default=text("'unconfigured'")),
        Column("external_identity_id", String, nullable=True),
        Column("external_identity_label", String, nullable=True),
        Column("session_generation", Integer, nullable=False, server_default=text("0")),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("last_validated_at", DateTime(timezone=True), nullable=True),
        #: NULL dopóki TTL sesji Bastionu nie jest znany (nie zgadujemy).
        Column("expires_at", DateTime(timezone=True), nullable=True),
        Column("revoked_at", DateTime(timezone=True), nullable=True),
        Column("last_error_code", String, nullable=True),
        CheckConstraint(
            "(scope = 'default' AND owner_judge_id IS NULL) OR (scope = 'personal' AND owner_judge_id IS NOT NULL)",
            name="ck_mentor_bastion_conn_scope_owner"),
    )
    attempts = Table(
        "mentor_bastion_login_attempts",
        metadata,
        #: Identyfikator próby w connectorze.
        Column("id", String, primary_key=True),
        Column("connection_key", String, nullable=False, index=True),
        Column("scope", String, nullable=False),
        #: Prawdziwy sędzia (`base_actor`), nigdy `act_as`.
        Column("initiator_judge_id", String, nullable=False, index=True),
        #: Kontekst działania w panelu (`?act_as=`), tylko do audytu.
        Column("acted_as_judge_id", String, nullable=True),
        Column("status", String, nullable=False, server_default=text("'creating'")),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("expires_at", DateTime(timezone=True), nullable=True),
        Column("consumed_at", DateTime(timezone=True), nullable=True),
        Column("verified_identity_id", String, nullable=True),
        Column("return_context_json", Text, nullable=False, server_default=text("'{}'")),
        Column("last_error_code", String, nullable=True),
    )
    jobs = Table(
        "mentor_bastion_clip_jobs",
        metadata,
        Column("id", String, primary_key=True),
        Column("clip_id", String, nullable=False, index=True),
        Column("pair_id", String, nullable=False),
        Column("match_id", String, nullable=False),
        Column("source_video_id", String, nullable=False),
        Column("source_bunny_item_id", BigInteger, nullable=False),
        Column("requested_by_real_judge_id", String, nullable=False),
        Column("acted_as_judge_id", String, nullable=True),
        #: Zadanie przypięte do konkretnego połączenia i zewnętrznego konta (handoff 6.3).
        Column("connection_id", String, nullable=True),
        Column("external_identity_id", String, nullable=True),
        Column("clip_revision", Integer, nullable=False, server_default=text("1")),
        Column("start_s", Integer, nullable=False),
        Column("end_s", Integer, nullable=False),
        Column("idempotency_key", String, nullable=False, unique=True),
        Column("request_fingerprint", String, nullable=False),
        Column("remote_clip_id", String, nullable=True),
        Column("remote_clip_code", String, nullable=True),
        Column("state", String, nullable=False, server_default=text("'queued'"), index=True),
        Column("attempts", Integer, nullable=False, server_default=text("0")),
        Column("next_attempt_at", DateTime(timezone=True), nullable=True),
        Column("lease_until", DateTime(timezone=True), nullable=True),
        Column("worker_id", String, nullable=True),
        Column("last_error_code", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("finished_at", DateTime(timezone=True), nullable=True),
        Column("asset_id", String, nullable=True),
        #: Etap 4: kiedy zlecenie poszlo do Bastionu (limit oczekiwania) i ile razy pytano o gotowosc (backoff).
        Column("submitted_at", DateTime(timezone=True), nullable=True),
        Column("poll_count", Integer, nullable=False, server_default=text("0")),
        #: Ostatni komunikat dla czlowieka (po polsku, bez adresow i sekretow).
        Column("last_error_message", String, nullable=True),
        #: Jedna operacja na daną rewizję klipu.
        UniqueConstraint("clip_id", "clip_revision", name="uq_mentor_bastion_job_clip_rev"),
    )
    Index("ix_mentor_bastion_jobs_pick", jobs.c.state, jobs.c.next_attempt_at)
    assets = Table(
        "mentor_clip_assets",
        metadata,
        Column("id", String, primary_key=True),
        Column("clip_id", String, nullable=False, index=True),
        Column("revision", Integer, nullable=False, server_default=text("1")),
        Column("status", String, nullable=False, server_default=text("'pending'")),
        Column("storage_key", String, nullable=True),
        Column("size", BigInteger, nullable=True),
        Column("sha256", String, nullable=True),
        Column("duration_s", Float, nullable=True),
        Column("width", Integer, nullable=True),
        Column("height", Integer, nullable=True),
        Column("poster_key", String, nullable=True),
        #: Dostawca pochodzenia ODDZIELNIE od `mentor_clips.source` (manual/proel/sheet...), które zostaje bez zmian.
        Column("origin_provider", String, nullable=False, server_default=text("'bastion'")),
        Column("remote_clip_id", String, nullable=True),
        Column("source_video_id", String, nullable=True),
        #: Zakres w pełnym meczu: lokalny plik gra 0..duration, a oryginalny czas zostaje tutaj.
        Column("source_start_s", Float, nullable=True),
        Column("source_end_s", Float, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        UniqueConstraint("clip_id", "revision", name="uq_mentor_clip_asset_rev"),
    )
    return connections, attempts, jobs, assets


#: Wykonywane przy starcie przez `app/db.py` (PostgreSQL), każde osobno. Zgodne wstecz: samo dokładanie kolumny.
MIGRATIONS = (
    #: Identyfikator źródła u dostawcy (Bastion: `bunny_item_id`). Stare wiersze: NULL.
    "ALTER TABLE mentor_match_videos ADD COLUMN IF NOT EXISTS external_id VARCHAR",
    #: Etap 4: rewizja pliku klipu (media_rev rośnie przy zmianie zakresu) i nowe pola kolejki.
    "ALTER TABLE mentor_clips ADD COLUMN IF NOT EXISTS media_rev INTEGER NOT NULL DEFAULT 1",
    "ALTER TABLE mentor_bastion_clip_jobs ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMPTZ",
    "ALTER TABLE mentor_bastion_clip_jobs ADD COLUMN IF NOT EXISTS poll_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE mentor_bastion_clip_jobs ADD COLUMN IF NOT EXISTS last_error_message VARCHAR",
)

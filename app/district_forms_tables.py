"""
Tabele formularzy okręgowych (10.11.2026) - sam schemat, bez połączenia z bazą.

Kontrakt: `docs/formularze-okregowe.md` §3.

  - `district_forms`               formularz albo lista deklaracji (definicja, odbiorcy, web, termin),
  - `district_form_entries`        wiersz listy albo odpowiedź formularza,
  - `district_form_log`            historia każdej zmiany komórki / odpowiedzi (z IP i urządzeniem dla webu),
  - `district_form_pairs`          logowanie QR na webie (wzór: exam_web),
  - `district_form_notifications`  dziennik wysyłek (deduplikacja) i zarazem skrzynka w aplikacji,
  - `district_form_uploads`        pliki pytań i odpowiedzi (`kind = form`).

Nowe tabele powstają przez `create_all`. Brak Alembica: kolumny dokładane później idą
przez `MIGRATIONS` (`ALTER ... IF NOT EXISTS`), każda instrukcja osobno przy starcie.
"""
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB

_JSON = JSON().with_variant(JSONB, "postgresql")


def define_tables(metadata):
    forms = Table(
        "district_forms",
        metadata,
        #: `secrets.token_hex(8)`.
        Column("id", String(16), primary_key=True),
        #: Kanoniczny klucz okręgu („SLASKIE").
        Column("province", String, nullable=False, index=True),
        #: list | form
        Column("kind", String, nullable=False),
        Column("title", String(160), nullable=False),
        Column("description", Text, nullable=True),
        Column("cover_json", _JSON, nullable=True),
        Column("schema_json", _JSON, nullable=False),
        Column("settings_json", _JSON, nullable=False),
        Column("audience_json", _JSON, nullable=False),
        #: Bloki informacyjne nad i pod formularzem (sec. 17): {"above": [...], "below": [...]}.
        Column("info_json", _JSON, nullable=True),
        Column("event_id", Integer, nullable=True, index=True),
        Column("web_enabled", Boolean, nullable=False, default=False),
        #: Raz nadany zostaje (wydrukowany QR dalej działa po wyłączeniu i włączeniu webu).
        Column("web_code", String(8), nullable=True, unique=True),
        Column("created_by", String, nullable=False),
        Column("created_by_name", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("published_at", DateTime(timezone=True), nullable=True),
        Column("closes_at", DateTime(timezone=True), nullable=True),
        Column("closed_at", DateTime(timezone=True), nullable=True),
        Column("archived_at", DateTime(timezone=True), nullable=True),
        Column("deleted_at", DateTime(timezone=True), nullable=True),
        #: Rośnie przy każdej zmianie; klient wysyła `If-Match: <rev>`.
        Column("rev", Integer, nullable=False, default=1),
    )
    entries = Table(
        "district_form_entries",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("form_id", String(16), nullable=False, index=True),
        #: NULL tylko dla gościa formularza otwartego.
        Column("judge_id", String, nullable=True),
        Column("guest_name", String, nullable=True),
        Column("cells_json", _JSON, nullable=True),
        Column("answers_json", _JSON, nullable=True),
        Column("verified", Boolean, nullable=False, default=False),
        #: app | web_qr | web - ostatnie źródło zapisu właściciela.
        Column("self_source", String, nullable=True),
        Column("web_device", String, nullable=True),
        Column("web_at", DateTime(timezone=True), nullable=True),
        Column("web_review", Boolean, nullable=False, default=False),
        Column("client_id", String, nullable=True),
        Column("fill_seconds", Integer, nullable=True),
        Column("submitted_at", DateTime(timezone=True), nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=True),
        UniqueConstraint("form_id", "judge_id", name="uq_district_form_entries_judge"),
        UniqueConstraint("form_id", "client_id", name="uq_district_form_entries_client"),
    )
    log = Table(
        "district_form_log",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("form_id", String(16), nullable=False),
        Column("entry_id", Integer, nullable=True),
        Column("owner_judge_id", String, nullable=True),
        #: NULL = cała odpowiedź formularza.
        Column("column_id", String, nullable=True),
        Column("old_json", _JSON, nullable=True),
        Column("new_json", _JSON, nullable=True),
        Column("actor_judge_id", String, nullable=True),
        Column("source", String, nullable=False),
        Column("ip", String, nullable=True),
        Column("user_agent", String, nullable=True),
        Column("device_id", String, nullable=True),
        Column("geo_json", _JSON, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    Index("ix_district_form_log_form_created", log.c.form_id, log.c.created_at)
    pairs = Table(
        "district_form_pairs",
        metadata,
        Column("code", String(8), primary_key=True),
        Column("poll_token_hash", String, nullable=False),
        Column("form_id", String(16), nullable=False),
        #: pending | approved | expired | used
        Column("status", String, nullable=False, default="pending"),
        Column("judge_id", String, nullable=True),
        Column("judge_name", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("expires_at", DateTime(timezone=True), nullable=False),
        Column("ip", String, nullable=True),
        Column("user_agent", String, nullable=True),
    )
    notifications = Table(
        "district_form_notifications",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("form_id", String(16), nullable=False),
        Column("judge_id", String, nullable=False),
        #: published | reminder | manual | web_review | deadline_today
        Column("kind", String, nullable=False),
        Column("slot", String, nullable=False),
        Column("sent_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        #: Treść wysłana pushem - ta sama trafia do skrzynki w aplikacji (`GET /district-forms/inbox`).
        Column("title", String, nullable=True),
        Column("body", Text, nullable=True),
        UniqueConstraint("form_id", "judge_id", "kind", "slot", name="uq_district_form_notifications"),
    )
    Index("ix_district_form_notifications_judge", notifications.c.judge_id, notifications.c.sent_at)
    uploads = Table(
        "district_form_uploads",
        metadata,
        Column("token", String(16), primary_key=True),
        Column("form_id", String(16), nullable=False, index=True),
        Column("judge_id", String, nullable=True),
        #: question | answer
        Column("purpose", String, nullable=False),
        Column("name", String, nullable=True),
        Column("mime", String, nullable=True),
        Column("size_bytes", Integer, nullable=False, default=0),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    return forms, entries, log, pairs, notifications, uploads


#: Jedno wydarzenie ma najwyżej jeden żywy formularz. Każda instrukcja osobno - brak jednej nie zatrzymuje startu.
MIGRATIONS = (
    # Bloki informacyjne (sec. 17) - tabela mogla juz powstac bez tej kolumny.
    "ALTER TABLE district_forms ADD COLUMN IF NOT EXISTS info_json JSONB DEFAULT '{\"above\":[],\"below\":[]}'::jsonb",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_district_forms_event ON district_forms (event_id) "
    "WHERE event_id IS NOT NULL AND deleted_at IS NULL",
)

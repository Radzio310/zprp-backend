"""Teczka pary (Dysk Google, 30.10.2026) - schematy. Kontrakt: `docs/mentor-panel.md`, § "Teczka pary".

`mentor_drive_connections`: JEDNO połączenie na parę (konto osoby, która podłączyła; tokeny zaszyfrowane AES-GCM),
`mentor_drive_files`: księga zapisów + trwała kolejka wysyłki (stan, dzierżawa, ponowienia),
`mentor_drive_folders`: pamięć podfolderów (find-or-create bez dubli po restarcie),
`mentor_drive_log`: dziennik działań z BAZY (append-only; zapis nigdy nie blokuje właściwej akcji).
"""

from sqlalchemy import BigInteger, Boolean, Column, DateTime, Index, Integer, String, Table, Text, UniqueConstraint, func, text


def define_tables(metadata):
    connections = Table(
        "mentor_drive_connections",
        metadata,
        Column("pair_id", String, primary_key=True),
        Column("owner_judge_id", String, nullable=False),
        Column("google_email", String, nullable=True),
        Column("google_name", String, nullable=True),
        #: AES-GCM(base64) z {access_token, refresh_token, expires_at}. Nigdy w odpowiedziach ani w logach.
        Column("token_enc", Text, nullable=False),
        #: `connected` | `needs_reconnect`.
        Column("state", String, nullable=False, server_default=text("'connected'")),
        Column("reconnect_reason", String, nullable=True),
        Column("reconnect_notified_at", DateTime(timezone=True), nullable=True),
        Column("folder_id", String, nullable=True),
        Column("folder_name", String, nullable=True),
        Column("folder_url", String, nullable=True),
        #: `FOLDER_GONE` itp., gdy folder przestał być dostępny (zadania czekają na nowy wybór).
        Column("folder_problem", String, nullable=True),
        #: `match_category` (domyślnie) | `match` | `category` | `flat`.
        Column("layout", String, nullable=False, server_default=text("'match_category'")),
        Column("partner_email", String, nullable=True),
        #: `none` | `ok` | `error` | `owner`.
        Column("share_status", String, nullable=False, server_default=text("'none'")),
        Column("share_error", String, nullable=True),
        Column("shared_at", DateTime(timezone=True), nullable=True),
        #: Ostatni udany odczyt listy osób z dostępem (JSON `{checked_at, perms[]}`); podawany jako `stale`, gdy Google nie odpowiada.
        Column("access_snapshot", Text, nullable=True),
        Column("connected_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    files = Table(
        "mentor_drive_files",
        metadata,
        Column("id", String, primary_key=True),
        Column("pair_id", String, nullable=False),
        Column("clip_id", String, nullable=False),
        #: `plain` | `card` (wariant z planszą).
        Column("variant", String, nullable=False, server_default=text("'plain'")),
        Column("match_id", String, nullable=False),
        Column("match_label", String, nullable=True),
        Column("category", String, nullable=True),
        Column("name", String, nullable=False),
        Column("thumb", Text, nullable=True),
        Column("author_judge_id", String, nullable=False),
        #: `waiting_mp4` -> `queued` -> `working` -> `done` | `failed` | `cancelled`.
        Column("state", String, nullable=False, server_default=text("'queued'")),
        Column("attempts", Integer, nullable=False, server_default=text("0")),
        Column("next_at", DateTime(timezone=True), nullable=True),
        Column("lease_until", DateTime(timezone=True), nullable=True),
        Column("worker_id", String, nullable=True),
        Column("error", String, nullable=True),
        Column("drive_file_id", String, nullable=True),
        Column("web_view_link", Text, nullable=True),
        Column("size", BigInteger, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("done_at", DateTime(timezone=True), nullable=True),
        #: Ostatnie sprawdzenie u Google, czy plik nadal jest (`/drive/verify`, tło). NULL = jeszcze nie sprawdzany.
        Column("verified_at", DateTime(timezone=True), nullable=True),
        UniqueConstraint("pair_id", "clip_id", "variant", name="uq_mentor_drive_files_clip"),
        Index("ix_mentor_drive_files_pair_updated", "pair_id", "updated_at"),
        Index("ix_mentor_drive_files_state", "state"),
    )
    folders = Table(
        "mentor_drive_folders",
        metadata,
        Column("pair_id", String, primary_key=True),
        Column("parent_id", String, primary_key=True),
        Column("name", String, primary_key=True),
        Column("folder_id", String, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    log = Table(
        "mentor_drive_log",
        metadata,
        #: Zwykle losowy; dla `clip_saved` deterministyczny (`cs-<plik>-<czas>`), co daje idempotentne uzupełnienie wstecz.
        Column("id", String, primary_key=True),
        Column("pair_id", String, nullable=False),
        Column("kind", String, nullable=False),
        #: Kto kliknął (puste = system). Przy `act_as` to mentor, w oczach którego działał administrator (`acted_by`).
        Column("actor_id", String, nullable=True),
        Column("acted_by", String, nullable=True),
        #: JSON z białej listy kluczy (`mentor_drive_rules.log_details`): nigdy tokenów ani adresów podpisanych.
        Column("details", Text, nullable=False, server_default=text("'{}'")),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Index("ix_mentor_drive_log_pair_created", "pair_id", "created_at"),
    )
    return connections, files, folders, log


#: Wykonywane przy starcie przez `app/db.py` (PostgreSQL), każde osobno. Samo dokładanie kolumny.
MIGRATIONS = (
    "ALTER TABLE mentor_drive_files ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ",
    "ALTER TABLE mentor_drive_connections ADD COLUMN IF NOT EXISTS access_snapshot TEXT",
    # Tabela `mentor_drive_log` powstaje z `metadata.create_all`; poniższe domykają ją, gdyby powstała bez indeksu.
    "CREATE INDEX IF NOT EXISTS ix_mentor_drive_log_pair_created ON mentor_drive_log (pair_id, created_at)",
)

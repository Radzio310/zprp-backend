"""
Tabele wdrożenia okręgu (`docs/wdrozenie-okregu.md`, sekcja 4).

Sam schemat - bez połączenia z bazą, żeby dało się go obejrzeć w teście.
Okręg jest kluczem kanonicznym (`settlement_province.canonical`, np. „SLASKIE").

  - `district_onboarding`           - stan okręgu: kod (tylko skrót), moduły, klucze, postęp, etap,
  - `district_onboarding_events`    - kto co wgrał (podpis z wejścia), NIGDY sekrety,
  - `district_onboarding_files`     - pliki od okręgu; bajty w bazie jak `board_attachments`,
    bo to dokumenty okręgu, a nie publiczne zdjęcia,
  - `sealed_secrets`                - szyfrogramy haseł ZPRP (NaCl sealed box), kasowane po
    „Wklejone do Railway",
  - `onboarding_sealing_keys`       - klucze publiczne administratora do sejfu.
"""

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB


def define_tables(metadata):
    onboarding = Table(
        "district_onboarding",
        metadata,
        Column("province", String, primary_key=True),
        #: sha256 kodu z pieprzem z env. Sam kod widzi administrator raz, przy wydaniu.
        Column("code_hash", String, nullable=True, unique=True),
        Column("code_version", Integer, nullable=False, server_default="0"),
        Column("code_issued_at", DateTime(timezone=True), nullable=True),
        Column("code_revoked", Boolean, nullable=False, server_default="false"),
        Column("modules", JSONB, nullable=False, server_default="[]"),
        #: {key: {status, updated_at, by, note, skip_reason, draft, ...}}
        Column("items", JSONB, nullable=False, server_default="{}"),
        Column("progress", Integer, nullable=False, server_default="0"),
        Column("stage", String, nullable=False, server_default="waiting"),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    events = Table(
        "district_onboarding_events",
        metadata,
        Column("id", BigInteger, primary_key=True, autoincrement=True),
        Column("province", String, nullable=False),
        Column("at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("by", String, nullable=True),
        Column("key", String, nullable=True),
        Column("action", String, nullable=False),
        #: Przechodzi przez `district_onboarding_rules.scrub` - bez haseł i szyfrogramów.
        Column("payload", JSONB, nullable=False, server_default="{}"),
        Index("ix_district_onboarding_events_province", "province", "id"),
    )
    files = Table(
        "district_onboarding_files",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("province", String, nullable=False),
        Column("key", String, nullable=False),
        Column("filename", String, nullable=False),
        Column("mime", String, nullable=False),
        Column("size", Integer, nullable=False),
        Column("sha256", String, nullable=False),
        Column("data", LargeBinary, nullable=False),
        Column("uploaded_by", String, nullable=True),
        Column("uploaded_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Index("ix_district_onboarding_files_province", "province", "key"),
    )
    sealed = Table(
        "sealed_secrets",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("province", String, nullable=False, index=True),
        Column("key", String, nullable=False),
        Column("login", String, nullable=True),
        #: NULL po „Wklejone do Railway" - szyfrogram znika, metadane zostają.
        Column("ciphertext", Text, nullable=True),
        Column("alg", String, nullable=False),
        Column("key_id", String, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("created_by", String, nullable=True),
        Column("consumed_at", DateTime(timezone=True), nullable=True),
    )
    sealing_keys = Table(
        "onboarding_sealing_keys",
        metadata,
        Column("key_id", String, primary_key=True),
        Column("public_key", String, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("created_by", String, nullable=True),
        Column("revoked_at", DateTime(timezone=True), nullable=True),
    )
    return onboarding, events, files, sealed, sealing_keys

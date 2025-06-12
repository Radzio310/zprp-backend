# app/db.py
import os
from sqlalchemy import (
    ARRAY,
    Column,
    DateTime,
    Integer,
    String,
    MetaData,
    Table,
    Text,
    create_engine,
    func,
)
from databases import Database

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./local.db")

# Połączenie do bazy
database = Database(DATABASE_URL)
metadata = MetaData()

# -------------------------
# Tabele
# -------------------------

# 1) Tabela tokenów kalendarza
calendar_tokens = Table(
    "calendar_tokens",
    metadata,
    Column("user_login", String, primary_key=True),
    Column("access_token", String, nullable=False),
    Column("refresh_token", String, nullable=False),
    Column("expires_at", String, nullable=False),
)

# 2) Tabela CSRF state dla OAuth2
oauth_states = Table(
    "oauth_states",
    metadata,
    Column("user_login", String, primary_key=True),
    Column("state", String, nullable=False),
)

# 3) Mappings between your match_id and calendar event_id
event_mappings = Table(
    "event_mappings",
    metadata,
    Column("user_login", String, primary_key=True),
    Column("match_id", String, primary_key=True),
    Column("event_id", String, nullable=False),
)

# 4) Tabela ogłoszeń (Silesia)
announcements = Table(
    "announcements",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("judge_id", String, nullable=False, index=True),
    Column("judge_name", String, nullable=True),
    Column("title", String, nullable=False),
    Column("content", Text, nullable=False),
    Column("image_url", String, nullable=True),
    Column("priority", Integer, nullable=False, default=0),
    Column("link", String, nullable=True), # link do ogłoszenia, może być pusty
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
)

# 5) Tabela “kalendarz niedyspozycji” Silesia
silesia_offtimes = Table(
    "silesia_offtimes",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("judge_id", String, nullable=False, index=True),
    Column("full_name", String, nullable=False),
    Column("data_json", Text, nullable=False),  # tu przechowujemy cały JSON jako tekst
    Column("updated_at", DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
)

# (6) Mecze do oddania
matches_to_offer = Table(
    "matches_to_offer",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("judge_id", String, nullable=False, index=True),
    Column("judge_name", String, nullable=False),
    Column("match_data", Text, nullable=False),           # JSON jako tekst
    Column("created_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
)

# (7) Mecze oczekujące na akceptację
matches_to_approve = Table(
    "matches_to_approve",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("original_offer_id", Integer, nullable=False, index=True),
    Column("judge_id", String, nullable=False, index=True),
    Column("judge_name", String, nullable=False),
    Column("match_data", Text, nullable=False),
    Column("assign_judges", ARRAY(String), nullable=False),  # lista ID
    Column("assign_names", ARRAY(String), nullable=False),   # lista imion
    Column("requested_at", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
)

# (8) Historia zdarzeń przy meczu
matches_events = Table(
    "matches_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("event_type", String, nullable=False),           # np. "offer","assign","approve","reject","delete"
    Column("event_time", DateTime(timezone=True),
           server_default=func.now(), nullable=False),
    Column("match_id", Integer, nullable=False, index=True), # odniesienie do offer_id
    Column("owner_judge_id", String, nullable=False),        # kto dodał ofertę
    Column("acting_judge_id", String, nullable=True),        # kto wykonał akcję
)

# (9) Tabela admin PIN
admin_pins = Table(
    "admin_pins",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("pin_hash", String, nullable=False),
)

# Tworzymy tabele przy starcie
engine = create_engine(DATABASE_URL)
metadata.create_all(engine)

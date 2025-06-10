# app/db.py
import os
from sqlalchemy import (
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
    Column("title", String, nullable=False),
    Column("content", Text, nullable=False),
    Column("image_url", String, nullable=True),
    Column("priority", Integer, nullable=False, default=0),
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

# Tworzymy tabele przy starcie
engine = create_engine(DATABASE_URL)
metadata.create_all(engine)

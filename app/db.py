import os
from sqlalchemy import (
    Column,
    Integer,
    String,
    MetaData,
    Table,
    create_engine,
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

# Tworzymy obie tabele przy starcie
engine = create_engine(DATABASE_URL)
metadata.create_all(engine)

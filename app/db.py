# app/db.py
import os
from sqlalchemy import (
    Column, Integer, String, MetaData, Table, create_engine
)
from databases import Database

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./local.db")

# Obiekt, który będziemy używać w kodzie do zapytań
database = Database(DATABASE_URL)
metadata = MetaData()

# Definicja tabeli do przechowywania tokenów kalendarza
calendar_tokens = Table(
    "calendar_tokens",
    metadata,
    Column("user_id", Integer, primary_key=True),
    Column("access_token", String, nullable=False),
    Column("refresh_token", String, nullable=False),
    Column("expires_at", String, nullable=False),
)

# Tworzymy tabele (przy starcie aplikacji)
engine = create_engine(DATABASE_URL)
metadata.create_all(engine)

import os
from sqlalchemy import (
    Column, String, MetaData, Table, create_engine
)
from databases import Database

# -----------------------------------
# Database connection and metadata
# -----------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./local.db")

database = Database(DATABASE_URL)
metadata = MetaData()

# -----------------------------------
# Table for storing Google Calendar tokens
# -----------------------------------
calendar_tokens = Table(
    "calendar_tokens",
    metadata,
    Column("user_login", String, primary_key=True),
    Column("access_token", String, nullable=False),
    Column("refresh_token", String, nullable=False),
    Column("expires_at", String, nullable=False),
)

# -----------------------------------
# Initialize database schema
# -----------------------------------
engine = create_engine(DATABASE_URL)
metadata.create_all(engine)

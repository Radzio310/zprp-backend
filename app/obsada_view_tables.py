"""Tabele Obsady na zywo (12.11.2026). Tworzone tu, nie w db.py (create_all tylko dla nich)."""
from sqlalchemy import Column, DateTime, Index, Integer, String, Table, Text, func

from app.db import engine, metadata

obsada_view = Table(
    "province_obsada_view",
    metadata,
    Column("province", String, primary_key=True),
    Column("mode", String, nullable=False, server_default="off"),
    Column("token", String(16), nullable=False, unique=True),
    Column("updated_by", String, nullable=True),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)

obsada_changes = Table(
    "province_obsada_changes",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("province", String, nullable=False),
    Column("match_id", String, nullable=False),
    Column("kind", String, nullable=False),
    # JSON jako Text - sterownik `databases` oddaje JSONB napisem.
    Column("before", Text, nullable=True),
    Column("after", Text, nullable=True),
    Column("at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Index("ix_obsada_changes_province_at", "province", "at"),
)

metadata.create_all(engine, tables=[obsada_view, obsada_changes])

"""Archiwum arkuszy ocen delegatów pobieranych w tle z konta sędziego."""

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    func,
    text,
)


def define_tables(metadata):
    # Oryginał każdego arkusza, ze wszystkich sezonów: HTML nowej oceny albo
    # PDF starej (skompresowane), tekst PDF-u i opis meczu. To źródło prawdy -
    # z niego da się kiedyś przeliczyć oceny bez ponownego chodzenia do ZPRP.
    documents = Table(
        "delegate_evaluation_documents",
        metadata,
        Column("source_key", String, primary_key=True),
        Column("path", Text, nullable=False),
        Column("kind", String, nullable=False),
        Column("match_id", String, nullable=False, index=True),
        Column("match_code", String, nullable=True),
        Column("season", String, nullable=False, server_default=text("''"), index=True),
        Column("province", String, nullable=True),
        Column("match_date", String, nullable=True),
        Column("referee_ids", JSON, nullable=False, server_default=text("'[]'")),
        Column("referee_names", JSON, nullable=False, server_default=text("'[]'")),
        Column("delegate_name", String, nullable=True),
        Column("submitted_by", String, nullable=True, index=True),
        Column("status", String, nullable=False, server_default=text("'queued'")),
        Column("attempts", Integer, nullable=False, server_default=text("0")),
        Column("error", Text, nullable=True),
        Column("content_hash", String, nullable=True),
        Column("html_gz", LargeBinary, nullable=True),
        Column("pdf_gz", LargeBinary, nullable=True),
        Column("pdf_text", Text, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("fetched_at", DateTime(timezone=True), nullable=True),
    )
    return documents

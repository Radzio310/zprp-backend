"""Schemat szkiców ocen młodych sędziów - sam schemat, bez połączenia z bazą."""
from sqlalchemy import Column, DateTime, String, Table, Text, func


def define_tables(metadata):
    young_rating_drafts = Table(
        "young_rating_drafts",
        metadata,
        Column("judge_id", String, primary_key=True),
        Column("draft_key", String, primary_key=True),
        #: Napis JSON - serwer go nie rozbiera (sterownik oddaje JSONB napisem).
        Column("payload", Text, nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    return (young_rating_drafts,)

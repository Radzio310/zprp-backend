"""Licznik dobowy odczytów składów („Wczytaj składy", 02.11.2026) - sam schemat, bez bazy.

Jeden wiersz = konto + dzień (po polsku) + rodzaj odczytu (`ai` z modelem, `text` z PDF-a regułami). Trwały w bazie, więc
restart serwera ani drugi proces nie zerują limitu. Nie zawiera niczego poza licznikiem: ani nazwisk, ani plików.
"""

from sqlalchemy import Column, Integer, String, Table, text


def define_tables(metadata):
    usage = Table(
        "lineup_read_usage",
        metadata,
        Column("judge_id", String, primary_key=True),
        #: Dzień polski RRRR-MM-DD.
        Column("day", String, primary_key=True),
        #: ai | text
        Column("kind", String, primary_key=True),
        Column("count", Integer, nullable=False, server_default=text("0")),
    )
    return (usage,)

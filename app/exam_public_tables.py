"""
Tabela strony publicznej wyników egzaminu (26.10.2026) - sam schemat, bez połączenia z bazą.

  - `exam_public_links`  link bazapodreka.app/wyniki/<kod>: poziom jawności, zdjęcia,
                         najtrudniejsze pytania, licznik wyświetleń, wyłączenie.

Jeden AKTYWNY link na (egzamin, wycinek okręgu). Wyłączony wiersz zostaje - ponowne
włączenie bez `new_code` przywraca TEN SAM kod (wydrukowany QR dalej działa).
Nowa tabela powstaje przez `create_all` - bez migracji kolumn.
"""
from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Table, func


def define_tables(metadata):
    links = Table(
        "exam_public_links",
        metadata,
        #: Kod z adresu - losuje serwer (8 znaków bez 0/O/1/l/i).
        Column("code", String, primary_key=True),
        Column("exam_id", String, nullable=False, index=True),
        #: Egzamin krajowy wystawiony przez komisję okręgu: tylko ten okręg (jak jej odczyt). NULL = całość.
        Column("cut_province", String, nullable=True),
        #: stats | initials | names | points
        Column("level", String, nullable=False, default="stats"),
        Column("photos", Boolean, nullable=False, default=False),
        Column("hardest", Boolean, nullable=False, default=False),
        #: province | elegant | premium - motyw strony (jak plik eksportu).
        Column("theme", String, nullable=False, default="province"),
        Column("views", Integer, nullable=False, default=0),
        Column("last_view_at", DateTime(timezone=True), nullable=True),
        Column("created_by", String, nullable=True),
        Column("created_by_name", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("disabled_at", DateTime(timezone=True), nullable=True),
        Column("disabled_by", String, nullable=True),
    )
    Index("ix_exam_public_links_exam_active", links.c.exam_id, links.c.disabled_at)
    return (links,)

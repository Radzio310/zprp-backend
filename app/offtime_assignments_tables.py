"""
Tabela niedyspozycji wpisanych sędziom przez obsadowego / Calendar Mastera / admina
(12.11.2026) - sam schemat, bez połączenia z bazą.

Jeden wiersz = jedna niedyspozycja jednego sędziego (z autorem). To OSOBNY magazyn,
bo blob `silesia_offtimes.data_json` jest nadpisywany w całości przez telefon sędziego.
Odczyty `/silesia/offtimes/*` dokładają te wiersze do listy sędziego dopiero przy
składaniu odpowiedzi, a `/offtimes/set` wycina je z przychodzącego bloba.

`from` / `to` trzymamy jako napisy ISO, dokładnie w kształcie wpisów `data_json`
(telefon porównuje je i rysuje bez przeliczeń). Usunięcie jest miękkie (`deleted_at`),
żeby telefon sędziego, który jeszcze trzyma stary blob, nie wskrzesił wpisu.
"""
from sqlalchemy import Column, DateTime, Index, String, Table, Text, func

def define_tables(metadata):
    offtime_assignments = Table(
        "silesia_offtime_assignments",
        metadata,
        Column("id", String, primary_key=True),  # uuid jako napis
        Column("province", String, nullable=False, index=True),
        Column("judge_id", String, nullable=False),
        Column("from", String, nullable=False),
        Column("to", String, nullable=True),
        Column("info", Text, nullable=True),
        Column("category_id", String, nullable=True),
        Column("category_name", String, nullable=True),
        Column("category_color", String, nullable=True),
        Column("created_by", String, nullable=False),
        Column("created_by_name", String, nullable=False, server_default=""),
        Column("created_by_role", String, nullable=False),  # obsadowy|calendar_master|admin
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column("updated_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        Column("updated_by", String, nullable=True),
        Column("deleted_at", DateTime(timezone=True), nullable=True),
        Index("ix_offtime_assignments_judge", "judge_id", "province"),
    )
    return (offtime_assignments,)

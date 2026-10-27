"""Zgłoszenia błędów rysowania z przeglądarki portalu (`app/client_errors.py`).

`client_error_reports`: jeden wiersz na odcisk (rodzaj, trasa, część, komunikat, build) -
ten sam błąd z wielu telefonów zwiększa `count` i przesuwa `last_at`, nie dokłada wierszy.
Bez danych osobowych: bez adresu IP, bez parametrów adresu, bez treści ekranu.
Nowa tabela (create_all), bez zmian w istniejących.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Integer, MetaData, String, Table, Text, func


def define_tables(metadata: MetaData) -> Table:
    return Table(
        "client_error_reports",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("fingerprint", String(64), nullable=False, unique=True, index=True),
        Column("kind", String(16), nullable=False),
        Column("route", String(120), nullable=False),
        Column("part", String(80), nullable=False),
        Column("message", String(300), nullable=False),
        Column("stack", Text, nullable=True),
        Column("ua", String(240), nullable=True),
        Column("build", String(40), nullable=True),
        Column("lite", Boolean, nullable=True),
        Column("standalone", Boolean, nullable=True),
        Column("width", Integer, nullable=True),
        Column("count", Integer, nullable=False, server_default="1"),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("last_at", DateTime(timezone=True), nullable=False, server_default=func.now(), index=True),
    )

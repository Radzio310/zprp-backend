"""Tabela wstępnych wyników skróconych - nakładka na oficjalną tabelę ZPRP.

Wpis żyje, dopóki oficjalna tabela nie "dogoni" wyniku (patrz
`standings_provisional.overlay_active`) albo nie minie TTL.
"""
from __future__ import annotations

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, Text, func


def define_table(metadata: MetaData) -> Table:
    return Table(
        "zprp_public_provisional_results",
        metadata,
        Column("match_id", String, primary_key=True),
        Column("competition_id", String, nullable=False, index=True),
        Column("home_team_id", String, nullable=False),
        Column("away_team_id", String, nullable=False),
        Column("score_home", Integer, nullable=False),
        Column("score_away", Integer, nullable=False),
        Column("shootout_home", Integer, nullable=True),
        Column("shootout_away", Integer, nullable=True),
        # Wynik meczu znany serwerowi przed wpisem, o ile oficjalna tabela go już liczyła.
        Column("prev_home", Integer, nullable=True),
        Column("prev_away", Integer, nullable=True),
        # Podpis oficjalnych wierszy obu drużyn w chwili wpisu (JSON): zmiana = ZPRP dogoniło.
        Column("base_json", Text, nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )

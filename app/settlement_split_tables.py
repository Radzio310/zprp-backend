"""
Tabela podziałów puli sędziego na listy sędziowskie (25.09.2026) - sam
schemat, bez połączenia z bazą. Reguła w `app/settlement_split_rules.py`,
trasy w `app/province_settlement_splits.py`.

  - `province_settlement_splits` - jeden podział na okręg, miesiąc i sędziego:
    listy (mecze + ręczne przesunięcia kwot), stan (szkic / wydane /
    porzucony), numery wydanych list i historia unieważnionych numerów.

JSON jako Text (nie JSONB): sterownik `databases` oddaje JSONB napisem, więc
każdy odczyt i tak musiałby go rozbierać - Text jest przynajmniej uczciwy.
"""

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Table, Text, func, text


def define_tables(metadata):
    splits = Table(
        "province_settlement_splits",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        #: Klucz okręgu z `settlement_province.canonical` („SLASKIE").
        Column("province", String, nullable=False),
        Column("period_year", Integer, nullable=False),
        Column("period_month", Integer, nullable=False),
        Column("judge_id", String, nullable=False),
        #: draft | issued | void
        Column("status", String, nullable=False, server_default=text("'draft'")),
        #: Numer wersji - zapis „na starym" (dwie karty naraz) dostaje 409.
        Column("rev", Integer, nullable=False, server_default=text("0")),
        #: [{letter, match_keys[], manual_shift}] jako napis JSON.
        Column("lists_json", Text, nullable=False, server_default=text("'[]'")),
        #: Przełączniki widoku, z którymi listy wydano.
        Column("include_future", Boolean, nullable=False, server_default=text("false")),
        Column("include_zprp", Boolean, nullable=False, server_default=text("false")),
        #: Numery wydanych list, w kolejności liter - napis JSON.
        Column("numbers_json", Text, nullable=False, server_default=text("'[]'")),
        #: Identyfikatory wpisów w `province_settlement_documents` - napis JSON.
        Column("document_ids_json", Text, nullable=False, server_default=text("'[]'")),
        #: Migawka list w dniu wydania (kwoty i mecze) - do duplikatu PDF
        #: i do wykrycia, że miesiąc zmienił się pod wydanymi listami.
        Column("snapshot_json", Text, nullable=False, server_default=text("'{}'")),
        #: Unieważnione wydania: [{numbers, voided_at, voided_by, reason}].
        Column("voided_json", Text, nullable=False, server_default=text("'[]'")),
        Column("issued_at", DateTime(timezone=True), nullable=True),
        Column("issued_by", String, nullable=True),
        Column("updated_by", String, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    Index(
        "ux_province_settlement_splits_key",
        splits.c.province,
        splits.c.period_year,
        splits.c.period_month,
        splits.c.judge_id,
        unique=True,
    )
    return (splits,)

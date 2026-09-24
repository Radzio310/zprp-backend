"""
Tabele Obsady 2.0 (24.09.2026) - same schematy, bez połączenia z bazą.

  - `province_mentor_pairs`       para mentorska przypisana PARZE sędziowskiej,
  - `province_assignment_board_drafts`  wspólny szkic kolejki zmian (jeden na
                                  okręg, z numerem wersji do wykrywania
                                  zapisu „na starym"),
  - `province_zprp_write_journal` dziennik KAŻDEGO udanego zapisu obsady
                                  i hali do ZPRP (ręczny, automat, cichy).

JSON jako Text (nie JSONB): sterownik `databases` oddaje JSONB napisem, więc
każdy odczyt i tak musiałby go rozbierać - Text jest przynajmniej uczciwy.
"""

from sqlalchemy import Column, DateTime, Index, Integer, String, Table, Text, func


def define_tables(metadata):
    mentor_pairs = Table(
        "province_mentor_pairs",
        metadata,
        Column("province", String, primary_key=True),
        #: Posortowane numery pary sędziowskiej złączone „|" - `pair_key`.
        Column("pair_key", String, primary_key=True),
        Column("judge_a", String, nullable=False),
        Column("judge_b", String, nullable=False),
        #: Lista numerów mentorów jako napis JSON.
        Column("mentor_ids", Text, nullable=False, default="[]"),
        Column("updated_by", String, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    drafts = Table(
        "province_assignment_board_drafts",
        metadata,
        Column("province", String, primary_key=True),
        Column("rev", Integer, nullable=False, default=0),
        #: Lista zmian kolejki jako napis JSON - serwer jej nie rozbiera.
        Column("changes", Text, nullable=False, default="[]"),
        Column("updated_by", String, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    journal = Table(
        "province_zprp_write_journal",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("province", String, nullable=False, index=True),
        #: Partia „Zapisz w ZPRP" - przy zapisie bez partii serwer nadaje własną.
        Column("batch_id", String, nullable=False, index=True),
        Column("match_id", String, nullable=False, index=True),
        Column("match_code", String, nullable=True),
        Column("match_label", String, nullable=True),
        #: slot | hall
        Column("kind", String, nullable=False),
        Column("slot", String, nullable=True),
        Column("before_id", String, nullable=True),
        Column("before_name", String, nullable=True),
        Column("after_id", String, nullable=True),
        Column("after_name", String, nullable=True),
        Column("hall_before", String, nullable=True),
        Column("hall_after", String, nullable=True),
        Column("actor", String, nullable=True),
        #: Przebieg automatu, z którego pochodzi zapis (gdy jest).
        Column("run_id", Integer, nullable=True),
        #: Wpis dziennika, który ten zapis cofa.
        Column("reverted_of", Integer, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    Index("ix_province_zprp_write_journal_prov_id", journal.c.province, journal.c.id)
    return mentor_pairs, drafts, journal

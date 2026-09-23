"""
Schemat wczytywania faktur jako wpłat klubów - same tabele, bez połączenia.

PLIKI PDF TRZYMAMY W BAZIE (BYTEA). Serwer na Railway nie ma trwałego
wolumenu: `/tmp` (tam siedzą np. wydruki rozliczeń) znika przy każdym
wdrożeniu, a faktura ma się dać otworzyć z historii i z wpłaty klubu także za
rok. Faktury są małe (kilkadziesiąt KB), a limit pliku pilnuje trasa. Kolumnę
`pdf` czytamy WYŁĄCZNIE w trasie pobrania pliku - listy jej nie wybierają.

JSON jako Text (nie JSONB): w tym projekcie JSONB wraca napisem, a Text jest
przynajmniej uczciwy co do typu.
"""

from sqlalchemy import Column, Date, DateTime, Float, Index, Integer, LargeBinary, String, Table, Text, func


def define_tables(metadata):
    batches = Table(
        "province_invoice_batches",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("province", String, nullable=False, index=True),
        Column("season", String, nullable=True),
        Column("created_by", String, nullable=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now()),
        Column("updated_at", DateTime(timezone=True), nullable=True),
        # Liczniki do listy historii - przeliczane po każdej zmianie pozycji.
        Column("files", Integer, nullable=False, server_default="0"),
        Column("read_ok", Integer, nullable=False, server_default="0"),
        Column("ai_used", Integer, nullable=False, server_default="0"),
        Column("approved", Integer, nullable=False, server_default="0"),
        Column("duplicates", Integer, nullable=False, server_default="0"),
        Column("total", Float, nullable=False, server_default="0"),
        Column("approved_total", Float, nullable=False, server_default="0"),
    )

    items = Table(
        "province_invoice_items",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("batch_id", Integer, nullable=False, index=True),
        Column("province", String, nullable=False, index=True),
        Column("file_name", String, nullable=True),
        Column("file_size", Integer, nullable=True),
        Column("file_sha256", String, nullable=True, index=True),
        Column("pdf", LargeBinary, nullable=True),
        # proposed | approved | rejected | duplicate | unreadable
        Column("status", String, nullable=False, server_default="proposed"),
        # rules | ai-text | ai-vision | none
        Column("method", String, nullable=True),
        Column("note", String, nullable=True),
        Column("parsed_json", Text, nullable=True),
        Column("match_json", Text, nullable=True),
        Column("invoice_no", String, nullable=True),
        Column("invoice_key", String, nullable=True, index=True),
        Column("seller_nip", String, nullable=True),
        Column("buyer_nip", String, nullable=True),
        Column("buyer_name", String, nullable=True),
        Column("issue_date", Date, nullable=True),
        Column("amount", Float, nullable=True),
        Column("description", String, nullable=True),
        Column("club_id", String, nullable=True),
        Column("confidence", Float, nullable=True),
        Column("entry_id", Integer, nullable=True, index=True),
        Column("decided_by", String, nullable=True),
        Column("decided_at", DateTime(timezone=True), nullable=True),
        Column("created_at", DateTime(timezone=True), server_default=func.now()),
    )

    # NIP nabywcy zapamiętany przy klubie - po pierwszej zatwierdzonej fakturze
    # kolejne trafiają do klubu bez zgadywania po nazwie.
    nips = Table(
        "province_club_nips",
        metadata,
        Column("province", String, primary_key=True),
        Column("nip", String, primary_key=True),
        Column("club_id", String, nullable=False, index=True),
        Column("buyer_name", String, nullable=True),
        Column("confirmed_by", String, nullable=True),
        Column("confirmed_at", DateTime(timezone=True), server_default=func.now()),
    )
    Index("ix_province_invoice_items_prov_key", items.c.province, items.c.invoice_key)
    return batches, items, nips

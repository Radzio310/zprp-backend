"""
Tabela ról sędziów z listy ZPRP (25.09.2026) - sam schemat, bez połączenia z bazą.

  - `province_judge_zprp_roles`  role z kolumny „Sędzia / Delegat / Stolikowy"
                                 listy oficjeli baza.zprp.pl, zapisywane przy
                                 synchronizacji niedyspozycji
                                 (`province_offtime_sync.persist_zprp_roles`).

Klucz: okręg KANONICZNY + numer sędziego. Wiersze spod innej pisowni okręgu
(ŚLĄSKIE / SLASKIE) synchronizacja sprząta, a odczyt i tak wybiera jeden wpis
(`assignment_roles.pick_role_rows`).

JSON jako Text (nie JSONB): sterownik `databases` oddaje JSONB napisem, więc
każdy odczyt i tak musiałby go rozbierać.
"""

from sqlalchemy import Column, DateTime, String, Table, Text, func


def define_tables(metadata):
    roles = Table(
        "province_judge_zprp_roles",
        metadata,
        Column("province", String, primary_key=True),
        Column("judge_id", String, primary_key=True),
        Column("full_name", String, nullable=True),
        #: Lista ról ("sedzia", "delegat", "stolikowy") jako napis JSON.
        #: Pusta lista = ZPRP nie podał ról, czyli „nie wiemy".
        Column("roles", Text, nullable=False, default="[]"),
        #: Surowy opis z listy („Sędzia\nStolikowy") - do podglądu.
        Column("roles_text", Text, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    return (roles,)

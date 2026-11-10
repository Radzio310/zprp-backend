"""Historia osób założonych kreatorem nowych sędziów (09.11.2026) - sam schemat.

Jeden wiersz = jedna osoba założona na baza.zprp.pl z panelu okręgu BAZA_web.
Wspólna dla okręgu (decyzja właściciela): z niej kreator wybiera osoby do maila
do ZPRP z prośbą o konta do logowania. Trzymamy tylko to, co trafia do maila -
bez PESEL-u, adresu i telefonu.
"""

from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, Table, func


def define_tables(metadata):
    onboarding = Table(
        "province_referee_onboarding",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("province", String, nullable=False, index=True),
        #: NrSedzia z ZPRP; pusty, gdy zapis przeszedł, ale ZPRP nie pokazał numeru.
        Column("nr_sedzia", String, nullable=True),
        #: created | unconfirmed
        Column("status", String, nullable=False, server_default="created"),
        Column("first_name", String, nullable=False),
        Column("last_name", String, nullable=False),
        Column("gender", String, nullable=True),
        Column("birth_year", Integer, nullable=True),
        Column("city", String, nullable=True),
        Column("email", String, nullable=True),
        #: ["sedzia", "delegat", "stolikowy"]
        Column("roles", JSON, nullable=True),
        #: manual | import
        Column("source", String, nullable=True),
        Column("batch_id", String, nullable=True),
        Column("created_by", String, nullable=True),
        Column("created_at", DateTime, nullable=False, server_default=func.now()),
        Column("mailed_at", DateTime, nullable=True),
        Column("mailed_by", String, nullable=True),
    )
    #: Badge zamówione w kreatorze dla osoby z historii (10.11.2026). Osobna tabela,
    #: bo historia stoi już na produkcji - nowa tabela powstaje sama, bez migracji.
    badges = Table(
        "province_referee_onboarding_badges",
        metadata,
        Column("record_id", Integer, primary_key=True),
        #: Nazwy badge okręgu (jak w `badges.name`), bez „Młodzi".
        Column("badges", JSON, nullable=False),
        #: Dodać do rejestru Młodych (`young_referees`).
        Column("young", Boolean, nullable=False, server_default="false"),
        #: Kiedy nadano (NULL = czeka, np. osoba bez numeru NrSedzia).
        Column("applied_at", DateTime, nullable=True),
        #: Krótki opis wyniku dla historii („nadano", „Młodzi: brak uprawnień" …).
        Column("note", String, nullable=True),
        Column("updated_by", String, nullable=True),
        Column("updated_at", DateTime, nullable=False, server_default=func.now()),
    )
    return (onboarding, badges)

"""
Rejestr oficjalnych dokumentów rozliczeń okręgu (06.10.2026) - sam schemat,
bez połączenia z bazą. Reguła w `app/settlement_register_rules.py`, trasy
w `app/province_settlement_register.py`.

SKĄD TO SIĘ WZIĘŁO. Każde kliknięcie „Zestawienie" zużywało numer w księdze,
więc poprawiony dokument dostawał kolejny numer, a księgowa traciła ciągłość
(zgłoszenie Wojtka Kaszni). Teraz:
  - zwykłe kliknięcie robi SZKIC (znak wodny, bez numeru, nic nie zapisujemy),
  - przytrzymanie wydaje dokument OFICJALNY: numer podpowiada rejestr
    (ostatni oficjalny + 1), a człowiek może go przed wydaniem zmienić,
  - usunięcie z rejestru zwalnia numer i pozycje (sędziów i części ich puli).

  - `province_settlement_register` - jeden wydany dokument: numer ciągły
    w roku i rodzaju, okres, pozycje (sędzia + część puli) i pełny kontekst
    wydruku, z którego powstaje ponowne pobranie.
  - `province_settlement_register_settings` - „kontynuacja numeracji":
    ostatni numer wydany poza systemem w danym roku i rodzaju.

JSON jako Text (nie JSONB) - jak w `settlement_split_tables`.
"""

from sqlalchemy import Boolean, Column, Date, DateTime, Index, Integer, String, Table, Text, func, text


def define_tables(metadata):
    register = Table(
        "province_settlement_register",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        #: Klucz okręgu z `settlement_province.canonical` („SLASKIE").
        Column("province", String, nullable=False),
        #: „zestawienie" | „przejazdy" - każdy rodzaj ma własny licznik.
        Column("kind", String, nullable=False),
        #: Rok numeracji (rok miesiąca wypłaty) i numer kolejny w tym roku.
        Column("number_year", Integer, nullable=False),
        Column("seq", Integer, nullable=False),
        #: Pełny numer na papierze: „SL/10/2026/14".
        Column("number", String, nullable=False),
        #: Okres rozliczenia: miesiąc wypłaty i własny okres (pusty = miesiąc).
        Column("period_year", Integer, nullable=False),
        Column("period_month", Integer, nullable=False),
        Column("period_id", String, nullable=False, server_default=text("''")),
        Column("period_label", String, nullable=True),
        Column("date_from", Date, nullable=True),
        Column("date_to", Date, nullable=True),
        Column("include_future", Boolean, nullable=False, server_default=text("false")),
        Column("include_zprp", Boolean, nullable=False, server_default=text("false")),
        #: Pozycje: [{judge_id, name, part, part_of, gross, net, ...}] - `part`
        #: to litera części puli („A"), pusty napis = cała pula sędziego.
        Column("items_json", Text, nullable=False, server_default=text("'[]'")),
        #: Sumy dokumentu (brutto, netto, do wypłaty, kilometry...).
        Column("totals_json", Text, nullable=False, server_default=text("'{}'")),
        #: Kontekst szablonu w dniu wydania (bez logo) - ponowne pobranie
        #: drukuje dokładnie ten sam papier, choćby miesiąc się później zmienił.
        Column("context_json", Text, nullable=False, server_default=text("'{}'")),
        Column("created_by", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    Index(
        "ux_province_settlement_register_number",
        register.c.province,
        register.c.kind,
        register.c.number_year,
        register.c.seq,
        unique=True,
    )
    Index(
        "ix_province_settlement_register_period",
        register.c.province,
        register.c.kind,
        register.c.period_year,
        register.c.period_month,
        register.c.period_id,
    )

    settings = Table(
        "province_settlement_register_settings",
        metadata,
        Column("province", String, primary_key=True),
        Column("kind", String, primary_key=True),
        Column("number_year", Integer, primary_key=True),
        #: Ostatni numer wydany POZA systemem - rejestr podpowiada od następnego.
        Column("start_after", Integer, nullable=False, server_default=text("0")),
        Column("updated_by", String, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    return register, settings

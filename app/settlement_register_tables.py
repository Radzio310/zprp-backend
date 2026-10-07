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
    w sezonie i rodzaju, okres, pozycje (sędzia + część puli) i pełny kontekst
    wydruku, z którego powstaje ponowne pobranie.
  - `province_settlement_register_settings` - „kontynuacja numeracji":
    ostatni numer wydany poza systemem w danym sezonie i rodzaju.

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
        #: Sezon numeracji - ROK JEGO POCZĄTKU (2026 = 2026/27, decyzja
        #: z 07.10.2026) - i numer kolejny w sezonie. Nazwa kolumny z czasów
        #: numeracji rocznej; tabela jest już na produkcji.
        Column("number_year", Integer, nullable=False),
        Column("seq", Integer, nullable=False),
        #: Pełny numer na papierze: „SL/2026_27/14" albo „SLP/2026_27/3".
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
        #: Sezon (rok początku), jak `number_year` w rejestrze.
        Column("number_year", Integer, primary_key=True),
        #: Ostatni numer wydany POZA systemem - rejestr podpowiada od następnego.
        Column("start_after", Integer, nullable=False, server_default=text("0")),
        Column("updated_by", String, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    #: Wygląd dokumentów okręgu (07.10.2026): na razie jedno pole - czy na
    #: Zestawieniu i Przejazdach pokazywać liczbę meczów (domyślnie NIE).
    doc_settings = Table(
        "province_settlement_doc_settings",
        metadata,
        Column("province", String, primary_key=True),
        Column("show_matches", Boolean, nullable=False, server_default=text("false")),
        #: Wiersz „45 sędziów · wystawiono 07.10.2026" pod tytułem.
        Column("show_subtitle", Boolean, nullable=False, server_default=text("true")),
        #: Okres rozliczenia w nagłówku: all | main_only (tylko lista A
        #: i dokument bez list) | none.
        Column("period_display", String, nullable=False, server_default=text("'all'")),
        #: Lista, z której najpierw schodzi kara za nieobecność („A").
        Column("penalty_list", String, nullable=False, server_default=text("'A'")),
        #: Lista, na której stoi sekcja „Nieobecności z Rejestru" (domyślnie A).
        Column("absences_list", String, nullable=False, server_default=text("'A'")),
        Column("updated_by", String, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    return register, settings, doc_settings

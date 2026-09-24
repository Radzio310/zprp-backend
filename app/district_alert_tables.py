"""
Tabele powiadomień okręgu z Obsady (mecz bez obsady, kolizja po zmianie terminu).

Sam schemat - bez połączenia z bazą, żeby dało się go obejrzeć w teście.
Konfiguracja i treści leżą jako NAPIS JSON (`Text`), a nie JSONB: sterownik
`databases` oddaje JSONB napisem i każdy odczyt i tak musiałby go rozbierać.

Cztery tabele:
  - `province_district_alert_settings` - JEDNA konfiguracja na okręg (klucz
    kanoniczny, np. „SLASKIE"), wspólna dla wszystkich obsadowych,
  - `province_district_alert_marks`    - pamięć „już ogłoszone" (klucz
    deduplikacji: mecz + etap albo sędzia + mecz + rodzaj kolizji + termin),
  - `province_district_alert_outbox`   - dziennik wysyłek: pushe czekające na
    koniec ciszy nocnej, wysłane pushe i maile (ekran pokazuje ostatnie wpisy),
  - `province_district_alert_times`    - ostatni znany termin meczu, po którym
    rozpoznajemy „termin się zmienił" niezależnie od monitora.
"""

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Table, Text, func


def define_tables(metadata):
    settings = Table(
        "province_district_alert_settings",
        metadata,
        #: Klucz kanoniczny okręgu (`settlement_province.canonical`).
        Column("province", String, primary_key=True),
        #: Cała konfiguracja obu alertów i ciszy nocnej - patrz
        #: `district_alert_rules.default_config`.
        Column("config", Text, nullable=False, default="{}"),
        Column("enabled", Boolean, nullable=False, default=False),
        Column("updated_by", String, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("last_check_at", DateTime(timezone=True), nullable=True),
        Column("last_sent_at", DateTime(timezone=True), nullable=True),
        Column("last_status", Text, nullable=True),
        Column("last_error", Text, nullable=True),
    )
    marks = Table(
        "province_district_alert_marks",
        metadata,
        Column("province", String, primary_key=True),
        Column("dedupe_key", String, primary_key=True),
        #: "unassigned" albo "collision".
        Column("alert", String, nullable=False),
        Column("match_id", String, nullable=True, index=True),
        Column("judge_id", String, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    outbox = Table(
        "province_district_alert_outbox",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("province", String, nullable=False),
        Column("alert", String, nullable=False),
        #: "push" albo "email".
        Column("channel", String, nullable=False),
        #: "judge" (sędzia z kolizją) albo "manager" (obsadowi i lista adresów).
        Column("audience", String, nullable=False),
        Column("match_id", String, nullable=True),
        #: Numery sędziów (push) albo adresy (mail) - lista JSON.
        Column("recipients", Text, nullable=False, default="[]"),
        Column("title", Text, nullable=False, default=""),
        Column("body", Text, nullable=False, default=""),
        #: Ładunek pusha (JSON) - dokąd prowadzi dotknięcie.
        Column("data", Text, nullable=False, default="{}"),
        #: Kiedy wolno wysłać (cisza nocna przesuwa na rano).
        Column("due_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        #: queued | sent | failed | cancelled
        Column("status", String, nullable=False, default="queued"),
        Column("detail", Text, nullable=True),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("sent_at", DateTime(timezone=True), nullable=True),
        Index("ix_district_alert_outbox_due", "status", "due_at"),
        Index("ix_district_alert_outbox_province", "province", "id"),
    )
    times = Table(
        "province_district_alert_times",
        metadata,
        Column("province", String, primary_key=True),
        Column("match_id", String, primary_key=True),
        #: Ostatni znany termin (prawdziwy UTC, jak `province_matches.match_at`).
        Column("match_at", DateTime(timezone=True), nullable=True),
        Column("seen_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    return settings, marks, outbox, times

"""
Tabele alertów mailowych o saldzie klubów (Rozliczenia BAZA_web).

Sam schemat - bez połączenia z bazą, żeby dało się go obejrzeć w teście.
Lista adresów leży jako NAPIS JSON (`Text`), a nie JSONB: sterownik `databases`
oddaje JSONB napisem i każdy odczyt i tak musiałby go rozbierać.
"""

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Table, Text, func


def define_tables(metadata):
    settings = Table(
        "province_alert_settings",
        metadata,
        #: Login VIP albo „judge:<numer>" - patrz `province_alert_rules.account_key`.
        Column("account_key", String, primary_key=True),
        Column("province", String, primary_key=True),
        #: Z tokenu przy zapisie - pętla sprawdza nimi, czy konto NADAL ma
        #: uprawnienie do Rozliczeń, zanim cokolwiek wyśle.
        Column("account_type", String, nullable=True),
        Column("login", String, nullable=True),
        Column("judge_id", String, nullable=True),
        Column("display_name", String, nullable=True),
        Column("enabled", Boolean, nullable=False, default=False),
        Column("threshold", Float, nullable=False, default=500.0),
        Column("interval_hours", Integer, nullable=False, default=24),
        Column("emails", Text, nullable=False, default="[]"),
        Column("last_check_at", DateTime(timezone=True), nullable=True),
        Column("last_sent_at", DateTime(timezone=True), nullable=True),
        #: Krótki opis ostatniego sprawdzenia dla ekranu ustawień.
        Column("last_status", Text, nullable=True),
        Column("last_error", Text, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    state = Table(
        "province_alert_state",
        metadata,
        Column("account_key", String, primary_key=True),
        Column("province", String, primary_key=True),
        #: Główny `club_id` budżetu.
        Column("budget_id", String, primary_key=True),
        Column("alerted_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("balance", Float, nullable=True),
        Column("threshold", Float, nullable=True),
    )
    return settings, state

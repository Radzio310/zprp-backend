"""
SMS z wynikiem meczu - konfiguracja i okręgi meczów (08.10.2026). Sam schemat.

Reguła w `app/sms_config_rules.py`, trasy w `app/sms_config.py`.

  - `sms_config` - jeden wiersz na zakres: `central` (mecze centralne, numer
    z ustaleń rozgrywek) albo slug okręgu („DOLNOSLASKIE"). Grupy (nazwa,
    kategorie, numer) jako JSON w tekście - jak w `settlement_split_tables`.
  - `match_province_cache` - okręg PROWADZĄCY mecz (`NazwaWZPR` z publicznego
    API rozgrywek) po numerze meczu ZPRP. Numer meczu nie zmienia związku, więc
    raz ustalony okręg trzymamy na stałe; pusty wynik (API milczało) ponawiamy.
"""

from sqlalchemy import Boolean, Column, DateTime, String, Table, Text, func, text


def define_tables(metadata):
    config = Table(
        "sms_config",
        metadata,
        #: „central" albo slug okręgu z `normalize_province`.
        Column("scope", String, primary_key=True),
        Column("enabled", Boolean, nullable=False, server_default=text("false")),
        #: Szablon treści: „central" (jak SMS z meczów centralnych, z ustawieniami
        #: treści sędziego) albo „pair" (para sędziowska, jak dotąd Dolny Śląsk).
        Column("template", String, nullable=False, server_default=text("'central'")),
        #: [{"name": "...", "categories": ["IIIM", ...], "phone": "602120659"}]
        Column("groups_json", Text, nullable=False, server_default=text("'[]'")),
        Column("updated_by", String, nullable=True),
        Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    provinces = Table(
        "match_province_cache",
        metadata,
        Column("match_id", String, primary_key=True),
        #: Slug okręgu prowadzącego albo pusty napis (rozgrywki centralne / brak danych).
        Column("province", String, nullable=False, server_default=text("''")),
        Column("checked_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    )
    return config, provinces

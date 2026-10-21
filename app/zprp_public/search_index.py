"""Indeksy wyszukiwarki publicznej (pg_trgm + numer meczu). Najlepsze starania, w tle.

Duże tabele (archiwum sezonów) budują się długo, więc to idzie w osobnym wątku po
imporcie bazy, a każda instrukcja ma własne połączenie: niepowodzenie jednej (brak
uprawnień do rozszerzenia) nie psuje reszty ani startu aplikacji.
"""

from __future__ import annotations

import logging
import threading

from sqlalchemy import text

log = logging.getLogger(__name__)

STATEMENTS = (
    "CREATE EXTENSION IF NOT EXISTS pg_trgm",
    # Numer meczu: prefiks bez wielkości liter i spacji.
    "CREATE INDEX IF NOT EXISTS ix_zpm_code_fold ON zprp_public_matches "
    "(lower(replace(match_code, ' ', '')) text_pattern_ops)",
    "CREATE INDEX IF NOT EXISTS ix_zpm_home_trgm ON zprp_public_matches USING gin (home_team_name gin_trgm_ops)",
    "CREATE INDEX IF NOT EXISTS ix_zpm_away_trgm ON zprp_public_matches USING gin (away_team_name gin_trgm_ops)",
    "CREATE INDEX IF NOT EXISTS ix_zpc_name_trgm ON zprp_public_clubs USING gin (name gin_trgm_ops)",
    "CREATE INDEX IF NOT EXISTS ix_zpt_name_trgm ON zprp_public_teams USING gin (name gin_trgm_ops)",
    "CREATE INDEX IF NOT EXISTS ix_zpcomp_name_trgm ON zprp_public_competitions USING gin (name gin_trgm_ops)",
    "CREATE INDEX IF NOT EXISTS ix_zpcomp_code_trgm ON zprp_public_competitions USING gin (code gin_trgm_ops)",
    "CREATE INDEX IF NOT EXISTS ix_zpp_first_trgm ON zprp_public_players USING gin (first_name gin_trgm_ops)",
    "CREATE INDEX IF NOT EXISTS ix_zpp_last_trgm ON zprp_public_players USING gin (last_name gin_trgm_ops)",
)


def ensure(engine) -> None:
    if engine.dialect.name != "postgresql":
        return
    for sql in STATEMENTS:
        try:
            with engine.begin() as conn:
                conn.execute(text(sql))
        except Exception as exc:  # noqa: BLE001
            log.warning("Indeks wyszukiwarki pominięty (%s): %s", sql[:60], exc)


def ensure_in_background(engine) -> None:
    threading.Thread(target=ensure, args=(engine,), name="search-indexes", daemon=True).start()

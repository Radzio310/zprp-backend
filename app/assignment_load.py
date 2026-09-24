"""
Obciążenie sędziów w sezonie i w miesiącach - baza dla równego podziału
Automatu, kandydatów na mecz i `load_by_month` w zakładce Sędziowie.

Reguła liczenia siedzi w liściu `judge_season_load` (kubełki, sezon, czas
polski, przykrycie rejestru świeżym terminarzem); tu tylko dwa zapytania.

⚠ `app.db` łączy się z bazą przy imporcie - importy bazy wchodzą do funkcji.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from app import assignment_rules as A
from app import judge_season_load as L
from app.settlement_province import canonical, spellings

logger = logging.getLogger(__name__)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


@dataclass
class SeasonBook:
    """Rejestr obsad sezonu i terminarz okręgu - gotowe do liczenia w pamięci."""

    register: list[dict] = field(default_factory=list)
    #: numer meczu -> {match_at, match_code, crew: {gniazdo: numer}}
    matches: dict[str, dict] = field(default_factory=dict)

    def counts(self, *, now: datetime | None = None, pending: Iterable[Any] = ()):
        """(sezon, miesiące) po numerze sędziego - z kolejką naniesioną na terminarz."""
        return L.counts_for_auto(
            self.register, self.matches, now=now or datetime.now(timezone.utc), pending=pending
        )

    def by_month(self, *, now: datetime | None = None) -> dict[str, dict[str, dict[str, int]]]:
        moment = now or datetime.now(timezone.utc)
        return L.tally_by_month(L.merged_rows(self.register, self.matches), now=moment)


async def load_season_book(province: str) -> SeasonBook:
    """
    Jedno pobranie na okręg: wiersze rejestru rozliczeń bieżącego sezonu
    i obsady z terminarza (`province_matches`) z tego samego okresu.

    Awaria rejestru nie zatrzymuje liczenia - zostaje sam terminarz, a ślad
    idzie do logu.
    """
    from sqlalchemy import and_, select

    from app.db import database, province_matches, province_settlement_matches
    from app.match_market_rules import state_dict
    from app.season_rules import season_start_year

    key = canonical(province) or _s(province).upper()
    now = datetime.now(timezone.utc)
    start_year = season_start_year(now) or now.year
    # Sezon z zapasem doby na granicach - dokładny podział robi `season_of`.
    since = datetime(start_year, 8, 1, tzinfo=timezone.utc) - timedelta(days=1)
    until = datetime(start_year + 1, 8, 1, tzinfo=timezone.utc) + timedelta(days=1)

    book = SeasonBook()
    try:
        rows = await database.fetch_all(
            select(
                province_settlement_matches.c.judge_id,
                province_settlement_matches.c.match_key,
                province_settlement_matches.c.match_at,
                province_settlement_matches.c.match_code,
                province_settlement_matches.c.role,
            ).where(
                and_(
                    province_settlement_matches.c.province == key,
                    province_settlement_matches.c.active.is_(True),
                    province_settlement_matches.c.match_at >= since,
                    province_settlement_matches.c.match_at < until,
                )
            )
        )
        book.register = [dict(row) for row in rows]
    except Exception:  # noqa: BLE001 - bez rejestru liczy sam terminarz
        logger.exception("[obciążenie] %s: rejestr rozliczeń", key)

    matches = await database.fetch_all(
        select(
            province_matches.c.match_id,
            province_matches.c.match_code,
            province_matches.c.match_at,
            province_matches.c.state_json,
        ).where(
            and_(
                province_matches.c.province.in_(spellings(key) or [key]),
                province_matches.c.active.is_(True),
                province_matches.c.match_at >= since,
                province_matches.c.match_at < until,
            )
        )
    )
    for row in matches:
        state = state_dict(row["state_json"]) or {}
        match_id = _s(row["match_id"])
        if not match_id:
            continue
        crew = {}
        for slot in A.FIELD_SLOTS + A.TABLE_SLOTS:
            person = A.slot_person(state, slot)
            crew[slot] = _s((person or {}).get("number"))
        book.matches[match_id] = {
            "match_at": row["match_at"],
            "match_code": _s(state.get("RozgrywkiCode") or row["match_code"]),
            "crew": crew,
        }
    return book

"""Wzbogacanie kart meczów o pola kontraktu rundy 3 (jedno wspólne miejsce).

Używane przez `api.py` (listy, szczegóły, overview) i `portal.py` (karty).
Sezony i kody rozgrywek to małe tabele - krótki cache nie obciąża bazy.
"""

from __future__ import annotations

import time
from typing import Any, Iterable

from sqlalchemy import select

from app.db import database, zprp_public_competitions, zprp_public_seasons
from app.zprp_public import match_rules as MR

_SEASONS_TTL = 300.0
_seasons_cache: dict[str, Any] = {"at": 0.0, "seasons": {}, "current": None}


async def seasons_info() -> tuple[dict[str, dict], str | None]:
    if time.monotonic() - _seasons_cache["at"] < _SEASONS_TTL and _seasons_cache["seasons"]:
        return _seasons_cache["seasons"], _seasons_cache["current"]
    rows = await database.fetch_all(
        select(zprp_public_seasons.c.season_id, zprp_public_seasons.c.name,
               zprp_public_seasons.c.start_year, zprp_public_seasons.c.active)
    )
    seasons = {r["season_id"]: dict(r) for r in rows}
    current = MR.current_season_id(seasons.values())
    _seasons_cache.update(at=time.monotonic(), seasons=seasons, current=current)
    return seasons, current


def invalidate() -> None:
    _seasons_cache["at"] = 0.0


async def enrich_matches(items: Iterable[dict[str, Any]]) -> None:
    """Dokłada winner_side, decided_by, match_code_full, season_name, is_current_season."""
    items = [i for i in items if isinstance(i, dict)]
    if not items:
        return
    seasons, current = await seasons_info()
    comp_ids = {i.get("competition_id") for i in items if i.get("competition_id") and "/" not in str(i.get("match_code") or "/")}
    codes: dict[str, str] = {}
    if comp_ids:
        rows = await database.fetch_all(
            select(zprp_public_competitions.c.competition_id, zprp_public_competitions.c.code)
            .where(zprp_public_competitions.c.competition_id.in_(list(comp_ids)))
        )
        codes = {r["competition_id"]: r["code"] for r in rows if r["code"]}
    for item in items:
        MR.apply_match_extras(item, seasons, current, codes)

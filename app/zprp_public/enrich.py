"""Wzbogacanie kart meczów o pola kontraktu rundy 3 (jedno wspólne miejsce).

Używane przez `api.py` (listy, szczegóły, overview) i `portal.py` (karty).
Sezony i kody rozgrywek to małe tabele - krótki cache nie obciąża bazy.
"""

from __future__ import annotations

import time
from typing import Any, Iterable

from sqlalchemy import and_, or_, select

from app.db import database, zprp_public_competitions, zprp_public_matches, zprp_public_seasons
from app.zprp_public import match_rules as MR
from app.zprp_public.proel_cards import apply_proel_fallback, invalidate as invalidate_proel

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
    invalidate_proel()


async def enrich_matches(items: Iterable[dict[str, Any]]) -> None:
    """Dokłada winner_side, decided_by, match_code_full, season_name, is_current_season
    oraz competition_category / competition_gender (H2H tylko w tej samej kategorii).

    Najpierw zapas z ProEla (godzina meczu bez godziny w ZPRP, wynik zakończonego
    protokołu, którego ZPRP jeszcze nie ma: `score_source`/`kickoff_source`/
    `result_pending`), potem zwycięzca - liczony już z wyniku po zapasie."""
    items = [i for i in items if isinstance(i, dict)]
    if not items:
        return
    await apply_proel_fallback(items)
    seasons, current = await seasons_info()
    comp_ids = {i.get("competition_id") for i in items if i.get("competition_id")}
    need_code = {i.get("competition_id") for i in items if i.get("competition_id") and "/" not in str(i.get("match_code") or "/")}
    codes: dict[str, str] = {}
    kinds: dict[str, tuple[Any, Any]] = {}
    if comp_ids:
        C = zprp_public_competitions
        rows = await database.fetch_all(
            select(C.c.competition_id, C.c.code, C.c.category, C.c.gender).where(C.c.competition_id.in_(list(comp_ids)))
        )
        codes = {r["competition_id"]: r["code"] for r in rows if r["code"] and r["competition_id"] in need_code}
        kinds = {r["competition_id"]: (r["category"], r["gender"]) for r in rows}
    for item in items:
        MR.apply_match_extras(item, seasons, current, codes)
        category, gender = kinds.get(item.get("competition_id"), (None, None))
        item.setdefault("competition_category", category)
        item.setdefault("competition_gender", gender)


async def attach_standing_records(rows: list[dict[str, Any]]) -> None:
    """Dokłada do wierszy tabeli `record` {w, wk, lk, l, source} (Z/Zk/Pk/P).

    Wiersze mogą mieć `extra_json` (surowy wiersz pokaz_tabela.php) - po
    odczytaniu kolumn karnych jest usuwany z odpowiedzi. Mecze drużyn w tych
    rozgrywkach (jedno zapytanie na całą listę) rozstrzygają, ile „Remisów"
    ZPRP to zwycięstwa, a ile porażki po rzutach karnych.
    """
    rows = [r for r in rows if isinstance(r, dict)]
    comps = sorted({str(r["competition_id"]) for r in rows if r.get("competition_id")})
    teams = sorted({str(r["team_id"]) for r in rows if r.get("team_id")})
    counted: dict[str, dict[str, dict]] = {}
    if comps and teams:
        M = zprp_public_matches
        found = await database.fetch_all(
            select(M.c.competition_id, M.c.home_team_id, M.c.away_team_id, M.c.score_home, M.c.score_away,
                   M.c.shootout_home, M.c.shootout_away, M.c.winner, M.c.walkover_team_id, M.c.withdrawn)
            .where(and_(M.c.competition_id.in_(comps), M.c.score_home.is_not(None), M.c.score_away.is_not(None),
                        or_(M.c.home_team_id.in_(teams), M.c.away_team_id.in_(teams))))
        )
        by_comp: dict[str, list[dict]] = {}
        for m in found:
            by_comp.setdefault(m["competition_id"], []).append(dict(m))
        counted = {cid: MR.count_team_results(ms) for cid, ms in by_comp.items()}
    for r in rows:
        mine = (counted.get(str(r.get("competition_id") or "")) or {}).get(str(r.get("team_id") or ""))
        r["record"] = MR.standing_record(r, mine)
        r.pop("extra_json", None)

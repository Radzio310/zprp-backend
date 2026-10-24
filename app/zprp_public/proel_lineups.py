"""Zapasowy skład z ProEla dla `GET /matches/{id}/overview` - odczyt z bazy.

Reguły i zasady prywatności: `proel_lineup_rules`. Tu tylko zapytania:
protokół meczu (`proel_matches` + `proel_match_state`), publiczne składy,
kadry i osoby towarzyszące tej samej drużyny w sezonie. Nigdy nie rzuca -
skład zapasowy jest dodatkiem i nie ma prawa wywrócić strony meczu.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, or_, select

from app.zprp_public import match_rules as MR
from app.zprp_public import proel_lineup_rules as PL
from app.zprp_public import proel_live_rules as L

log = logging.getLogger(__name__)

_RANK = {"approved": 3, "finished": 2, "in_progress": 1}


def _row(r: Any) -> Dict[str, Any]:
    return dict(r._mapping) if hasattr(r, "_mapping") else dict(r)


def pick(rows: List[Dict[str, Any]], match_id: str) -> Optional[Dict[str, Any]]:
    """Zatwierdzony > zakończony > w toku (tylko po starcie LIVE); dokładne id ZPRP przed samym numerem."""
    good = [r for r in rows
            if (not r.get("zprp_match_id") or str(r["zprp_match_id"]) == str(match_id))
            and ((r.get("status") in ("finished", "approved")) or r.get("live_started_at") is not None)]
    good.sort(key=lambda r: (_RANK.get(r.get("status") or "in_progress", 0),
                             str(r.get("zprp_match_id") or "") == str(match_id),
                             str(r.get("doc_at") or "")), reverse=True)
    return good[0] if good else None


def _blob(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


async def load_protocol(match: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Publiczny protokół meczu z ProEla: {row, blob, host_home} albo None."""
    from app.db import database, proel_match_state as S, saved_matches as T
    from app.proel_training_key import TRAINING_KEY_LIKE

    match_id = str(match.get("match_id") or "")
    code = str(match.get("match_code") or "").strip()
    cond = [T.c.zprp_match_id == match_id]
    if code:
        cond.append(T.c.match_number == code)
    rows = await database.fetch_all(
        select(T.c.match_number, T.c.zprp_match_id, T.c.status, T.c.updated_at.label("doc_at"), S.c.live_started_at)
        .select_from(T.outerjoin(S, S.c.match_number == T.c.match_number))
        .where(or_(*cond)).where(~T.c.match_number.ilike(TRAINING_KEY_LIKE))
    )
    row = pick([_row(r) for r in rows], match_id)
    if not row:
        return None
    got = await database.fetch_one(select(T.c.data_json).where(T.c.match_number == row["match_number"]))
    blob = _blob(_row(got).get("data_json") if got else None)
    if not L.is_public_blob(blob) or not isinstance(blob.get("matchConfig"), dict):
        return None
    host_home = L.host_is_home(blob["matchConfig"], match.get("home_team_name"), match.get("away_team_name"))
    return {"row": row, "blob": blob, "host_home": host_home}


async def _team_public(team_id: str, season_id: Optional[str], match_id: str) -> Dict[str, Any]:
    """Publiczne dane drużyny: występy z numerami, kadra, osoby towarzyszące."""
    from app.db import (database, zprp_public_match_players as MP, zprp_public_match_staff as MS,
                        zprp_public_matches as M, zprp_public_team_rosters as R)

    season_cond = [M.c.season_id == season_id] if season_id else []
    apps = await database.fetch_all(
        select(MP.c.player_id, MP.c.shirt_number, MP.c.position, M.c.scheduled_at.label("at"))
        .select_from(MP.join(M, M.c.match_id == MP.c.match_id))
        .where(and_(MP.c.team_id == team_id, MP.c.match_id != match_id, *season_cond))
    )
    roster_cond = [R.c.season_id == season_id] if season_id else []
    roster = await database.fetch_all(
        select(R.c.player_id, R.c.shirt_number).where(and_(R.c.team_id == team_id, R.c.active.is_(True), *roster_cond))
    )
    staff = await database.fetch_all(
        select(MS.c.team_id, MS.c.person_id, MS.c.side, MS.c.first_name, MS.c.last_name, MS.c.role, MS.c.function,
               MS.c.source_json, M.c.scheduled_at.label("at"))
        .select_from(MS.join(M, M.c.match_id == MS.c.match_id))
        .where(and_(MS.c.team_id == team_id, MS.c.match_id != match_id, *season_cond))
        .order_by(M.c.scheduled_at.desc()).limit(200)
    )
    return {
        "apps": [_row(r) for r in apps],
        "roster": [_row(r) for r in roster],
        "staff": [MR.staff_view(_row(r)) for r in staff],
    }


async def _players_by_id(ids: List[str]) -> Dict[str, Dict[str, Any]]:
    from app.db import database, zprp_public_players as P

    ids = sorted({i for i in ids if i})
    if not ids:
        return {}
    rows = await database.fetch_all(select(P).where(P.c.player_id.in_(ids)))
    return {str(r["player_id"]): {k: _row(r).get(k) for k in PL.PUBLIC_PLAYER_KEYS} for r in rows}


async def build_fallback(match: Dict[str, Any], protocol: Dict[str, Any]) -> Dict[str, Any]:
    """-> {"lineups": {home, away}, "staff": [...], "score": {...}|None, "status": ...}."""
    blob, host_home, row = protocol["blob"], protocol["host_home"], protocol["row"]
    stats = PL.protocol_stats(blob, host_home)
    roster = PL.proel_roster(blob, host_home)
    lineups: Dict[str, List[Dict[str, Any]]] = {"home": [], "away": []}
    staff: List[Dict[str, Any]] = []
    for side in PL.SIDES:
        team_id = str(match.get(f"{side}_team_id") or "") or None
        pub = await _team_public(team_id, match.get("season_id"), str(match.get("match_id"))) if team_id else {"apps": [], "roster": [], "staff": []}
        by_number = PL.number_index(pub["apps"], pub["roster"])
        team_ids = {str(a["player_id"]) for a in pub["apps"] + pub["roster"] if a.get("player_id")}
        card_ids = {str(e["zprp_id"]) for e in roster[side]["players"] if e.get("zprp_id")}
        card_ids |= {str(e["zprp_id"]) for e in (roster[side].get("struck") or {}).values() if e.get("zprp_id")}
        public = await _players_by_id(sorted(team_ids | card_ids))
        team_pool = [public[i] for i in team_ids if i in public]
        positions: Dict[str, str] = {}
        for a in sorted(pub["apps"], key=lambda a: str(a.get("at") or "")):
            if a.get("position"):
                positions[str(a["player_id"])] = a["position"]
        lineups[side] = PL.build_players(roster[side]["players"], stats[side]["players"], side, team_id, public,
                                         by_number, team_pool, positions, roster[side].get("struck"))
        staff.extend(PL.build_staff(roster[side]["staff"], stats[side]["staff"], side, team_id,
                                    PL.staff_index(pub["staff"])))
    return {
        "lineups": lineups,
        "staff": staff,
        "score": PL.final_score(blob, host_home, row.get("status")),
        "status": row.get("status"),
        "updated_at": row.get("doc_at"),
    }


async def fallback_for(match: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Skład zapasowy albo None (brak protokołu, protokół testowy, błąd). Nigdy nie rzuca."""
    try:
        protocol = await load_protocol(match)
        if not protocol:
            return None
        return await build_fallback(match, protocol)
    except Exception:
        log.debug("[zprp_public] skład z ProEla %s", match.get("match_id"), exc_info=True)
        return None

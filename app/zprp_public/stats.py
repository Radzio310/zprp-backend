"""Ekran „Statystyki" portalu BAZA pod Ręką - baza, pamięć podręczna, pętla w tle.

Kontrakt: `docs/stats.md`. Trasy (`/api/v1/handball/stats/...`, publiczne):
`filters`, `today`, `season`, `geo`, `trends`, `proel`.

Koszt pod kontrolą:
* migawka sezonu (`stats_rules.Frame`): kilka zapytań z GROUP BY (sumy zawodników
  na drużynę i rozgrywki, wielkie występy) + zwarte mecze sezonu; budowa w wątku,
  w tle co 15 min dla bieżącego sezonu, inne sezony na żądanie (stara migawka jest
  podawana dalej, a nowa liczy się w tle - nikt nie czeka),
* odpowiedzi sekcji w pamięci 10 min pod kluczem zakresu i chwili migawki,
* „Dziś" - świeże zapytanie o mecze doby co 20 s (wspólne dla wszystkich zakresów),
  bloby ProEla czytane tylko po zmianie zapisu,
* streszczenia protokołów ProEl trwale w `zprp_public_stats_snapshots`.
Prywatność: z ProEla wyłącznie zdarzenia sportowe; zawodnicy tylko z publicznych
tabel ZPRP (numer -> zawodnik regułą `proel_lineup_rules`, nazwiska z kart ProEl
służą tylko do sprawdzenia i nigdy nie wychodzą).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Query
from sqlalchemy import and_, func, or_, select

from app import time_pl as TP
from app.db import (
    database,
    proel_match_state as S,
    saved_matches as T,
    zprp_public_associations,
    zprp_public_clubs,
    zprp_public_competitions,
    zprp_public_match_players as MP,
    zprp_public_matches as M,
    zprp_public_players,
    zprp_public_seasons,
    zprp_public_team_rosters,
)
from app.proel_training_key import TRAINING_KEY_LIKE
from app.zprp_public import corrections
from app.zprp_public import proel_card_rules as PCR
from app.zprp_public import proel_lineup_rules as PL
from app.zprp_public import proel_live_rules as L
from app.zprp_public import stats_proel_rules as P
from app.zprp_public import stats_rules as R
from app.zprp_public import stats_today_rules as TD
from app.zprp_public.enrich import seasons_info
from app.zprp_public.portal import _card_cols, _cards

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/handball/stats", tags=["handball_stats"])

FRAME_TTL = 900.0
RESP_TTL = 600.0
FILTERS_TTL = 900.0
TODAY_TTL = 25
TODAY_BASE_TTL = 20.0
TEAM_TTL = 600.0
LOOP_INTERVAL = float(os.getenv("STATS_INTERVAL_SECONDS", "900"))
START_DELAY = float(os.getenv("STATS_START_DELAY_SECONDS", "90"))
FRAMES_MAX = 2
RESP_MAX = 400
BIG_GOALS = 9
BIG_SEVENS = 4
PROEL_BATCH = 20
PROEL_PER_CYCLE = int(os.getenv("STATS_PROEL_PER_CYCLE", "600"))
PROEL_ON_DEMAND = 60
TICKER_WINDOW = timedelta(minutes=90)

_frames: Dict[str, Tuple[float, R.Frame]] = {}
_frame_locks: Dict[str, asyncio.Lock] = {}
_refreshing: set = set()
_resp: Dict[str, Tuple[float, Any]] = {}
_resp_locks: Dict[str, asyncio.Lock] = {}
_proel_mem: Dict[str, Dict[str, Any]] = {}
_proel_state: Dict[str, Any] = {"loaded": False, "lock": None}
_today: Dict[str, Any] = {"at": 0.0, "base": None, "lock": None}
_derived: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
_team_cache: Dict[Tuple[str, str], Tuple[float, Dict[str, Any]]] = {}


def _row(r: Any) -> Dict[str, Any]:
    return dict(r._mapping) if hasattr(r, "_mapping") else dict(r)


def _aware(dt: Any) -> Optional[datetime]:
    if isinstance(dt, str) and dt.strip():
        try:
            dt = datetime.fromisoformat(dt.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(dt, datetime):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _iso(dt: Any) -> Optional[str]:
    if isinstance(dt, datetime):
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()
    return str(dt) if dt else None


def _blob(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


def _snapshots_table():
    # Przez sys.modules: test podmienia `app.db`, a stara tabela nie może wyciec z innego modułu.
    db = sys.modules.get("app.db")
    return getattr(db, "__dict__", {}).get("zprp_public_stats_snapshots")


def clear_cache() -> None:
    _frames.clear()
    _resp.clear()
    _proel_mem.clear()
    _proel_state["loaded"] = False
    _today.update(at=0.0, base=None)
    _derived.clear()
    _team_cache.clear()


async def _cached(key: str, ttl: float, factory: Callable[[], Awaitable[Any]]) -> Any:
    """Odpowiedź w pamięci; równoległe pierwsze żądania czekają na jedno liczenie."""
    hit = _resp.get(key)
    if hit and time.monotonic() - hit[0] < ttl:
        return hit[1]
    lock = _resp_locks.setdefault(key, asyncio.Lock())
    async with lock:
        hit = _resp.get(key)
        if hit and time.monotonic() - hit[0] < ttl:
            return hit[1]
        value = await factory()
        if len(_resp) >= RESP_MAX:
            _resp.clear()
            _resp_locks.clear()
        _resp[key] = (time.monotonic(), value)
    return value


# ---------------------------------------------------------------------------
# Streszczenia protokołów ProEl
# ---------------------------------------------------------------------------


async def _load_persisted() -> None:
    table = _snapshots_table()
    if table is None:
        return
    try:
        rows = await database.fetch_all(select(table.c.key, table.c.source_at, table.c.value_json).where(table.c.kind == "proel"))
    except Exception:  # noqa: BLE001 - trwała pamięć jest dodatkiem
        log.debug("[stats] brak trwałych streszczeń ProEl", exc_info=True)
        return
    for r in rows:
        d = _row(r)
        value = _blob(d.get("value_json"))
        number = str(d["key"]).split(":", 1)[-1]
        if value.get("v") == P.VERSION:
            _proel_mem[number] = {**value, "doc_at": d.get("source_at")}


async def _persist(number: str, doc_at: str, value: Dict[str, Any]) -> None:
    table = _snapshots_table()
    if table is None:
        return
    from app.zprp_public.store import upsert_values

    try:
        await upsert_values(table, {"key": f"proel:{number}", "kind": "proel", "source_at": doc_at, "value_json": value,
                                    "built_at": datetime.now(timezone.utc)}, key_columns=("key",))
    except Exception:  # noqa: BLE001
        log.debug("[stats] zapis streszczenia %s pominięty", number, exc_info=True)


def _summarize_batch(rows: List[Any], meta: Dict[str, Dict[str, Any]]) -> List[Tuple[str, str, Dict[str, Any]]]:
    out = []
    for r in rows:
        d = _row(r)
        number = str(d["match_number"])
        info = meta.get(number) or {}
        try:
            summary = P.protocol_summary(_blob(d.get("data_json")), {**info, "match_number": number})
        except Exception:  # noqa: BLE001 - zepsuty blob = brak streszczenia
            summary = None
        out.append((number, info.get("doc_at") or "", summary or {"v": P.VERSION, "skip": True}))
    return out


async def refresh_proel(max_blobs: int = PROEL_PER_CYCLE) -> int:
    """Dociąga streszczenia nowych/zmienionych protokołów. Zwraca liczbę przeczytanych blobów."""
    if _proel_state["lock"] is None:
        _proel_state["lock"] = asyncio.Lock()
    async with _proel_state["lock"]:
        if not _proel_state["loaded"]:
            await _load_persisted()
            _proel_state["loaded"] = True
        rows = await database.fetch_all(
            select(T.c.match_number, T.c.zprp_match_id, T.c.status, T.c.updated_at)
            .where(T.c.status.in_(P.FINISHED)).where(~T.c.match_number.ilike(TRAINING_KEY_LIKE))
        )
        meta: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            d = _row(r)
            meta[str(d["match_number"])] = {"zprp_match_id": d.get("zprp_match_id"), "status": d.get("status"),
                                            "doc_at": _iso(d.get("updated_at"))}
        for gone in [k for k in _proel_mem if k not in meta]:
            _proel_mem.pop(gone, None)
        todo = [n for n, info in meta.items() if (_proel_mem.get(n) or {}).get("doc_at") != info["doc_at"]][:max_blobs]
        for i in range(0, len(todo), PROEL_BATCH):
            chunk = todo[i:i + PROEL_BATCH]
            got = await database.fetch_all(select(T.c.match_number, T.c.data_json).where(T.c.match_number.in_(chunk)))
            for number, doc_at, value in await asyncio.to_thread(_summarize_batch, list(got), meta):
                _proel_mem[number] = {**value, "doc_at": doc_at}
                await _persist(number, doc_at, value)
        return len(todo)


def _proel_values() -> List[Dict[str, Any]]:
    return [v for v in _proel_mem.values() if not v.get("skip")]


# ---------------------------------------------------------------------------
# Migawka sezonu
# ---------------------------------------------------------------------------


async def current_season() -> Optional[str]:
    return (await seasons_info())[1]


async def _resolve(season_id: str) -> Optional[str]:
    return season_id.strip() or await current_season()


def _frame_from_rows(season, comps, assocs, clubs, matches, players, big, lineup) -> R.Frame:
    frame = R.build_frame(
        _row(season) if season else {"season_id": None},
        [_row(r) for r in comps], [_row(r) for r in assocs], clubs, [_row(r) for r in matches],
        [_row(r) for r in players], [_row(r) for r in big], [_row(r)["match_id"] for r in lineup],
    )
    frame.proel = P.link(_proel_values(), frame)
    return frame


async def _build_frame(season_id: Optional[str]) -> R.Frame:
    started = time.monotonic()
    C = zprp_public_competitions
    season = await database.fetch_one(select(zprp_public_seasons.c.season_id, zprp_public_seasons.c.name)
                                      .where(zprp_public_seasons.c.season_id == season_id)) if season_id else None
    season_cond = M.c.season_id == season_id
    played_cond = and_(season_cond, M.c.score_home.is_not(None))
    comps, assocs, club_rows, matches, players, big, lineup = await asyncio.gather(
        database.fetch_all(select(C.c.competition_id, C.c.name, C.c.gender, C.c.category, C.c.association_id, C.c.association_name)
                           .where(C.c.season_id == season_id)),
        database.fetch_all(select(zprp_public_associations.c.association_id, zprp_public_associations.c.name,
                                  zprp_public_associations.c.full_name)),
        database.fetch_all(select(zprp_public_clubs.c.club_id, zprp_public_clubs.c.association_id, zprp_public_clubs.c.name,
                                  zprp_public_clubs.c.logo_url)),
        database.fetch_all(select(
            M.c.match_id, M.c.competition_id, M.c.competition_name, M.c.match_code,
            M.c.home_team_id, M.c.away_team_id, M.c.home_club_id, M.c.away_club_id, M.c.home_team_name, M.c.away_team_name,
            M.c.scheduled_at, M.c.score_home, M.c.score_away, M.c.halftime_home, M.c.halftime_away,
            M.c.shootout_home, M.c.shootout_away, M.c.winner, M.c.withdrawn, M.c.walkover_team_id, M.c.spectators,
            M.c.referee_1_id, M.c.referee_1_name, M.c.referee_2_id, M.c.referee_2_name,
        ).where(season_cond)),
        database.fetch_all(
            select(MP.c.player_id, MP.c.team_id, M.c.competition_id, func.count().label("apps"),
                   func.sum(MP.c.goals).label("goals"), func.sum(MP.c.penalty_goals).label("penalty_goals"),
                   func.sum(MP.c.penalty_attempts).label("penalty_attempts"), func.sum(MP.c.two_minutes).label("two_minutes"),
                   func.sum(MP.c.disqualifications + MP.c.direct_red_cards).label("red_cards"),
                   func.sum(MP.c.warnings).label("warnings"))
            .select_from(MP.join(M, M.c.match_id == MP.c.match_id)).where(played_cond)
            .group_by(MP.c.player_id, MP.c.team_id, M.c.competition_id)
        ),
        database.fetch_all(
            select(MP.c.match_id, MP.c.player_id, MP.c.team_id, MP.c.side, MP.c.goals, MP.c.penalty_goals)
            .select_from(MP.join(M, M.c.match_id == MP.c.match_id))
            .where(and_(played_cond, or_(MP.c.goals >= BIG_GOALS, MP.c.penalty_goals >= BIG_SEVENS)))
        ),
        database.fetch_all(select(MP.c.match_id).select_from(MP.join(M, M.c.match_id == MP.c.match_id))
                           .where(played_cond).group_by(MP.c.match_id)),
    )
    clubs = [_row(r) for r in club_rows]
    await corrections.apply("club", clubs)
    fetched = time.monotonic()
    frame = await asyncio.to_thread(_frame_from_rows, season, comps, assocs, clubs, matches, players, big, lineup)
    log.info("[stats] migawka %s: %d meczów, %d wierszy zawodników, %d protokołów; SQL %.2f s, budowa %.2f s",
             season_id, len(frame.matches), len(frame.players), len(frame.proel), fetched - started, time.monotonic() - fetched)
    return frame


def _store_frame(season_id: str, frame: R.Frame) -> None:
    if season_id not in _frames and len(_frames) >= FRAMES_MAX:
        oldest = min(_frames, key=lambda k: _frames[k][0])
        _frames.pop(oldest, None)
    _frames[season_id] = (time.monotonic(), frame)


async def rebuild_frame(season_id: str) -> R.Frame:
    frame = await _build_frame(season_id)
    _store_frame(season_id, frame)
    return frame


def _kick_refresh(season_id: str) -> None:
    if season_id in _refreshing:
        return
    _refreshing.add(season_id)

    async def go() -> None:
        try:
            await refresh_proel(PROEL_ON_DEMAND)
            await rebuild_frame(season_id)
        except Exception:  # noqa: BLE001
            log.exception("[stats] odświeżenie migawki %s", season_id)
        finally:
            _refreshing.discard(season_id)

    asyncio.create_task(go())


async def get_frame(season_id: Optional[str]) -> R.Frame:
    key = season_id or ""
    hit = _frames.get(key)
    if hit:
        if time.monotonic() - hit[0] >= FRAME_TTL:
            _kick_refresh(key)
        return hit[1]
    lock = _frame_locks.setdefault(key, asyncio.Lock())
    async with lock:
        hit = _frames.get(key)
        if hit:
            return hit[1]
        await refresh_proel(PROEL_ON_DEMAND)
        return await rebuild_frame(key)


def _stamp(frame: R.Frame) -> str:
    return frame.built_at.isoformat()


# ---------------------------------------------------------------------------
# Imiona i nazwiska (tylko publiczne ZPRP)
# ---------------------------------------------------------------------------


def _player_slots(obj: Any, out: List[Dict[str, Any]]) -> None:
    if isinstance(obj, dict):
        if "player_id" in obj and "first_name" in obj and obj.get("player_id") and obj.get("first_name") is None:
            out.append(obj)
        for v in obj.values():
            _player_slots(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _player_slots(v, out)


async def fill_players(payload: Any) -> Any:
    slots: List[Dict[str, Any]] = []
    _player_slots(payload, slots)
    ids = sorted({str(s["player_id"]) for s in slots})
    if not ids:
        return payload
    P_ = zprp_public_players
    rows = [_row(r) for r in await database.fetch_all(
        select(P_.c.player_id, P_.c.first_name, P_.c.last_name, P_.c.photo_url).where(P_.c.player_id.in_(ids)))]
    await corrections.apply("player", rows)
    found = {str(r["player_id"]): r for r in rows}
    for s in slots:
        hit = found.get(str(s["player_id"]))
        if hit:
            s.update(first_name=hit.get("first_name"), last_name=hit.get("last_name"), photo_url=hit.get("photo_url"))
    return payload


def _envelope(frame: Optional[R.Frame], scope: R.Scope, body: Dict[str, Any], refresh: int) -> Dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "next_refresh_s": refresh,
        "snapshot_at": frame.built_at.isoformat() if frame else None,
        "scope": scope.as_dict(),
        "season": {"season_id": frame.season_id, "name": frame.season_name} if frame else None,
        **body,
    }


# ---------------------------------------------------------------------------
# Sekcje (wspólne dla tras i pętli w tle)
# ---------------------------------------------------------------------------


async def build_season(scope: R.Scope) -> Dict[str, Any]:
    frame = await get_frame(scope.season_id)

    async def go() -> Dict[str, Any]:
        body = await asyncio.to_thread(R.season_stats, frame, scope)
        return _envelope(frame, scope, await fill_players(body), int(RESP_TTL))

    return await _cached(f"season|{scope.key()}|{_stamp(frame)}", RESP_TTL, go)


async def build_geo(scope: R.Scope) -> Dict[str, Any]:
    frame = await get_frame(scope.season_id)

    async def go() -> Dict[str, Any]:
        return _envelope(frame, scope, await asyncio.to_thread(R.geo_stats, frame, scope), int(RESP_TTL))

    return await _cached(f"geo|{scope.key()}|{_stamp(frame)}", RESP_TTL, go)


async def build_proel(scope: R.Scope) -> Dict[str, Any]:
    frame = await get_frame(scope.season_id)

    async def go() -> Dict[str, Any]:
        return _envelope(frame, scope, await asyncio.to_thread(P.aggregate, frame, scope), int(RESP_TTL))

    return await _cached(f"proel|{scope.key()}|{_stamp(frame)}", RESP_TTL, go)


def _trends_parts(frame: R.Frame, scope: R.Scope, today) -> Dict[str, Any]:
    ms = R.scoped(frame, scope)
    return {
        "weekly": R.weekly_series(ms, today),
        "cumulative": R.cumulative(frame, ms, today),
        "records": R.match_records(frame, scope) + P.records(frame, scope),
        "busiest": R.busiest_day(ms, today),
        "leader": R.province_leader(frame, scope),
    }


async def build_trends(scope: R.Scope) -> Dict[str, Any]:
    frame = await get_frame(scope.season_id)

    async def go() -> Dict[str, Any]:
        today = TP.warsaw_today()
        # Sezon i ProEl z ich własnej pamięci (ten sam zakres) - ciekawostki nie liczą ich drugi raz.
        season, proel = await build_season(scope), await build_proel(scope)
        parts = await asyncio.to_thread(_trends_parts, frame, scope, today)
        await fill_players({"records": parts["records"]})
        facts = R.build_facts(season, parts, proel, parts["busiest"], parts["leader"])
        body = {"weekly": parts["weekly"], "cumulative": parts["cumulative"], "records": parts["records"], "facts": facts}
        return _envelope(frame, scope, body, int(RESP_TTL))

    return await _cached(f"trends|{scope.key()}|{_stamp(frame)}|{TP.warsaw_today()}", RESP_TTL, go)


async def build_filters(season_id: Optional[str]) -> Dict[str, Any]:
    frame = await get_frame(season_id)

    async def go() -> Dict[str, Any]:
        seasons, current = await seasons_info()
        opts = await asyncio.to_thread(R.filter_options, frame)
        listing = sorted(seasons.values(), key=lambda s: (-(s.get("start_year") or 0), str(s.get("season_id"))))
        body = {
            "seasons": [{"season_id": s["season_id"], "name": s.get("name"), "start_year": s.get("start_year"),
                         "active": bool(s.get("active")), "current": s["season_id"] == current} for s in listing],
            **opts,
            "defaults": {"season_id": current},
        }
        return _envelope(frame, R.Scope(season_id=season_id), body, int(FILTERS_TTL))

    return await _cached(f"filters|{season_id}|{_stamp(frame)}", FILTERS_TTL, go)


# ---------------------------------------------------------------------------
# Dziś
# ---------------------------------------------------------------------------


async def _team_public(team_id: str, season_id: Optional[str]) -> Dict[str, Any]:
    """Publiczne numery drużyny w sezonie (występy + kadra) i jej zawodnicy - 10 min w pamięci."""
    key = (team_id, season_id or "")
    hit = _team_cache.get(key)
    if hit and time.monotonic() - hit[0] < TEAM_TTL:
        return hit[1]
    season_cond = [M.c.season_id == season_id] if season_id else []
    apps = [_row(r) for r in await database.fetch_all(
        select(MP.c.player_id, MP.c.shirt_number, M.c.scheduled_at.label("at"))
        .select_from(MP.join(M, M.c.match_id == MP.c.match_id)).where(and_(MP.c.team_id == team_id, *season_cond)))]
    R_ = zprp_public_team_rosters
    roster_cond = [R_.c.season_id == season_id] if season_id else []
    roster = [_row(r) for r in await database.fetch_all(
        select(R_.c.player_id, R_.c.shirt_number).where(and_(R_.c.team_id == team_id, R_.c.active.is_(True), *roster_cond)))]
    value = {"apps": apps, "roster": roster, "by_number": PL.number_index(apps, roster),
             "ids": sorted({str(a["player_id"]) for a in apps + roster if a.get("player_id")})}
    if len(_team_cache) > 2000:
        _team_cache.clear()
    _team_cache[key] = (time.monotonic(), value)
    return value


async def _public_players(ids: List[str]) -> Dict[str, Dict[str, Any]]:
    ids = sorted({i for i in ids if i})
    if not ids:
        return {}
    rows = await database.fetch_all(select(zprp_public_players).where(zprp_public_players.c.player_id.in_(ids)))
    return {str(_row(r)["player_id"]): {k: _row(r).get(k) for k in PL.PUBLIC_PLAYER_KEYS} for r in rows}


def _derive(blob: Dict[str, Any], card: Dict[str, Any], status: Any) -> Dict[str, Any]:
    """Z bloba to, czego potrzebuje „Dziś" (w orientacji ZPRP). `roster` z nazwiskami tylko do sprawdzeń."""
    if not L.is_public_blob(blob) or not isinstance(blob.get("matchConfig"), dict):
        return {"public": False}
    host_home = L.host_is_home(blob["matchConfig"], card.get("home_team_name"), card.get("away_team_name"))
    board = L.board(blob, host_home)
    return {
        "public": True,
        "day": PCR.blob_day(blob),
        "tl": L.timeline(blob, host_home),
        "board": board,
        "stats": PL.protocol_stats(blob, host_home),
        "roster": PL.proel_roster(blob, host_home),
        "result": PCR.proel_result(blob, status, card.get("home_team_name"), card.get("away_team_name")),
    }


def _derive_many(todo: List[Tuple[Dict[str, Any], Dict[str, Any], Any]]) -> List[Dict[str, Any]]:
    out = []
    for row, card, raw in todo:
        try:
            out.append(_derive(_blob(raw), card, row.get("status")))
        except Exception:  # noqa: BLE001 - zepsuty blob nie psuje dnia
            out.append({"public": False})
    return out


_RANK = {"approved": 3, "finished": 2, "in_progress": 1}


def _pick(cands: List[Tuple[Dict[str, Any], Dict[str, Any]]], card: Dict[str, Any]) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    day = card.get("scheduled_at").date() if isinstance(card.get("scheduled_at"), datetime) else None
    good = []
    for row, d in cands:
        if not d.get("public"):
            continue
        zid = str(row.get("zprp_match_id") or "").strip()
        if not zid and d.get("day") not in (None, day):
            continue
        good.append((row, d))
    good.sort(key=lambda x: (bool(str(x[0].get("zprp_match_id") or "").strip()), _RANK.get(x[0].get("status") or "", 0),
                             _iso(x[0].get("doc_at")) or ""), reverse=True)
    return good[0] if good else None


def _zprp_lines(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for r in rows:
        nr = str(r.get("shirt_number") or "").strip()
        out.append({"player_id": r.get("player_id"), "number": int(nr) if nr.isdigit() else None, "side": r.get("side"),
                    "team_id": r.get("team_id"), "goals": int(r.get("goals") or 0), "penalty_goals": int(r.get("penalty_goals") or 0),
                    "two_minutes": int(r.get("two_minutes") or 0),
                    "red": int(r.get("disqualifications") or 0) + int(r.get("direct_red_cards") or 0),
                    "warnings": int(r.get("warnings") or 0)})
    return out


def _zprp_complete(lines: List[Dict[str, Any]], card: Dict[str, Any]) -> bool:
    if not lines or card.get("score_home") is None or card.get("score_away") is None:
        return False
    got = {"home": 0, "away": 0}
    for l in lines:
        if l.get("side") in got:
            got[l["side"]] += l["goals"]
    return got["home"] == card["score_home"] and got["away"] == card["score_away"]


async def _proel_lines(card: Dict[str, Any], d: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for side in PL.SIDES:
        team_id = str(card.get(f"{side}_team_id") or "") or None
        pub = await _team_public(team_id, card.get("season_id")) if team_id else {"by_number": {}, "ids": []}
        roster = d["roster"][side]
        card_ids = [str(e["zprp_id"]) for e in roster["players"] if e.get("zprp_id")]
        card_ids += [str(e["zprp_id"]) for e in (roster.get("struck") or {}).values() if e.get("zprp_id")]
        public = await _public_players(pub["ids"] + card_ids)
        pool = [public[i] for i in pub["ids"] if i in public]
        rows = PL.build_players(roster["players"], d["stats"][side]["players"], side, team_id, public, pub["by_number"], pool,
                                None, roster.get("struck"))
        for r in rows:
            nr = str(r.get("shirt_number") or "")
            out.append({"player_id": r.get("player_id"), "number": int(nr) if nr.isdigit() else None, "side": side,
                        "team_id": team_id, "goals": int(r.get("goals") or 0), "penalty_goals": int(r.get("penalty_goals") or 0),
                        "two_minutes": int(r.get("two_minutes") or 0),
                        "red": int(r.get("disqualifications") or 0) + int(r.get("direct_red_cards") or 0),
                        "warnings": int(r.get("warnings") or 0)})
    return out


async def _build_today_base() -> Dict[str, Any]:
    now_utc = TP.utc_now()
    now_local = TP.warsaw_now()
    day_start, day_end = TP.day_bounds(now_local.date())
    cards = await _cards(await database.fetch_all(
        select(*_card_cols()).where(and_(M.c.scheduled_at >= day_start, M.c.scheduled_at < day_end))))
    ids = [str(c["match_id"]) for c in cards]
    codes = sorted({str(c.get("match_code") or "").strip() for c in cards} - {""})
    proel_rows: List[Dict[str, Any]] = []
    if ids or codes:
        cond = [T.c.zprp_match_id.in_(ids)] if ids else []
        if codes:
            cond.append(and_(T.c.match_number.in_(codes), or_(T.c.zprp_match_id.is_(None), T.c.zprp_match_id == "")))
        proel_rows = [_row(r) for r in await database.fetch_all(
            select(T.c.match_number, T.c.zprp_match_id, T.c.status, T.c.updated_at.label("doc_at"), S.c.live_started_at, S.c.lease_until)
            .select_from(T.outerjoin(S, S.c.match_number == T.c.match_number))
            .where(or_(*cond)).where(~T.c.match_number.ilike(TRAINING_KEY_LIKE)))]
    by_id = {str(c["match_id"]): c for c in cards}
    by_code: Dict[str, List[Dict[str, Any]]] = {}
    for c in cards:
        if c.get("match_code"):
            by_code.setdefault(str(c["match_code"]).strip(), []).append(c)
    pairs: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for row in proel_rows:
        zid = str(row.get("zprp_match_id") or "").strip()
        targets = [by_id[zid]] if zid and zid in by_id else ([] if zid else by_code.get(str(row["match_number"]).strip(), []))
        pairs.extend((row, c) for c in targets)
    keys = [(str(r["match_number"]), _iso(r.get("doc_at")) or "", str(c["match_id"])) for r, c in pairs]
    need = sorted({k[0] for k in keys if k not in _derived})
    if need:
        blobs = {str(_row(b)["match_number"]): _row(b).get("data_json") for b in await database.fetch_all(
            select(T.c.match_number, T.c.data_json).where(T.c.match_number.in_(need)))}
        todo = [(r, c, blobs.get(k[0])) for (r, c), k in zip(pairs, keys) if k not in _derived]
        for k, d in zip([k for k in keys if k not in _derived], await asyncio.to_thread(_derive_many, todo)):
            _derived[k] = d
    used = set(keys)
    for stale in [k for k in _derived if k not in used]:
        _derived.pop(stale, None)
    cands: Dict[str, List[Tuple[Dict[str, Any], Dict[str, Any]]]] = {}
    for (r, c), k in zip(pairs, keys):
        cands.setdefault(str(c["match_id"]), []).append((r, _derived.get(k) or {}))

    lineup_rows: Dict[str, List[Dict[str, Any]]] = {}
    if ids:
        for r in await database.fetch_all(
            select(MP.c.match_id, MP.c.team_id, MP.c.player_id, MP.c.side, MP.c.shirt_number, MP.c.goals, MP.c.penalty_goals,
                   MP.c.two_minutes, MP.c.disqualifications, MP.c.direct_red_cards, MP.c.warnings)
            .where(MP.c.match_id.in_(ids))
        ):
            d = _row(r)
            lineup_rows.setdefault(str(d["match_id"]), []).append(d)

    frame = await get_frame(await current_season())
    items: List[Dict[str, Any]] = []
    for c in cards:
        pick = _pick(cands.get(str(c["match_id"]), []), c)
        row, d = pick if pick else (None, None)
        ph = P.phase(row, now_utc) if row else None
        if d and d.get("result") and (c.get("score_home") is None or c.get("score_away") is None):
            PCR.apply(c, {"result": d["result"]})
        comp = frame.comps.get(str(c.get("competition_id") or "")) or R.comp_from_name(c.get("competition_id"), c.get("competition_name"))
        clock = dict((d or {}).get("board", {}).get("clock") or {})
        if clock.get("main_ms") is not None:
            clock["label"] = L.mmss(clock["main_ms"])
        zl = _zprp_lines(lineup_rows.get(str(c["match_id"]), []))
        played = c.get("score_home") is not None and c.get("score_away") is not None
        if zl and (_zprp_complete(zl, c) or not d):
            lineup = {"source": "zprp", "players": zl}
        elif d and ph in ("live", "finished"):
            lineup = {"source": "proel", "players": await _proel_lines(c, d)}
        elif zl:
            lineup = {"source": "zprp", "players": zl}
        else:
            lineup = {"source": None, "players": []}
        doc_at = _aware((row or {}).get("doc_at"))
        recent = doc_at is not None and now_utc - doc_at <= TICKER_WINDOW
        items.append({
            "card": c, "comp": comp, "province": R.match_province(comp, c.get("home_club_id"), frame.clubs),
            "phase": ph, "live_score": (d or {}).get("board", {}).get("score") if ph == "live" and not played else None,
            "clock": clock if ph == "live" else None,
            "ticker": P.ticker(d["tl"], clock, doc_at) if d and ph in ("live", "finished") and recent else [],
            "lineup": lineup,
        })
    return {"items": items, "now_local": now_local, "season_id": frame.season_id, "stamp": now_utc.isoformat()}


async def today_base() -> Dict[str, Any]:
    if _today["lock"] is None:
        _today["lock"] = asyncio.Lock()
    if _today["base"] is not None and time.monotonic() - _today["at"] < TODAY_BASE_TTL:
        return _today["base"]
    async with _today["lock"]:
        if _today["base"] is None or time.monotonic() - _today["at"] >= TODAY_BASE_TTL:
            _today["base"] = await _build_today_base()
            _today["at"] = time.monotonic()
    return _today["base"]


async def build_today(scope: R.Scope) -> Dict[str, Any]:
    base = await today_base()
    frame = await get_frame(base["season_id"])
    scope = scope.with_season(base["season_id"])

    async def go() -> Dict[str, Any]:
        body = await asyncio.to_thread(TD.compute_today, base["items"], scope, frame, base["now_local"])
        return _envelope(frame, scope, await fill_players(body), TODAY_TTL)

    return await _cached(f"today|{scope.key()}|{base['stamp']}", TODAY_BASE_TTL, go)


# ---------------------------------------------------------------------------
# Trasy
# ---------------------------------------------------------------------------

_GENDER = "^[MKXmkx]?$"
_AGE = "^[1-5]?$"
_LEVEL = "^(central|district)?$"


async def _scope(season_id: str, gender: str, category: str, age: str, level: str, province: str) -> R.Scope:
    return R.Scope.parse(await _resolve(season_id), gender, category, age, level, province)


@router.get("/filters")
async def stats_filters(season_id: str = Query("", max_length=40)) -> Dict[str, Any]:
    return await build_filters(await _resolve(season_id))


@router.get("/today")
async def stats_today(
    gender: str = Query("", pattern=_GENDER), category: str = Query("", max_length=200),
    age: str = Query("", pattern=_AGE), level: str = Query("", pattern=_LEVEL), province: str = Query("", max_length=400),
) -> Dict[str, Any]:
    return await build_today(R.Scope.parse(None, gender, category, age, level, province))


@router.get("/season")
async def stats_season(
    season_id: str = Query("", max_length=40), gender: str = Query("", pattern=_GENDER), category: str = Query("", max_length=200),
    age: str = Query("", pattern=_AGE), level: str = Query("", pattern=_LEVEL), province: str = Query("", max_length=400),
) -> Dict[str, Any]:
    return await build_season(await _scope(season_id, gender, category, age, level, province))


@router.get("/geo")
async def stats_geo(
    season_id: str = Query("", max_length=40), gender: str = Query("", pattern=_GENDER), category: str = Query("", max_length=200),
    age: str = Query("", pattern=_AGE), level: str = Query("", pattern=_LEVEL), province: str = Query("", max_length=400),
) -> Dict[str, Any]:
    return await build_geo(await _scope(season_id, gender, category, age, level, province))


@router.get("/trends")
async def stats_trends(
    season_id: str = Query("", max_length=40), gender: str = Query("", pattern=_GENDER), category: str = Query("", max_length=200),
    age: str = Query("", pattern=_AGE), level: str = Query("", pattern=_LEVEL), province: str = Query("", max_length=400),
) -> Dict[str, Any]:
    return await build_trends(await _scope(season_id, gender, category, age, level, province))


@router.get("/proel")
async def stats_proel(
    season_id: str = Query("", max_length=40), gender: str = Query("", pattern=_GENDER), category: str = Query("", max_length=200),
    age: str = Query("", pattern=_AGE), level: str = Query("", pattern=_LEVEL), province: str = Query("", max_length=400),
) -> Dict[str, Any]:
    return await build_proel(await _scope(season_id, gender, category, age, level, province))


# ---------------------------------------------------------------------------
# Pętla w tle
# ---------------------------------------------------------------------------


async def run_once() -> Dict[str, Any]:
    """Jeden cykl: streszczenia ProEl, migawka bieżącego sezonu, rozgrzanie sekcji bez filtrów."""
    started = time.monotonic()
    blobs = await refresh_proel()
    sid = await current_season()
    if not sid:
        return {"season_id": None}
    frame = await rebuild_frame(sid)
    scope = R.Scope(season_id=sid)
    for build in (build_filters, build_season, build_geo, build_trends, build_proel):
        await (build(sid) if build is build_filters else build(scope))
    took = time.monotonic() - started
    log.info("[stats] cykl: sezon %s, %d meczów, %d nowych protokołów, %.1f s", sid, len(frame.matches), blobs, took)
    return {"season_id": sid, "matches": len(frame.matches), "proel_read": blobs, "seconds": round(took, 2)}


async def run_stats_scheduler() -> None:
    if os.getenv("STATS_DISABLED", "").strip() in ("1", "true", "yes"):
        log.info("[stats] pętla wyłączona (STATS_DISABLED)")
        return
    await asyncio.sleep(START_DELAY)
    while True:
        try:
            await run_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - pętla nie może umrzeć
            log.exception("[stats] cykl statystyk")
        await asyncio.sleep(LOOP_INTERVAL)

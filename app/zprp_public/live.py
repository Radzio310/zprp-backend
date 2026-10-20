"""LIVE i przebieg meczu z ProEla dla portalu BAZA pod RĘKĄ (publiczne, tylko odczyt).

* `GET /api/v1/handball/live`                 mecze w toku (ProEl) + „powinny trwać" i „za chwilę" z terminarza,
* `GET /api/v1/handball/matches/{id}/timeline` przebieg meczu minuta po minucie, tablica wyniku.

Oba przyjmują `since` (odcisk z poprzedniej odpowiedzi) i `wait` (do 25 s):
serwer trzyma zapytanie, dopóki telefon sekretarza czegoś nie zapisze. Bazę
pyta JEDEN wspólny zegar (co ~1,5 s, niezależnie od liczby oglądających),
a gotowa odpowiedź leży w pamięci pod odciskiem - sto osób na tym samym meczu
kosztuje tyle co jedna.

„LIVE" tylko ze źródła: mecz ma w ProElu znacznik startu i świeży zapis albo
żywy leasing prowadzącego. Terminarz nigdy nie daje statusu live.
Dane wyłącznie sportowe - patrz `proel_live_rules`.
"""
from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import and_, or_, select

from app.db import database, proel_match_state as S, saved_matches as T, zprp_public_matches as M
from app.proel_match_key import zprp_id_of
from app.proel_training_key import TRAINING_KEY_LIKE
from app.zprp_public import proel_live_rules as L
from app.zprp_public.portal import _card_cols, _cards

router = APIRouter(prefix="/api/v1/handball", tags=["handball_live"])

WARSAW = ZoneInfo("Europe/Warsaw")
LIVE_FRESH = timedelta(minutes=20)       # bez leasingu: ostatni zapis nie starszy niż tyle
JUST_FINISHED = timedelta(minutes=90)    # „zakończone przed chwilą"
WINDOW_BACK = timedelta(minutes=135)     # terminarz: „powinny trwać"
SOON_AHEAD = timedelta(minutes=120)      # terminarz: „za chwilę"
TICK_S = 1.5
MAX_WAIT_S = 25


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Any) -> Optional[datetime]:
    if not isinstance(dt, datetime):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _iso(dt: Any) -> Optional[str]:
    d = _aware(dt)
    return d.isoformat() if d else None


def _blob(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


# ---------------------------------------------------------------------------
# Wspólny zegar: odciski zestawu meczów w toku i pojedynczych meczów
# ---------------------------------------------------------------------------

class _Memo:
    """Wynik zapytania ważny przez `ttl` sekund; równoległe żądania czekają na jedno zapytanie."""

    def __init__(self, ttl: float):
        self.ttl, self.at, self.value, self.lock = ttl, 0.0, None, asyncio.Lock()

    async def get(self, fn):
        if self.value is not None and time.monotonic() - self.at < self.ttl:
            return self.value
        async with self.lock:
            if self.value is None or time.monotonic() - self.at >= self.ttl:
                self.value = await fn()
                self.at = time.monotonic()
        return self.value


_live_rows_memo = _Memo(TICK_S)
_live_built: Dict[str, Any] = {"token": None, "body": None}
_match_memo: Dict[str, _Memo] = {}
_timeline_built: Dict[str, Tuple[str, dict]] = {}


async def _live_rows() -> List[Dict[str, Any]]:
    """Lekkie wiersze (bez bloba) kandydatów do LIVE: żywy leasing albo świeży zapis."""
    now = _utc_now()
    rows = await database.fetch_all(
        select(
            S.c.match_number, S.c.zprp_match_id, S.c.rev, S.c.live_started_at, S.c.lease_until,
            T.c.status, T.c.updated_at.label("doc_at"), T.c.zprp_match_id.label("doc_zid"),
        )
        .select_from(S.join(T, T.c.match_number == S.c.match_number))
        .where(~S.c.match_number.ilike(TRAINING_KEY_LIKE))
        .where(or_(S.c.lease_until > now, T.c.updated_at > now - JUST_FINISHED))
        .where(or_(S.c.live_started_at.is_not(None), T.c.status.in_(("finished", "approved"))))
        .limit(120)
    )
    return [dict(r._mapping) if hasattr(r, "_mapping") else dict(r) for r in rows]


def _token(rows: List[Dict[str, Any]], extra: str = "") -> str:
    return L.doc_token([(r.get("match_number"), r.get("rev"), _iso(r.get("doc_at")), r.get("status")) for r in rows] + [extra])


def _phase(row: Dict[str, Any], now: datetime) -> Optional[str]:
    """live | finished | None (porzucony albo przedmeczowy)."""
    status = row.get("status")
    doc_at = _aware(row.get("doc_at"))
    if status in ("finished", "approved"):
        return "finished" if doc_at and now - doc_at <= JUST_FINISHED else None
    lease = _aware(row.get("lease_until"))
    if row.get("live_started_at") is None:
        return None
    if (lease and lease > now) or (doc_at and now - doc_at <= LIVE_FRESH):
        return "live"
    return None


async def _zprp_cards(ids: List[str], codes: List[str]) -> Tuple[Dict[str, dict], Dict[str, dict]]:
    by_id: Dict[str, dict] = {}
    by_code: Dict[str, dict] = {}
    cond = []
    if ids:
        cond.append(M.c.match_id.in_(ids))
    if codes:
        local = datetime.now(WARSAW).replace(tzinfo=None)
        cond.append(and_(M.c.match_code.in_(codes), M.c.scheduled_at >= local - timedelta(days=1),
                         M.c.scheduled_at <= local + timedelta(days=1)))
    if not cond:
        return by_id, by_code
    cards = await _cards(await database.fetch_all(select(*_card_cols()).where(or_(*cond))))
    for c in cards:
        by_id[str(c["match_id"])] = c
        if c.get("match_code"):
            by_code.setdefault(str(c["match_code"]).strip(), c)
    return by_id, by_code


def _live_item(card: dict, row: Dict[str, Any], blob: Dict[str, Any], phase: str) -> Dict[str, Any]:
    cfg = blob.get("matchConfig") if isinstance(blob.get("matchConfig"), dict) else {}
    host_home = L.host_is_home(cfg, card.get("home_team_name"), card.get("away_team_name"))
    tl = L.timeline(blob, host_home)
    return {
        **card,
        "status": "live" if phase == "live" else card.get("status"),
        "live": {
            "phase": phase,
            "proel_status": row.get("status"),
            "rev": int(row.get("rev") or 0),
            "updated_at": _iso(row.get("doc_at")),
            **L.board(blob, host_home),
            "half_ms": tl["half_ms"],
            "last_events": L.last_events(tl["events"], 3),
            "goals_count": sum(1 for e in tl["events"] if e["kind"] in ("goal", "seven_goal")),
        },
    }


async def _build_live(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    now = _utc_now()
    wanted = [(r, p) for r in rows if (p := _phase(r, now))]
    blobs: Dict[str, Dict[str, Any]] = {}
    if wanted:
        got = await database.fetch_all(
            select(T.c.match_number, T.c.data_json).where(T.c.match_number.in_([r["match_number"] for r, _ in wanted]))
        )
        for g in got:
            d = dict(g._mapping) if hasattr(g, "_mapping") else dict(g)
            blobs[d["match_number"]] = _blob(d.get("data_json"))
    ids, codes = [], []
    for r, _ in wanted:
        b = blobs.get(r["match_number"]) or {}
        zid = str(r.get("doc_zid") or r.get("zprp_match_id") or zprp_id_of(b) or "").strip()
        r["_zid"] = zid
        if zid:
            ids.append(zid)
        else:
            codes.append(str(r["match_number"]).strip())
    by_id, by_code = await _zprp_cards(ids, codes)

    live: List[dict] = []
    finished: List[dict] = []
    seen: set = set()
    for r, phase in wanted:
        blob = blobs.get(r["match_number"]) or {}
        if not L.is_public_blob(blob):
            continue
        card = by_id.get(r["_zid"]) if r["_zid"] else by_code.get(str(r["match_number"]).strip())
        if not card or card["match_id"] in seen:
            continue
        seen.add(card["match_id"])
        target = live if phase == "live" else finished
        target.append(_live_item(card, r, blob, phase))

    local = datetime.now(WARSAW).replace(tzinfo=None)
    sched = await _cards(await database.fetch_all(
        select(*_card_cols())
        .where(M.c.scheduled_at >= local - WINDOW_BACK, M.c.scheduled_at <= local + SOON_AHEAD)
        .order_by(M.c.scheduled_at).limit(200)
    ))
    window, soon = [], []
    for c in sched:
        if c["match_id"] in seen or c.get("withdrawn"):
            continue
        at = c.get("scheduled_at")
        if not isinstance(at, datetime):
            continue
        if at <= local and c["status"] == "scheduled":
            window.append(c)
        elif at > local:
            soon.append(c)
    live.sort(key=lambda c: (c.get("scheduled_at") or datetime.min, c["match_id"]))
    finished.sort(key=lambda c: c["live"].get("updated_at") or "", reverse=True)
    return {"live": live, "finished": finished, "window": window, "soon": soon[:40]}


async def _wait_for(get_token, since: str, wait: int) -> str:
    """Czeka (do `wait` s), aż odcisk przestanie być równy `since`. Zwraca aktualny odcisk."""
    token = await get_token()
    if not since or wait <= 0:
        return token
    deadline = time.monotonic() + min(wait, MAX_WAIT_S)
    while token == since and time.monotonic() < deadline:
        await asyncio.sleep(TICK_S)
        token = await get_token()
    return token


@router.get("/live")
async def live_matches(
    since: str = Query("", max_length=64, description="Odcisk z poprzedniej odpowiedzi"),
    wait: int = Query(0, ge=0, le=MAX_WAIT_S, description="Ile sekund czekać na zmianę"),
) -> Dict[str, Any]:
    async def token() -> str:
        rows = await _live_rows_memo.get(_live_rows)
        # Terminarz zmienia się co minutę - minuta wchodzi do odcisku, żeby „powinny trwać" przechodziło do „za chwilę".
        return _token(rows, datetime.now(WARSAW).strftime("%H:%M"))

    tok = await _wait_for(token, since, wait)
    if _live_built["token"] != tok or _live_built["body"] is None:
        rows = await _live_rows_memo.get(_live_rows)
        _live_built["body"] = await _build_live(rows)
        _live_built["token"] = tok
    return {"token": tok, "server_now": _utc_now().isoformat(), "changed": tok != since, **_live_built["body"]}


# ---------------------------------------------------------------------------
# Przebieg jednego meczu
# ---------------------------------------------------------------------------

async def _match_rows(match_id: str, code: str) -> List[Dict[str, Any]]:
    cond = [T.c.zprp_match_id == match_id]
    if code:
        cond.append(T.c.match_number == code)
    rows = await database.fetch_all(
        select(T.c.match_number, T.c.zprp_match_id, T.c.status, T.c.updated_at.label("doc_at"),
               S.c.rev, S.c.live_started_at, S.c.lease_until)
        .select_from(T.outerjoin(S, S.c.match_number == T.c.match_number))
        .where(or_(*cond)).where(~T.c.match_number.ilike(TRAINING_KEY_LIKE))
    )
    return [dict(r._mapping) if hasattr(r, "_mapping") else dict(r) for r in rows]


def _pick(rows: List[Dict[str, Any]], match_id: str) -> Optional[Dict[str, Any]]:
    """Zatwierdzony > zakończony > w toku; dokładne id ZPRP przed samym numerem."""
    good = [r for r in rows if not r.get("zprp_match_id") or str(r["zprp_match_id"]) == str(match_id)]
    rank = {"approved": 3, "finished": 2, "in_progress": 1}
    good.sort(key=lambda r: (rank.get(r.get("status") or "in_progress", 0),
                             str(r.get("zprp_match_id") or "") == str(match_id),
                             _iso(r.get("doc_at")) or ""), reverse=True)
    return good[0] if good else None


@router.get("/matches/{match_id}/timeline")
async def match_timeline(
    match_id: str,
    since: str = Query("", max_length=64),
    wait: int = Query(0, ge=0, le=MAX_WAIT_S),
) -> Dict[str, Any]:
    match = await database.fetch_one(
        select(M.c.match_id, M.c.match_code, M.c.home_team_name, M.c.away_team_name).where(M.c.match_id == match_id)
    )
    if not match:
        raise HTTPException(404, "Nie znaleziono meczu")
    m = dict(match._mapping) if hasattr(match, "_mapping") else dict(match)
    code = str(m.get("match_code") or "").strip()
    memo = _match_memo.setdefault(match_id, _Memo(TICK_S))
    if len(_match_memo) > 500:
        _match_memo.clear()
        _match_memo[match_id] = memo

    async def rows() -> List[Dict[str, Any]]:
        return await memo.get(lambda: _match_rows(match_id, code))

    async def token() -> str:
        r = _pick(await rows(), match_id)
        return _token([r] if r else [])

    tok = await _wait_for(token, since, wait)
    cached = _timeline_built.get(match_id)
    if cached and cached[0] == tok:
        return {**cached[1], "changed": tok != since, "server_now": _utc_now().isoformat()}

    row = _pick(await rows(), match_id)
    body: Dict[str, Any] = {"token": tok, "available": False, "phase": None, "events": [], "shootout": None}
    if row:
        got = await database.fetch_one(select(T.c.data_json).where(T.c.match_number == row["match_number"]))
        blob = _blob((dict(got._mapping) if hasattr(got, "_mapping") else dict(got)).get("data_json") if got else None)
        if L.is_public_blob(blob) and blob.get("matchConfig"):
            now = _utc_now()
            status = row.get("status") or "in_progress"
            if status in ("finished", "approved"):
                phase = "finished"
            else:
                phase = _phase({**row, "status": status}, now) or ("stale" if row.get("live_started_at") else "pre")
            cfg = blob["matchConfig"]
            host_home = L.host_is_home(cfg, m.get("home_team_name"), m.get("away_team_name"))
            tl = L.timeline(blob, host_home)
            body = {
                "token": tok,
                "available": bool(tl["events"]) or phase == "live",
                "phase": phase,
                "proel_status": status,
                "updated_at": _iso(row.get("doc_at")),
                "sides": "direct" if host_home else "swapped",
                "half_ms": tl["half_ms"],
                "events": tl["events"],
                "shootout": tl["shootout"],
                "board": L.board(blob, host_home),
            }
    if len(_timeline_built) > 300:
        _timeline_built.clear()
    _timeline_built[match_id] = (tok, body)
    return {**body, "changed": tok != since, "server_now": _utc_now().isoformat()}

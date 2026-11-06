"""Mecze TOWARZYSKIE z ProEla w BAZIE pod Ręką - zapytania i trasa listy (publiczne, tylko odczyt).

Reguły i prywatność: `friendly_rules`. Tu tylko baza:
* `eligible_rows`  zapisy ProEla bez IdZawody (nie szkoleniowe), które wystartowały,
* `load_cards`     karty tych meczów (blob czytany raz na wersję zapisu, potem z pamięci),
* `overview`       odpowiedź w kształcie `GET /matches/{id}/overview`,
* `GET /api/v1/handball/friendlies`  historia (zakończone), od najnowszych.

Mecz towarzyski nie ma wiersza w `zprp_public_matches`, więc nie trafia do tabel ligowych ani
rankingów - te czytają wyłącznie ZPRP i `public_rows_clause`.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import or_, select

from app.db import database, proel_match_state as S, saved_matches as T, zprp_public_matches as M
from app.proel_training_key import TRAINING_KEY_LIKE
from app.zprp_public import friendly_rules as F
from app.zprp_public import proel_lineup_rules as PL
from app.zprp_public import proel_live_rules as L

router = APIRouter(prefix="/api/v1/handball", tags=["handball_friendly"])

MAX_PAGE = 60
_CACHE_MAX = 600
#: (klucz, odcisk zapisu) -> karta albo None (zapis nie jest meczem towarzyskim).
_cards_cache: Dict[Tuple[str, str], Optional[Dict[str, Any]]] = {}


def _row(r: Any) -> Dict[str, Any]:
    return dict(r._mapping) if hasattr(r, "_mapping") else dict(r)


def _blob(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


def _stamp(doc_at: Any) -> str:
    return doc_at.isoformat() if isinstance(doc_at, datetime) else str(doc_at or "")


def _aware(dt: Any) -> Optional[datetime]:
    if not isinstance(dt, datetime):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def eligible_rows(key: str = "", limit: int = 400) -> List[Dict[str, Any]]:
    """Lekkie wiersze (bez bloba) zapisów, które MOGĄ być towarzyskie: bez IdZawody, nie szkoleniowe, wystartowały."""
    q = (
        select(T.c.match_number, T.c.status, T.c.updated_at.label("doc_at"),
               S.c.rev, S.c.live_started_at, S.c.lease_until)
        .select_from(T.outerjoin(S, S.c.match_number == T.c.match_number))
        .where(~T.c.match_number.ilike(TRAINING_KEY_LIKE))
        .where(or_(T.c.zprp_match_id.is_(None), T.c.zprp_match_id == ""))
        .where(or_(S.c.zprp_match_id.is_(None), S.c.zprp_match_id == ""))
        .where(or_(T.c.status.in_(F.FINISHED), S.c.live_started_at.is_not(None)))
    )
    if key:
        q = q.where(T.c.match_number == key)
    rows = await database.fetch_all(q.order_by(T.c.updated_at.desc()).limit(limit))
    return [_row(r) for r in rows]


async def _known_codes(codes: List[str]) -> set:
    """Numery, które istnieją w terminarzu ZPRP - taki zapis to mecz rozgrywek, nie towarzyski."""
    codes = sorted({c for c in codes if c})
    if not codes:
        return set()
    rows = await database.fetch_all(select(M.c.match_code).where(M.c.match_code.in_(codes)))
    return {str(_row(r).get("match_code") or "").strip() for r in rows}


async def load_cards(rows: List[Dict[str, Any]], want: Optional[int] = None) -> List[Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]]:
    """-> [(wiersz, karta, blob)] dla zapisów, które są meczami towarzyskimi (kolejność wejścia).

    Blob czytany tylko dla wersji, której pamięć jeszcze nie zna; `want` kończy po tylu trafieniach.
    """
    from app.proel_match_key import is_shared_key
    from app.proel_training_key import match_number_from_key

    known = await _known_codes([match_number_from_key(r["match_number"]) for r in rows if not is_shared_key(r["match_number"])])
    out: List[Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]] = []
    for r in rows:
        key = str(r["match_number"])
        if not is_shared_key(key) and match_number_from_key(key) in known:
            continue
        ck = (key, _stamp(r.get("doc_at")))
        if ck in _cards_cache and _cards_cache[ck] is None:
            continue
        got = await database.fetch_one(select(T.c.data_json).where(T.c.match_number == key))
        blob = _blob(_row(got).get("data_json") if got else None)
        if not F.is_friendly_blob(blob):
            if len(_cards_cache) > _CACHE_MAX:
                _cards_cache.clear()
            _cards_cache[ck] = None
            continue
        out.append((r, F.card(key, r.get("status"), r.get("doc_at"), blob, r.get("live_started_at")), blob))
        if want is not None and len(out) >= want:
            break
    return out


async def find(match_id: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]]:
    """Jeden mecz towarzyski po identyfikatorze portalu albo None."""
    key = F.key_of_id(match_id)
    if not key:
        return None
    rows = await eligible_rows(key, 1)
    got = await load_cards(rows, 1)
    return got[0] if got else None


async def overview(match_id: str) -> Dict[str, Any]:
    """Odpowiedź w kształcie `match_overview` dla meczu towarzyskiego."""
    found = await find(match_id)
    if not found:
        raise HTTPException(404, "Nie znaleziono meczu")
    row, card, blob = found
    parts = F.lineups(blob)
    done = row.get("status") in F.FINISHED
    score = L.board(blob, True).get("score") if blob else None
    lineups_score = {"home": score["home"], "away": score["away"]} if (done and score) else None
    sums = parts["sums"]
    total = (score["home"] + score["away"]) if score else 0
    goals_known = bool(sums["home"] + sums["away"]) or total == 0

    def side(prefix: str) -> Dict[str, Any]:
        return {"team_id": None, "team_name": card.get(f"{prefix}_team_name"), "club_id": None, "club_name": None,
                "logo_url": None, "city": None, "score": card.get(f"score_{prefix}"),
                "halftime": card.get(f"halftime_{prefix}"), "shootout": None}

    status = "finished" if done else "live"
    return {
        "match": {**card, "status": status, "times_source": "baza_protocol"},
        "status": status,
        "friendly": True,
        "home": side("home"),
        "away": side("away"),
        "venue": {"name": card.get("venue_name"), "city": card.get("venue_city"), "street": None, "number": None,
                  "capacity": None, "lat": None, "lon": None, "coords_precision": None},
        "officials": F.officials(blob),
        "lineups": parts["lineups"],
        "lineups_goals_known": goals_known,
        "lineups_source": {"home": "proel", "away": "proel"},
        "lineups_complete": True,
        "lineups_refresh": False,
        "lineups_score": lineups_score,
        "staff": parts["staff"],
        "head_to_head": [],
        "standings": [],
        "events": [],
        "events_available": False,
        "details_pending": False,
    }


def details(over: Dict[str, Any]) -> Dict[str, Any]:
    """Kształt `GET /matches/{id}` z przeglądu."""
    players = [p for side_list in over["lineups"].values() for p in side_list]
    return {"match": over["match"], "players": players, "staff": over["staff"], "details_pending": False}


@router.get("/friendlies")
async def friendlies(
    limit: int = Query(20, ge=1, le=MAX_PAGE),
    offset: int = Query(0, ge=0, le=5000),
) -> Dict[str, Any]:
    """Zakończone mecze towarzyskie, od najnowszych (historia). Na żywo - w `GET /live`."""
    rows = [r for r in await eligible_rows() if r.get("status") in F.FINISHED]
    found = await load_cards(rows, offset + limit + 1)
    page = found[offset:offset + limit]
    return {"items": [c for _r, c, _b in page], "limit": limit, "offset": offset, "count": len(page),
            "has_more": len(found) > offset + limit}

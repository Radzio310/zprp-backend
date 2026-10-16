"""Czasy kar z protokołów sędziowskich BAZA (`proel_matches.data_json.protocol`).

Upstream ZPRP podaje tylko liczniki kar. Czasy (MM:SS) mamy z protokołu stolikowego
prowadzonego w aplikacji BAZA: lista zdarzeń `protocol` z `type`, `team` (host/guest),
`player` (numer zawodnika albo litera A-E osoby towarzyszącej), `time` (ms), `shootout`.
Tylko mecze zakończone/zatwierdzone. Logika czysta, bez bazy.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, List, Optional

SIDE = {"host": "home", "guest": "away"}
_LETTERS = {"A", "B", "C", "D", "E"}


def mmss(ms: Any) -> Optional[str]:
    try:
        total = max(0, int(ms)) // 1000
    except (TypeError, ValueError):
        return None
    return "%02d:%02d" % (total // 60, total % 60)


def _fold(text: Any) -> str:
    base = unicodedata.normalize("NFKD", str(text or "").lower().replace("ł", "l"))
    return re.sub(r"[^a-z ]", "", "".join(c for c in base if not unicodedata.combining(c)))


def _empty() -> Dict[str, Any]:
    return {"warning_time": None, "two_minutes_times": [], "disqualification_time": None, "extra_penalty_time": None}


def extract_times(blob: Any) -> Dict[str, Dict[str, Any]]:
    """-> {"home": {"players": {numer: czasy}, "staff": {litera: czasy}, "names": {numer: nazwisko}}, "away": ...}"""
    out: Dict[str, Dict[str, Any]] = {s: {"players": {}, "staff": {}, "names": {}} for s in ("home", "away")}
    if not isinstance(blob, dict):
        return out
    cfg = blob.get("matchConfig") if isinstance(blob.get("matchConfig"), dict) else {}
    for team, side in SIDE.items():
        for card in cfg.get(f"{team}PlayerCards") or []:
            if isinstance(card, dict) and card.get("number") is not None and card.get("fullName"):
                try:
                    out[side]["names"][int(card["number"])] = str(card["fullName"])
                except (TypeError, ValueError):
                    pass
    for ev in blob.get("protocol") or []:
        if not isinstance(ev, dict) or ev.get("shootout") or ev.get("team") not in SIDE:
            continue
        kind, t = ev.get("type"), mmss(ev.get("time"))
        if t is None or kind not in ("warning", "penalty1", "penalty2", "penalty3", "penaltyExtra", "disqualification", "disqualificationBlue"):
            continue
        who = ev.get("player")
        bucket, key = None, None
        if isinstance(who, str) and who.strip().upper() in _LETTERS:
            bucket, key = "staff", who.strip().upper()
        else:
            try:
                bucket, key = "players", int(who)
            except (TypeError, ValueError):
                continue
        rec = out[SIDE[ev["team"]]][bucket].setdefault(key, _empty())
        if kind == "warning":
            rec["warning_time"] = rec["warning_time"] or t
        elif kind in ("penalty1", "penalty2", "penalty3"):
            if t not in rec["two_minutes_times"]:
                rec["two_minutes_times"] = sorted(rec["two_minutes_times"] + [t])[:3]
        elif kind == "penaltyExtra":
            rec["extra_penalty_time"] = rec["extra_penalty_time"] or t
        else:
            rec["disqualification_time"] = rec["disqualification_time"] or t
    return out


def _name_ok(public_last: Any, protocol_name: Optional[str]) -> bool:
    """Gdy protokół zna nazwisko, musi pasować; brak nazwiska nie blokuje (dopasowanie po numerze)."""
    if not protocol_name or not public_last:
        return True
    last = _fold(public_last).split()
    return bool(last) and all(part in _fold(protocol_name) for part in last[:1])


def apply_times(players: List[dict], staff: List[dict], extracted: Dict[str, Dict[str, Any]]) -> int:
    """Wpisuje czasy w istniejące elementy (mutuje). Zwraca liczbę uzupełnionych osób."""
    n = 0
    for p in players:
        side = extracted.get(p.get("side") or "") or {}
        try:
            num = int(p.get("shirt_number"))
        except (TypeError, ValueError):
            continue
        rec = (side.get("players") or {}).get(num)
        if rec and _name_ok(p.get("last_name"), (side.get("names") or {}).get(num)):
            p.update(_copy(rec))
            n += 1
    for s in staff:
        rec = ((extracted.get(s.get("side") or "") or {}).get("staff") or {}).get(s.get("letter"))
        if rec:
            s.update(_copy(rec))
            n += 1
    return n


def _copy(rec: Dict[str, Any]) -> Dict[str, Any]:
    out = {**rec, "two_minutes_times": list(rec["two_minutes_times"])}
    if rec.get("extra_penalty_time"):
        out["extra_penalty"] = True
    return out


def pick_row(rows: List[dict], match_id: str) -> Optional[dict]:
    """Najlepszy zapis protokołu: po ZPRP id (albo bez id, gdy numer meczu pasuje), zatwierdzony przed zakończonym."""
    good = [r for r in rows if r.get("status") in ("approved", "finished")
            and (not r.get("zprp_match_id") or str(r["zprp_match_id"]) == str(match_id))]
    good.sort(key=lambda r: (str(r.get("zprp_match_id") or "") == str(match_id), r.get("status") == "approved"), reverse=True)
    return good[0] if good else None


async def attach_protocol_times(match: dict, players: List[dict], staff: List[dict]) -> Optional[str]:
    """Uzupełnia czasy kar z protokołu BAZA. Zwraca "baza_protocol" albo None. Nigdy nie rzuca."""
    try:
        from sqlalchemy import or_, select
        from app.db import database, saved_matches as T

        match_id, code = str(match.get("match_id") or ""), str(match.get("match_code") or "").strip()
        cond = [T.c.zprp_match_id == match_id]
        if code:
            cond.append(T.c.match_number == code)
        rows = await database.fetch_all(
            select(T.c.match_number, T.c.zprp_match_id, T.c.status, T.c.data_json).where(or_(*cond))
        )
        row = pick_row([dict(r._mapping) for r in rows], match_id)
        if not row:
            return None
        blob = row["data_json"]
        if isinstance(blob, str):
            import json
            blob = json.loads(blob)
        if isinstance(blob, dict) and isinstance(blob.get("matchConfig"), dict) and blob["matchConfig"].get("training") is not None:
            return None
        apply_times(players, staff, extract_times(blob))
        return "baza_protocol"
    except Exception:  # protokół jest dodatkiem - nigdy nie psuje publicznego widoku
        return None

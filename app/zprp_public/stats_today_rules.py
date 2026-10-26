"""„Dziś na żywo" ekranu Statystyki - czyste reguły składania dnia (bez bazy).

Wejście: lista pozycji dnia przygotowana przez `stats.py` (karta meczu po zapasie
ProEla, rozgrywki, województwo, faza protokołu, wynik na żywo, skład wybrany
dla meczu, ostatnie bramki z protokołu w orientacji ZPRP). Jedno źródło bramek
na mecz: wynik ZPRP, inaczej zakończony protokół, inaczej bieżący wynik w toku.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from app import time_pl as TP
from app.zprp_public import portal_rules as PR
from app.zprp_public import stats_rules as R

TICKER_MAX = 30
TOP_SCORERS = 10


def _played(card: Dict[str, Any]) -> bool:
    return card.get("score_home") is not None and card.get("score_away") is not None


def _counted(card: Dict[str, Any]) -> bool:
    return _played(card) and not card.get("withdrawn") and not card.get("walkover_team_id")


def card_ref(item: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
    c = item["card"]
    at = c.get("scheduled_at")
    return {
        "match_id": c.get("match_id"),
        "home_team_id": c.get("home_team_id"), "away_team_id": c.get("away_team_id"),
        "home_team_name": c.get("home_team_name"), "away_team_name": c.get("away_team_name"),
        "home_club_id": c.get("home_club_id"), "away_club_id": c.get("away_club_id"),
        "home_logo_url": c.get("home_logo_url"), "away_logo_url": c.get("away_logo_url"),
        "score_home": c.get("score_home"), "score_away": c.get("score_away"),
        "shootout_home": c.get("shootout_home"), "shootout_away": c.get("shootout_away"),
        "halftime_home": c.get("halftime_home"), "halftime_away": c.get("halftime_away"),
        "scheduled_at": at.isoformat() if isinstance(at, datetime) else at,
        "competition_id": c.get("competition_id"), "competition_name": c.get("competition_name"),
        "category": item["comp"].key, "province": item["province"],
        "score_source": c.get("score_source") or ("proel_live" if item.get("phase") == "live" else None),
        **extra,
    }


def _player(item: Dict[str, Any], line: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not line.get("player_id"):
        return None
    c = item["card"]
    side = line.get("side") or "home"
    return {"player_id": line["player_id"], "first_name": None, "last_name": None, "photo_url": None,
            "team_id": line.get("team_id") or c.get(f"{side}_team_id"), "team_name": c.get(f"{side}_team_name"),
            "club_id": c.get(f"{side}_club_id"), "club_logo_url": c.get(f"{side}_logo_url")}


def _goals(item: Dict[str, Any]) -> Optional[int]:
    c = item["card"]
    if _counted(c):
        return int(c["score_home"]) + int(c["score_away"])
    if not _played(c) and item.get("phase") == "live" and item.get("live_score"):
        return int(item["live_score"].get("home") or 0) + int(item["live_score"].get("away") or 0)
    return None


def compute_today(items: List[Dict[str, Any]], scope: "R.Scope", frame: "R.Frame", now_local: datetime) -> Dict[str, Any]:
    today = now_local.date()
    mine = [it for it in items if scope.comp_ok(it["comp"]) and scope.province_ok(it["province"])]
    counts = {"total": len(mine), "played": 0, "live": 0, "upcoming": 0, "pending": 0, "no_hour": 0, "withdrawn": 0}
    goals = {"total": 0, "final": 0, "live": 0, "avg_per_match": None, "sources": {"zprp": 0, "proel": 0, "proel_live": 0}}
    final_matches = 0
    disc = {"two_minutes": 0, "red_cards": 0, "warnings": 0, "matches_counted": 0}
    hours: Dict[int, List[int]] = defaultdict(lambda: [0, 0, 0, 0])
    by_cat: Dict[str, Dict[str, int]] = defaultdict(lambda: {"matches": 0, "played": 0, "live": 0, "goals": 0})
    by_prov: Dict[str, Dict[str, int]] = defaultdict(lambda: {"matches": 0, "played": 0, "live": 0, "goals": 0})
    scorers: List[Dict[str, Any]] = []
    ticker: List[Dict[str, Any]] = []
    live_list: List[Dict[str, Any]] = []

    for it in mine:
        c = it["card"]
        played = _played(c)
        live = not played and it.get("phase") == "live"
        state = "played" if played else "withdrawn" if c.get("withdrawn") else "live" if live else \
            "upcoming" if PR.is_upcoming(c, now_local) else "pending"
        counts[state] += 1
        at = c.get("scheduled_at")
        if not played and not TP.has_kickoff_time(at):
            counts["no_hour"] += 1
        g = _goals(it)
        cat, prov = by_cat[it["comp"].key], by_prov[it["province"]]
        for bucket in (cat, prov):
            bucket["matches"] += 1
            bucket["played"] += 1 if played else 0
            bucket["live"] += 1 if live else 0
            bucket["goals"] += g or 0
        if g is not None:
            goals["total"] += g
            if live:
                goals["live"] += g
                goals["sources"]["proel_live"] += 1
            else:
                goals["final"] += g
                final_matches += 1
                goals["sources"]["proel" if c.get("score_source") == "proel" else "zprp"] += 1
        if isinstance(at, datetime) and TP.has_kickoff_time(at):
            hours[at.hour][0] += 1
            hours[at.hour][1] += g or 0
            hours[at.hour][2] += 1 if played else 0
            hours[at.hour][3] += 1 if live else 0
        lineup = it.get("lineup") or {}
        if lineup.get("source") and (played or live):
            disc["matches_counted"] += 1
            for line in lineup.get("players") or []:
                disc["two_minutes"] += int(line.get("two_minutes") or 0)
                disc["red_cards"] += int(line.get("red") or 0)
                disc["warnings"] += int(line.get("warnings") or 0)
                if line.get("goals"):
                    scorers.append({"player": _player(it, line), "number": line.get("number"),
                                    "team_name": c.get(f'{line.get("side") or "home"}_team_name'),
                                    "goals": int(line["goals"]), "penalty_goals": int(line.get("penalty_goals") or 0),
                                    "match": card_ref(it), "source": lineup["source"]})
        by_number = {(l.get("side"), l.get("number")): l for l in lineup.get("players") or [] if l.get("number") is not None}
        for ev in it.get("ticker") or []:
            line = by_number.get((ev["side"], ev.get("number")))
            ticker.append({"match": card_ref(it), **ev, "player": _player(it, line) if line else None, "live": live})
        if live:
            clock = it.get("clock") or {}
            live_list.append(card_ref(it, live_score=it.get("live_score"), minute=_minute(clock), clock=clock.get("label"),
                                      phase="live"))

    goals["avg_per_match"] = R.avg(goals["final"], final_matches)
    finished = [it for it in mine if _counted(it["card"])]

    def total(it: Dict[str, Any]) -> int:
        return int(it["card"]["score_home"]) + int(it["card"]["score_away"])

    def margin(it: Dict[str, Any]) -> int:
        return abs(int(it["card"]["score_home"]) - int(it["card"]["score_away"]))

    top = max(finished, key=lambda it: (total(it), margin(it), str(it["card"]["match_id"])), default=None)
    win = max(finished, key=lambda it: (margin(it), total(it), str(it["card"]["match_id"])), default=None)
    scorers.sort(key=lambda s: (-s["goals"], s["penalty_goals"], str(s["match"]["match_id"]), s.get("number") or 0))
    ticker.sort(key=lambda e: (e.get("at") or "", e["t_ms"]), reverse=True)
    weekday = R.weekday_average(frame, scope, today)
    yesterday = R.day_summary(frame, scope, today - timedelta(days=1))
    delta = None
    if goals["avg_per_match"] is not None and weekday.get("avg_goals") is not None:
        delta = round(goals["avg_per_match"] - weekday["avg_goals"], 2)
    return {
        "date": today.isoformat(),
        "weekday": today.weekday(),
        "counts": counts,
        "goals": goals,
        "highest_scoring": card_ref(top, total=total(top)) if top else None,
        "biggest_win": card_ref(win, margin=margin(win)) if win and margin(win) else None,
        "top_scorers": scorers[:TOP_SCORERS],
        "discipline": disc,
        "goals_by_hour": [{"hour": h, "matches": hours[h][0], "goals": hours[h][1], "played": hours[h][2], "live": hours[h][3]}
                          for h in sorted(hours)],
        "comparison": {"weekday_avg": weekday, "yesterday": yesterday, "delta_avg_goals": delta},
        "ticker": ticker[:TICKER_MAX],
        "live": sorted(live_list, key=lambda c: (c.get("scheduled_at") or "", str(c["match_id"]))),
        "by_category": [{"key": k, "label": R.CATEGORY_LABELS[k], **by_cat[k]} for k in R.CATEGORY_LABELS if k in by_cat],
        "by_province": [{"key": k, "label": R.province_label(k) or k, **by_prov[k]}
                        for k in list(R.PROVINCES) + [R.UNKNOWN] if k in by_prov],
    }


def _minute(clock: Dict[str, Any]) -> Optional[int]:
    main = clock.get("main_ms")
    return int(main) // 60_000 + 1 if main else None

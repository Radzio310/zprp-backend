"""Przegląd kolejki: tabela po każdej kolejce, ruchy w tabeli i statystyki kolejki.

Czyste reguły (bez bazy i sieci); zapytania składa `extras.round_review`.

Ruchy w tabeli: miejsce po kolejce N kontra miejsce po kolejce N-1, obie
tabele liczone TYM SAMYM sposobem z wyników meczów do danej kolejki (z wynikami
z protokołu elektronicznego, gdy ZPRP jeszcze ich nie ma). Oficjalna tabela
ZPRP jest zawsze „po ostatnim meczu" - porównanie jej z czymkolwiek nie mówi,
co zmieniła konkretna kolejka.

Kolejność w tabeli jak we wstępnym przeliczeniu portalu
(`standings_provisional.rank`): punkty, mecze bezpośrednie remisujących
(punkty, różnica, bramki), różnica bramek, bramki zdobyte; pełny remis =
wspólne miejsce (ex aequo). Punkty: 3/2/1/0 (Z/Zk/Pk/P) w lidze „za 3",
2/1/0 w lidze „za 2" (wnioskowane z oficjalnej tabeli). Remisu nie nazywamy.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from app import standings_provisional as SP
from app.zprp_public import match_rules as MR
from app.zprp_public import round_rules as ROUNDS

NO_ORDER = 10 ** 6
FORM_LENGTH = 5
TOP_SCORERS = 5
TOP_PENALTIES = 3
#: Najwyżej tyle meczów w listach powrotów i rozstrzygnięć w końcówce.
TOP_MATCHES = 3
#: Odrobiona strata (bramki), od której mecz trafia do „powrotów" z protokołu.
COMEBACK_MIN = 3
#: Przedziały czasu gry na wykresie bramek (6 x 10 min w meczu 2 x 30).
PERIODS = 6


def _i(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Kolejność kolejek i przypisanie meczów
# ---------------------------------------------------------------------------


def day_order(days: List[dict]) -> Dict[str, int]:
    """matchday_id -> numer porządkowy (0, 1, ...).

    Rundy po kolei wg najwcześniejszego dnia (bez dat: kolejność z bazy),
    w rundzie wg `sequence` (Lp ZPRP), potem numeru z nazwy („Seria 8").
    """
    first_day: Dict[str, str] = {}
    first_seen: Dict[str, int] = {}
    for i, d in enumerate(days):
        rid = str(d.get("round_id") or "")
        first_seen.setdefault(rid, i)
        start = ROUNDS.matchday_range(d.get("starts_on"), d.get("ends_on"))[0]
        if start and (rid not in first_day or start < first_day[rid]):
            first_day[rid] = start
    rounds = sorted(first_seen, key=lambda r: (first_day.get(r) or "9999", first_seen[r]))
    round_rank = {r: i for i, r in enumerate(rounds)}

    def key(item: Tuple[int, dict]) -> tuple:
        i, d = item
        seq = d.get("sequence")
        num = ROUNDS.matchday_number(d.get("number"), d.get("name"))
        return (round_rank[str(d.get("round_id") or "")], seq if seq is not None else NO_ORDER, num or NO_ORDER, i)

    ordered = sorted(enumerate(days), key=key)
    return {str(d["matchday_id"]): pos for pos, (_, d) in enumerate(ordered)}


def assign_days(matches: Iterable[dict], days: List[dict]) -> List[dict]:
    """Kopie meczów z `matchday_id` z kolejki, w której mecz się odbył.

    Mecz bez kolejki (bywa przy dopisanych meczach) trafia do ostatniej
    kolejki, która zaczęła się nie później niż on - tak, jak liczy go tabela.
    """
    known = {str(d["matchday_id"]) for d in days}
    windows = []
    for d in days:
        start = ROUNDS.matchday_range(d.get("starts_on"), d.get("ends_on"))[0]
        if start:
            windows.append((start, str(d["matchday_id"])))
    windows.sort()
    out = []
    for m in matches:
        m = dict(m)
        if str(m.get("matchday_id") or "") not in known:
            day = ROUNDS.iso_day(m.get("scheduled_at"))
            hit = [mid for start, mid in windows if day and start <= day]
            m["matchday_id"] = hit[-1] if hit else None
        out.append(m)
    return out


def team_groups(standings: Iterable[dict], round_teams: Iterable[str]) -> Dict[str, str]:
    """team_id -> klucz grupy z oficjalnej tabeli (grupy liczymy osobno).

    Drużyna w kilku tabelach (faza zasadnicza i finałowa) dostaje tę, w której
    gra najwięcej drużyn z wybranej kolejki. Jedna grupa = pusty słownik.
    """
    members: Dict[str, set] = {}
    for r in standings:
        tid = str(r.get("team_id") or "")
        if tid:
            members.setdefault(f'{r.get("table_id") or ""}|{r.get("group_id") or ""}', set()).add(tid)
    if len(members) < 2:
        return {}
    playing = set(round_teams)
    out: Dict[str, str] = {}
    for key in sorted(members, key=lambda k: -len(members[k] & playing)):
        for tid in members[key]:
            out.setdefault(tid, key)
    return out


# ---------------------------------------------------------------------------
# Tabela po kolejce
# ---------------------------------------------------------------------------


def counts(m: dict) -> bool:
    """Czy mecz wchodzi do tabeli (jak `match_rules.simulate_table`)."""
    if not m.get("home_team_id") or not m.get("away_team_id"):
        return False
    if m.get("withdrawn") and not m.get("walkover_team_id"):
        return False
    return m.get("score_home") is not None and m.get("score_away") is not None


def match_points(m: dict, win_pts: int = 3) -> Tuple[int, int]:
    """(punkty gospodarza, punkty gościa): 3/2/1/0 albo 2/1/0 w lidze „za 2"."""
    side, decided = MR.outcome(m)
    if side is None:
        return 1, 1
    if decided == "shootout":
        won, lost = (2, 1) if win_pts == 3 else (win_pts, 0)
    else:
        won, lost = win_pts, 0
    return (won, lost) if side == "home" else (lost, won)


def _row(teams: Dict[str, dict], tid: str, name: Any, club: Any) -> dict:
    row = teams.get(tid)
    if row is None:
        row = teams[tid] = {"team_id": tid, "team_name": name, "club_id": club, "matches": 0, "points": 0,
                            "goals_for": 0, "goals_against": 0, "record": MR.empty_record()}
    else:
        row["team_name"] = row["team_name"] or name
        row["club_id"] = row["club_id"] or club
    return row


def build_table(matches: Iterable[dict], win_pts: int = 3, teams: Iterable[dict] = (),
                group_of: Optional[Dict[str, str]] = None) -> List[dict]:
    """Tabela (z `position`) z rozegranych meczów; `teams` = drużyny z zerem (jak w tabeli ZPRP).

    `group_of` dzieli tabelę na grupy (mecz między grupami się nie liczy);
    wiersze mają wtedy `group`, a miejsca liczone są w grupie.
    """
    group_of = group_of or {}
    rows: Dict[str, dict] = {}
    for t in teams:
        if t.get("team_id"):
            _row(rows, str(t["team_id"]), t.get("team_name"), t.get("club_id"))
    played = []
    for m in matches:
        if not counts(m):
            continue
        ht, at = str(m["home_team_id"]), str(m["away_team_id"])
        if group_of.get(ht, "") != group_of.get(at, ""):
            continue
        played.append(m)
        h, a = _i(m["score_home"]), _i(m["score_away"])
        ph, pa = match_points(m, win_pts)
        for tid, name, club, gf, ga, pts, side in ((ht, m.get("home_team_name"), m.get("home_club_id"), h, a, ph, "home"),
                                                   (at, m.get("away_team_name"), m.get("away_club_id"), a, h, pa, "away")):
            r = _row(rows, tid, name, club)
            r["matches"] += 1
            r["points"] += pts
            r["goals_for"] += gf
            r["goals_against"] += ga
            code = MR.side_result(m, side)
            if code:
                r["record"][code.lower()] += 1
    by_group: Dict[str, List[dict]] = {}
    for r in rows.values():
        r["goal_difference"] = r["goals_for"] - r["goals_against"]
        by_group.setdefault(group_of.get(r["team_id"], ""), []).append(r)
    out: List[dict] = []
    for key in sorted(by_group):
        ranked = SP.rank(by_group[key], played, win_pts)
        for r in ranked:
            if group_of:
                r["group"] = key
        out.extend(ranked)
    return out


def _form(matches: List[dict], team_id: str) -> List[str]:
    codes = [MR.team_result_detail(m, team_id) for m in matches]
    return [c for c in codes if c][-FORM_LENGTH:]


def table_moves(matches: Iterable[dict], order: Dict[str, int], target_id: str, win_pts: int = 3,
                teams: Iterable[dict] = (), group_of: Optional[Dict[str, str]] = None) -> List[dict]:
    """Ruchy w tabeli po kolejce `target_id`: miejsce teraz i po poprzedniej kolejce.

    Pierwsza kolejka (przed nią nic rozegranego): `previous_position` None,
    `status` „new". `previous` to to samo co `previous_position` (pole klienta).
    """
    target = order.get(target_id)
    if target is None:
        return []
    teams = list(teams)
    ordered = sorted(
        (m for m in matches if order.get(str(m.get("matchday_id") or ""), NO_ORDER) <= target),
        key=lambda m: (order.get(str(m.get("matchday_id") or ""), NO_ORDER), str(m.get("scheduled_at") or ""), str(m.get("match_id") or "")),
    )
    before = [m for m in ordered if m.get("matchday_id") != target_id]
    current = [m for m in ordered if m.get("matchday_id") == target_id and counts(m)]
    after_table = build_table(ordered, win_pts, teams, group_of)
    first_round = not any(counts(m) for m in before)
    before_rows = {} if first_round else {r["team_id"]: r for r in build_table(before, win_pts, teams, group_of)}
    played = [m for m in ordered if counts(m)]
    out = []
    for r in after_table:
        tid = r["team_id"]
        prev = before_rows.get(tid)
        prev_pos = prev["position"] if prev else None
        delta = prev_pos - r["position"] if prev_pos is not None else None
        status = "new" if delta is None else "up" if delta > 0 else "down" if delta < 0 else "same"
        mine = [m for m in current if tid in (str(m.get("home_team_id")), str(m.get("away_team_id")))]
        out.append({
            **{k: r.get(k) for k in ("team_id", "team_name", "club_id", "position", "points", "matches",
                                     "goals_for", "goals_against", "goal_difference", "record")},
            **({"group": r["group"]} if "group" in r else {}),
            "previous_position": prev_pos,
            "previous": prev_pos,
            "delta": delta,
            "status": status,
            "points_before": prev["points"] if prev else 0,
            "points_gained": r["points"] - (prev["points"] if prev else 0),
            "form": _form([m for m in played if tid in (str(m.get("home_team_id")), str(m.get("away_team_id")))], tid),
            "round_results": [_round_result(m, tid) for m in mine],
        })
    return out


def _round_result(m: dict, team_id: str) -> dict:
    home = str(m.get("home_team_id")) == team_id
    own, opp = (m.get("score_home"), m.get("score_away")) if home else (m.get("score_away"), m.get("score_home"))
    return {"match_id": m.get("match_id"), "code": MR.team_result_detail(m, team_id), "home": home,
            "goals_for": own, "goals_against": opp,
            "opponent": m.get("away_team_name") if home else m.get("home_team_name")}


# ---------------------------------------------------------------------------
# Statystyki kolejki
# ---------------------------------------------------------------------------


def _match_brief(m: dict) -> dict:
    side, decided = MR.outcome(m)
    return {k: m.get(k) for k in ("match_id", "home_team_id", "away_team_id", "home_team_name", "away_team_name",
                                  "home_club_id", "away_club_id", "home_logo_url", "away_logo_url",
                                  "score_home", "score_away", "halftime_home", "halftime_away")} | {
        "winner_side": side, "decided_by": decided}


def _team_brief(m: dict, side: str) -> dict:
    return {"team_id": m.get(f"{side}_team_id"), "team_name": m.get(f"{side}_team_name"),
            "club_id": m.get(f"{side}_club_id"), "logo_url": m.get(f"{side}_logo_url"), "match_id": m.get("match_id")}


def _goals(m: dict) -> int:
    return _i(m.get("score_home")) + _i(m.get("score_away"))


def _is_result(m: dict) -> bool:
    """Prawdziwy wynik na boisku (walkower nie wchodzi do średnich bramek)."""
    return counts(m) and not m.get("walkover_team_id")


def _avg(total: float, n: int) -> Optional[float]:
    return round(total / n, 2) if n else None


def _trend(now: Optional[float], base: Optional[float], tolerance: float) -> Optional[dict]:
    if now is None or base is None:
        return None
    delta = round(now - base, 2)
    return {"round": now, "season": base, "delta": delta,
            "trend": "same" if abs(delta) < tolerance else "up" if delta > 0 else "down"}


def _summary(matches: List[dict]) -> dict:
    games = [m for m in matches if _is_result(m)]
    decided = [MR.outcome(m) for m in matches if counts(m)]
    home = sum(1 for side, _ in decided if side == "home")
    return {"matches": len(games), "goals": sum(_goals(m) for m in games), "avg_goals": _avg(sum(_goals(m) for m in games), len(games)),
            "home_wins": home, "away_wins": sum(1 for side, _ in decided if side == "away"),
            "home_win_share": _avg(home * 100, len(decided)),
            "shootouts": sum(1 for _, how in decided if how == "shootout")}


def round_stats(round_matches: Iterable[dict], season_matches: Iterable[dict], players: Iterable[dict] = (),
                season_cards: Optional[dict] = None, timelines: Optional[Dict[str, dict]] = None) -> dict:
    """Liczby kolejki: bramki, średnia, rekordy meczów, rozstrzygnięcia, strzelcy, kary, porównanie z sezonem.

    `players`: wiersze zawodników z meczów kolejki (`goals`, `two_minutes`, ...).
    `season_cards`: {"matches", "two_minutes"} - kary w meczach sezonu z protokołami.
    `timelines`: match_id -> wynik `proel_live_rules.timeline` (gdy jest protokół).
    """
    played = [m for m in round_matches if counts(m)]
    games = [m for m in played if _is_result(m)]
    now, season = _summary(played), _summary(list(season_matches))
    split = {"regular": 0, "shootout": 0, "walkover": 0, "undecided": 0}
    for m in played:
        side, how = MR.outcome(m)
        split["undecided" if side is None else how] += 1

    biggest = max(games, key=lambda m: (abs(_i(m["score_home"]) - _i(m["score_away"])), _goals(m)), default=None)
    highest = max(games, key=lambda m: (_goals(m), -abs(_i(m["score_home"]) - _i(m["score_away"]))), default=None)
    sides = [(m, s) for m in games for s in ("home", "away")]
    attack = max(sides, key=lambda x: (_i(x[0][f"score_{x[1]}"]), -_i(x[0][f"score_{'away' if x[1] == 'home' else 'home'}"])), default=None)
    defense = min(sides, key=lambda x: (_i(x[0][f"score_{'away' if x[1] == 'home' else 'home'}"]), -_i(x[0][f"score_{x[1]}"])), default=None)

    team_of_round = None
    winners = [(m, MR.outcome(m)[0]) for m in games]
    winners = [(m, s) for m, s in winners if s]
    if winners:
        m, s = max(winners, key=lambda x: (abs(_i(x[0]["score_home"]) - _i(x[0]["score_away"])), _i(x[0][f"score_{x[1]}"])))
        other = "away" if s == "home" else "home"
        team_of_round = {**_team_brief(m, s), "goals_for": _i(m[f"score_{s}"]), "goals_against": _i(m[f"score_{other}"]),
                         "margin": abs(_i(m["score_home"]) - _i(m["score_away"])), "opponent": m.get(f"{other}_team_name"),
                         "rule": "najwyższe zwycięstwo kolejki"}

    players = [p for p in players if p.get("player_id")]
    scorers = sorted((p for p in players if _i(p.get("goals")) > 0),
                     key=lambda p: (-_i(p.get("goals")), _i(p.get("penalty_attempts")), str(p.get("name") or "")))[:TOP_SCORERS]
    penalised = sorted((p for p in players if _i(p.get("two_minutes")) > 0),
                       key=lambda p: (-_i(p.get("two_minutes")), str(p.get("name") or "")))[:TOP_PENALTIES]
    team_mins: Dict[str, dict] = {}
    for p in players:
        if _i(p.get("two_minutes")) and p.get("team_id"):
            t = team_mins.setdefault(str(p["team_id"]), {"team_id": p["team_id"], "team_name": p.get("team_name"),
                                                         "club_id": p.get("club_id"), "logo_url": p.get("club_logo_url"), "two_minutes": 0})
            t["two_minutes"] += _i(p.get("two_minutes"))
    with_players = {str(p.get("match_id")) for p in players if p.get("match_id")}
    two_total = sum(_i(p.get("two_minutes")) for p in players)
    round_two = _avg(two_total, len(with_players))
    season_two = _avg(_i((season_cards or {}).get("two_minutes")), _i((season_cards or {}).get("matches")))

    keep = ("player_id", "name", "photo_url", "team_id", "team_name", "club_id", "club_logo_url", "match_id")
    return {
        "matches": now["matches"], "goals": now["goals"], "avg_goals": now["avg_goals"],
        "home_wins": now["home_wins"], "away_wins": now["away_wins"], "decided": split,
        "biggest_win": {**_match_brief(biggest), "margin": abs(_i(biggest["score_home"]) - _i(biggest["score_away"]))} if biggest else None,
        "highest_scoring": {**_match_brief(highest), "goals": _goals(highest)} if highest else None,
        "best_attack": {**_team_brief(attack[0], attack[1]), "goals": _i(attack[0][f"score_{attack[1]}"])} if attack else None,
        "best_defense": {**_team_brief(defense[0], defense[1]),
                         "conceded": _i(defense[0][f"score_{'away' if defense[1] == 'home' else 'home'}"])} if defense else None,
        "team_of_round": team_of_round,
        "top_scorers": [{**{k: p.get(k) for k in keep}, "goals": _i(p.get("goals")), "penalty_goals": _i(p.get("penalty_goals")),
                         "penalty_attempts": _i(p.get("penalty_attempts"))} for p in scorers],
        "most_penalised": [{**{k: p.get(k) for k in keep}, "two_minutes": _i(p.get("two_minutes"))} for p in penalised],
        "team_penalties": sorted(team_mins.values(), key=lambda t: (-t["two_minutes"], str(t["team_name"] or "")))[:TOP_PENALTIES],
        "two_minutes": two_total if with_players else None,
        "protocols": len(with_players),
        "season": season,
        "compare": {
            "avg_goals": _trend(now["avg_goals"], season["avg_goals"], 0.5),
            "home_win_share": _trend(now["home_win_share"], season["home_win_share"], 5.0),
            "avg_two_minutes": _trend(round_two, season_two, 0.3),
        },
        "halftime_turns": halftime_turns(games),
        "protocol": protocol_extras(games, timelines or {}),
    }


def halftime_turns(matches: Iterable[dict]) -> List[dict]:
    """Mecze odwrócone po przerwie: zwycięzca przegrywał do przerwy (dane ZPRP)."""
    out = []
    for m in matches:
        hh, ha = m.get("halftime_home"), m.get("halftime_away")
        side, _ = MR.outcome(m)
        if hh is None or ha is None or side is None:
            continue
        behind = (_i(ha) - _i(hh)) if side == "home" else (_i(hh) - _i(ha))
        if behind > 0:
            out.append({**_match_brief(m), "team": _team_brief(m, side), "deficit": behind})
    return sorted(out, key=lambda x: -x["deficit"])[:TOP_MATCHES]


def protocol_extras(matches: Iterable[dict], timelines: Dict[str, dict]) -> Optional[dict]:
    """Z protokołów ProEl: bramki w przedziałach czasu, powroty i zmiany prowadzenia. None bez protokołów."""
    used = [(m, timelines[str(m.get("match_id"))]) for m in matches if timelines.get(str(m.get("match_id")))]
    used = [(m, tl) for m, tl in used if any(e.get("kind") in ("goal", "seven_goal") for e in tl.get("events") or [])]
    if not used:
        return None
    half = _i(used[0][1].get("half_ms")) or 30 * 60_000
    periods = [{"from": round(i * 2 * half / PERIODS / 60_000), "to": round((i + 1) * 2 * half / PERIODS / 60_000),
                "goals": 0, "home": 0, "away": 0} for i in range(PERIODS)]
    comebacks, lead_changes, late = [], 0, []
    for m, tl in used:
        hms = _i(tl.get("half_ms")) or half
        side, _ = MR.outcome(m)
        worst, leader, state, ahead_since = 0, None, None, None
        for e in tl.get("events") or []:
            if e.get("kind") not in ("goal", "seven_goal"):
                continue
            t = _i(e.get("t"))
            i = min(PERIODS - 1, max(0, int(t * PERIODS / (2 * hms))))
            periods[i]["goals"] += 1
            periods[i][e.get("side") if e.get("side") in ("home", "away") else "home"] += 1
            sc = e.get("score") or {}
            h, a = _i(sc.get("home")), _i(sc.get("away"))
            if side:
                worst = max(worst, (a - h) if side == "home" else (h - a))
            now = "home" if h > a else "away" if a > h else None
            if now and leader and now != leader:
                lead_changes += 1
            if now == side and state != side:
                ahead_since = t  # zwycięzca wychodzi na prowadzenie (ostatni raz = gol na zwycięstwo)
            state = now
            leader = now or leader
        if side and worst >= COMEBACK_MIN:
            comebacks.append({**_match_brief(m), "team": _team_brief(m, side), "deficit": worst})
        if side and state == side and ahead_since is not None and ahead_since >= 2 * hms - 5 * 60_000:
            late.append({**_match_brief(m), "team": _team_brief(m, side), "minute": ahead_since // 60_000 + 1})
    return {"matches": len(used), "half_minutes": half // 60_000, "goals_by_period": periods,
            "comebacks": sorted(comebacks, key=lambda x: -x["deficit"])[:TOP_MATCHES], "lead_changes": lead_changes,
            "late_winners": sorted(late, key=lambda x: -x["minute"])[:TOP_MATCHES]}

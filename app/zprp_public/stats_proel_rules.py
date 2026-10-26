"""Statystyki z protokołów ProEl (ekran „Statystyki") - czyste reguły, bez bazy.

Wejście to wyłącznie PUBLICZNY przebieg meczu (`proel_live_rules.timeline`):
strona, numer, rodzaj zdarzenia, czas gry, wynik po zdarzeniu. Streszczenie
jednego protokołu (`protocol_summary`) nie zawiera numerów ani nazwisk - same
liczniki i czasy - więc można je trwale trzymać w `zprp_public_stats_snapshots`.

Streszczenie jest w orientacji ProEla (home = gospodarz w protokole). Stronę
ZPRP dobiera `orient` przy łączeniu z meczem (`host_is_home` po nazwach drużyn).
Reguły gry jak `analysis.ts` w BAZA_web: kara (2 min, czerwona, niebieska, Kd)
osłabia na 2 minuty, bramka w przewadze = rywal ma więcej osób na ławce kar,
efekt czasu drużyny = bilans 5 min przed i 5 min po.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.zprp_public import proel_live_rules as L
from app.zprp_public import stats_rules as R

VERSION = 1
SUSPENSION_MS = 120_000
WINDOW_MS = 300_000
GOAL_KINDS = ("goal", "seven_goal")
SUSPENSION_KINDS = ("two_min", "red", "blue", "extra")
FINISHED = ("finished", "approved")
COMEBACK_MIN = 3
COMEBACKS_TOP = 3
RUN_MIN = 3
LIVE_FRESH = timedelta(minutes=20)
JUST_FINISHED = timedelta(minutes=90)
HALF_BREAK_MS = 10 * 60_000
SIDES = ("home", "away")


def _other(side: str) -> str:
    return "away" if side == "home" else "home"


def _short(susp: List[Dict[str, Any]], side: str, t: int) -> int:
    n = sum(1 for s in susp if s["side"] == side and s["t"] <= t < s["t"] + SUSPENSION_MS)
    return min(n, 2)


def minute_bin(t: int, full_ms: int) -> int:
    """Indeks 0..59 minuty meczu skalowanej do 60 (połowy 20/25 min też dają 60 przedziałów)."""
    if full_ms <= 0:
        full_ms = 2 * L.DEFAULT_HALF_MIN * 60_000
    return max(0, min(59, (max(0, int(t) - 1) * 60) // full_ms))


def summarize(tl: Dict[str, Any]) -> Dict[str, Any]:
    """Liczniki jednego przebiegu (`proel_live_rules.timeline`). Strony jak w przebiegu."""
    hms = int(tl.get("half_ms") or L.DEFAULT_HALF_MIN * 60_000)
    full = 2 * hms
    evs = list(tl.get("events") or [])
    goals = [e for e in evs if e["kind"] in GOAL_KINDS]
    susp = [e for e in evs if e["kind"] in SUSPENSION_KINDS]

    minutes = [0] * 60
    halves = [0, 0]
    for g in goals:
        minutes[minute_bin(g["t"], full)] += 1
        halves[1 if g.get("half") == 2 else 0] += 1

    pp = sh = 0
    for g in goals:
        own, opp = _short(susp, g["side"], g["t"] - 1), _short(susp, _other(g["side"]), g["t"] - 1)
        if opp > own:
            pp += 1
        elif own > opp:
            sh += 1
    win_own = win_opp = 0
    for s in susp:
        for g in goals:
            if s["t"] < g["t"] <= s["t"] + SUSPENSION_MS:
                if g["side"] == s["side"]:
                    win_own += 1
                else:
                    win_opp += 1

    to_n = to_before = to_after = to_pos = 0
    for e in evs:
        if e["kind"] != "timeout":
            continue
        before = [g for g in goals if e["t"] - WINDOW_MS <= g["t"] < e["t"]]
        after = [g for g in goals if e["t"] < g["t"] <= e["t"] + WINDOW_MS]
        b = sum(1 if g["side"] == e["side"] else -1 for g in before)
        a = sum(1 if g["side"] == e["side"] else -1 for g in after)
        to_n += 1
        to_before += b
        to_after += a
        to_pos += 1 if a - b > 0 else 0

    lead_changes = ties = 0
    leader: Optional[str] = None
    prev_diff = 0
    deficit = {"home": 0, "away": 0}
    ht_score = {"home": 0, "away": 0}
    for g in goals:
        diff = g["score"]["home"] - g["score"]["away"]
        now = "home" if diff > 0 else "away" if diff < 0 else None
        if now is None and prev_diff != 0:
            ties += 1
        if now and leader and now != leader:
            lead_changes += 1
        if now:
            leader = now
        deficit["home"] = max(deficit["home"], -diff)
        deficit["away"] = max(deficit["away"], diff)
        prev_diff = diff
        if g.get("half") != 2:
            ht_score = dict(g["score"])

    run = None
    i = 0
    while i < len(goals):
        j = i
        while j + 1 < len(goals) and goals[j + 1]["side"] == goals[i]["side"]:
            j += 1
        n = j - i + 1
        if n >= RUN_MIN and (run is None or n > run[1]):
            run = [goals[i]["side"], n, goals[i]["t"], goals[j]["t"]]
        i = j + 1

    best5 = None
    for side in SIDES:
        ts = [g["t"] for g in goals if g["side"] == side]
        k = 0
        for j, t in enumerate(ts):
            while ts[k] < t - WINDOW_MS + 1:
                k += 1
            n = j - k + 1
            if best5 is None or n > best5[1]:
                best5 = [side, n, ts[k]]

    final = dict(goals[-1]["score"]) if goals else {"home": 0, "away": 0}
    winner = "home" if final["home"] > final["away"] else "away" if final["away"] > final["home"] else None
    decider = None
    if winner:
        for k in range(len(goals) - 1, -1, -1):
            before = goals[k - 1]["score"] if k > 0 else {"home": 0, "away": 0}
            own = before[winner] - before[_other(winner)]
            if own <= 0:
                if goals[k]["side"] == winner:
                    decider = [winner, goals[k]["t"]]
                break
    ht_diff = ht_score["home"] - ht_score["away"]
    return {
        "v": VERSION,
        "half_ms": hms,
        "goals": final,
        "minutes": minutes,
        "halves": halves,
        "sevens": [sum(1 for e in evs if e["kind"] in ("seven_goal", "seven_miss")), sum(1 for e in evs if e["kind"] == "seven_goal")],
        "susp": len(susp),
        "two_min": sum(1 for e in evs if e["kind"] == "two_min"),
        "reds": sum(1 for e in evs if e["kind"] in ("red", "blue")),
        "pp": [pp, sh],
        "window": [win_own, win_opp],
        "to": [to_n, to_before, to_after, to_pos],
        "first": [goals[0]["side"], goals[0]["t"]] if goals else None,
        "ht": "home" if ht_diff > 0 else "away" if ht_diff < 0 else None,
        "lead_changes": lead_changes,
        "ties": ties,
        "deficit": deficit,
        "run": run,
        "best5": best5 if best5 and best5[1] >= 2 else None,
        "last5": sum(minutes[55:]),
        "first5": sum(minutes[:5]),
        "decider": decider,
    }


def protocol_summary(blob: Any, row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Streszczenie protokołu (orientacja ProEla) albo None: test/szkolenie, brak zdarzeń, mecz w toku."""
    if str(row.get("status") or "") not in FINISHED or not L.is_public_blob(blob):
        return None
    cfg = blob.get("matchConfig") if isinstance(blob.get("matchConfig"), dict) else None
    if cfg is None:
        return None
    tl = L.timeline(blob, True)
    if not any(e["kind"] in GOAL_KINDS for e in tl["events"]):
        return None
    from app.zprp_public.proel_card_rules import blob_day

    day = blob_day(blob)
    zid = str(row.get("zprp_match_id") or "").strip() or _blob_match_id(cfg)
    out = summarize(tl)
    out.update({
        "zid": zid or None,
        "code": str(row.get("match_number") or "").strip() or None,
        "day": day.isoformat() if day else None,
        "status": row.get("status"),
        "cfg": {"host": cfg.get("hostTeamName"), "guest": cfg.get("guestTeamName"), "swapped": bool(cfg.get("hostSwapped"))},
    })
    return out


def _blob_match_id(cfg: Dict[str, Any]) -> str:
    text = str(cfg.get("matchId") or "").strip()
    return text if text.isdigit() else ""


def orient(summary: Dict[str, Any], host_home: bool) -> Dict[str, Any]:
    """Streszczenie w orientacji ZPRP (zamiana stron, gdy gospodarz ProEla to gość w ZPRP)."""
    if host_home:
        return summary
    flip = {"home": "away", "away": "home"}
    out = dict(summary)
    out["goals"] = {"home": summary["goals"]["away"], "away": summary["goals"]["home"]}
    out["deficit"] = {"home": summary["deficit"]["away"], "away": summary["deficit"]["home"]}
    out["ht"] = flip.get(summary.get("ht")) if summary.get("ht") else None
    for key in ("first", "run", "best5", "decider"):
        v = summary.get(key)
        out[key] = [flip[v[0]], *v[1:]] if v else None
    return out


def link(summaries: Iterable[Dict[str, Any]], frame: "R.Frame") -> Dict[str, Dict[str, Any]]:
    """Streszczenia -> {match_id: streszczenie w orientacji ZPRP}. Zatwierdzony przed zakończonym."""
    best: Dict[str, Tuple[tuple, Dict[str, Any]]] = {}
    for s in summaries:
        if not isinstance(s, dict) or s.get("v") != VERSION:
            continue
        m = frame.by_id.get(str(s.get("zid") or "")) if s.get("zid") else None
        by_id = m is not None
        if m is None and s.get("code") and s.get("day"):
            try:
                m = frame.by_code_day.get((s["code"], date.fromisoformat(s["day"])))
            except ValueError:
                m = None
        if m is None:
            continue
        cfg = s.get("cfg") or {}
        host_home = L.host_is_home({"hostTeamName": cfg.get("host"), "guestTeamName": cfg.get("guest"),
                                    "hostSwapped": cfg.get("swapped")}, m.home_team_name, m.away_team_name)
        rank = (s.get("status") == "approved", by_id, str(s.get("doc_at") or ""))
        old = best.get(m.match_id)
        if old is None or rank > old[0]:
            best[m.match_id] = (rank, orient(s, host_home))
    return {mid: v for mid, (_, v) in best.items()}


def _winner(m: "R.Match", s: Dict[str, Any]) -> Optional[str]:
    if m.res in ("W", "WK"):
        return "home"
    if m.res in ("L", "LK"):
        return "away"
    g = s["goals"]
    return "home" if g["home"] > g["away"] else "away" if g["away"] > g["home"] else None


def _ref(m: "R.Match", frame: "R.Frame") -> Dict[str, Any]:
    """Karta meczu; bez wyniku ZPRP - wynik z protokołu (`score_source: "proel"`)."""
    ref = R.match_ref(m, frame)
    s = frame.proel.get(m.match_id)
    if m.sh is None and s:
        ref.update(score_home=s["goals"]["home"], score_away=s["goals"]["away"], score_source="proel")
    return ref


def _minute(t: Any) -> int:
    return int(t) // 60_000 + 1


def _usable(m: "R.Match") -> bool:
    """Rozegrany (bez walkowera) albo jeszcze bez wyniku ZPRP - wtedy wynik daje protokół."""
    return m.counted or (not m.played and not m.withdrawn and not m.walkover)


def aggregate(frame: "R.Frame", scope: "R.Scope") -> Dict[str, Any]:
    ms = R.scoped(frame, scope)
    played = [m for m in ms if m.counted or (_usable(m) and m.match_id in frame.proel)]
    items = [(frame.proel[m.match_id], m) for m in played if m.match_id in frame.proel]
    n = len(items)
    minutes = [0] * 60
    halves = [0, 0]
    sev_a = sev_g = susp = pp = sh = w_own = w_opp = 0
    to_n = to_b = to_a = to_pos = 0
    lead = ties = 0
    first_n = first_w = ht_n = ht_w = comebacks = 0
    biggest = None
    backs: List[Tuple[int, str, "R.Match"]] = []
    runs, best5 = [], []
    for s, m in items:
        for i, v in enumerate(s["minutes"]):
            minutes[i] += v
        halves[0] += s["halves"][0]
        halves[1] += s["halves"][1]
        sev_a += s["sevens"][0]
        sev_g += s["sevens"][1]
        susp += s["susp"]
        pp += s["pp"][0]
        sh += s["pp"][1]
        w_own += s["window"][0]
        w_opp += s["window"][1]
        to_n += s["to"][0]
        to_b += s["to"][1]
        to_a += s["to"][2]
        to_pos += s["to"][3]
        lead += s["lead_changes"]
        ties += s["ties"]
        win = _winner(m, s)
        if win and s.get("first"):
            first_n += 1
            first_w += 1 if s["first"][0] == win else 0
        if win and s.get("ht"):
            ht_n += 1
            ht_w += 1 if s["ht"] == win else 0
        if win:
            d = s["deficit"][win]
            if d >= COMEBACK_MIN:
                comebacks += 1
                backs.append((d, win, m))
                if biggest is None or d > biggest[0]:
                    biggest = (d, win, m)
        if s.get("run"):
            runs.append((s["run"], m))
        if s.get("best5"):
            best5.append((s["best5"], m))
    goals = sum(minutes)
    by_cat: Dict[str, List[int]] = {}
    for m in played:
        row = by_cat.setdefault(m.comp.key, [0, 0])
        row[1] += 1
        row[0] += 1 if m.match_id in frame.proel else 0
    runs.sort(key=lambda x: (-x[0][1], x[0][3] - x[0][2], x[1].match_id))
    best5.sort(key=lambda x: (-x[0][1], x[1].match_id))
    return {
        "matches": n,
        "coverage": {"protocols": n, "played_matches": len(played), "pct": R.pct(n, len(played)),
                     "by_category": [{"key": k, "label": R.CATEGORY_LABELS[k], "protocols": by_cat[k][0], "played": by_cat[k][1],
                                      "pct": R.pct(by_cat[k][0], by_cat[k][1])} for k in R.CATEGORY_LABELS if k in by_cat]},
        "goals_by_minute": [{"minute": i + 1, "goals": v} for i, v in enumerate(minutes)],
        "goals_by_5min": [{"from": i * 5, "to": i * 5 + 5, "goals": sum(minutes[i * 5:i * 5 + 5])} for i in range(12)],
        "halves": {"first": halves[0], "second": halves[1], "second_pct": R.pct(halves[1], goals)},
        "last5_share_pct": R.pct(sum(minutes[55:]), goals),
        "first5_share_pct": R.pct(sum(minutes[:5]), goals),
        "sevens": {"attempts": sev_a, "goals": sev_g, "pct": R.pct(sev_g, sev_a), "per_match": R.avg(sev_a, n)},
        "suspensions": {"count": susp, "per_match": R.avg(susp, n), "pp_goals": pp, "sh_goals": sh,
                        "pp_goal_pct": R.pct(pp, goals), "window_own": R.avg(w_own, susp), "window_opp": R.avg(w_opp, susp),
                        "pp_per_match": R.avg(pp, n)},
        "timeouts": {"count": to_n, "per_match": R.avg(to_n, n), "before_diff": R.avg(to_b, to_n), "after_diff": R.avg(to_a, to_n),
                     "avg_swing": R.avg(to_a - to_b, to_n), "positive_pct": R.pct(to_pos, to_n)},
        "comebacks": {"matches": comebacks, "pct": R.pct(comebacks, n),
                      "biggest": {"match": _ref(biggest[2], frame), "side": biggest[1], "deficit": biggest[0]} if biggest else None,
                      "top": [{"match": _ref(m, frame), "side": w, "deficit": d}
                              for d, w, m in sorted(backs, key=lambda x: (-x[0], x[2].match_id))[:COMEBACKS_TOP]]},
        "lead_changes_avg": R.avg(lead, n), "ties_avg": R.avg(ties, n),
        "first_goal_winner_pct": R.pct(first_w, first_n),
        "halftime_leader_win_pct": R.pct(ht_w, ht_n),
        "longest_runs": [{"match": _ref(m, frame), "side": r[0], "goals": r[1], "from_minute": _minute(r[2]),
                          "to_minute": _minute(r[3])} for r, m in runs[:R.TOP_N]],
        "best_5min": [{"match": _ref(m, frame), "side": b[0], "goals": b[1], "from_minute": _minute(b[2])}
                      for b, m in best5[:R.TOP_N]],
    }


def records(frame: "R.Frame", scope: "R.Scope") -> List[Dict[str, Any]]:
    items = [(frame.proel[m.match_id], m) for m in R.scoped(frame, scope) if _usable(m) and m.match_id in frame.proel]
    out: List[Dict[str, Any]] = []
    firsts = [(s["first"], m) for s, m in items if s.get("first")]
    if firsts:
        f, m = min(firsts, key=lambda x: (x[0][1], x[1].match_id))
        out.append(R.record("fastest_goal", "Najszybsza bramka meczu", round(f[1] / 1000), "s", _ref(m, frame),
                            side=f[0], minute=_minute(f[1]), detail=L.mmss(f[1]), source="proel"))
    backs = [(s["deficit"][w], w, m) for s, m in items if (w := _winner(m, s)) and s["deficit"][w] >= COMEBACK_MIN]
    if backs:
        d, w, m = max(backs, key=lambda x: (x[0], x[2].match_id))
        out.append(R.record("biggest_comeback", "Największy odrobiony dystans", d, R.plural(d, "bramka", "bramki", "bramek"),
                            _ref(m, frame), side=w, source="proel"))
    five = [(s["best5"], m) for s, m in items if s.get("best5")]
    if five:
        b, m = max(five, key=lambda x: (x[0][1], x[1].match_id))
        out.append(R.record("most_goals_5min", "Najwięcej bramek w 5 minut", b[1], R.plural(b[1], "bramka", "bramki", "bramek"),
                            _ref(m, frame), side=b[0], minute=_minute(b[2]), source="proel"))
    runs = [(s["run"], m) for s, m in items if s.get("run")]
    if runs:
        r, m = max(runs, key=lambda x: (x[0][1], -(x[0][3] - x[0][2]), x[1].match_id))
        out.append(R.record("longest_run", "Najdłuższa seria bramek z rzędu", r[1], R.plural(r[1], "bramka", "bramki", "bramek"),
                            _ref(m, frame), side=r[0], minute=_minute(r[2]),
                            detail=f"{L.mmss(r[2])}-{L.mmss(r[3])}", source="proel"))
    late = [(s["decider"], m) for s, m in items if s.get("decider") and m.res in ("W", "L") and s["decider"][0] == _winner(m, s)]
    if late:
        d, m = max(late, key=lambda x: (x[0][1], x[1].match_id))
        out.append(R.record("latest_winner", "Najpóźniejsza zwycięska bramka", _minute(d[1]), "min", _ref(m, frame),
                            side=d[0], minute=_minute(d[1]), detail=L.mmss(d[1]), source="proel"))
    return out


# ---------------------------------------------------------------------------
# Dziś: protokoły w toku i świeżo zakończone
# ---------------------------------------------------------------------------


def _aware(dt: Any) -> Optional[datetime]:
    if isinstance(dt, str) and dt.strip():
        try:
            dt = datetime.fromisoformat(dt.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(dt, datetime):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def phase(row: Dict[str, Any], now: datetime) -> Optional[str]:
    """live | finished | None - ta sama reguła co `/live` (start + leasing albo świeży zapis)."""
    status = row.get("status")
    doc_at = _aware(row.get("doc_at"))
    if status in FINISHED:
        return "finished"
    if row.get("live_started_at") is None:
        return None
    lease = _aware(row.get("lease_until"))
    if (lease and lease > now) or (doc_at and now - doc_at <= LIVE_FRESH):
        return "live"
    return None


def ticker(tl: Dict[str, Any], clock: Dict[str, Any], doc_at: Optional[datetime], limit: int = 6) -> List[Dict[str, Any]]:
    """Ostatnie bramki protokołu z szacowaną chwilą (zapis minus czas gry od bramki)."""
    goals = [e for e in tl.get("events") or [] if e["kind"] in GOAL_KINDS][-limit:]
    saved_ms = clock.get("saved_at_ms") or (int(_aware(doc_at).timestamp() * 1000) if _aware(doc_at) else None)
    main = int(clock.get("main_ms") or 0)
    second = not clock.get("first_half", True)
    out = []
    for g in reversed(goals):
        at = None
        if saved_ms:
            back = max(0, main - int(g["t"]))
            if second and g.get("half") == 1:
                back += HALF_BREAK_MS
            at = datetime.fromtimestamp((saved_ms - back) / 1000, tz=timezone.utc).isoformat()
        out.append({"side": g["side"], "kind": g["kind"], "t_ms": int(g["t"]), "minute": _minute(g["t"]), "clock": L.mmss(g["t"]),
                    "half": g.get("half"), "score": dict(g["score"]), "number": g.get("number"), "at": at})
    return out


def live_minute(clock: Dict[str, Any]) -> Optional[int]:
    main = clock.get("main_ms")
    return _minute(main) if main else None

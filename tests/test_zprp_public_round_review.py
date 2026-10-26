"""Przegląd kolejki: ruchy w tabeli kolejka po kolejce i statystyki kolejki (czyste reguły).

Zgłoszenie z 26.10.2026 (Superliga, zakładka Kolejka): „Ruchy w tabeli" pokazywały
kreskę przy każdej drużynie. Serwer liczył miejsca, ale pod `previous_position`,
a portal czytał `previous` - każde porównanie wychodziło „bez zmian". Teraz
odpowiedź niesie oba pola, status ruchu i punkty zdobyte w kolejce.
"""

from app.zprp_public import round_review_rules as RV


def _m(mid, day, home, away, sh, sa, **extra):
    return {"match_id": mid, "matchday_id": day, "home_team_id": home, "away_team_id": away,
            "home_team_name": home.upper(), "away_team_name": away.upper(), "home_club_id": f"c-{home}",
            "away_club_id": f"c-{away}", "score_home": sh, "score_away": sa, "scheduled_at": f"2026-10-0{day[-1]} 18:00", **extra}


DAYS = [
    {"matchday_id": "D3", "round_id": "R1", "number": 3, "sequence": 3, "name": "Seria 3", "starts_on": "2026-10-03"},
    {"matchday_id": "D1", "round_id": "R1", "number": 1, "sequence": 1, "name": "Seria 1", "starts_on": "2026-10-01"},
    {"matchday_id": "D2", "round_id": "R1", "number": 2, "sequence": 2, "name": "Seria 2", "starts_on": "2026-10-02"},
]
ORDER = RV.day_order(DAYS)
TEAMS = [{"team_id": t, "team_name": t.upper()} for t in ("a", "b", "c", "d")]
MATCHES = [
    _m("1", "D1", "a", "b", 30, 20),
    _m("2", "D1", "c", "d", 25, 24),
    _m("3", "D2", "b", "c", 28, 27),
    _m("4", "D2", "d", "a", 30, 22),
    _m("5", "D3", "a", "c", 26, 26, shootout_home=3, shootout_away=4),
    _m("6", "D3", "b", "d", 31, 21),
]


def _moves(day, **kw):
    return {m["team_id"]: m for m in RV.table_moves(MATCHES, ORDER, day, 3, TEAMS, **kw)}


def test_kolejnosc_kolejek_z_sekwencji_a_bez_niej_z_nazwy():
    assert ORDER == {"D1": 0, "D2": 1, "D3": 2}
    days = [{"matchday_id": "x", "round_id": "R", "sequence": None, "name": "Seria 10"},
            {"matchday_id": "y", "round_id": "R", "sequence": None, "name": "Seria 9"}]
    assert RV.day_order(days) == {"y": 0, "x": 1}
    # Druga runda (później w kalendarzu) po pierwszej, choć w bazie stoi wcześniej.
    days = [{"matchday_id": "p1", "round_id": "PO", "sequence": 1, "name": "1/2", "starts_on": "2027-04-01"},
            {"matchday_id": "s1", "round_id": "RS", "sequence": 1, "name": "Seria 1", "starts_on": "2026-09-01"}]
    assert RV.day_order(days) == {"s1": 0, "p1": 1}


def test_pierwsza_kolejka_bez_porownania():
    moves = _moves("D1")
    assert all(m["previous_position"] is None and m["previous"] is None and m["delta"] is None for m in moves.values())
    assert {m["status"] for m in moves.values()} == {"new"}
    assert moves["a"]["position"] == 1 and moves["a"]["points_gained"] == 3
    assert moves["b"]["position"] == 4 and moves["b"]["round_results"][0]["code"] == "L"


def test_miejsca_po_kolejce_kontra_poprzednia():
    # Po 1.: a(3, +10), c(3, +1), d(0, -1), b(0, -10).
    # Po 2.: wszyscy po 3 pkt, mecze bezpośrednie nie rozstrzygają -> różnica: d +7, a +2, c 0, b -9.
    two = _moves("D2")
    assert [two[t]["position"] for t in "dacb"] == [1, 2, 3, 4]
    assert (two["d"]["previous"], two["d"]["delta"], two["d"]["status"]) == (3, 2, "up")
    assert (two["a"]["delta"], two["a"]["status"]) == (-1, "down")
    assert (two["c"]["previous_position"], two["c"]["delta"]) == (2, -1)
    assert (two["b"]["delta"], two["b"]["status"], two["b"]["points_gained"]) == (0, "same", 3)
    assert two["d"]["form"] == ["L", "W"] and two["d"]["points_before"] == 0


def test_rzuty_karne_2_1_i_kody_bez_remisu():
    three = _moves("D3")
    # c wygrywa karne z a: c +2, a +1; b wygrywa z d +3.
    assert three["c"]["points_gained"] == 2 and three["a"]["points_gained"] == 1
    assert three["c"]["round_results"][0]["code"] == "WK" and three["a"]["round_results"][0]["code"] == "LK"
    assert three["a"]["record"] == {"w": 1, "wk": 0, "lk": 1, "l": 1}
    assert three["c"]["form"] == ["W", "L", "WK"]


def test_liga_za_2_punkty():
    rows = RV.build_table([_m("1", "D1", "a", "b", 20, 19)], 2)
    assert [(r["team_id"], r["points"]) for r in rows] == [("a", 2), ("b", 0)]
    assert RV.match_points({"score_home": 20, "score_away": 20}, 2) == (1, 1)


def test_remis_punktowy_rozstrzyga_mecz_bezposredni_przed_roznica_bramek():
    # x i y po 3 pkt; y ma dużo lepszą różnicę bramek, ale x wygrał mecz bezpośredni.
    ms = [_m("1", "D1", "x", "y", 25, 24), _m("2", "D1", "y", "q", 40, 10),
          _m("3", "D1", "w", "x", 20, 10), _m("4", "D1", "w", "q", 20, 19)]
    rows = {r["team_id"]: r for r in RV.build_table(ms, 3)}
    assert rows["x"]["points"] == rows["y"]["points"] == 3 and rows["y"]["goal_difference"] > rows["x"]["goal_difference"]
    assert [r["team_id"] for r in sorted(rows.values(), key=lambda r: r["position"])] == ["w", "x", "y", "q"]
    # Trójka z tą samą liczbą punktów: mini-tabela ich meczów (różnica y +19, x -9, z -10).
    tri = [_m("1", "D1", "x", "y", 25, 24), _m("2", "D1", "y", "z", 40, 20), _m("3", "D1", "z", "x", 30, 20)]
    assert [r["team_id"] for r in RV.build_table(tri, 3)] == ["y", "x", "z"]


def test_ex_aequo_wspolne_miejsce_i_druzyny_bez_meczu():
    rows = RV.build_table([_m("1", "D1", "a", "b", 30, 20)], 3, TEAMS)
    pos = {r["team_id"]: r["position"] for r in rows}
    assert pos == {"a": 1, "c": 2, "d": 2, "b": 4}


def test_mecz_bez_kolejki_trafia_do_kolejki_z_daty_i_wycofany_sie_nie_liczy():
    ms = RV.assign_days([{**_m("9", "?", "a", "b", 30, 20), "matchday_id": None, "scheduled_at": "2026-10-02 19:00"}], DAYS)
    assert ms[0]["matchday_id"] == "D2"
    assert not RV.counts({**_m("1", "D1", "a", "b", 30, 20), "withdrawn": True})
    assert RV.counts({**_m("1", "D1", "a", "b", 10, 0), "withdrawn": True, "walkover_team_id": "a"})


def test_grupy_licza_sie_osobno():
    standings = [{"table_id": "T", "group_id": g, "team_id": t} for g, ts in (("A", "ab"), ("B", "cd")) for t in ts]
    group_of = RV.team_groups(standings, {"a", "b", "c", "d"})
    assert group_of["a"] == group_of["b"] != group_of["c"]
    ms = [_m("1", "D1", "a", "b", 20, 10), _m("2", "D1", "c", "d", 10, 20), _m("3", "D1", "a", "c", 10, 30)]
    moves = {m["team_id"]: m for m in RV.table_moves(ms, ORDER, "D1", 3, TEAMS, group_of)}
    assert (moves["a"]["position"], moves["d"]["position"], moves["c"]["position"]) == (1, 1, 2)
    assert moves["a"]["matches"] == 1  # mecz między grupami poza tabelą
    assert RV.team_groups(standings[:2], {"a"}) == {}


def test_statystyki_kolejki():
    rnd = [_m("1", "D2", "a", "b", 30, 20, halftime_home=12, halftime_away=14),
           _m("2", "D2", "c", "d", 26, 26, shootout_home=2, shootout_away=4),
           _m("3", "D2", "e", "f", 25, 31),
           _m("4", "D2", "g", "h", None, None)]
    season = rnd[:3] + [_m("5", "D1", "a", "c", 20, 20, shootout_home=5, shootout_away=4), _m("6", "D1", "b", "d", 22, 20)]
    players = [
        {"player_id": "p1", "name": "Jan A", "team_id": "a", "match_id": "1", "goals": 9, "penalty_attempts": 0, "two_minutes": 0},
        {"player_id": "p2", "name": "Piotr B", "team_id": "f", "match_id": "3", "goals": 9, "penalty_attempts": 3, "two_minutes": 2,
         "team_name": "F"},
        {"player_id": "p3", "name": "Adam C", "team_id": "f", "match_id": "3", "goals": 1, "two_minutes": 3, "team_name": "F"},
    ]
    s = RV.round_stats(rnd, season, players, {"matches": 10, "two_minutes": 40})
    assert (s["matches"], s["goals"], s["avg_goals"]) == (3, 158, 52.67)
    assert (s["home_wins"], s["away_wins"]) == (1, 2)
    assert s["decided"] == {"regular": 2, "shootout": 1, "walkover": 0, "undecided": 0}
    assert s["biggest_win"]["match_id"] == "1" and s["biggest_win"]["margin"] == 10
    assert s["highest_scoring"]["match_id"] == "3" and s["highest_scoring"]["goals"] == 56
    assert s["best_attack"]["team_id"] == "f" and s["best_attack"]["goals"] == 31
    assert s["best_defense"]["team_id"] == "a" and s["best_defense"]["conceded"] == 20
    assert s["team_of_round"]["team_id"] == "a" and s["team_of_round"]["margin"] == 10
    assert [p["player_id"] for p in s["top_scorers"]] == ["p1", "p2", "p3"]  # mniej karnych wyżej
    assert [p["player_id"] for p in s["most_penalised"]] == ["p3", "p2"]
    assert s["team_penalties"][0] == {"team_id": "f", "team_name": "F", "club_id": None, "logo_url": None, "two_minutes": 5}
    assert s["two_minutes"] == 5 and s["protocols"] == 2
    assert s["season"]["matches"] == 5 and s["season"]["avg_goals"] == 48.0
    assert s["compare"]["avg_goals"] == {"round": 52.67, "season": 48.0, "delta": 4.67, "trend": "up"}
    assert s["compare"]["avg_two_minutes"]["trend"] == "down"  # 2,5 na mecz kontra 4 w sezonie
    assert [t["match_id"] for t in s["halftime_turns"]] == ["1"] and s["halftime_turns"][0]["deficit"] == 2
    assert s["protocol"] is None
    empty = RV.round_stats([], [], [])
    assert empty["matches"] == 0 and empty["avg_goals"] is None and empty["biggest_win"] is None and empty["two_minutes"] is None


def _goal(t_min, side, h, a):
    return {"t": int(t_min * 60_000), "kind": "goal", "side": side, "score": {"home": h, "away": a}}


def test_dodatki_z_protokolu_bramki_w_czasie_i_powroty():
    m = _m("1", "D2", "a", "b", 4, 3)
    # Gość prowadzi 3:0, gospodarz odrabia i wygrywa golem w 58. minucie.
    events = [_goal(2, "away", 0, 1), _goal(12, "away", 0, 2), _goal(25, "away", 0, 3), _goal(33, "home", 1, 3),
              _goal(45, "home", 2, 3), _goal(51, "home", 3, 3), _goal(57.5, "home", 4, 3)]
    out = RV.protocol_extras([m], {"1": {"half_ms": 30 * 60_000, "events": events}})
    assert [p["goals"] for p in out["goals_by_period"]] == [1, 1, 1, 1, 1, 2]
    assert (out["goals_by_period"][5]["from"], out["goals_by_period"][5]["to"], out["goals_by_period"][5]["home"]) == (50, 60, 2)
    assert out["comebacks"][0]["deficit"] == 3 and out["comebacks"][0]["team"]["team_id"] == "a"
    assert out["late_winners"][0]["minute"] == 58 and out["lead_changes"] == 1
    assert RV.protocol_extras([m], {}) is None

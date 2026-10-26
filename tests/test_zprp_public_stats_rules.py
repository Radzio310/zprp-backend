"""Ekran „Statystyki" - czyste reguły (stats_rules, stats_proel_rules, stats_today_rules)."""

from datetime import date, datetime, timedelta

import pytest

from app.zprp_public import proel_live_rules as L
from app.zprp_public import stats_proel_rules as P
from app.zprp_public import stats_rules as R
from app.zprp_public import stats_today_rules as TD


# ---------------------------------------------------------------------------
# Klasyfikacja
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,age,key", [
    ("LOTTO Superliga", "1", "OS"),
    ("Superliga Kobiet", "1", "OS"),
    ("Liga Centralna Mężczyzn", "1", "LC"),
    ("I liga mężczyzn", "1", "I"),
    ("II Liga Mężczyzn gr. 4", "1", "II"),
    ("III liga kobiet", "1", "III"),
    ("Śląska Liga Juniorów Młodszych", "3", "Jm"),
    ("Wielkopolska Liga Juniorek", "2", "J"),
    ("Liga Młodzików", "4", "Ml"),
    ("Śląska Liga Dziewcząt", "5", "Ml1213"),
    ("Dzieci 12-13 lat", None, "Ml1213"),
    ("Liga okręgowa mężczyzn", "1", "S"),
    ("Turniej", None, "OTHER"),
    ("Puchar Polski Mężczyzn", "1", "PP"),
    ("Mistrzostwa Polski Juniorów", "2", "MP"),
    ("Superpuchar Polski", "1", "SP"),
])
def test_klucz_kategorii_jak_w_portalu(name, age, key):
    assert R.league_key(name, age) == key


def test_szczebel_centralny_po_kategorii_albo_braku_wojewodztwa():
    assert R.level_of("II", "slaskie") == "central"
    assert R.level_of("J", "slaskie") == "district"
    assert R.level_of("J", "") == "central"


def test_zakres_normalizuje_i_klucz_jest_stabilny():
    a = R.Scope.parse("S1", "k", "J,OS, J", "2", "District", "slaskie,mazowieckie")
    b = R.Scope.parse("S1", "K", "OS,J", "2", "district", "mazowieckie,slaskie")
    assert a == b and a.key() == b.key()
    assert a.categories == ("J", "OS") and a.provinces == ("mazowieckie", "slaskie")
    assert a.without_provinces().provinces == ()
    assert R.Scope.parse().key() == "|||||"
    assert R.Scope.parse(category="XX,YY", province="atlantyda,mordor").key() == R.Scope.parse(category="ZZ", province="x").key()


def test_liczby_po_polsku():
    assert R.plural(1, "bramka", "bramki", "bramek") == "bramka"
    assert R.plural(3, "bramka", "bramki", "bramek") == "bramki"
    assert R.plural(13, "bramka", "bramki", "bramek") == "bramek"
    assert R.plural(22, "bramka", "bramki", "bramek") == "bramki"
    assert R.fmt_int(10000) == "10 000"
    assert R.fmt_dec(1.55, 1) in ("1,6", "1,5")
    assert R.fmt_date(date(2026, 10, 26)) == "26 października"


# ---------------------------------------------------------------------------
# Migawka sezonu
# ---------------------------------------------------------------------------

T0 = datetime(2026, 9, 5, 18, 0)
NAMES = {"t1": "Pogoń Szczecin", "t2": "Wisła Płock", "t3": "Górnik Zabrze", "t4": "Azoty Puławy"}


def _m(mid, comp, h, a, days, sh=None, sa=None, **kw):
    clubs = {"t1": "c1", "t2": "c2", "t3": "c3", "t4": "c4"}
    return {"match_id": mid, "competition_id": comp, "competition_name": None, "match_code": kw.pop("code", None),
            "home_team_id": h, "away_team_id": a, "home_club_id": clubs[h], "away_club_id": clubs[a],
            "home_team_name": NAMES[h], "away_team_name": NAMES[a], "scheduled_at": T0 + timedelta(days=days),
            "score_home": sh, "score_away": sa, "halftime_home": kw.pop("hh", None), "halftime_away": kw.pop("ha", None),
            "shootout_home": kw.pop("soh", None), "shootout_away": kw.pop("soa", None), "winner": kw.pop("winner", None),
            "withdrawn": kw.pop("withdrawn", False), "walkover_team_id": kw.pop("walkover", None),
            "spectators": kw.pop("spectators", None), "referee_1_id": kw.pop("ref", "r1"), "referee_1_name": "Sędzia A",
            "referee_2_id": None, "referee_2_name": None, **kw}


def frame(proel=()):
    comps = [
        {"competition_id": "OS", "name": "Superliga Mężczyzn", "gender": "M", "category": "1", "association_name": "Departament Rozgrywek"},
        {"competition_id": "JS", "name": "Śląska Liga Juniorów", "gender": "M", "category": "2", "association_name": "ŚLĄSKIE"},
        {"competition_id": "JK", "name": "Mazowiecka Liga Juniorek", "gender": "K", "category": "2", "association_name": "MAZOWIECKIE"},
    ]
    assocs = [{"association_id": "12", "name": "ŚLĄSKIE"}, {"association_id": "7", "name": "MAZOWIECKIE"}]
    clubs = [{"club_id": "c1", "association_id": "12", "name": "Klub 1", "logo_url": "https://l/1.png"},
             {"club_id": "c2", "association_id": "7", "name": "Klub 2", "logo_url": None},
             {"club_id": "c3", "association_id": "12", "name": "Klub 3", "logo_url": None},
             {"club_id": "c4", "association_id": None, "name": "Klub 4", "logo_url": None}]
    matches = [
        _m("m1", "OS", "t1", "t2", 0, 30, 25, hh=15, ha=12, spectators=900),
        _m("m2", "OS", "t2", "t1", 7, 28, 28, soh=4, soa=5, hh=14, ha=13),   # gość po karnych
        _m("m3", "OS", "t4", "t1", 8, 20, 31),                              # gospodarz bez województwa
        _m("m4", "JS", "t1", "t3", 1, 40, 22, code="S/J/1"),
        _m("m5", "JS", "t3", "t1", 9, 10, 0, walkover="t3", winner="1"),  # walkower - bez bramek
        _m("m6", "JK", "t2", "t4", 2, None, None),                         # przed nami
        _m("m7", "OS", "t1", "t2", 14, 33, 30, ref="r2"),
    ]
    players = [
        {"player_id": "p1", "team_id": "t1", "competition_id": "OS", "apps": 4, "goals": 30, "penalty_goals": 6, "penalty_attempts": 7,
         "two_minutes": 3, "red_cards": 1, "warnings": 1},
        {"player_id": "p1", "team_id": "t1", "competition_id": "JS", "apps": 1, "goals": 12, "penalty_goals": 0, "penalty_attempts": 0,
         "two_minutes": 0, "red_cards": 0, "warnings": 0},
        {"player_id": "p2", "team_id": "t2", "competition_id": "OS", "apps": 3, "goals": 20, "penalty_goals": 9, "penalty_attempts": 9,
         "two_minutes": 5, "red_cards": 0, "warnings": 2},
    ]
    big = [{"match_id": "m4", "player_id": "p1", "team_id": "t1", "side": "home", "goals": 12, "penalty_goals": 0}]
    f = R.build_frame({"season_id": "S1", "name": "2026/27"}, comps, assocs, clubs, matches, players, big, ["m1", "m4"])
    f.proel = P.link(proel, f)
    return f


def test_wojewodztwo_meczu_centralnego_to_klub_gospodarza():
    f = frame()
    assert f.by_id["m1"].province == "slaskie"
    assert f.by_id["m2"].province == "mazowieckie"
    assert f.by_id["m3"].province == R.UNKNOWN
    assert f.by_id["m4"].province == "slaskie" and f.by_id["m4"].comp.level == "district"
    assert f.by_id["m1"].comp.level == "central"
    assert f.teams["t2"].province == "mazowieckie"


def test_sezon_bilans_bez_remisow_i_walkower_bez_bramek():
    s = R.season_stats(frame(), R.Scope(season_id="S1"))
    t, res = s["totals"], s["results"]
    assert t["matches"] == 7 and t["played"] == 6 and t["remaining"] == 1 and t["walkovers"] == 1
    assert t["goals"] == 30 + 25 + 56 + 51 + 62 + 63
    assert res["decided"] == 6 and res["away_wk"] == 1 and res["home_w"] == 4 and res["away_w"] == 1
    assert res["shootout_pct"] == round(100 / 6, 1)
    assert {h["goals"] for h in s["goals_histogram"]} == {55, 56, 51, 62, 63}
    assert s["highest_scoring"][0]["match_id"] == "m7" and s["biggest_wins"][0]["match_id"] == "m4"
    assert s["top_scorers"][0]["player"]["player_id"] == "p1" and s["top_scorers"][0]["goals"] == 42
    assert s["top_scorers"][0]["player"]["team_name"] == "Pogoń Szczecin"
    assert s["top_seven_m"][0]["player"]["player_id"] == "p2"
    assert s["discipline"]["two_minutes"] == 8 and s["discipline"]["matches_with_lineups"] == 2
    assert s["attendance"]["top"][0]["spectators"] == 900
    assert s["halftime"]["matches"] == 2  # m2 z karnymi też: prowadzący (gosp.) przegrał po karnych
    streak = s["win_streaks"][0]
    assert streak["team"]["team_id"] == "t1" and streak["length"] == 4 and streak["current"] is False
    # Łańcuch wyników wokół serii: W W WK W (seria) L (walkower) W.
    assert streak["form"] == ["W", "W", "WK", "W", "L", "W"] and streak["form_streak"] == [0, 3]
    scatter = {x["team_id"]: x for x in s["teams_scatter"]}
    assert s["teams_scatter"][0]["team_id"] == "t1" and scatter["t1"]["name"] == "Pogoń Szczecin"
    assert all(x["matches"] >= R.MIN_TEAM_MATCHES for x in s["teams_scatter"])
    assert t["referees"] == 2 and t["players"] == 2


def test_okno_serii_dlugiej_i_starej():
    at = datetime(2026, 9, 1)
    res = [(at + timedelta(days=i), str(i), c) for i, c in enumerate(["L", "W", "W", "W", "L", "L", "W"])]
    form, span = R.streak_form(res, limit=5)
    assert form == ["L", "W", "W", "W", "L"] and span == [1, 3]
    long = [(at + timedelta(days=i), str(i), "W") for i in range(20)]
    form, span = R.streak_form(long, limit=12)
    assert len(form) == 12 and span == [0, 11]
    assert R.streak_form([(at, "1", "L")]) == (["L"], None)


def test_sezon_zakres_kategorii_i_wojewodztwa():
    f = frame()
    juniors = R.season_stats(f, R.Scope.parse("S1", category="J"))
    assert juniors["totals"]["matches"] == 3
    assert juniors["top_scorers"][0]["goals"] == 12
    slask = R.season_stats(f, R.Scope.parse("S1", province="slaskie"))
    assert slask["totals"]["matches"] == len([m for m in f.matches if m.province == "slaskie"])
    # Zawodnicy wg własnego klubu: p2 (Klub 2, mazowieckie) wypada.
    assert [x["player"]["player_id"] for x in slask["top_scorers"]] == ["p1"]


def test_geo_suma_wojewodztw_rowna_calosci():
    f = frame()
    g = R.geo_stats(f, R.Scope(season_id="S1"))
    rows = g["provinces"] + ([g["unknown"]] if g["unknown"] else [])
    for k in ("matches", "played", "goals"):
        assert sum(r[k] for r in rows) == g["totals"][k]
    assert len(g["provinces"]) == 16
    slask = next(r for r in g["provinces"] if r["key"] == "slaskie")
    assert slask["clubs"] == 2 and slask["players"] == 1
    assert g["levels"]["central"]["matches"] == 4 and g["levels"]["district"]["matches"] == 3
    only = R.geo_stats(f, R.Scope.parse("S1", province="slaskie"))
    assert [r["key"] for r in only["provinces"]] == ["slaskie"] and only["unknown"] is None
    assert only["totals"]["matches"] == slask["matches"]


def test_trendy_tygodnie_kamienie_milowe_i_prognoza():
    f = frame()
    ms = R.scoped(f, R.Scope(season_id="S1"))
    today = (T0 + timedelta(days=20)).date()
    weekly = R.weekly_series(ms, today)
    assert sum(w["matches"] for w in weekly) == 6
    cum = R.cumulative(f, ms, today)
    assert cum["total_goals"] == 287 and cum["daily"][-1]["cumulative"] == 287
    assert cum["milestones"] == []
    assert cum["next_milestone"]["goals"] == 1000 and cum["next_milestone"]["remaining"] == 713
    assert cum["next_milestone"]["projected_date"] is not None
    assert R.milestone_steps(250_000)[-2:] == [100_000, 200_000]
    assert R.next_milestone(10_000) == 25_000 and R.next_milestone(130_000) == 200_000


def test_kamien_milowy_wskazuje_mecz_z_bramka_nr_n():
    f = frame()
    for m in f.matches:
        if m.counted:
            m.sh = (m.sh or 0) + 200
    cum = R.cumulative(f, R.scoped(f, R.Scope()), date(2027, 1, 1))
    first = cum["milestones"][0]
    assert first["goals"] == 1000
    # m1 255, m4 262, m2 456 (973), m3 251 (1224) -> tysięczna bramka w m3 (m6 bez wyniku, m5 walkower).
    assert first["match"]["match_id"] == "m3"


def test_rekordy_i_ciekawostki_po_polsku():
    f = frame()
    recs = {r["kind"]: r for r in R.match_records(f, R.Scope())}
    assert recs["highest_scoring_match"]["value"] == 63
    assert recs["top_individual_game"]["player"]["player_id"] == "p1"
    assert recs["highest_attendance"]["value"] == 900
    season = R.season_stats(f, R.Scope())
    season["top_scorers"][0]["player"].update(first_name="Jan", last_name="Kowalski")
    trends = {"cumulative": R.cumulative(f, R.scoped(f, R.Scope()), date(2026, 9, 30))}
    facts = R.build_facts(season, trends, None, R.busiest_day(R.scoped(f, R.Scope()), date(2026, 9, 30)), None)
    texts = " ".join(x["text"] for x in facts)
    assert "Jan Kowalski prowadzi w klasyfikacji strzelców: 42 bramki" in texts
    assert "Gospodarze" not in texts  # mniej niż 10 rozstrzygniętych - bez procentów z powietrza
    assert all(set(x) == {"kind", "text", "value", "match_id"} for x in facts)


def test_filtry_licza_mecze_i_zawsze_16_wojewodztw():
    opts = R.filter_options(frame())
    assert {c["key"]: c["matches"] for c in opts["categories"]} == {"OS": 4, "J": 3}
    assert {g["key"] for g in opts["genders"]} == {"M", "K"}
    assert len(opts["provinces"]) == 16
    assert next(l for l in opts["levels"] if l["key"] == "central")["matches"] == 4


# ---------------------------------------------------------------------------
# ProEl
# ---------------------------------------------------------------------------


def _ev(kind, team, t, player=7, half=None):
    return {"type": kind, "team": team, "player": player, "time": t, "half": half or (1 if t <= 1_800_000 else 2)}


def _blob(protocol, host="Pogoń Szczecin", guest="Wisła Płock", **cfg):
    return {"matchConfig": {"hostTeamName": host, "guestTeamName": guest, "halfTime": 30, "matchId": "m1",
                            "hostPlayerCards": [{"number": 7, "fullName": "Tajne Nazwisko"}], **cfg},
            "protocol": protocol}


def test_streszczenie_protokolu_przewaga_czasy_serie():
    protocol = [
        _ev("goal", "guest", 20_000),                 # pierwsza bramka gościa w 1. minucie
        _ev("penalty1", "guest", 100_000),           # gość ukarany 1:40-3:40
        _ev("goal", "host", 110_000),                # bramka w przewadze
        _ev("goal", "host", 130_000),
        _ev("goal", "host", 150_000),                # seria 3
        _ev("penaltyKickMissed", "host", 200_000),
        _ev("teamTime", "guest", 400_000),
        _ev("goal", "guest", 450_000),
        _ev("goal", "guest", 1_700_000),
        _ev("penaltyKickScored", "host", 3_500_000, half=2),
    ]
    tl = L.timeline(_blob(protocol), True)
    s = P.summarize(tl)
    assert s["goals"] == {"home": 4, "away": 3}
    assert sum(s["minutes"]) == 7 and s["minutes"][58] == 1 and s["minutes"][0] == 1
    assert s["halves"] == [6, 1]
    assert s["pp"] == [3, 0] and s["window"] == [0, 3]
    assert s["sevens"] == [2, 1]
    assert s["to"][0] == 1 and s["to"][1] == -3 and s["to"][2] == 1 and s["to"][3] == 1
    assert s["first"] == ["away", 20_000] and s["ht"] is None
    assert s["run"] == ["home", 3, 110_000, 150_000] and s["best5"] == ["home", 3, 110_000]
    assert s["deficit"] == {"home": 1, "away": 2} and s["lead_changes"] == 1
    assert s["decider"] == ["home", 3_500_000] and s["last5"] == 1
    flipped = P.orient(s, False)
    assert flipped["goals"] == {"home": 3, "away": 4} and flipped["first"] == ["home", 20_000]
    assert flipped["run"][0] == "away" and flipped["deficit"] == {"home": 2, "away": 1}


def test_streszczenie_bez_danych_osobowych_i_tylko_publiczne_zakonczone():
    blob = _blob([_ev("goal", "host", 60_000)])
    s = P.protocol_summary(blob, {"status": "finished", "match_number": "S/J/1", "zprp_match_id": None})
    assert s["zid"] == "m1" or s["zid"] is None
    assert "Tajne" not in str(s)
    assert P.protocol_summary(blob, {"status": "in_progress"}) is None
    test = _blob([_ev("goal", "host", 60_000)], isTest=True)
    assert P.protocol_summary(test, {"status": "finished"}) is None


def test_laczenie_po_id_albo_numerze_i_dniu_z_orientacja_zprp():
    tl_blob = _blob([_ev("goal", "host", 60_000), _ev("goal", "host", 120_000)], host="Górnik Zabrze", guest="Pogoń Szczecin")
    s = P.protocol_summary(tl_blob, {"status": "approved", "match_number": "S/J/1"})
    s["zid"] = None
    s["day"] = (T0 + timedelta(days=1)).date().isoformat()
    f = frame([s])
    got = f.proel["m4"]  # m4: T1 (gosp.) - T3; w protokole gospodarzem T3 -> zamiana stron
    assert got["goals"] == {"home": 0, "away": 2}
    wrong_day = dict(s, day="2020-01-01")
    assert frame([wrong_day]).proel == {}


def test_agregat_proel_pierwsza_bramka_i_pokrycie():
    s = P.protocol_summary(_blob([_ev("goal", "host", 60_000), _ev("goal", "guest", 70_000), _ev("goal", "host", 3_000_000)]),
                           {"status": "finished", "match_number": "X", "zprp_match_id": "m1"})
    f = frame([s])
    agg = P.aggregate(f, R.Scope())
    assert agg["matches"] == 1 and agg["coverage"]["played_matches"] == 5
    assert agg["first_goal_winner_pct"] == 100.0
    assert sum(x["goals"] for x in agg["goals_by_minute"]) == 3
    recs = {r["kind"]: r for r in P.records(f, R.Scope())}
    assert recs["fastest_goal"]["detail"] == "01:00" and recs["latest_winner"]["minute"] == 51
    juniors = P.aggregate(f, R.Scope.parse(category="J"))
    assert juniors["matches"] == 0 and juniors["coverage"]["pct"] == 0.0
    assert agg["comebacks"]["top"] == []


def test_agregat_proel_powroty_top():
    # Gość prowadzi 3:0, gospodarz wygrywa 4:3 (m1: wynik ZPRP 30:25 dla gospodarza).
    evs = [_ev("goal", "guest", 60_000 + i * 10_000) for i in range(3)] + [_ev("goal", "host", 900_000 + i * 60_000) for i in range(4)]
    s = P.protocol_summary(_blob(evs), {"status": "finished", "match_number": "X", "zprp_match_id": "m1"})
    agg = P.aggregate(frame([s]), R.Scope())
    top = agg["comebacks"]["top"]
    assert agg["comebacks"]["matches"] == 1 and len(top) == 1
    assert top[0]["match"]["match_id"] == "m1" and top[0]["side"] == "home" and top[0]["deficit"] == 3


def test_faza_jak_live():
    now = datetime(2026, 10, 26, 15, 0).astimezone()
    assert P.phase({"status": "finished"}, now) == "finished"
    assert P.phase({"status": "in_progress", "live_started_at": None}, now) is None
    assert P.phase({"status": "in_progress", "live_started_at": now, "lease_until": now + timedelta(seconds=30)}, now) == "live"
    assert P.phase({"status": "in_progress", "live_started_at": now, "doc_at": now - timedelta(hours=1)}, now) is None


# ---------------------------------------------------------------------------
# Dziś
# ---------------------------------------------------------------------------


def _item(mid, comp, province, sh=None, sa=None, phase=None, live=None, at=None, source="zprp", lineup=None, ticker=()):
    card = {"match_id": mid, "home_team_name": "A", "away_team_name": "B", "home_team_id": "t1", "away_team_id": "t2",
            "scheduled_at": at or datetime(2026, 10, 26, 12, 0), "score_home": sh, "score_away": sa,
            "score_source": source if sh is not None else None, "withdrawn": False, "competition_id": comp.competition_id}
    return {"card": card, "comp": comp, "province": province, "phase": phase, "live_score": live,
            "clock": {"main_ms": 2_400_000, "label": "40:00"} if phase == "live" else None,
            "lineup": lineup or {"source": None, "players": []}, "ticker": list(ticker)}


def test_dzis_jedno_zrodlo_bramek_na_mecz():
    f = frame()
    os_, js = f.comps["OS"], f.comps["JS"]
    now = datetime(2026, 10, 26, 15, 0)
    items = [
        _item("a", os_, "slaskie", 30, 28, lineup={"source": "zprp", "players": [
            {"player_id": "p1", "number": 7, "side": "home", "team_id": "t1", "goals": 9, "penalty_goals": 2, "two_minutes": 2,
             "red": 0, "warnings": 1}]}),
        _item("b", js, "slaskie", 20, 10, phase="finished", source="proel"),
        _item("c", js, "slaskie", phase="live", live={"home": 12, "away": 11},
              ticker=[{"side": "home", "kind": "goal", "t_ms": 2_390_000, "minute": 40, "clock": "39:50", "half": 2,
                       "score": {"home": 12, "away": 11}, "number": 7, "at": "2026-10-26T13:59:00+00:00"}],
              lineup={"source": "proel", "players": [{"player_id": None, "number": 7, "side": "home", "team_id": "t1",
                                                      "goals": 5, "penalty_goals": 0, "two_minutes": 1, "red": 1, "warnings": 0}]}),
        _item("d", js, "mazowieckie", at=datetime(2026, 10, 26, 18, 0)),
        _item("e", js, "slaskie", at=datetime(2026, 10, 26, 0, 0)),
    ]
    out = TD.compute_today(items, R.Scope(), f, now)
    assert out["counts"] == {"total": 5, "played": 2, "live": 1, "upcoming": 2, "pending": 0, "no_hour": 1, "withdrawn": 0}
    assert out["goals"]["total"] == 58 + 30 + 23 and out["goals"]["live"] == 23
    assert out["goals"]["sources"] == {"zprp": 1, "proel": 1, "proel_live": 1}
    assert out["goals"]["avg_per_match"] == 44.0
    assert out["highest_scoring"]["match_id"] == "a" and out["biggest_win"]["match_id"] == "b"
    assert [s["goals"] for s in out["top_scorers"]] == [9, 5] and out["top_scorers"][1]["player"] is None
    assert out["discipline"] == {"two_minutes": 3, "red_cards": 1, "warnings": 1, "matches_counted": 2}
    assert out["ticker"][0]["match"]["match_id"] == "c" and out["ticker"][0]["live"] is True
    assert [l["match_id"] for l in out["live"]] == ["c"] and out["live"][0]["minute"] == 41
    assert sum(r["matches"] for r in out["by_province"]) == 5
    by_hour = {h["hour"]: h for h in out["goals_by_hour"]}
    assert by_hour[12]["matches"] == 3 and by_hour[12]["played"] == 2 and by_hour[12]["live"] == 1
    assert by_hour[18]["played"] == 0 and by_hour[18]["live"] == 0 and 0 not in by_hour
    maz = TD.compute_today(items, R.Scope.parse(province="mazowieckie"), f, now)
    assert maz["counts"]["total"] == 1 and maz["goals"]["total"] == 0
    assert out["comparison"]["yesterday"]["date"] == "2026-10-25"

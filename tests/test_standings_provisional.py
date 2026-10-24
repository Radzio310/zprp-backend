"""Wstępne przeliczenie tabeli po wyniku skróconym + limit odświeżeń (czyste reguły, bez bazy)."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import standings_provisional as SP


def _row(tid, name, m, w, d, l, gf, ga, pts):
    return {"team_id": tid, "team_name": name, "matches": m, "wins": w, "draws": d, "losses": l,
            "goals_for": gf, "goals_against": ga, "goal_difference": gf - ga, "points": pts}


def _table():
    # Cztery drużyny, 3 pkt za wygraną: A 6, B 4, C 3, D 1 (suma zgodna z meczami).
    return [
        _row("A", "Alfa", 2, 2, 0, 0, 60, 40, 6),
        _row("B", "Beta", 2, 1, 1, 0, 50, 45, 4),
        _row("C", "Gamma", 2, 1, 0, 1, 48, 50, 3),
        _row("D", "Delta", 2, 0, 1, 1, 40, 63, 1),
    ]


def test_wygrana_dolicza_mecz_punkty_i_bramki():
    out = SP.apply_result(_table(), "C", "B", 30, 25)
    c = next(r for r in out if r["team_id"] == "C")
    b = next(r for r in out if r["team_id"] == "B")
    assert (c["matches"], c["wins"], c["points"], c["goals_for"], c["goals_against"]) == (3, 2, 6, 78, 75)
    assert (b["matches"], b["losses"], b["points"], b["goal_difference"]) == (3, 1, 4, 0)
    assert c["provisional"] and b["provisional"]


def test_zmiana_miejsca_po_wyniku():
    rows = SP.apply_result(_table(), "C", "B", 30, 25)
    ranked = SP.rank(rows, [])
    pos = {r["team_id"]: r["position"] for r in ranked}
    # C ma 6 pkt jak A: bilans ogólny A (+20) kontra C (+3) - A pierwsza, C druga, B trzecia.
    assert pos == {"A": 1, "C": 2, "B": 3, "D": 4}


def test_remis_nierozstrzygniety_to_wspolne_miejsce():
    rows = [_row("A", "Alfa", 1, 1, 0, 0, 20, 10, 3), _row("B", "Beta", 1, 1, 0, 0, 20, 10, 3),
            _row("C", "Gamma", 1, 0, 0, 1, 10, 20, 0), _row("D", "Delta", 1, 0, 0, 1, 10, 20, 0)]
    ranked = SP.rank(rows, [])
    assert [r["position"] for r in ranked] == [1, 1, 3, 3]


def test_mecze_bezposrednie_przed_bilansem():
    # Równe punkty; X ma gorszy bilans ogólny, ale wygrał mecz bezpośredni z Y.
    rows = [_row("X", "Xi", 3, 2, 0, 1, 50, 50, 6), _row("Y", "Ypsilon", 3, 2, 0, 1, 70, 50, 6)]
    matches = [{"home_team_id": "X", "away_team_id": "Y", "score_home": 21, "score_away": 20}]
    ranked = SP.rank(rows, matches)
    assert [r["team_id"] for r in ranked] == ["X", "Y"]
    assert [r["position"] for r in ranked] == [1, 2]


def test_remis_w_meczu_to_punkt_dla_obu_a_karne_dwa_i_jeden():
    rows = SP.apply_result(_table(), "C", "D", 25, 25)
    assert next(r for r in rows if r["team_id"] == "C")["points"] == 4
    assert next(r for r in rows if r["team_id"] == "D")["points"] == 2
    karne = SP.apply_result(_table(), "C", "D", 25, 25, shootout=(4, 3))
    assert next(r for r in karne if r["team_id"] == "C")["points"] == 5
    assert next(r for r in karne if r["team_id"] == "D")["points"] == 2


def test_system_dwa_punkty_wnioskowany_z_tabeli():
    rows = [_row("A", "A", 2, 2, 0, 0, 40, 30, 4), _row("B", "B", 2, 1, 0, 1, 35, 35, 2),
            _row("C", "C", 2, 0, 0, 2, 25, 35, 0)]
    assert SP.win_points(rows) == 2
    assert SP.win_points(_table()) == 3
    out = SP.apply_result(rows, "C", "B", 30, 20)
    assert next(r for r in out if r["team_id"] == "C")["points"] == 2


def test_poprawka_wyniku_cofa_poprzedni():
    # C wygrało 30:25 z B (już liczone), sędzia poprawia na 25:30.
    counted = SP.apply_result(_table(), "C", "B", 30, 25)
    fixed = SP.apply_result(counted, "C", "B", 25, 30, previous=(30, 25))
    c = next(r for r in fixed if r["team_id"] == "C")
    assert (c["matches"], c["wins"], c["losses"], c["points"]) == (3, 1, 2, 3)
    assert (c["goals_for"], c["goals_against"]) == (73, 80)


def _overlay(base_rows, **kw):
    by = {r["team_id"]: r for r in base_rows}
    ov = {"match_id": "m1", "competition_id": "k1", "home_team_id": "C", "away_team_id": "B",
          "score_home": 30, "score_away": 25, "shootout_home": None, "shootout_away": None,
          "prev_home": None, "prev_away": None,
          "base_json": json.dumps(SP.signature(by, "C", "B")),
          "created_at": datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)}
    ov.update(kw)
    return ov


NOW = datetime(2026, 10, 24, 12, 30, tzinfo=timezone.utc)


def test_nakladka_obowiazuje_dopoki_zprp_nie_przeliczylo():
    base = _table()
    ov = _overlay(base)
    ranked, applied = SP.provisional_group(base, [], [ov], NOW)
    assert applied and all(r.get("provisional") for r in ranked if r["team_id"] in ("C", "B"))
    # ZPRP przeliczyło: mecze C wzrosły - nakładka przestaje obowiązywać, bez podwójnego liczenia.
    official = SP.apply_result(base, "C", "B", 30, 25)
    again, applied2 = SP.provisional_group(official, [], [ov], NOW)
    assert not applied2 and again == official


def test_nakladka_wygasa_po_ttl_i_bez_druzyny_w_tabeli():
    base = _table()
    ov = _overlay(base)
    assert not SP.overlay_active(ov, {r["team_id"]: r for r in base}, NOW + timedelta(hours=49))
    assert not SP.overlay_active(ov, {"C": base[2]}, NOW)


def test_parse_wyniku_skroconego():
    assert SP.parse_short_result({"wynik_gosp_full": "30", "wynik_gosc_full": "25"}) == {
        "home": 30, "away": 25, "shootout_home": None, "shootout_away": None}
    assert SP.parse_short_result({"wynik_gosp_full": "30", "wynik_gosc_full": ""}) is None
    assert SP.parse_short_result({"widzowie": "100"}) is None
    assert SP.parse_short_result({"wynik_gosp_full": "20", "wynik_gosc_full": "20",
                                  "dogrywka_karne_gosp": "4", "dogrywka_karne_gosc": "3"})["shootout_home"] == 4


# --- limit odświeżeń ---------------------------------------------------------


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.mark.asyncio
async def test_jedno_odswiezenie_ligi_na_dwie_minuty():
    clock = Clock()
    gate = SP.RefreshGate(clock)
    calls = []

    async def fetch():
        calls.append(clock.t)

    first = await gate.run("liga", fetch, 120)
    assert first.ran and not first.throttled
    clock.t += 60
    second = await gate.run("liga", fetch, 120)
    assert second.throttled and not second.ran
    clock.t += 61
    third = await gate.run("liga", fetch, 120)
    assert third.ran
    assert len(calls) == 2
    # inna liga nie jest blokowana
    assert (await gate.run("inna", fetch, 120)).ran


@pytest.mark.asyncio
async def test_rownolegle_wywolania_czekaja_na_jedno_pobranie():
    gate = SP.RefreshGate(Clock())
    started = asyncio.Event()
    release = asyncio.Event()
    calls = []

    async def fetch():
        calls.append(1)
        started.set()
        await release.wait()

    t1 = asyncio.create_task(gate.run("liga", fetch, 120))
    await started.wait()
    t2 = asyncio.create_task(gate.run("liga", fetch, 120))
    t3 = asyncio.create_task(gate.run("liga", fetch, 120))
    await asyncio.sleep(0)
    release.set()
    r1, r2, r3 = await asyncio.gather(t1, t2, t3)
    assert len(calls) == 1
    assert r1.ran and r2.throttled and r3.throttled


@pytest.mark.asyncio
async def test_nieudane_pobranie_nie_otwiera_okna():
    clock = Clock()
    gate = SP.RefreshGate(clock)

    async def boom():
        raise RuntimeError("zprp 500")

    res = await gate.run("liga", boom, 120)
    assert res.error and res.ran
    ok = []

    async def fine():
        ok.append(1)

    assert (await gate.run("liga", fine, 120)).ran and ok


def test_auto_wybiera_ligi_po_meczu_i_pilnuje_15_minut():
    now = datetime(2026, 10, 24, 18, 0)
    matches = [
        {"competition_id": "k1", "scheduled_at": datetime(2026, 10, 24, 15, 0)},   # skończony
        {"competition_id": "k2", "scheduled_at": datetime(2026, 10, 24, 17, 30)},  # trwa
        {"competition_id": "k3", "scheduled_at": datetime(2026, 10, 24, 9, 0)},    # za dawno (9 h)
        {"competition_id": "k4", "scheduled_at": datetime(2026, 10, 24, 14, 0)},   # świeżo pobrany
    ]
    ages = {"k4": 300.0}
    got = SP.pick_auto_competitions(matches, now, lambda cid: ages.get(cid))
    assert got == ["k1"]
    ages["k4"] = 1000.0
    assert SP.pick_auto_competitions(matches, now, lambda cid: ages.get(cid)) == ["k1", "k4"]

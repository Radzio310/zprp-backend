"""Bilans w czterech stanach (Z/Zk/Pk/P): piłka ręczna nie zna remisu."""

from app.zprp_public import match_rules as MR
from app.zprp_public import portal_rules as R


def _m(h, a, sh, sa, **kw):
    return {"home_team_id": h, "away_team_id": a, "score_home": sh, "score_away": sa, **kw}


def test_wynik_druzyny_w_czterech_stanach():
    assert MR.team_result_detail(_m("a", "b", 30, 20), "a") == "W"
    assert MR.team_result_detail(_m("a", "b", 30, 20), "b") == "L"
    so = _m("a", "b", 25, 25, shootout_home=3, shootout_away=4)
    assert (MR.team_result_detail(so, "a"), MR.team_result_detail(so, "b")) == ("LK", "WK")
    # Walkower: zwycięstwo/porażka w regulaminowym trybie, nawet bez wyniku.
    wo = _m("a", "b", None, None, walkover_team_id="b", winner="1")
    assert (MR.team_result_detail(wo, "a"), MR.team_result_detail(wo, "b")) == ("W", "L")
    # Równy wynik bez serii karnych w danych: nierozstrzygnięty (nigdy „remis").
    assert MR.team_result_detail(_m("a", "b", 22, 22), "a") is None
    assert MR.team_result_detail(_m("a", "b", None, None), "a") is None
    assert MR.team_result_detail(_m("a", "b", 30, 20), "x") is None


def test_bilans_i_punkty():
    rec = MR.tally_results(["W", "WK", None, "LK", "L", "W", "D"])
    assert rec == {"w": 2, "wk": 1, "lk": 1, "l": 1}
    assert MR.record_points(rec) == 3 * 2 + 2 + 1
    assert [MR.basic_result(c) for c in ("W", "WK", "LK", "L", None)] == ["W", "W", "L", "L", None]


def test_team_record_karne_to_nie_remis():
    matches = [
        _m("a", "b", 30, 20, scheduled_at=1),
        _m("c", "a", 25, 25, shootout_home=3, shootout_away=5, scheduled_at=2),  # Zk
        _m("a", "d", 28, 28, shootout_home=2, shootout_away=4, scheduled_at=3),  # Pk
        _m("a", "e", 10, 12, scheduled_at=4),
        _m("a", "f", 20, 20, scheduled_at=5),  # bez karnych w danych
    ]
    rec = R.team_record(matches, lambda side, m: m[f"{side}_team_id"] == "a")
    assert rec["record"] == {"w": 1, "wk": 1, "lk": 1, "l": 1}
    assert (rec["wins_regular"], rec["wins_shootout"], rec["losses_shootout"], rec["losses_regular"]) == (1, 1, 1, 1)
    # Stare pola (zgodność): karne liczą się do zwycięstw/porażek, `draws` to tylko nierozstrzygnięte.
    assert (rec["played"], rec["wins"], rec["draws"], rec["losses"]) == (5, 2, 1, 2)
    assert rec["form"] == ["W", "W", "L", "L", "D"]
    assert rec["form_detail"] == ["W", "WK", "LK", "L"]
    assert rec["win_rate"] == 0.4


def test_kolumny_karnych_w_wierszu_tabeli():
    assert MR.explicit_shootout_columns({"ZwyciestwaKarne": "2", "PrzegraneKarne": "1", "BramkiKarne": "40"}) == (2, 1)
    assert MR.explicit_shootout_columns('{"wygrane_po_karnych": 1, "porazki_po_karnych": 0}') == (1, 0)
    assert MR.explicit_shootout_columns({"Zwyciestwa": "5", "Remisy": "1"}) is None
    assert MR.explicit_shootout_columns(None) is None


def test_bilans_tabeli_z_kolumn_meczow_i_punktow():
    # Źródło podaje karne w „Remisach", a osobne kolumny je rozbijają.
    row = {"wins": 4, "draws": 2, "losses": 1, "matches": 7, "points": 15,
           "extra_json": {"ZwyciestwaKarne": 1, "PrzegraneKarne": 1}}
    assert MR.standing_record(row) == {"w": 4, "wk": 1, "lk": 1, "l": 1, "source": "zprp"}
    # Bez kolumn: rozbicie z meczów drużyny w rozgrywkach.
    row = {"wins": 4, "draws": 2, "losses": 1, "matches": 7, "points": 16}
    counted = {"played": 7, "w": 4, "wk": 2, "lk": 0, "l": 1}
    assert MR.standing_record(row, counted) == {"w": 4, "wk": 2, "lk": 0, "l": 1, "source": "matches"}
    # Mecze niepełne: rozbicie z punktów 3/2/1/0 (16 = 3*4 + 2*2 + 0).
    assert MR.standing_record(row, {"played": 3, "w": 1, "wk": 1, "lk": 0, "l": 1}) == \
        {"w": 4, "wk": 2, "lk": 0, "l": 1, "source": "points"}
    # Punkty nie pasują do systemu 3/2/1/0 i brak meczów: nie zgadujemy.
    assert MR.standing_record({"wins": 4, "draws": 2, "losses": 1, "matches": 7, "points": 9}) is None
    # Źródło wlicza karne do zwycięstw/porażek („Remisy" = 0): odejmujemy policzone z meczów.
    row = {"wins": 5, "draws": 0, "losses": 2, "matches": 7, "points": 16}
    assert MR.standing_record(row, {"played": 7, "w": 4, "wk": 1, "lk": 1, "l": 1}) == \
        {"w": 4, "wk": 1, "lk": 1, "l": 1, "source": "matches"}
    # Brak karnych i brak meczów: W/L wprost ze źródła.
    assert MR.standing_record({"wins": 3, "draws": 0, "losses": 2, "matches": 5, "points": 9}) == \
        {"w": 3, "wk": 0, "lk": 0, "l": 2, "source": "zprp"}


def test_liczenie_bilansu_druzyn_z_meczow():
    matches = [
        _m("a", "b", 30, 20),
        _m("b", "a", 25, 25, shootout_home=4, shootout_away=3),
        _m("a", "c", 20, 20),  # nierozstrzygnięty - nie wchodzi
        _m("a", "c", 20, 10, withdrawn=True),  # wycofanie bez walkowera - nie wchodzi
    ]
    out = MR.count_team_results(matches)
    assert out["a"] == {"played": 2, "w": 1, "wk": 0, "lk": 1, "l": 0}
    assert out["b"] == {"played": 2, "w": 0, "wk": 1, "lk": 0, "l": 1}
    assert "c" not in out

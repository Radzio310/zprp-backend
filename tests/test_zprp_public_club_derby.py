"""Derby klubu (dwie drużyny tego samego klubu): hero i listy mówią to samo.

Mecz dwóch drużyn klubu leżał na liście „Rozegrane” (`match_counts.played`),
ale `team_record` go pomijał - liczba w hero bywała niższa. Teraz derby to
jeden rozegrany mecz klubu, bez wpływu na bilans W/WK/LK/L, bramki i formę.
"""

from datetime import date, datetime, timedelta

from app.zprp_public import portal_rules as R


def _at(days: int) -> datetime:
    return datetime.combine(date.today() + timedelta(days=days), datetime.min.time()) + timedelta(hours=18)


def _cards():
    return [
        {"scheduled_at": _at(-10), "home_club_id": "k", "away_club_id": "x", "home_team_id": "k1", "away_team_id": "x1", "score_home": 30, "score_away": 20},
        # derby: k2 (klub k) - k1 (klub k)
        {"scheduled_at": _at(-7), "home_club_id": "k", "away_club_id": "k", "home_team_id": "k2", "away_team_id": "k1", "score_home": 25, "score_away": 27},
        {"scheduled_at": _at(-3), "home_club_id": "y", "away_club_id": "k", "home_team_id": "y1", "away_team_id": "k2", "score_home": 31, "score_away": 22},
        {"scheduled_at": _at(5), "home_club_id": "k", "away_club_id": "k", "home_team_id": "k1", "away_team_id": "k2", "score_home": None, "score_away": None},
    ]


def _club(side: str, m: dict) -> bool:
    return m.get(f"{side}_club_id") == "k"


def test_derby_klubu_liczy_sie_raz_w_rozegranych():
    cards = _cards()
    rec = R.team_record(cards, _club)
    counts = R.match_counts(cards, datetime.now())
    assert rec["played"] == counts["played"] == 3
    assert rec["derbies"] == 1


def test_derby_poza_bilansem_bramkami_i_forma():
    rec = R.team_record(_cards(), _club)
    assert rec["record"] == {"w": 1, "wk": 0, "lk": 0, "l": 1}
    assert (rec["wins"], rec["losses"], rec["draws"]) == (1, 1, 0)
    assert (rec["goals_for"], rec["goals_against"]) == (52, 51)
    assert rec["form_detail"] == ["W", "L"]
    # Średnie i odsetek zwycięstw z meczów z bilansem (2), nie z 3 rozegranych.
    assert rec["win_rate"] == 0.5 and rec["avg_goals_for"] == 26.0
    # Derby gra klub-gospodarz: dom 2 (w tym derby), wyjazd 1.
    assert (rec["home_played"], rec["away_played"]) == (2, 1)


def test_druzyna_bez_derbow_bez_zmian():
    rec = R.team_record(_cards(), lambda side, m: m.get(f"{side}_team_id") == "k1")
    assert rec["played"] == 2 and rec["derbies"] == 0
    assert rec["record"] == {"w": 2, "wk": 0, "lk": 0, "l": 0}


def test_same_derby_bez_bilansu():
    rec = R.team_record([_cards()[1]], _club)
    assert rec["played"] == 1 and rec["derbies"] == 1
    assert rec["win_rate"] is None and rec["avg_goals_for"] is None and rec["form"] == []

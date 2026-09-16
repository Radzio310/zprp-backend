"""Wnioski z analizy w Automacie (`app/insights_policy.py`)."""
from __future__ import annotations

from types import SimpleNamespace

from app import insights_policy as P


def need(**values):
    base = {"difficulty": 0.8, "tier": 0.55, "category": "Junior", "host": "MKS Ruda", "guest": "Grunwald"}
    base.update(values)
    return SimpleNamespace(**base)


ANALYSIS = {
    "meta": {"predict_threshold": 0.6},
    "judges": [
        {"judge_id": "1", "field": 40, "dominant": {"category": "Junior", "share": 0.7}, "top_tier": 0.55, "hard_share": 0.4, "peer_share": 0.15},
        {"judge_id": "2", "field": 5, "young": True, "top_tier": 0.25, "hard_share": 0.0, "peer_share": 0.15},
        {"judge_id": "3", "field": 30, "top_tier": 0.7, "hard_share": 0.1, "peer_share": 0.15},
    ],
    "conclusions": [
        {"key": "experience_before_hard", "rule": {"params": {"min_field_matches": 20}}},
        {"key": "category_specialization", "rule": {"params": {"min_share": 0.55}}},
        {"key": "stable_pairs", "affected": {"pairs": [{"a": "1", "b": "3"}]}, "rule": {"params": {}}},
        {"key": "team_repetition", "rule": {"params": {"max_per_team": 3}}},
        {"key": "development_path", "affected": {"growing": [{"judge_id": "2"}]}, "rule": {"params": {"max_step": 0.15}}},
        {"key": "fair_hard_share", "rule": {"params": {}}},
        {"key": "mentors", "affected": {"mentors": [{"judge_id": "3"}], "candidates": []}, "rule": {"params": {}}},
    ],
}


def policy(**modes):
    rules = {key: {"enabled": True, "mode": mode, "strength": 100} for key, mode in modes.items()}
    return P.build_policy(ANALYSIS, rules, current_season_field=[("1", "MKS Ruda", "X"), ("1", "MKS Ruda", "Y"), ("1", "Z", "MKS Ruda")])


def test_bez_wybranych_wnioskow_automat_bez_zmian():
    assert P.build_policy(ANALYSIS, {}) is None
    assert P.build_policy(ANALYSIS, {"mentors": {"enabled": False, "mode": "hard"}}) is None


def test_twarde_zasady_z_powodem():
    rules = policy(
        experience_before_hard="hard",
        team_repetition="hard",
        development_path="hard",
        fair_hard_share="hard",
        mentors="hard",
    )
    assert rules.refuse("2", need(), kind="field", partner_id=None, round_no=1) == "za mało meczów przed trudnym (5 z 20)"
    assert rules.refuse("1", need(), kind="field", partner_id=None, round_no=1) == "już 3 mecze drużyny MKS Ruda w sezonie"
    assert rules.refuse("2", need(difficulty=0.1, tier=0.55), kind="field", partner_id=None, round_no=1) == "za wysoki szczebel na teraz"
    assert rules.refuse("2", need(difficulty=0.1, tier=0.25), kind="field", partner_id="1", round_no=1) == "młody sędzia tylko z mentorem"
    assert rules.refuse("2", need(difficulty=0.1, tier=0.25), kind="field", partner_id="3", round_no=1) is None
    # stolik nie podlega wnioskom o boisku
    assert rules.refuse("2", need(), kind="table", partner_id=None, round_no=1) is None


def test_sprawdzona_para_tylko_w_pierwszym_obiegu():
    rules = policy(stable_pairs="hard")
    assert rules.refuse("2", need(), kind="field", partner_id="1", round_no=1) == "na trudny mecz najpierw sprawdzona para"
    assert rules.refuse("2", need(), kind="field", partner_id="1", round_no=2) is None
    assert rules.refuse("3", need(), kind="field", partner_id="1", round_no=1) is None


def test_punkty_przechylaja_i_mowia_dlaczego():
    rules = policy(category_specialization="points", stable_pairs="points", mentors="points", fair_hard_share="points")
    delta, why = rules.points("1", need(), kind="field", partner_id="3", round_no=1)
    assert delta < 0 or "więcej trudnych niż grupa" in why
    assert "specjalizacja: Junior" in why and "sprawdzona para" in why
    young_delta, young_why = rules.points("2", need(difficulty=0.1), kind="field", partner_id="3", round_no=1)
    assert young_delta < 0 and "para z mentorem młodego" in young_why


def test_licznik_druzyny_rosnie_po_przydziale():
    rules = policy(team_repetition="hard")
    assert rules.refuse("3", need(), kind="field", partner_id=None, round_no=1) is None
    for _ in range(3):
        rules.note_assigned("3", need(), kind="field")
    assert rules.refuse("3", need(), kind="field", partner_id=None, round_no=1).startswith("już 3 mecze")


def test_ustawienia_obsadowego_wygrywaja_z_analiza():
    rules = P.build_policy(
        ANALYSIS,
        {"experience_before_hard": {"enabled": True, "mode": "hard", "params": {"min_field_matches": 3}}},
    )
    assert rules.refuse("2", need(), kind="field", partner_id=None, round_no=1) is None
    assert P.normalize_rule({"mode": "cos", "strength": 999}) == {"enabled": False, "mode": "points", "strength": 100, "params": {}}

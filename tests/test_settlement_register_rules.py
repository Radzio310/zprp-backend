# -*- coding: utf-8 -*-
"""
Rejestr oficjalnych dokumentów rozliczeń (06.10.2026).

Zgłoszenie Wojtka Kaszni: księgowa chce ciągłej numeracji, a każde kliknięcie
„Zestawienie" zużywało numer. Teraz szkic nie ma numeru, oficjalny dostaje
numer ciągły w roku (z podpowiedzią i ręczną zmianą), a część puli sędziego
może stać tylko na jednym oficjalnym dokumencie.
"""
from __future__ import annotations

from app import settlement_register_rules as G


def test_numer_ciagly_w_roku_z_podpowiedzia():
    assert G.number_text("SL", 2026, 10, 14) == "SL/10/2026/14"
    assert G.number_prefix("SL", 2026, 3) == "SL/03/2026/"
    assert G.suggest_seq([]) == 1
    assert G.suggest_seq([1, 2, 5]) == 6
    # Kontynuacja roku z ustawień: ręcznie wydano już 13 dokumentów.
    assert G.suggest_seq([], start_after=13) == 14
    assert G.suggest_seq([14, 15], start_after=13) == 16
    # Usunięcie ostatniego zwalnia numer.
    assert G.suggest_seq([1, 2]) == 3


def test_reczny_numer_nie_moze_byc_zajety():
    assert G.seq_problem(7, [1, 2, 3]) is None
    assert "już w rejestrze" in G.seq_problem(2, [1, 2, 3])
    assert G.seq_problem(0, []) is not None
    assert G.seq_problem("abc", []) is not None
    assert G.seq_problem(G.MAX_SEQ + 1, []) is not None


DOCS = [
    {"number": "SL/10/2026/3", "items": [{"judge_id": "10", "part": "A"}, {"judge_id": "11", "part": ""}]},
]


def test_zajetosc_czesci_i_calej_puli():
    taken = G.taken_map(DOCS)
    assert G.taken_by("10", "A", taken) == "SL/10/2026/3"
    assert G.taken_by("10", "B", taken) is None
    # Cała pula sędziego 10 jest zablokowana jego częścią A.
    assert G.taken_by("10", "", taken) == "SL/10/2026/3"
    # Cała pula sędziego 11 blokuje każdą jego część.
    assert G.taken_by("11", "A", taken) == "SL/10/2026/3"
    assert G.taken_by("12", "", taken) is None
    assert G.judge_view(taken) == {"10": {"A": "SL/10/2026/3"}, "11": {"": "SL/10/2026/3"}}


def test_oficjalny_pomija_zajete_szkic_tylko_oznacza():
    taken = G.taken_map(DOCS)
    candidates = [
        {"judge_id": "10", "part": "A"},
        {"judge_id": "10", "part": "B"},
        {"judge_id": "12", "part": ""},
    ]
    items, skipped = G.select_items(candidates, taken, skip_taken=True)
    assert [(i["judge_id"], i["part"]) for i in items] == [("10", "B"), ("12", "")]
    assert skipped == [{"judge_id": "10", "part": "A", "taken_by": "SL/10/2026/3"}]

    items, skipped = G.select_items(candidates, taken, skip_taken=False)
    assert len(items) == 3 and not skipped
    assert items[0]["taken_by"] == "SL/10/2026/3"
    assert "taken_by" not in items[1]


def test_wybor_czesci_od_sedziego():
    assert G.wanted_parts(["A", "B"], None) == ["A", "B"]
    assert G.wanted_parts(["A", "B"], ["a"]) == ["A"]
    assert G.wanted_parts(["A", "B"], []) == []
    assert G.wanted_parts(["A", "B"], ["C"]) == []


def test_kara_schodzi_najpierw_z_czesci_a():
    parts = [{"letter": "A", "net": 264.0}, {"letter": "B", "net": 77.44}]
    assert G.allocate_penalty(parts, 0) == {"A": 0.0, "B": 0.0}
    assert G.allocate_penalty(parts, 50) == {"A": 50.0, "B": 0.0}
    assert G.allocate_penalty(parts, 300) == {"A": 264.0, "B": 36.0}
    # Więcej niż netto wszystkich części - nadwyżka zostaje na A.
    assert G.allocate_penalty(parts, 400) == {"A": 322.56, "B": 77.44}


def test_dopisek_czesci():
    assert G.part_label("A", 2) == "część A z 2"
    assert G.part_label("", 0) == ""

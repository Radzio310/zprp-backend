"""Dziennik meczu o badaniach - po ludzku i z nazwiskiem.

„Zmiana pól: badania zawodnika nr 77 (gospodarzy)" mówiła, KTÓRE pole się
zmieniło, ale nie KOGO to dotyczy ani skąd przyszło. Trzy zdarzenia badań
mają to powiedzieć jednym zdaniem.
"""
from __future__ import annotations

from app.proel_journal import (
    EVENT_LABELS,
    event_summary,
    exam_events_from_ops,
    exam_players_sentence,
)


def test_exam_events_have_labels():
    assert EVENT_LABELS["exam.confirmed"] == "Potwierdzenie badań"
    assert EVENT_LABELS["exam.withdrawn"] == "Cofnięcie potwierdzenia badań"
    assert EVENT_LABELS["exam.promoted"] == "Badania potwierdzone przez ZPRP"


def test_players_sentence_names_number_person_and_side():
    players = [
        {"team": "host", "number": 77, "name": "GAKIDOVA Ivana"},
        {"team": "guest", "number": "3", "name": ""},
        {"team": "", "number": "", "name": ""},
    ]
    assert exam_players_sentence(players) == "nr 77 GAKIDOVA Ivana (gospodarzy), nr 3 (gości)"
    assert exam_players_sentence(None) == ""


def test_confirmation_says_where_it_was_made():
    d = {"players": [{"team": "host", "number": 77, "name": "GAKIDOVA Ivana"}], "source": "config"}
    assert event_summary("exam.confirmed", d) == (
        "Potwierdzono ręcznie: nr 77 GAKIDOVA Ivana (gospodarzy) - w ekranie konfiguracji"
    )
    d["source"] = "sheet"
    assert event_summary("exam.withdrawn", d).startswith("Cofnięto potwierdzenie: nr 77 GAKIDOVA Ivana (gospodarzy) - w arkuszu")
    # Bez listy zawodników zdanie nadal jest zdaniem, nie pustką.
    assert event_summary("exam.confirmed", {}) == "Potwierdzono ręcznie badania"


def test_promotion_says_who_replaced_whom():
    d = {"players": [{"team": "host", "number": 77, "name": "GAKIDOVA Ivana", "from": "manual", "to": "zprp"}]}
    assert event_summary("exam.promoted", d) == (
        "Baza związku potwierdziła badania: nr 77 GAKIDOVA Ivana (gospodarzy) - ręczny znacznik zastąpiony"
    )


def test_patch_ops_become_exam_events_only_when_they_are_all_exams():
    ops = [
        ("exam.host.#77", {"mark": "manual", "name": "GAKIDOVA Ivana"}),
        ("exam.guest.#3", {"mark": "none", "name": "NOWAK Anna"}),
    ]
    events = exam_events_from_ops(ops)
    assert [e for e, _ in events] == ["exam.confirmed", "exam.withdrawn"]
    assert events[0][1] == {
        "players": [{"team": "host", "number": "77", "name": "GAKIDOVA Ivana"}],
        "source": "sheet",
    }
    # Patch mieszany zostaje ogólną „Zmianą pól".
    assert exam_events_from_ops(ops + [("sig.team.host", "podpis")]) == []
    assert exam_events_from_ops([("cos.nowego", {})]) == []
    assert exam_events_from_ops([]) == []

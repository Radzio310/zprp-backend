"""Formularze okręgowe - pytanie „Terminy” (24.11.2026): schemat, odpowiedzi, pełne terminy, propozycja przydziału."""
from __future__ import annotations

import pytest

from app import district_form_export as X
from app import district_form_schema as SC
from app import district_form_slots as SLOTS
from app.district_forms_rules import FormError


def slots_question(mode="optimize", **extra):
    q = {
        "id": "dyzur",
        "type": "slots",
        "title": "Dyżur przy stoliku",
        "slot_mode": mode,
        "slots": [
            {"id": "a", "start": "2026-11-27T14:00", "end": "2026-11-27T16:00", "capacity": 2},
            {"id": "b", "start": "2026-11-27T16:00", "capacity": 1},
            {"id": "c", "start": "2026-11-28T10:00", "capacity": 1},
        ],
    }
    q.update(extra)
    return q


def schema(q):
    return SC.clean_form_schema({"sections": [{"id": "s1", "questions": [q]}]})


def question(q):
    return SC.questions(SC.sections_of(schema(q)))[0]


# --- schemat --------------------------------------------------------------


def test_schema_keeps_slots_and_defaults():
    out = schema(slots_question())
    q = out["sections"][0]["questions"][0]
    assert q["slot_mode"] == "optimize"
    assert [x["id"] for x in q["slots"]] == ["a", "b", "c"]
    assert q["slots"][1]["end"] is None


@pytest.mark.parametrize(
    "change, needle",
    [
        ({"slots": []}, "co najmniej jeden termin"),
        ({"slots": [{"id": "a", "start": "2026-11-27T14:00"}, {"id": "a", "start": "2026-11-28T14:00"}]}, "identyfikator"),
        ({"slots": [{"id": "a", "start": "2026-11-27T14:00", "end": "2026-11-27T13:00"}]}, "przed początkiem"),
        ({"slots": [{"id": "a", "start": "2026-11-27T14:00"}, {"id": "b", "start": "2026-11-27T14:00"}]}, "dwa razy"),
        ({"slots": [{"id": "a", "start": "2026-02-30T14:00"}]}, "nie ma"),
        ({"slot_max_per_person": 5}, "limit terminów"),
    ],
)
def test_schema_rejects(change, needle):
    with pytest.raises(FormError) as caught:
        schema(slots_question(**change))
    assert needle in caught.value.message


def test_schema_rejects_bad_mode_and_capacity():
    with pytest.raises(FormError):
        schema(slots_question(mode="lottery"))
    with pytest.raises(FormError):
        schema(slots_question(slots=[{"id": "a", "start": "2026-11-27T14:00", "capacity": 0}]))


def test_slot_label_polish():
    assert SC.slot_label({"start": "2026-11-27T14:00", "end": "2026-11-27T16:00"}) == "pt. 27.11, 14:00-16:00"
    assert SC.slot_label({"start": "2026-11-29T09:05"}) == "niedz. 29.11, 09:05"


# --- odpowiedzi -------------------------------------------------------------


def check(q, value):
    sections = SC.sections_of(schema(q))
    return SC.check_answers(sections, {"dyzur": value})


def test_answer_sorted_and_deduplicated():
    clean, errors = check(slots_question(), ["c", "a", "a"])
    assert errors == {}
    assert clean["dyzur"] == ["a", "c"]


def test_answer_unknown_slot():
    _clean, errors = check(slots_question(), ["zzz"])
    assert "odśwież" in errors["dyzur"]


def test_answer_wrong_shape():
    _clean, errors = check(slots_question(), {"a": True})
    assert errors["dyzur"] == "Zaznacz terminy."


def test_first_come_limit_per_person():
    _clean, errors = check(slots_question("first_come", slot_max_per_person=1), ["a", "b"])
    assert errors["dyzur"] == "Zapisać się można najwyżej na 1 termin."
    _clean, errors = check(slots_question("first_come", slot_max_per_person=2), ["a", "b", "c"])
    assert errors["dyzur"] == "Zapisać się można najwyżej na 2 terminy."


def test_optimize_has_no_pick_limit():
    _clean, errors = check(slots_question(slot_max_per_person=1), ["a", "b", "c"])
    assert errors == {}


def test_required_empty():
    _clean, errors = check(slots_question(required=True), [])
    assert errors["dyzur"] == "To pytanie jest obowiązkowe."


def test_terms_word():
    assert [SC.terms_word(n) for n in (1, 2, 5, 12, 22, 25)] == ["termin", "terminy", "terminów", "terminów", "terminy", "terminów"]


def test_answer_text_and_stats():
    q = question(slots_question())
    assert SC.answer_text(q, ["a", "c"]) == "pt. 27.11, 14:00-16:00; sob. 28.11, 10:00"
    stat = SC.question_stat(q, [{"dyzur": ["a"]}, {"dyzur": ["a", "b"]}, {}])
    assert stat["kind"] == "slots" and stat["answered"] == 2
    assert [(x["id"], x["count"], x["capacity"]) for x in stat["slots"]] == [("a", 2, 2), ("b", 1, 1), ("c", 0, 1)]


# --- kto pierwszy, ten lepszy -------------------------------------------------


def test_full_conflicts_only_new_picks():
    q = question(slots_question("first_come"))
    taken = {"a": 2, "b": 0}
    assert SLOTS.full_conflicts(q, ["a", "b"], [], taken) == ["a"]
    # Już trzymany termin zostaje, nawet jeśli dziś jest pełny.
    assert SLOTS.full_conflicts(q, ["a", "b"], ["a"], taken) == []
    assert "chwilę przed Tobą" in SLOTS.full_message(q, ["a"])


def test_full_conflicts_ignored_in_optimize():
    q = question(slots_question())
    assert SLOTS.full_conflicts(q, ["a"], [], {"a": 99}) == []


def test_occupancy_order_and_unknown():
    q = question(slots_question("first_come"))
    occ = SLOTS.occupancy(q, [("j1", {"dyzur": ["a", "zzz"]}), ("j2", {"dyzur": ["a"]}), ("j3", {})])
    assert occ == {"a": ["j1", "j2"], "b": [], "c": []}


# --- propozycja przydziału ---------------------------------------------------------


def test_propose_covers_every_slot():
    out = SLOTS.propose([("a", 2), ("b", 1), ("c", 1)], {"j1": ["a", "b", "c"], "j2": ["a"], "j3": ["c"], "j4": ["a", "b"]})
    assert out["missing"] == {}
    assert sorted(len(v) for v in out["assign"].values()) == [1, 1, 2]
    assert max(out["load"].values()) == 1


def test_propose_balances_load():
    # Dwie osoby mogą wszędzie, cztery terminy po jednej osobie: po dwa terminy na głowę, nie 3+1.
    out = SLOTS.propose([("a", 1), ("b", 1), ("c", 1), ("d", 1)], {"j1": ["a", "b", "c", "d"], "j2": ["a", "b", "c", "d"]})
    assert out["load"] == {"j1": 2, "j2": 2}


def test_propose_rare_person_goes_where_only_they_can():
    out = SLOTS.propose([("a", 1), ("b", 1)], {"j1": ["a", "b"], "j2": ["a"]})
    assert out["assign"] == {"a": ["j2"], "b": ["j1"]}


def test_propose_reports_missing():
    out = SLOTS.propose([("a", 3), ("b", 1)], {"j1": ["a"], "j2": ["a"]})
    assert out["missing"] == {"a": 1, "b": 1}


def test_propose_respects_max_per_person():
    out = SLOTS.propose([("a", 1), ("b", 1), ("c", 1)], {"j1": ["a", "b", "c"]}, max_per_person=2)
    assert out["load"] == {"j1": 2}
    assert sum(out["missing"].values()) == 1


def test_propose_deterministic_and_ignores_unknown():
    avail = {"j2": ["a", "x"], "j1": ["a"], "j3": ["x"]}
    first = SLOTS.propose([("a", 1)], avail)
    assert first == SLOTS.propose([("a", 1)], dict(reversed(list(avail.items()))))
    assert "j3" not in first["load"]


def test_propose_scales():
    slots = [(f"s{i}", 2) for i in range(40)]
    avail = {f"j{p}": [f"s{i}" for i in range(40) if (i + p) % 3] for p in range(60)}
    out = SLOTS.propose(slots, avail)
    assert out["missing"] == {}
    loads = list(out["load"].values())
    assert max(loads) - min(loads) <= 1


# --- plan komisji ---------------------------------------------------------------


def test_clean_assign():
    q = question(slots_question())
    assert SLOTS.clean_assign(q, {"a": ["j1", "j1", "j2"]}, {"j1", "j2"}) == {"a": ["j1", "j2"], "b": [], "c": []}
    with pytest.raises(SLOTS.PlanError, match="spoza"):
        SLOTS.clean_assign(q, {"a": ["obcy"]}, {"j1"})
    with pytest.raises(SLOTS.PlanError, match="za dużo"):
        SLOTS.clean_assign(q, {"b": ["j1", "j2"]}, {"j1", "j2"})
    with pytest.raises(SLOTS.PlanError, match="nie ma"):
        SLOTS.clean_assign(q, {"zzz": []}, {"j1"})


def test_per_person_and_push_text():
    q = question(slots_question())
    mine = SLOTS.per_person(q, {"c": ["j1"], "a": ["j1", "j2"]})
    assert mine == {"j1": ["a", "c"], "j2": ["a"]}
    _title, body = SLOTS.push_text("Turniej", q, ["a"])
    assert body == "Twój termin: pt. 27.11, 14:00-16:00."
    _title, body = SLOTS.push_text("Turniej", q, ["a", "c"])
    assert body.startswith("Twoje terminy: ")


def test_export_adds_assignment_column():
    raw = schema(slots_question())
    responses = [{"answers": {"dyzur": ["a", "b"]}, "name": "Jan", "judge_id": "j1", "submitted_at": None}]
    plans = {"dyzur": {"assign": {"b": ["j1"]}, "approved_at": "2026-11-24T10:00:00+00:00"}}
    header, rows = X.form_table(raw, responses, with_person=True, plans=plans)
    assert header[-1] == "Przydział: Dyżur przy stoliku"
    assert rows[0][-1] == "pt. 27.11, 16:00"
    header, _rows = X.form_table(raw, responses, with_person=True, plans={"dyzur": {"assign": {}, "approved_at": None}})
    assert not header[-1].startswith("Przydział")


def test_plan_changes_first_approval_notifies_everyone():
    q = question(slots_question())
    changed, removed = SLOTS.plan_changes(q, None, {"a": ["j1", "j2"], "c": ["j1"]})
    assert changed == {"j1": ["a", "c"], "j2": ["a"]} and removed == []


def test_plan_changes_only_changed_and_removed():
    q = question(slots_question())
    old = {"a": ["j1", "j2"], "c": ["j3"]}
    new = {"a": ["j1"], "b": ["j4"], "c": ["j3", "j1"]}
    changed, removed = SLOTS.plan_changes(q, old, new)
    assert changed == {"j1": ["a", "c"], "j4": ["b"]}  # j1 dostał dodatkowy termin, j4 nowy
    assert removed == ["j2"]                             # j3 bez zmian


def test_plan_changes_nothing_changed():
    q = question(slots_question())
    same = {"a": ["j1"], "b": ["j2"]}
    assert SLOTS.plan_changes(q, dict(same), dict(same)) == ({}, [])
    assert "zdjęty" in SLOTS.removed_text("Turniej")[1]


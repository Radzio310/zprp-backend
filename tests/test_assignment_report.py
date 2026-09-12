from datetime import datetime

from app.assignment_auto import Gap, MatchNeed, Plan, Proposal
from app.assignment_people import make_judge
from app.assignment_report import build_report, plan_rows, slot_label, why_without_km

JAN = make_judge("1", "KOWALSKI Jan", city="Gliwice", letters=["II"])
ANNA = make_judge("2", "NOWAK Anna", city="Zabrze", letters=["II"])


def need(match_id, code, day="2026-10-05", **rest):
    moment = datetime.fromisoformat(f"{day}T18:00")
    return MatchNeed(
        match_id=match_id,
        code=code,
        moment=moment,
        day=moment.date(),
        host_city=rest.pop("city", "Katowice"),
        host=rest.pop("host", "Gospodarz"),
        guest=rest.pop("guest", "Gość"),
        field_needed=rest.pop("field", ["pierwszy", "drugi"]),
        table_needed=rest.pop("table", []),
        **rest,
    )


def proposal(match_id, code, slot, judge, km, round_no=1):
    return Proposal(
        match_id=match_id,
        code=code,
        slot=slot,
        judge_id=judge.judge_id,
        judge_name=judge.name,
        km=km,
        score=0.0,
        reasons=[f"{km} km"],
        round_no=round_no,
    )


def sample():
    needs = [need("1", "S/JmM/1"), need("2", "S/JmM/2", day="2026-10-12")]
    plan = Plan(
        proposals=[
            proposal("1", "S/JmM/1", "pierwszy", JAN, 20),
            proposal("1", "S/JmM/1", "drugi", ANNA, 40),
            proposal("2", "S/JmM/2", "pierwszy", JAN, 60, round_no=2),
        ],
        gaps=[Gap(match_id="2", code="S/JmM/2", slot="drugi", reason="niedyspozycja (3)")],
    )
    return plan, needs


def test_counts_add_up():
    plan, needs = sample()
    report = build_report(plan, needs, judges={"1": JAN, "2": ANNA})
    assert report["matches"] == 2
    assert report["slots"] == 4
    assert report["filled"] == 3
    assert report["gaps"] == 1
    assert report["rounds"] == {"first": 2, "later": 1}


def test_travel_spread_is_what_the_user_asked_for():
    plan, needs = sample()
    travel = build_report(plan, needs)["travel"]
    assert travel["total"] == 120.0
    assert travel["avg"] == 40.0
    assert travel["max"] == 60.0
    assert travel["min"] == 20.0
    assert travel["unknown"] == 0


def test_unknown_distance_is_counted_not_treated_as_zero():
    needs = [need("1", "S/JmM/1", field=["pierwszy"])]
    plan = Plan(proposals=[proposal("1", "S/JmM/1", "pierwszy", JAN, None)])
    report = build_report(plan, needs)
    assert report["travel"]["unknown"] == 1
    assert report["travel"]["avg"] is None
    assert report["judges"][0]["unknown_km"] == 1


def test_each_judge_has_his_own_line():
    plan, needs = sample()
    report = build_report(plan, needs, judges={"1": JAN, "2": ANNA})
    first = report["judges"][0]
    assert first["name"] == "KOWALSKI Jan"       # dwa mecze, wiec na gorze
    assert first["matches"] == 2
    assert first["city"] == "Gliwice"
    assert first["km"]["avg"] == 40.0
    assert first["days"] == ["2026-10-05", "2026-10-12"]


def test_matches_already_held_count_to_the_balance():
    plan, needs = sample()
    report = build_report(plan, needs, load_before={"2": 4})
    rows = {row["judge_id"]: row for row in report["judges"]}
    assert rows["2"]["total"] == 5                # cztery wczesniej, jeden teraz
    assert rows["1"]["total"] == 2
    assert report["balance"] == {"max": 5, "min": 2, "spread": 3}


def test_gaps_carry_their_reason_and_day():
    plan, needs = sample()
    [gap] = build_report(plan, needs)["gaps_detail"]
    assert gap["slot_label"] == "sędzia II"
    assert gap["reason"] == "niedyspozycja (3)"
    assert gap["day"] == "2026-10-12"


def test_competitions_show_where_the_holes_are():
    plan, needs = sample()
    [row] = build_report(plan, needs)["competitions"]
    assert row["key"] == "S"
    assert row["matches"] == 2 and row["filled"] == 3 and row["gaps"] == 1


def test_plan_rows_group_by_match_in_slot_order():
    plan, needs = sample()
    rows = plan_rows(plan, needs)
    assert [row["code"] for row in rows] == ["S/JmM/1", "S/JmM/2"]
    assert [slot["slot"] for slot in rows[0]["slots"]] == ["pierwszy", "drugi"]
    assert rows[0]["host"] == "Gospodarz"
    assert rows[0]["time"] == "18:00"


def test_slot_label_falls_back_to_the_raw_name():
    assert slot_label("sekretarz") == "sekretarz"
    assert slot_label("nieznane") == "nieznane"


def test_reasons_keep_km_but_the_plan_line_does_not_repeat_it():
    # Kilometry stoją w planie osobnym znaczkiem, więc w uzasadnieniu byłyby
    # powtórką: „12 km · dzień preferowany 12 km".
    assert why_without_km(["12 km", "dzień preferowany"]) == ["dzień preferowany"]
    assert why_without_km(["0 km", "miejscowy, brano w ostatniej kolejności"]) == [
        "miejscowy, brano w ostatniej kolejności"
    ]
    assert why_without_km(["45.5 km"]) == []
    # „nie znamy odległości" to powód, nie liczba - zostaje.
    assert why_without_km(["nie znamy odległości"]) == ["nie znamy odległości"]
    # Nazwisko z „km" w środku nie jest odległością.
    assert why_without_km(["para z KM Nowak"]) == ["para z KM Nowak"]


def test_plan_rows_carry_both_lists():
    plan, needs = sample()
    [slot] = [s for s in plan_rows(plan, needs)[0]["slots"] if s["slot"] == "pierwszy"]
    assert slot["reasons"] == ["20 km"]
    assert slot["why"] == []

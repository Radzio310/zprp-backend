from app.delegate_evaluation_comparisons import comparisons_for_form, parameter_key


def form(identifier, grade, *, kind="delegate", pair=("1", "2"), title="Decyzje"):
    return {
        "id": identifier,
        "kind": kind,
        "referee_ids": list(pair),
        "evaluation_json": {
            "sections": [{"key": "I", "mainGrade": grade, "items": [{"title": title, "grade": grade}]}]
        },
    }


def test_parameter_key_ignores_polish_marks_and_punctuation():
    assert parameter_key("  Współpraca — Sędziów! ") == "wspolpraca-sedziow"


def test_current_form_is_excluded_and_three_other_sheets_unlock_delta():
    target = form("current", "E")
    rows = [target, form("a", "D"), form("b", "D"), form("c", "C")]
    result = comparisons_for_form(target, pair_rows=rows)
    overall = result["same_kind"]["pair"]["overall"]
    assert overall == {"average": 3.67, "delta": 1.33, "samples": 3, "available": True}


def test_less_than_three_reference_sheets_is_reported_without_delta():
    target = form("current", "E")
    result = comparisons_for_form(target, pair_rows=[target, form("a", "D"), form("b", "C")])
    assert result["same_kind"]["pair"]["overall"] == {
        "average": None,
        "delta": None,
        "samples": 2,
        "available": False,
    }


def test_same_kind_and_combined_pools_are_separate():
    target = form("current", "G")
    delegates = [form(str(i), "D") for i in range(3)]
    mentors = [form(f"m{i}", "A", kind="mentor") for i in range(3)]
    result = comparisons_for_form(target, pair_rows=[target, *delegates, *mentors], include_combined=True)
    assert result["same_kind"]["pair"]["overall"]["average"] == 4.0
    assert result["combined"]["pair"]["overall"]["average"] == 2.5


def test_pair_district_and_national_scopes_use_their_own_populations():
    target = form("current", "G")
    same_pair = [form(f"p{i}", "E") for i in range(3)]
    district_other_pair = [form(f"d{i}", "D", pair=("3", "4")) for i in range(3)]
    national_other_pair = [form(f"n{i}", "A", pair=("5", "6")) for i in range(3)]
    result = comparisons_for_form(
        target,
        pair_rows=[target, *same_pair, *district_other_pair],
        district_rows=[target, *same_pair, *district_other_pair],
        national_rows=[target, *same_pair, *district_other_pair, *national_other_pair],
    )["same_kind"]
    assert result["pair"]["overall"]["samples"] == 3
    assert result["district"]["overall"]["samples"] == 6
    assert result["national"]["overall"]["samples"] == 9
    assert result["pair"]["overall"]["average"] == 5.0
    assert result["national"]["overall"]["average"] == 3.33

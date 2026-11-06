"""Rules of the home city frozen at the moment of settlement (06.11.2026)."""
from types import SimpleNamespace

from app import settlement_home_lock as HL


def test_apply_locks_restores_frozen_fields_only_for_locked_rows():
    batch = {
        ("1", "d:42"): {"home_city": "Gliwice", "distance_km": 27.0, "distance_source": "google", "city": "Bytom"},
        ("1", "d:43"): {"home_city": "Gliwice", "distance_km": 12.0, "distance_source": "table", "city": "Zabrze"},
    }
    locked = {("1", "d:42"): {"home_city": "Katowice", "distance_km": 14.0, "distance_source": "table"}}
    assert HL.apply_locks(batch, locked) == 1
    assert batch["1", "d:42"] == {"home_city": "Katowice", "distance_km": 14.0, "distance_source": "table", "city": "Bytom"}
    assert batch["1", "d:43"]["home_city"] == "Gliwice"
    # Second pass changes nothing.
    assert HL.apply_locks(batch, locked) == 0


def test_lock_keys_of_skips_empty_and_duplicates():
    matches = [SimpleNamespace(match_key="d:1"), SimpleNamespace(match_key="d:1"), SimpleNamespace(match_key=""), {"match_key": "o:2"}]
    assert HL.lock_keys_of(matches) == ["d:1", "o:2"]


def test_home_story_period_settled_from_previous_city():
    rows = [
        {"home_city": "Katowice", "home_locked": "7/S/2026"},
        {"home_city": "katowice ", "home_locked": "7/S/2026"},
        {"home_city": "", "home_locked": None},
    ]
    story = HL.home_story(rows, "Gliwice")
    assert story["changed"] is True
    assert story["settled"] == "all"
    assert story["current"] == "Gliwice"
    assert story["cities"] == [
        {"city": "Katowice", "matches": 2, "locked": 2, "documents": ["7/S/2026"], "current": False}
    ]


def test_home_story_mixed_period_and_unchanged_city():
    mixed = HL.home_story(
        [{"home_city": "Katowice", "home_locked": "7/S/2026"}, {"home_city": "Gliwice", "home_locked": None}],
        "Gliwice",
    )
    assert mixed["changed"] is True and mixed["settled"] == "some"
    assert [c["current"] for c in mixed["cities"]] == [False, True]

    same = HL.home_story([{"home_city": "Gliwice", "home_locked": None}], "gliwice")
    assert same["changed"] is False and same["settled"] == "none"

    assert HL.home_story([{"home_city": ""}], "Gliwice") is None
    # Unknown current city: nothing to compare, nothing "changed".
    assert HL.home_story([{"home_city": "Katowice"}], "")["changed"] is False

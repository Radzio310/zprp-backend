"""Licznik boisko/stolik w sezonie - reguła z `app/judge_season_load.py`."""
from __future__ import annotations

from datetime import datetime, timezone

from app import judge_season_load as L
from app import settlement_rates as R

NOW = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)


def row(judge, when, code, role):
    return {"judge_id": judge, "match_at": when, "match_code": code, "role": role}


def at(month, day, year=2026):
    return datetime(year, month, day, 18, 0, tzinfo=timezone.utc)


def test_district_field_and_table_are_counted_separately():
    out = L.tally(
        [
            row("5689", at(9, 5), "S/MlK1213/7", R.ROLE_FIELD),
            row("5689", at(9, 6), "S/MlK1213/8", R.ROLE_FIELD),
            row("5689", at(9, 7), "S/MlK1213/9", R.ROLE_TABLE),
        ],
        now=NOW,
    )
    assert out["5689"]["field"] == 2
    assert out["5689"]["table"] == 1


def test_league_table_counts_but_league_field_and_delegate_do_not():
    out = L.tally(
        [
            row("1", at(9, 5), "LCK/6", R.ROLE_TABLE),
            row("1", at(9, 6), "IMD/3", R.ROLE_FIELD),
            row("1", at(9, 7), "IMD/3", R.ROLE_DELEGATE),
            row("1", at(9, 8), "S/MlK1213/7", R.ROLE_DELEGATE),
        ],
        now=NOW,
    )
    assert out["1"] == {"field": 0, "table": 1, "future_field": 0, "future_table": 0}


def test_future_assignments_are_in_the_total_and_marked_separately():
    out = L.tally(
        [
            row("1", at(9, 5), "S/MlK1213/7", R.ROLE_FIELD),
            row("1", at(10, 4), "S/MlK1213/8", R.ROLE_FIELD),
            row("1", at(10, 5), "LCK/6", R.ROLE_TABLE),
        ],
        now=NOW,
    )
    assert out["1"] == {"field": 2, "table": 1, "future_field": 1, "future_table": 1}


def test_previous_season_and_undated_rows_are_skipped():
    out = L.tally(
        [
            row("1", at(5, 10), "S/MlK1213/7", R.ROLE_FIELD),
            row("1", None, "S/MlK1213/7", R.ROLE_FIELD),
            row("", at(9, 5), "S/MlK1213/7", R.ROLE_FIELD),
        ],
        now=NOW,
    )
    assert out == {}


def test_kind_of_matches_the_bucket_rule():
    assert L.kind_of("S/PPK/2", R.ROLE_FIELD) == "field"
    assert L.kind_of("LCK/6", R.ROLE_TABLE) == "table"
    assert L.kind_of("IMD/3", R.ROLE_FIELD) is None

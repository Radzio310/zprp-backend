from datetime import date

import pytest

from app.province_clubs_bulk import (
    BULK_LIMIT,
    clean_club_ids,
    closing_amounts,
    closing_day,
    entry_bucket,
    parse_club_filter,
    settles_since,
)


def test_closing_brings_every_debt_to_zero_and_leaves_overpayment():
    assert closing_amounts({"a": -500, "b": 120, "c": 0}, {}) == {"a": 500.0}


def test_reclosing_adjusts_the_one_existing_entry():
    # Po zamknieciu doszedl mecz za 100 zl - wpis rosnie.
    assert closing_amounts({"a": -100}, {"a": 500}) == {"a": 600.0}
    # Mecz zdjety po zamknieciu - wpis maleje.
    assert closing_amounts({"a": 80}, {"a": 500}) == {"a": 420.0}
    # Nigdy ponizej zera: 0 znaczy, ze wpis znika.
    assert closing_amounts({"a": 900}, {"a": 500}) == {"a": 0.0}


def test_closing_only_the_chosen_clubs():
    assert closing_amounts({"a": -500, "b": -50}, {}, {"b"}) == {"b": 50.0}


def test_closing_entry_is_its_own_bucket():
    assert entry_bucket("in", "season-close") == "settled"
    assert entry_bucket("in", "manual") == "in"
    assert entry_bucket("out", None) == "out"


def test_closing_day_is_season_end_or_today():
    assert closing_day(date(2026, 8, 31), date(2026, 9, 11)) == date(2026, 8, 31)
    assert closing_day(date(2027, 8, 31), date(2026, 9, 11)) == date(2026, 9, 11)


def test_clean_club_ids_drops_blanks_and_duplicates_keeping_order():
    assert clean_club_ids([" 12", "", None, "15", "12", 19]) == ["12", "15", "19"]


def test_clean_club_ids_refuses_empty_selection():
    with pytest.raises(ValueError):
        clean_club_ids([" ", None])
    with pytest.raises(ValueError):
        clean_club_ids(None)


def test_clean_club_ids_caps_one_action():
    assert len(clean_club_ids([str(i) for i in range(BULK_LIMIT)])) == BULK_LIMIT
    with pytest.raises(ValueError):
        clean_club_ids([str(i) for i in range(BULK_LIMIT + 1)])


def test_enabling_clears_the_since_date():
    assert settles_since(True, date(2026, 9, 1), date(2026, 9, 11)) is None


def test_disabling_starts_today_unless_a_day_is_given():
    assert settles_since(False, None, date(2026, 9, 11)) == date(2026, 9, 11)
    assert settles_since(False, date(2026, 9, 1), date(2026, 9, 11)) == date(2026, 9, 1)


def test_parse_club_filter():
    assert parse_club_filter(None) is None
    assert parse_club_filter("") is None
    assert parse_club_filter(" , ") is None
    assert parse_club_filter("12, 15,,19") == {"12", "15", "19"}

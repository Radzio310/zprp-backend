from datetime import date

import pytest

from app.province_clubs_bulk import (
    BULK_LIMIT,
    clean_club_ids,
    parse_club_filter,
    settles_since,
)


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

from datetime import date, datetime, timezone

from app.offtime_rules import (
    busy_minutes_on_day,
    city_at,
    is_available_at,
    match_moment,
    parse_entries,
    as_local,
)


def test_time_with_zone_becomes_polish_wall_clock():
    # 4 pazdziernika Polska ma UTC+2.
    assert as_local("2026-10-04T15:00:00+00:00") == datetime(2026, 10, 4, 17, 0)
    assert as_local("2026-10-04T17:00:00") == datetime(2026, 10, 4, 17, 0)
    assert as_local("") is None


def test_match_time_keeps_its_hour():
    # ⚠ W bazie termin meczu ma tzinfo=UTC, ale niesie godzine POLSKA.
    stored = datetime(2026, 10, 4, 17, 0, tzinfo=timezone.utc)
    assert match_moment(stored) == datetime(2026, 10, 4, 17, 0)


def test_entry_without_end_takes_the_whole_day():
    offtimes, _ = parse_entries([{"from": "2026-10-04T09:00:00"}])
    [off] = offtimes
    assert off.all_day
    assert off.start == datetime(2026, 10, 4, 0, 0)
    assert not is_available_at(offtimes, datetime(2026, 10, 4, 17, 0))


def test_match_entry_blocks_two_hours():
    offtimes, _ = parse_entries([{"from": "2026-10-04T17:00:00", "isMatch": True}])
    assert not is_available_at(offtimes, datetime(2026, 10, 4, 18, 0), tolerance_minutes=0)
    assert is_available_at(offtimes, datetime(2026, 10, 4, 19, 30), tolerance_minutes=0)


def test_tolerance_works_only_at_the_edges():
    offtimes, _ = parse_entries(
        [{"from": "2026-10-04T12:00:00", "to": "2026-10-04T16:00:00"}]
    )
    # Kwadrans przed koncem - zapas wystarcza.
    assert is_available_at(offtimes, datetime(2026, 10, 4, 15, 45), tolerance_minutes=30)
    # Srodek przedzialu przy zwyklym zapasie - zajety.
    assert not is_available_at(offtimes, datetime(2026, 10, 4, 14, 0), tolerance_minutes=30)
    # ⚠ Zapas wiekszy niz polowa przedzialu sprawia, ze KAZDA chwila jest „przy
    # krawedzi" - tak samo liczy to aplikacja i tak ma zostac.
    assert is_available_at(offtimes, datetime(2026, 10, 4, 14, 0), tolerance_minutes=120)


def test_bazowa_with_range_covers_whole_days():
    offtimes, _ = parse_entries(
        [
            {
                "from": "2026-10-01T08:00:00",
                "to": "2026-10-05T10:00:00",
                "category_name": "BAZOWA",
            }
        ]
    )
    [off] = offtimes
    assert off.all_day
    assert off.start.date() == date(2026, 10, 1)
    assert off.end.date() == date(2026, 10, 5)
    assert not is_available_at(offtimes, datetime(2026, 10, 3, 17, 0))


def test_temp_city_wins_for_those_days():
    _, cities = parse_entries(
        [
            {
                "entry_type": "TEMP_CITY",
                "temp_city_name": "Kraków",
                "from": "2026-10-03T00:00:00",
                "to": "2026-10-06T00:00:00",
            }
        ]
    )
    assert city_at("Gliwice", cities, datetime(2026, 10, 4, 17, 0)) == "Kraków"
    assert city_at("Gliwice", cities, datetime(2026, 10, 9, 17, 0)) == "Gliwice"


def test_busy_minutes_for_the_micro_preview():
    offtimes, _ = parse_entries(
        [{"from": "2026-10-04T12:00:00", "to": "2026-10-04T16:00:00"}]
    )
    assert busy_minutes_on_day(offtimes, date(2026, 10, 4)) == 240
    assert busy_minutes_on_day(offtimes, date(2026, 10, 5)) == 0


def test_no_date_means_we_do_not_know_so_free():
    offtimes, _ = parse_entries([{"from": "2026-10-04T09:00:00"}])
    assert is_available_at(offtimes, None)

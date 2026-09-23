"""Grupy sędziów na liście przejazdów - `app/settlement_pdf_groups.py`."""
from __future__ import annotations

from app.settlement_pdf_groups import group_by_judge


def trip(judge, name, km, amount, day="01.09.2026"):
    return {"judge_id": judge, "name": name, "total_km": km, "amount": amount, "day_label": day}


def test_trips_of_one_judge_are_summed_under_him():
    groups = group_by_judge(
        [
            trip("1", "KOWALSKI Jan", 44, 35.2),
            trip("1", "KOWALSKI Jan", 30, 24.0),
            trip("1", "KOWALSKI Jan", 96, 76.8),
            trip("2", "NOWAK Anna", 60, 48.0),
        ]
    )
    assert [g["lp"] for g in groups] == [1, 2]
    assert groups[0]["total_km"] == 170
    assert groups[0]["total_amount"] == 136.0
    assert len(groups[0]["trips"]) == 3
    assert groups[1]["total_amount"] == 48.0


def test_single_trip_judge_still_gets_a_group():
    groups = group_by_judge([trip("7", "LIS Ewa", 10, 8.0)])
    assert groups == [
        {
            "judge_id": "7",
            "name": "LIS Ewa",
            "trips": [trip("7", "LIS Ewa", 10, 8.0)],
            "lp": 1,
            "total_km": 10,
            "total_amount": 8.0,
        }
    ]


def test_scattered_rows_land_in_one_group_in_first_seen_order():
    groups = group_by_judge(
        [
            trip("2", "NOWAK Anna", 10, 8.0, "02.09.2026"),
            trip("1", "KOWALSKI Jan", 20, 16.0),
            trip("2", "NOWAK Anna", 5, 4.0, "09.09.2026"),
        ]
    )
    assert [g["judge_id"] for g in groups] == ["2", "1"]
    assert [t["day_label"] for t in groups[0]["trips"]] == ["02.09.2026", "09.09.2026"]
    assert groups[0]["total_amount"] == 12.0


def test_money_is_rounded_once_per_judge():
    groups = group_by_judge([trip("1", "A", 1, 0.1), trip("1", "A", 1, 0.2)])
    assert groups[0]["total_amount"] == 0.3

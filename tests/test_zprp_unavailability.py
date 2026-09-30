import os
from datetime import date

import pytest

if not os.getenv("DATABASE_URL", "").startswith("postgres"):
    pytest.skip(
        "Import backendu wymaga Postgresa (schemat używa JSONB/UUID).",
        allow_module_level=True,
    )

from app.zprp_unavailability import (
    central_conflicts,
    detect_category,
    render_overlap_email,
)


def test_detect_category_prefers_second_league_over_first_league():
    assert detect_category("IIM4/10") == "IIM"
    assert detect_category("IIK2/3") == "IIK"


def test_central_conflicts_filters_disabled_categories_and_duplicates():
    match = {
        "id": "206769",
        "code": "IIM4/10",
        "startAt": "2026-10-17T16:00:00",
        "home": "Gospodarze",
        "away": "Goście",
        "role": "sędzia 1",
    }
    assert central_conflicts([match, match], ["IIM"]) == [
        {**match, "category": "IIM"}
    ]
    assert central_conflicts([match], ["LCM"]) == []


def test_overlap_email_contains_range_judge_reason_and_match():
    subject, html, text = render_overlap_email(
        {
            "judge_name": "Jan Kowalski",
            "judge_id": "5124",
            "date_from": date(2026, 10, 17),
            "date_to": date(2026, 10, 18),
            "reason": "Wyjazd",
            "matches_json": [
                {
                    "code": "IIM4/10",
                    "category": "IIM",
                    "startAt": "2026-10-17T16:00:00",
                    "home": "Gospodarze",
                    "away": "Goście",
                    "role": "sędzia 1",
                }
            ],
        }
    )
    assert "Jan Kowalski" in subject
    assert "17.10.2026" in html
    assert "IIM4/10" in html
    assert "Wyjazd" in text
    assert "Gospodarze - Goście" in text

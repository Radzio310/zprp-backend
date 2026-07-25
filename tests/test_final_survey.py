import os
from datetime import datetime, timedelta, timezone

import pytest

if not os.getenv("DATABASE_URL", "").startswith("postgres"):
    pytest.skip(
        "Import modułu ankiety inicjalizuje schemat JSONB; test wymaga środowiska Postgres.",
        allow_module_level=True,
    )

from fastapi import HTTPException

from app.beach.final_survey import (
    CORE_QUESTIONS,
    DEFAULT_ROLES,
    SurveyResponseRequest,
    _default_config,
    _normalized_config,
    _phase,
    _question_aggregate,
    _questions,
    _survey_window,
    _user_roles,
    _validate_answers,
)


def _schedule(*matches, slot_interval=40):
    return {
        "schedule": {
            "config": {
                "slotInterval": slot_interval,
                "days": [
                    {"date": "2026-07-25", "startTime": "08:00", "endTime": "20:00"},
                    {"date": "2026-07-26", "startTime": "08:00", "endTime": "20:00"},
                ],
            },
            "matches": list(matches),
        }
    }


def _required_answers():
    return {
        "overall": 8,
        "courts": 4,
        "sand": 4,
        "organization": 5,
        "information": 4,
        "schedule": 4,
        "refereeing": 5,
        "accommodation": "na",
        "catering": "na",
        "return_likelihood": 9,
        "strengths": ["courts"],
        "priorities": ["information", "schedule", "sand"],
    }


def test_default_config_contains_default_roles_and_full_core_template():
    config = _default_config()

    assert config["enabled_roles"] == DEFAULT_ROLES
    assert [question["id"] for question in _questions(config)] == [
        question["id"] for question in CORE_QUESTIONS
    ]


def test_window_uses_warsaw_time_explicit_end_and_slot_fallback():
    data = _schedule(
        {
            "id": "opening",
            "kind": "tournament_opening",
            "dayIndex": 0,
            "startTime": "07:30",
            "endTime": "08:00",
        },
        {
            "id": "m1",
            "dayIndex": 0,
            "startTime": "08:15",
            "endTime": "09:05",
        },
        {
            "id": "m2",
            "dayIndex": 1,
            "startTime": "18:20",
        },
        slot_interval=45,
    )

    opens_at, closes_at = _survey_window({}, data, _default_config())

    # In July Warsaw is UTC+2.
    assert opens_at == datetime(2026, 7, 25, 6, 15, tzinfo=timezone.utc)
    # Last match: 18:20 + 45 minutes, then +48 hours.
    assert closes_at == datetime(2026, 7, 28, 17, 5, tzinfo=timezone.utc)


def test_window_handles_match_ending_after_midnight():
    data = _schedule(
        {
            "id": "late",
            "dayIndex": 0,
            "startTime": "23:45",
            "endTime": "00:30",
        },
    )

    opens_at, closes_at = _survey_window({}, data, _default_config())

    assert opens_at == datetime(2026, 7, 25, 21, 45, tzinfo=timezone.utc)
    assert closes_at == datetime(2026, 7, 27, 22, 30, tzinfo=timezone.utc)


def test_window_without_real_matches_returns_waiting_state():
    data = _schedule(
        {
            "id": "break",
            "kind": "court_break",
            "dayIndex": 0,
            "startTime": "09:00",
            "endTime": "09:30",
        },
    )

    assert _survey_window({}, data, _default_config()) == (None, None)


def test_window_applies_editable_relative_availability():
    data = _schedule(
        {
            "id": "m1",
            "dayIndex": 0,
            "startTime": "10:00",
            "endTime": "10:45",
        },
    )
    config = {
        **_default_config(),
        "open_offset_minutes": -60,
        "close_after_hours": 72,
    }

    opens_at, closes_at = _survey_window({}, data, config)

    assert opens_at == datetime(2026, 7, 25, 7, 0, tzinfo=timezone.utc)
    assert closes_at == datetime(2026, 7, 28, 8, 45, tzinfo=timezone.utc)


def test_phase_boundaries_are_exact():
    opens_at = datetime(2026, 7, 25, 8, 0, tzinfo=timezone.utc)
    closes_at = opens_at + timedelta(hours=48)

    assert _phase(opens_at, closes_at, opens_at - timedelta(seconds=1)) == "upcoming"
    assert _phase(opens_at, closes_at, opens_at) == "open"
    assert _phase(opens_at, closes_at, closes_at) == "open"
    assert _phase(opens_at, closes_at, closes_at + timedelta(microseconds=1)) == "closed"
    assert _phase(None, None, opens_at) == "no_schedule"


def test_user_with_multiple_assignments_gets_every_matching_role_once():
    user = {
        "id": 11,
        "roles": [
            {"type": "coach", "team_id": 7, "verified": "approved"},
            {"type": "player", "team_id": 7, "verified": "approved"},
            {"type": "coach", "team_id": 99, "verified": "approved"},
            {"type": "player", "team_id": 8, "verified": "pending"},
        ],
    }
    data = {
        "hosts": [{"id": 11}],
        "head_judge_id": 11,
        "judges": [{"id": 11, "role": "table"}],
        "invited_team_ids": [7],
        "custom_teams": [{"name": "Drużyna własna", "coach_user_id": 11}],
    }

    roles, team_ids, custom_names = _user_roles(user, data)

    assert roles == ["host", "head_judge", "table_judge", "coach", "player"]
    assert team_ids == [7]
    assert custom_names == ["Drużyna własna"]


def test_field_judge_is_not_mistaken_for_table_judge():
    roles, team_ids, custom_names = _user_roles(
        {"id": 12, "roles": []},
        {"judges": [{"id": 12, "role": "field"}]},
    )

    assert roles == ["field_judge"]
    assert team_ids == []
    assert custom_names == []


def test_submit_accepts_one_to_three_strengths_but_requires_three_priorities():
    questions = _questions(_default_config())
    answers = _required_answers()

    normalized = _validate_answers(answers, questions, submit=True)
    assert normalized["strengths"] == ["courts"]
    assert normalized["priorities"] == ["information", "schedule", "sand"]

    answers["priorities"] = ["information", "schedule"]
    with pytest.raises(HTTPException) as error:
        _validate_answers(answers, questions, submit=True)
    assert error.value.status_code == 422


def test_draft_may_be_incomplete_and_unknown_questions_fail_closed():
    questions = _questions(_default_config())

    assert _validate_answers({"overall": 7}, questions, submit=False) == {"overall": 7}
    with pytest.raises(HTTPException) as error:
        _validate_answers({"future_unknown": "x"}, questions, submit=False)
    assert error.value.status_code == 422


def test_not_applicable_is_excluded_from_rating_average():
    question = next(item for item in CORE_QUESTIONS if item["id"] == "accommodation")
    rows = [
        {"answers": {"accommodation": "na"}},
        {"answers": {"accommodation": 5}},
        {"answers": {"accommodation": 3}},
        {"answers": {}},
    ]

    aggregate = _question_aggregate(question, rows)

    assert aggregate["count"] == 2
    assert aggregate["average"] == 4
    assert aggregate["distribution"] == {"3": 1, "5": 1}


def test_custom_question_is_sanitized_ordered_and_keeps_supported_type():
    config = _normalized_config(
        {
            "enabled_roles": ["coach", "player", "not-a-role"],
            "additional_question_ids": ["facilities"],
            "custom_questions": [
                {
                    "id": "custom_useful_1",
                    "title": "Jak oceniasz odprawę?",
                    "type": "single",
                    "required": True,
                    "options": ["Świetnie", "Dobrze", "Do poprawy", "Źle"],
                }
            ],
            "question_order": ["custom_useful_1", "overall", "facilities"],
        }
    )

    questions = _questions(config)
    custom = questions[0]
    assert config["enabled_roles"] == ["coach", "player"]
    assert custom["id"] == "custom_useful_1"
    assert custom["type"] == "single"
    assert len(custom["options"]) == 4
    assert questions[1]["id"] == "overall"
    assert "facilities" in [question["id"] for question in questions]


def test_config_allows_disabling_every_role_and_clamps_window_values():
    config = _normalized_config(
        {
            "enabled_roles": [],
            "open_offset_minutes": -9999,
            "close_after_hours": 9999,
        }
    )

    assert config["enabled_roles"] == []
    assert config["open_offset_minutes"] == -720
    assert config["close_after_hours"] == 168


def test_response_request_accepts_optimistic_lock_timestamp():
    request = SurveyResponseRequest(
        answers={"overall": 8},
        perspective_roles=["coach"],
        submit=False,
        expected_updated_at="2026-07-25T19:30:00.123456+00:00",
    )

    assert request.expected_updated_at == datetime(
        2026, 7, 25, 19, 30, 0, 123456, tzinfo=timezone.utc
    )

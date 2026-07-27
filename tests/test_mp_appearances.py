from datetime import datetime, timezone

from app.beach.mp_appearances import (
    _embedded_proel_link,
    _merge_evidence,
    _played_schedule_matches,
    effective_protocol_ids,
    first_team_matches,
    infer_mp_phase,
    season_year_label,
)


def test_mp_phase_prefers_explicit_value_and_infers_final_from_polish_name():
    assert infer_mp_phase("Finał MP Seniorów", "MP") == "final"
    assert infer_mp_phase("Turniej eliminacyjny", "MP") == "elimination"
    assert infer_mp_phase("Finał MP", "MP", "elimination") == "elimination"
    assert infer_mp_phase("Finał", "Woj") is None


def test_season_id_is_presented_as_calendar_year():
    assert season_year_label("7") == "2025"
    assert season_year_label("8") == "2026"


def test_historical_proel_link_prefers_embedded_match_extras():
    assert _embedded_proel_link(
        {
            "matchConfig": {
                "extras": {
                    "tournamentId": "71",
                    "scheduleMatchId": "match-5",
                }
            }
        }
    ) == (71, "match-5")


def test_effective_protocol_list_does_not_replace_explicit_empty_list():
    assert effective_protocol_ids(
        {"protocol_players": [], "default_players": [11, 12]}
    ) == []
    assert effective_protocol_ids({"default_players": ["11", 12, "bad"]}) == [
        11,
        12,
    ]


def test_first_team_match_uses_schedule_day_and_original_time():
    tournament = {
        "event_date": datetime(2026, 8, 1, tzinfo=timezone.utc),
    }
    data = {
        "schedule": {
            "config": {
                "days": [
                    {"date": "2026-08-01"},
                    {"date": "2026-08-02"},
                ]
            },
            "matches": [
                {
                    "id": "m2",
                    "dayIndex": 1,
                    "startTime": "10:00",
                    "teamA": {"id": 7, "name": "A"},
                    "teamB": {"id": 8, "name": "B"},
                },
                {
                    "id": "m1",
                    "dayIndex": 0,
                    "startTime": "10:30",
                    "originalTime": "09:30",
                    "teamA": {"id": 7, "name": "A"},
                    "teamB": {"id": 9, "name": "C"},
                },
            ],
        }
    }
    first = first_team_matches(tournament, data)
    assert first[7][0] == datetime(2026, 8, 1, 7, 30, tzinfo=timezone.utc)


def test_proel_denominator_excludes_unplayed_cancelled_and_walkovers():
    data = {
        "schedule": {
            "matches": [
                {
                    "id": "played",
                    "status": "finished",
                    "teamA": {"id": 1},
                    "teamB": {"id": 2},
                },
                {
                    "id": "scheduled",
                    "status": "scheduled",
                    "teamA": {"id": 1},
                    "teamB": {"id": 3},
                },
                {
                    "id": "cancelled",
                    "status": "finished",
                    "cancelled": True,
                    "teamA": {"id": 1},
                    "teamB": {"id": 4},
                },
                {
                    "id": "walkover",
                    "status": "finished",
                    "walkover": True,
                    "teamA": {"id": 1},
                    "teamB": {"id": 5},
                },
            ]
        }
    }
    assert [match["id"] for match in _played_schedule_matches(data)] == [
        "played"
    ]


def test_strongest_positive_evidence_wins_without_losing_audit_sources():
    bucket = {}
    _merge_evidence(bucket, 42, "frozen_warning", {"source": "frozen_list"})
    _merge_evidence(bucket, 42, "finished_proel", {"source": "proel"})
    _merge_evidence(bucket, 42, "approved_proel", {"source": "proel"})
    assert bucket[42]["status"] == "approved_proel"
    assert len(bucket[42]["sources"]) == 3

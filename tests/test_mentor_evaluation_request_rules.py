from datetime import datetime, timedelta, timezone

import pytest

from app.mentor_evaluation_request_rules import cooldown_hours, normalized_video_url, request_target_error


def test_only_member_of_evaluated_pair_can_request():
    error = request_target_error(
        actor_id="99", pair=("1", "2"), assigned_mentors=("10",), requested_mentors=("10",)
    )
    assert error and error[0] == 403


def test_only_assigned_active_mentor_can_be_targeted():
    error = request_target_error(
        actor_id="1", pair=("1", "2"), assigned_mentors=("10",), requested_mentors=("11",)
    )
    assert error and error[0] == 422


def test_published_mentor_cannot_be_requested_again():
    error = request_target_error(
        actor_id="1",
        pair=("1", "2"),
        assigned_mentors=("10", "11"),
        requested_mentors=("10", "11"),
        completed_mentors=("11",),
    )
    assert error and error[0] == 409


def test_multiple_assigned_mentors_are_allowed():
    assert request_target_error(
        actor_id="2", pair=("1", "2"), assigned_mentors=("10", "11"), requested_mentors=("10", "11")
    ) is None


def test_retry_uses_72_hour_shared_cooldown():
    stamp = datetime(2026, 10, 13, 12, tzinfo=timezone.utc)
    assert cooldown_hours(last_sent_at=stamp, now=stamp + timedelta(hours=71, minutes=1)) == 1
    assert cooldown_hours(last_sent_at=stamp, now=stamp + timedelta(hours=72)) == 0
    assert cooldown_hours(last_sent_at=stamp, now=stamp + timedelta(hours=2), fulfilled_at=stamp) == 0


def test_video_url_accepts_only_http_or_https():
    assert normalized_video_url(" https://video.example/mecz ") == "https://video.example/mecz"
    assert normalized_video_url("") == ""
    with pytest.raises(ValueError):
        normalized_video_url("javascript:alert(1)")

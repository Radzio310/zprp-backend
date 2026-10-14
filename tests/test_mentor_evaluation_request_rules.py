from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import MetaData

from app.mentor_evaluation_request_rules import cooldown_hours, normalized_video_url, request_target_error, video_provider, youtube_thumbnail
from app.mentor_evaluation_tables import define_tables


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


def test_video_link_is_normalized_and_recognizes_provider():
    assert normalized_video_url(" HTTPS://YouTube.com/watch?v=AbCdEf123 ") == "https://youtube.com/watch?v=AbCdEf123"
    assert video_provider("https://youtu.be/AbCdEf123") == "youtube"
    assert video_provider("https://youtube.com/live/Sitswd4YP4k?is=wFgQlbrD2P6gvx4G") == "youtube"
    assert video_provider("https://vimeo.com/123456") == "vimeo"
    assert video_provider("https://example.org/replay") == "video"
    assert youtube_thumbnail("https://youtube.com/watch?v=AbCdEf123").endswith("/AbCdEf123/hqdefault.jpg")
    assert youtube_thumbnail("https://youtube.com/live/Sitswd4YP4k?is=wFgQlbrD2P6gvx4G").endswith(
        "/Sitswd4YP4k/hqdefault.jpg"
    )


def test_match_video_table_keeps_many_unique_links_per_match():
    _, _, _, videos = define_tables(MetaData())
    assert videos.name == "mentor_match_videos"
    assert {column.name for column in videos.columns} >= {"match_id", "url", "normalized_url", "provider", "added_by"}
    unique = next(constraint for constraint in videos.constraints if constraint.name == "uq_mentor_match_video_url")
    assert [column.name for column in unique.columns] == ["match_id", "normalized_url"]

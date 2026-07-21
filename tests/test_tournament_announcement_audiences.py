from app.beach.announcement_audience import (
    announcement_is_visible,
    filter_announcements_for_viewer,
)


def _visible(announcement, **overrides):
    context = {
        "user_id": 10,
        "user_team_ids": set(),
        "is_tournament_judge": False,
        "is_tournament_team_member": False,
        "can_manage_announcements": False,
    }
    context.update(overrides)
    return announcement_is_visible(announcement, **context)


def test_public_announcement_is_visible_to_everyone():
    assert _visible({"id": "public", "text": "Public"}) is True
    assert _visible({"audiences": [{"type": "all"}]}) is True


def test_judge_audiences_are_limited_to_tournament_judges():
    group = {"audiences": [{"type": "judges"}]}
    direct = {"audiences": [{"type": "judge", "id": 10}]}

    assert _visible(group) is False
    assert _visible(group, is_tournament_judge=True) is True
    assert _visible(direct, user_id=11, is_tournament_judge=True) is False
    assert _visible(direct, user_id=10) is True


def test_team_audiences_are_limited_to_tournament_team_members():
    group = {"audiences": [{"type": "teams"}]}
    direct = {"audiences": [{"type": "team", "id": 7}]}

    assert _visible(group) is False
    assert _visible(group, is_tournament_team_member=True) is True
    assert _visible(direct, user_team_ids={8}) is False
    assert _visible(direct, user_team_ids={7}) is True


def test_unknown_personalized_audience_fails_closed():
    assert _visible({"audiences": [{"type": "future_private_role"}]}) is False


def test_manager_can_see_every_audience_for_moderation():
    assert _visible(
        {"audiences": [{"type": "judge", "id": 999}]},
        can_manage_announcements=True,
    ) is True


def test_response_filter_does_not_mutate_stored_tournament_data():
    data = {
        "announcements": [
            {"id": "public", "text": "Public"},
            {"id": "judges", "audiences": [{"type": "judges"}]},
            {"id": "team-7", "audiences": [{"type": "team", "id": 7}]},
        ],
        "judges": [{"id": 20}],
        "invited_team_ids": [7],
    }
    viewer = {
        "user_id": 10,
        "team_ids": set(),
        "is_admin": False,
        "capabilities": set(),
        "assigned_judge_can_manage": False,
    }

    filtered = filter_announcements_for_viewer(data, viewer)

    assert [item["id"] for item in filtered["announcements"]] == ["public"]
    assert len(data["announcements"]) == 3

"""A retried calendar POST must not create another Google event."""

import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.calendar_event_ids import google_event_id


def test_google_event_id_is_stable_and_scoped_to_user_and_match():
    first = google_event_id("judge-1", "211647")
    assert first == google_event_id("judge-1", "211647")
    assert first != google_event_id("judge-2", "211647")
    assert first != google_event_id("judge-1", "211648")
    assert len(first) == 68
    assert all(char in "0123456789abcdefghijklmnopqrstuv" for char in first)


def payload():
    from app.calendar import EventCreate

    return EventCreate(
        matchId="211647",
        summary="ZPE/PM/1",
        start=datetime.datetime(2026, 9, 23, 19, tzinfo=datetime.timezone.utc),
        end=datetime.datetime(2026, 9, 23, 21, tzinfo=datetime.timezone.utc),
        location="Koszalin",
        colorId="9",
        reminders=[],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mapped_id", [None, "old-google-event"])
async def test_post_reuses_existing_event_or_assigns_a_stable_id(mapped_id):
    pytest.importorskip("googleapiclient")
    from app.calendar import create_event

    service = MagicMock()
    events = service.events.return_value
    events.insert.return_value.execute.return_value = {"id": "stable-google-event"}
    events.update.return_value.execute.return_value = {"id": "old-google-event"}
    credentials = MagicMock()
    credentials.expired = False
    tokens = {
        "expires_at": "2030-01-01T00:00:00",
        "access_token": "token",
        "refresh_token": "refresh",
    }
    settings = MagicMock(GOOGLE_CLIENT_ID="client", GOOGLE_CLIENT_SECRET="secret")
    with (
        patch("app.calendar.get_calendar_tokens", new=AsyncMock(return_value=tokens)),
        patch("app.calendar.get_event_mapping", new=AsyncMock(return_value=mapped_id)),
        patch("app.calendar.save_event_mapping", new=AsyncMock()) as save_mapping,
        patch("app.calendar.Credentials", return_value=credentials),
        patch("app.calendar.build", return_value=service),
    ):
        result = await create_event(payload(), settings, "judge-1")

    if mapped_id:
        assert result == {"eventId": "old-google-event"}
        events.insert.assert_not_called()
        save_mapping.assert_not_called()
    else:
        body = events.insert.call_args.kwargs["body"]
        assert body["id"] == google_event_id("judge-1", "211647")
        assert result == {"eventId": "stable-google-event"}
        save_mapping.assert_awaited_once_with("judge-1", "211647", "stable-google-event")

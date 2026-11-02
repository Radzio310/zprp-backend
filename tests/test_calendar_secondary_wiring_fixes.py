"""Poprawki po przeglądzie widziane od strony tras `app/calendar.py`."""

from __future__ import annotations

import pytest

pytest.importorskip("jose")

from fastapi import HTTPException  # noqa: E402

from tests.calendar_secondary_support import connect  # noqa: E402
from tests.test_calendar_secondary_wiring import FakeFlow, cal, payload, settings  # noqa: E402,F401

U = "judge-1"


async def test_partial_consent_does_not_overwrite_token_or_state(cal):
    cal.env.store.tokens[U] = {"access_token": "old", "refresh_token": "oldr", "expires_at": "x", "scope": None}
    cal.storage.states["d~part"] = U
    # Google oddał tylko część zakresów poziomu district (bez calendar.events)
    original = FakeFlow.__init__

    def partial(self, scopes):
        original(self, scopes)
        self.oauth2session.token["scope"] = "https://www.googleapis.com/auth/calendar.app.created openid"

    FakeFlow.__init__ = partial
    try:
        res = await cal.m.oauth2callback("code", "d~part", settings())
    finally:
        FakeFlow.__init__ = original
    assert res.headers["location"] == "baza://kalendarz?connected=false&calendar_error=scope_missing"
    assert cal.env.store.tokens[U]["access_token"] == "old"  # token nietknięty
    assert not cal.env.store.setups.get(U)  # stan nietknięty
    assert not cal.env.world.calendar_ids()


async def test_delete_of_primary_entry_without_access_is_403_and_keeps_mapping(cal):
    connect(cal.env, U)
    cal.env.store.maps[(U, "u1")] = {"user_login": U, "match_id": "u1", "event_id": "e", "calendar_id": None}
    with pytest.raises(HTTPException) as err:
        await cal.m.delete_event("u1", settings(), U)
    assert err.value.status_code == 403 and err.value.detail["code"] == "district_access_required"
    assert (U, "u1") in cal.env.store.maps


async def test_post_keeps_quiet_about_color_and_marks_it_for_settings(cal):
    connect(cal.env, U)
    cal.env.world.fail.append(("patch_calendar_list", 403, None))
    out = await cal.m.create_event(payload(cal), settings(), U)
    assert out["eventId"] and "warning" not in out
    assert cal.env.store.setups[U]["color_pending"] == "whistle"

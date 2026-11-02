"""Nieudane odświeżenie tokenu w silniku: te same kody co globalny handler RefreshError."""

import pytest

from app.calendar_secondary_rules import GoogleError, SecondaryError


@pytest.mark.parametrize("status,code,http", [(401, "calendar_reconnect_required", 403), (503, "calendar_google_unavailable", 503)])
async def test_refresh_failure_maps_to_shared_codes(monkeypatch, status, code, http):
    from app import calendar_secondary_google as g
    from app.calendar_secondary_store import SecondaryStore

    async def tokens(self, user):
        return {"access_token": "a", "refresh_token": "r", "expires_at": "2020-01-01T00:00:00", "scope": None}

    async def boom(*a, **k):
        raise GoogleError(status)

    monkeypatch.setattr(SecondaryStore, "get_tokens", tokens)
    monkeypatch.setattr(g, "_api_from_tokens", boom)
    deps = g.build_deps(type("S", (), {"GOOGLE_CALENDAR_SECONDARY_ENABLED": True})())
    with pytest.raises(SecondaryError) as err:
        await deps.api_current("u")
    assert err.value.code == code and err.value.status == http

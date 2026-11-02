"""Trasy `app/calendar.py` przy fladze włączonej i wyłączonej.

`app.calendar` importuje biblioteki Google i `app.db` (łączy się z bazą przy
imporcie), więc na czas testu podstawiamy atrapy tych modułów i importujemy
plik od nowa. Po teście wszystko wraca do stanu sprzed (także `sys.modules`).
"""

from __future__ import annotations

import datetime
import importlib
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

pytest.importorskip("jose")

from fastapi import HTTPException  # noqa: E402

from app.calendar_event_ids import google_event_id  # noqa: E402
from tests.calendar_secondary_support import (  # noqa: E402
    DISTRICT_SCOPE,
    MATCHES_SCOPE,
    NOW,
    connect,
    make_deps,
)

U = "judge-1"
START = datetime.datetime(2026, 12, 1, 18, tzinfo=datetime.timezone.utc)
END = datetime.datetime(2026, 12, 1, 20, tzinfo=datetime.timezone.utc)
FLAG_OFF_FILES = ("app.calendar", "app.calendar_utils", "app.calendar_storage")


class FakeFlow:
    made: list = []

    def __init__(self, scopes):
        self.scopes = scopes
        self.auth_kwargs = None
        self.fetch = None
        self.redirect_uri = None
        self.credentials = SimpleNamespace(
            token="newtok", refresh_token="newref", expiry=datetime.datetime(2030, 1, 1), scopes=scopes, id_token=None
        )
        self.oauth2session = SimpleNamespace(
            token={"scope": " ".join(scopes) + " https://www.googleapis.com/auth/userinfo.email", "id_token": None}
        )
        FakeFlow.made.append(self)

    @classmethod
    def from_client_config(cls, config, scopes):
        return cls(scopes)

    def authorization_url(self, **kwargs):
        self.auth_kwargs = kwargs
        return "https://accounts.google.com/auth?x=1", kwargs.get("state", "gen-state")

    def fetch_token(self, **kwargs):
        self.fetch = kwargs


class Storage:
    """Atrapa app.calendar_storage zapisująca wywołania."""

    def __init__(self, store):
        self.store = store
        self.calls: list = []
        self.states: dict[str, str] = {}

    def module(self):
        m = types.ModuleType("app.calendar_storage")
        st = self

        async def save_oauth_state(user, state):
            st.states[state] = user

        async def get_oauth_state(user):
            return None

        async def get_user_login_by_state(state):
            return st.states.get(state)

        async def save_calendar_tokens(user, access_token, refresh_token, expires_at, *scope):
            st.calls.append(("save_calendar_tokens", user, scope))
            await st.store.save_tokens(user, access_token, refresh_token, expires_at, scope[0] if scope else None)

        async def get_calendar_tokens(user):
            return await st.store.get_tokens(user)

        async def delete_calendar_tokens(user):
            st.calls.append(("delete_calendar_tokens", user))
            await st.store.delete_tokens(user)

        unset = object()

        async def save_event_mapping(user, match_id, event_id, calendar_id=unset):
            cal = () if calendar_id is unset else (calendar_id,)
            st.calls.append(("save_event_mapping", user, match_id, event_id, cal))
            await st.store.save_mapping(user, match_id, event_id, None if calendar_id is unset else calendar_id)

        async def get_event_mapping(user, match_id):
            row = await st.store.get_mapping(user, match_id)
            return row["event_id"] if row else None

        async def delete_event_mapping(user, match_id):
            await st.store.delete_mapping(user, match_id)

        for fn in (
            save_oauth_state, get_oauth_state, get_user_login_by_state, save_calendar_tokens,
            get_calendar_tokens, delete_calendar_tokens, save_event_mapping, get_event_mapping,
            delete_event_mapping,
        ):
            setattr(m, fn.__name__, fn)
        return m


@pytest.fixture
def cal():
    FakeFlow.made.clear()
    env = make_deps()
    storage = Storage(env.store)
    errors = types.ModuleType("googleapiclient.errors")

    class HttpError(Exception):
        def __init__(self, status):
            self.resp = SimpleNamespace(status=status)

    errors.HttpError = HttpError
    discovery = types.ModuleType("googleapiclient.discovery")
    discovery.build = MagicMock()
    pkg = types.ModuleType("googleapiclient")
    pkg.discovery, pkg.errors = discovery, errors
    flow_mod = types.ModuleType("google_auth_oauthlib.flow")
    flow_mod.Flow = FakeFlow
    flow_pkg = types.ModuleType("google_auth_oauthlib")
    flow_pkg.flow = flow_mod
    stubs = {
        "googleapiclient": pkg,
        "googleapiclient.discovery": discovery,
        "googleapiclient.errors": errors,
        "google_auth_oauthlib": flow_pkg,
        "google_auth_oauthlib.flow": flow_mod,
        "app.calendar_storage": storage.module(),
    }
    saved = {k: sys.modules.get(k) for k in [*stubs, *FLAG_OFF_FILES]}
    for name in FLAG_OFF_FILES:
        sys.modules.pop(name, None)
    sys.modules.update(stubs)
    try:
        module = importlib.import_module("app.calendar")
        module.build_secondary_deps = lambda settings: env.deps
        module.build = MagicMock()
        yield SimpleNamespace(m=module, env=env, storage=storage)
    finally:
        for name, old in saved.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


def settings(flag=True):
    return SimpleNamespace(
        GOOGLE_CLIENT_ID="cid",
        GOOGLE_CLIENT_SECRET="sec",
        BACKEND_URL="https://api",
        FRONTEND_DEEP_LINK="baza://kalendarz",
        GOOGLE_CALENDAR_SECONDARY_ENABLED=flag,
    )


def payload(cal, title="⚽️ ZPE/1", target=None, match="211647", reminders=None):
    return cal.m.EventCreate(
        matchId=match, summary=title, start=START, end=END, location="Hala", colorId="9",
        reminders=reminders if reminders is not None else [{"method": "popup", "minutes": 60}],
        target=target,
    )


def error_of(exc: HTTPException):
    return exc.status_code, exc.detail


# ── auth-url ───────────────────────────────────────────────────────────────
async def test_auth_url_flag_off_is_the_old_flow(cal):
    out = await cal.m.get_auth_url("district", settings(False), U)
    flow = FakeFlow.made[-1]
    assert flow.scopes == [
        "https://www.googleapis.com/auth/calendar.events",
        "https://www.googleapis.com/auth/calendar.readonly",
    ]
    assert flow.auth_kwargs["include_granted_scopes"] == "true" and "state" not in flow.auth_kwargs
    assert out.status_code == 200


@pytest.mark.parametrize("tier,granted", [(None, "false"), ("matches", "false"), ("district", "true")])
async def test_auth_url_flag_on_picks_scopes_and_carries_tier_in_state(cal, tier, granted):
    await cal.m.get_auth_url(tier, settings(), U)
    flow = FakeFlow.made[-1]
    assert flow.auth_kwargs["include_granted_scopes"] == granted
    assert flow.auth_kwargs["state"][:2] == ("d~" if tier == "district" else "m~")
    assert ("https://www.googleapis.com/auth/calendar.events" in flow.scopes) == (tier == "district")
    assert "https://www.googleapis.com/auth/calendar.app.created" in flow.scopes
    assert cal.storage.states[flow.auth_kwargs["state"]] == U


async def test_auth_url_flag_on_rejects_unknown_tier(cal):
    with pytest.raises(HTTPException) as err:
        await cal.m.get_auth_url("root", settings(), U)
    assert error_of(err.value)[0] == 400 and err.value.detail["code"] == "invalid_tier"


# ── callback ───────────────────────────────────────────────────────────────
async def test_callback_flag_off_keeps_old_token_write_without_scope(cal):
    cal.storage.states["s1"] = U
    cal.env.store.tokens[U] = {"access_token": "a", "refresh_token": "oldref", "expires_at": "x", "scope": None}
    res = await cal.m.oauth2callback("code", "s1", settings(False))
    call = [c for c in cal.storage.calls if c[0] == "save_calendar_tokens"][0]
    assert call[2] == ()  # żadnego zakresu: kolumna scope nietknięta
    assert res.headers["location"] == "baza://kalendarz?connected=true"


async def test_callback_flag_on_first_connection_saves_scopes_and_creates_calendars(cal):
    state = "m~abc"
    cal.storage.states[state] = U
    res = await cal.m.oauth2callback("code", state, settings())
    tok = cal.env.store.tokens[U]
    assert "calendar.app.created" in tok["scope"] and "calendar.events" not in tok["scope"]
    assert len(cal.env.world.calendar_ids()) == 2
    assert res.headers["location"] == "baza://kalendarz?connected=true"
    assert res.background is None  # nic do przenoszenia
    assert cal.env.store.setups[U]["migrated"] is True


async def test_callback_flag_on_legacy_reconnect_parks_token_and_schedules_job(cal):
    cal.env.store.tokens[U] = {"access_token": "old", "refresh_token": "oldr", "expires_at": "x", "scope": None}
    cal.storage.states["m~z"] = U
    res = await cal.m.oauth2callback("code", "m~z", settings())
    assert cal.env.store.setups[U]["park_access"] == "old"
    assert res.background is not None
    await res.background()  # zadanie w tle: nic do przeniesienia, kończy się sukcesem
    assert cal.env.store.setups[U]["job_state"] == "done" and cal.env.store.setups[U]["migrated"] is True


async def test_callback_flag_on_bad_state_and_exchange_failure_are_coded(cal):
    with pytest.raises(HTTPException) as err:
        await cal.m.oauth2callback("code", "nieznany", settings())
    assert err.value.status_code == 400
    cal.storage.states["m~q"] = U
    FakeFlow.fetch_token = MagicMock(side_effect=ValueError("boom"))
    try:
        with pytest.raises(HTTPException) as err:
            await cal.m.oauth2callback("code", "m~q", settings())
        assert err.value.detail["code"] == "token_exchange_failed" and "Nie udało się" in err.value.detail["message"]
    finally:
        del FakeFlow.fetch_token


# ── zapis wydarzeń ─────────────────────────────────────────────────────────
async def test_post_flag_on_match_goes_to_secondary_and_never_builds_primary_service(cal):
    connect(cal.env, U)
    out = await cal.m.create_event(payload(cal), settings(), U)
    assert out["eventId"] == google_event_id(U, "211647")
    assert cal.env.store.maps[(U, "211647")]["calendar_id"] in cal.env.world.calendars
    cal.m.build.assert_not_called()


async def test_post_flag_on_unavailability_needs_district(cal):
    connect(cal.env, U)
    with pytest.raises(HTTPException) as err:
        await cal.m.create_event(payload(cal, title="Urlop", match="u1"), settings(), U)
    assert err.value.status_code == 403 and err.value.detail["code"] == "district_access_required"
    with pytest.raises(HTTPException):
        await cal.m.create_event(payload(cal, target="primary"), settings(), U)


async def test_post_flag_on_district_primary_uses_old_path_with_extras_and_cleans_previous(cal):
    connect(cal.env, U, scope=DISTRICT_SCOPE)
    # wpis meczu leżał w kalendarzu drugorzędnym; teraz idzie do głównego
    await cal.m.create_event(payload(cal, match="7"), settings(), U)
    old_cal = cal.env.store.maps[(U, "7")]["calendar_id"]
    service = MagicMock()
    service.events.return_value.insert.return_value.execute.return_value = {"id": "prim-1"}
    cal.m.build.return_value = service
    out = await cal.m.create_event(payload(cal, match="7", target="primary", reminders=[{"method": "email", "minutes": 30}]), settings(), U)
    assert out == {"eventId": "prim-1"}
    body = service.events.return_value.insert.call_args.kwargs["body"]
    assert body["transparency"] == "opaque"
    assert body["reminders"]["overrides"] == [{"method": "email", "minutes": 30}]
    assert cal.env.store.maps[(U, "7")]["calendar_id"] is None
    assert not cal.env.world.events_in(old_cal)  # stare miejsce posprzątane po zapisie w nowym


async def test_post_flag_on_legacy_account_keeps_the_old_path(cal):
    connect(cal.env, U, scope=None)
    service = MagicMock()
    service.events.return_value.insert.return_value.execute.return_value = {"id": "prim-2"}
    cal.m.build.return_value = service
    out = await cal.m.create_event(payload(cal), settings(), U)
    assert out == {"eventId": "prim-2"}
    body = service.events.return_value.insert.call_args.kwargs["body"]
    assert "transparency" not in body and body["colorId"] == "9"
    save = [c for c in cal.storage.calls if c[0] == "save_event_mapping"][-1]
    assert save[4] == ()  # zapis jak dotąd, bez calendar_id


async def test_post_flag_off_ignores_target_and_never_touches_secondary(cal):
    connect(cal.env, U, scope=None)

    def boom(_):
        raise AssertionError("flaga wyłączona: kalendarze drugorzędne nie mogą być ruszone")

    cal.m.build_secondary_deps = boom
    service = MagicMock()
    service.events.return_value.insert.return_value.execute.return_value = {"id": "prim-3"}
    cal.m.build.return_value = service
    out = await cal.m.create_event(payload(cal, target="whistle"), settings(False), U)
    assert out == {"eventId": "prim-3"}
    assert "transparency" not in service.events.return_value.insert.call_args.kwargs["body"]


async def test_put_flag_on_needs_mapping_then_updates_in_place(cal):
    connect(cal.env, U)
    with pytest.raises(HTTPException) as err:
        await cal.m.update_event(payload(cal), "211647", settings(), U)
    assert err.value.status_code == 404
    await cal.m.create_event(payload(cal), settings(), U)
    out = await cal.m.update_event(payload(cal, title="⚽️ ZPE/zmiana"), "211647", settings(), U)
    cid = cal.env.store.maps[(U, "211647")]["calendar_id"]
    assert len(cal.env.world.events_in(cid)) == 1
    assert cal.env.world.events_in(cid)[out["eventId"]]["summary"] == "⚽️ ZPE/zmiana"


async def test_delete_flag_on_removes_from_mapped_calendar(cal):
    connect(cal.env, U)
    await cal.m.create_event(payload(cal), settings(), U)
    cid = cal.env.store.maps[(U, "211647")]["calendar_id"]
    await cal.m.delete_event("211647", settings(), U)
    assert not cal.env.world.events_in(cid) and (U, "211647") not in cal.env.store.maps


# ── odczyt kalendarza głównego, rozłączanie ────────────────────────────────
async def test_reading_primary_is_403_for_matches_level_only(cal):
    connect(cal.env, U)
    for call in (
        lambda: cal.m.list_events(30, settings(), U),
        lambda: cal.m.list_event_labels(settings(), U),
        lambda: cal.m.create_event_label(cal.m.EventLabelCreate(hex="#112233"), settings(), U),
    ):
        with pytest.raises(HTTPException) as err:
            await call()
        assert err.value.status_code == 403 and err.value.detail["code"] == "district_access_required"


async def test_reading_primary_guard_is_off_without_flag(cal):
    def boom(_):
        raise AssertionError("flaga wyłączona")

    cal.m.build_secondary_deps = boom
    await cal.m._guard_primary_read(settings(False), U)


async def test_disconnect_flag_on_with_and_without_removal(cal):
    connect(cal.env, U)
    await cal.m.create_event(payload(cal), settings(), U)
    ids = cal.env.world.calendar_ids()
    res = await cal.m.disconnect_calendar(False, settings(), U)
    assert res.status_code == 200 and U not in cal.env.store.tokens
    assert set(cal.env.world.calendar_ids()) == set(ids)  # zostaw wpisy
    res = await cal.m.disconnect_calendar(None, settings(), U)
    assert res.status_code == 400  # już rozłączone
    connect(cal.env, U)
    res = await cal.m.disconnect_calendar(True, settings(), U)
    assert res.status_code == 200 and not cal.env.world.calendar_ids()


async def test_disconnect_flag_off_is_the_old_behaviour(cal):
    connect(cal.env, U, scope=None)
    res = await cal.m.disconnect_calendar(True, settings(False), U)
    assert res.status_code == 200 and U not in cal.env.store.tokens
    assert ("delete_calendar", "x") not in cal.env.world.log
    assert (await cal.m.disconnect_calendar(None, settings(False), U)).status_code == 400
    assert NOW and MATCHES_SCOPE

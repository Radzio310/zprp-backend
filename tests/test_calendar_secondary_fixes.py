"""Kalendarze drugorzędne: poprawki po przeglądzie (rozłączanie, park, liczniki, kolor, wyścig)."""

from __future__ import annotations

import pytest

from app.calendar_event_ids import google_event_id
from app.calendar_secondary_engine import (
    after_connect,
    disconnect,
    put_setup,
    run_job,
    setup_view,
    start_migration,
)
from app.calendar_secondary_rules import SecondaryError
from tests.calendar_secondary_support import DISTRICT_SCOPE, connect, make_deps
from tests.test_calendar_secondary_engine import (
    NEW,
    STOPWATCH,
    U,
    WHISTLE,
    legacy_account,
    post,
    reconnect_matches,
)


async def test_failed_mode_job_resumes_via_migrate_and_put_setup_starts_on_leftovers():
    env = connect(make_deps(), U)
    await post(env, "1", WHISTLE)
    await put_setup(env.deps, U, {"mode": "one"})
    env.store.setups[U]["job_state"] = "failed"  # przerwane, wpisy dalej w starym układzie
    job, started = await start_migration(env.deps, U)
    assert started is True and job["kind"] == "mode"
    env.store.setups[U]["job_state"] = "failed"
    # PUT bez zmiany trybu też startuje zadanie, bo w mapowaniach zostały wpisy starego układu
    _, _, start = await put_setup(env.deps, U, {"busy": True})
    assert start is True
    job = await run_job(env.deps, U)
    assert job["state"] == "done"
    _, _, start = await put_setup(env.deps, U, {"busy": True})
    assert start is False  # nic nie zostało


async def test_legacy_disconnect_with_removal_deletes_future_matches_and_forgets_mappings():
    env = make_deps()
    legacy_account(env)
    was, warnings = await disconnect(env.deps, U, remove_calendars=True)
    assert was and not warnings
    assert set(env.world.events_in("primary")) == {"ev-m-unavail", "ev-m-past"}
    assert (U, "m-whistle") not in env.store.maps and (U, "m-stop") not in env.store.maps
    assert (U, "m-unavail") in env.store.maps and (U, "m-past") in env.store.maps
    assert U not in env.store.tokens and not env.store.setups.get(U, {}).get("park_access")
    assert not env.store.setups.get(U, {}).get("legacy_left")


async def test_legacy_disconnect_without_removal_keeps_events_and_reconnect_says_so():
    env = make_deps()
    legacy_account(env)
    await disconnect(env.deps, U, remove_calendars=False)
    assert "ev-m-whistle" in env.world.events_in("primary")  # "zostaw wpisy"
    assert (U, "m-whistle") not in env.store.maps and env.store.setups[U]["legacy_left"] is True
    assert not env.store.setups[U].get("park_access")  # token nie jest zatrzymywany
    start, _ = await after_connect(env.deps, U, previous=None, new_tokens=NEW, email=None)
    assert start is True  # zostały mapowania niedyspozycji i historii: zadanie przejdzie po nich
    await run_job(env.deps, U)
    view = await setup_view(env.deps, U)
    assert view["job"]["state"] == "done" and "mogły zostać" in view["job"]["note"]
    assert env.store.setups[U]["legacy_left"] is False


async def test_disconnect_after_revoked_consent_still_clears_everything_with_warnings():
    env = make_deps()
    legacy_account(env)
    await reconnect_matches(env)
    env.store.setups[U].update(job_state="running", park_access="old")

    async def revoked(user):
        raise SecondaryError(401, "google_auth_failed", "cofnięte")

    env.deps.api_current = revoked
    env.deps.api_parked = revoked
    was, warnings = await disconnect(env.deps, U, remove_calendars=True)
    assert was and warnings
    assert U not in env.store.tokens and not env.store.setups[U].get("park_access")
    assert env.store.setups[U]["job_state"] == "failed"
    assert env.store.setups[U]["legacy_left"] is True


async def test_reconnect_after_disconnect_does_not_mask_primary_mappings():
    env = make_deps()
    legacy_account(env)
    env.store.tokens.pop(U)  # token zniknął bez sprzątania
    start, _ = await after_connect(env.deps, U, previous=None, new_tokens=NEW, email=None)
    assert start is True and not env.store.setups[U].get("migrated")
    job = await run_job(env.deps, U)  # brak dostępu do primary: jawna uwaga, nie cisza
    assert job["state"] == "done" and job["note"] and env.store.setups[U]["migrated"] is True


async def test_unusable_parked_token_gives_visible_note_and_never_500s_after_write():
    env = make_deps()
    legacy_account(env)
    await reconnect_matches(env)

    async def broken(user):
        raise SecondaryError(401, "google_auth_failed", "park martwy")

    env.deps.api_parked = broken
    job = await run_job(env.deps, U)
    assert job["state"] == "done" and job["note"]
    # zapis nowego wpisu po wcześniejszym wpisie w primary: ostrzeżenie, nie wyjątek
    env.store.maps[(U, "p1")] = {"user_login": U, "match_id": "p1", "event_id": "old1", "calendar_id": None}
    env.store.setups[U]["park_access"] = "x"  # park jeszcze jest, ale martwy
    out = await post(env, "p1")
    assert "warning" in out and out["eventId"]
    assert env.store.maps[(U, "p1")]["calendar_id"]


async def test_district_reconsent_replaces_parked_token():
    env = make_deps()
    legacy_account(env)
    await reconnect_matches(env)
    assert env.store.setups[U]["park_access"] == "old"
    district = {**NEW, "scope": DISTRICT_SCOPE}
    await after_connect(env.deps, U, previous=env.store.tokens[U], new_tokens=district, email=None)
    assert not env.store.setups[U].get("park_access")


async def test_color_failure_warns_in_post_and_is_retried_later():
    env = connect(make_deps(), U)
    env.world.fail.append(("patch_calendar_list", 403, None))
    out = await post(env, "1")
    assert "koloru" in out["warning"] and "ponownie" in out["warning"]
    assert env.store.setups[U]["color_pending"] == "whistle"
    out2 = await post(env, "1")  # kolejny zapis ponawia kolor
    assert "warning" not in out2 and not env.store.setups[U]["color_pending"]
    cal = env.store.setups[U]["whistle_id"]
    assert env.world.calendars[cal]["backgroundColor"] == "#33b679"
    env.world.fail.append(("patch_calendar_list", 500, None))
    await post(env, "2", STOPWATCH)  # nowy kalendarz, nowa awaria koloru
    assert env.store.setups[U]["color_pending"] == "stopwatch"
    await setup_view(env.deps, U)  # GET /setup ponawia
    assert not env.store.setups[U]["color_pending"]


async def test_migration_skips_row_changed_during_the_job():
    env = make_deps()
    legacy_account(env)
    await reconnect_matches(env)
    stale = await env.store.list_mappings(U)
    # aplikacja zdążyła przepisać m-whistle, zanim zadanie doszło do wiersza
    env.store.maps[(U, "m-whistle")] = {
        "user_login": U, "match_id": "m-whistle", "event_id": "nowy", "calendar_id": "cal-x",
    }

    async def stale_list(user):
        return stale

    env.store.list_mappings = stale_list
    job = await run_job(env.deps, U)
    assert job["state"] == "done" and job["skipped"] == 1 and job["done"] == 1
    assert env.store.maps[(U, "m-whistle")]["event_id"] == "nowy"
    assert not any(
        e[0] == "insert_event" and e[2] == google_event_id(U, "m-whistle") for e in env.world.log
    )

"""Kalendarze drugorzędne Google: silnik na atrapie Google (bez sieci i bazy)."""

from __future__ import annotations

import datetime

import pytest

from app.calendar_event_ids import google_event_id
from app.calendar_secondary_engine import (
    after_connect,
    disconnect,
    plan_write,
    put_setup,
    remove_event,
    require_primary_read,
    run_job,
    setup_view,
    start_migration,
    write_event,
)
from app.calendar_secondary_rules import SecondaryError

from tests.calendar_secondary_support import (
    DISTRICT_SCOPE,
    FUTURE,
    FUTURE_END,
    MATCHES_SCOPE,
    NOW,
    PAST,
    FakeStore,
    World,
    connect,
    make_deps,
)

U = "judge-1"
START = datetime.datetime(2026, 12, 1, 18, tzinfo=datetime.timezone.utc)
END = datetime.datetime(2026, 12, 1, 20, tzinfo=datetime.timezone.utc)
WHISTLE = "⚽️ ZPE/PM/1"
STOPWATCH = "⏱️ ZPE/PM/2"


async def post(env, match_id, title=WHISTLE, target=None, reminders=None, user=U):
    plan = await plan_write(env.deps, user, title, target)
    assert plan is not None
    return await write_event(
        env.deps,
        user,
        plan,
        match_id,
        summary=title,
        start=START,
        end=END,
        location="Hala",
        reminders=reminders if reminders is not None else [{"method": "popup", "minutes": 180}],
    )


# ── trasowanie ─────────────────────────────────────────────────────────────
async def test_flag_off_means_no_plan_and_no_store_access():
    env = make_deps(flag=False)
    connect(env, U)
    assert await plan_write(env.deps, U, WHISTLE, None) is None
    await require_primary_read(env.deps, U)  # nie rzuca


async def test_legacy_token_keeps_old_path():
    env = make_deps()
    connect(env, U, scope=None)
    assert await plan_write(env.deps, U, WHISTLE, None) is None
    await require_primary_read(env.deps, U)  # legacy czyta kalendarz główny


async def test_not_connected_has_no_plan():
    assert await plan_write(make_deps().deps, U, WHISTLE, None) is None


@pytest.mark.parametrize(
    "title,target,mode,kind",
    [
        (WHISTLE, None, "two", "whistle"),
        (STOPWATCH, None, "two", "stopwatch"),
        ("⚽ ZPE", None, "two", "whistle"),  # bez selektora emoji
        (WHISTLE, "stopwatch", "two", "stopwatch"),  # jawny cel wygrywa
        (WHISTLE, None, "one", "shared"),
        (STOPWATCH, None, "one", "shared"),
    ],
)
async def test_routes_by_prefix_target_and_mode(title, target, mode, kind):
    env = connect(make_deps(), U)
    env.store.setups[U]["mode"] = mode
    plan = await plan_write(env.deps, U, title, target)
    assert plan.kind == kind


async def test_primary_needs_district_level():
    env = connect(make_deps(), U)
    with pytest.raises(SecondaryError) as err:
        await plan_write(env.deps, U, "Urlop", None)
    assert err.value.status == 403 and err.value.code == "district_access_required"
    with pytest.raises(SecondaryError):
        await plan_write(env.deps, U, WHISTLE, "primary")
    connect(env, U, scope=DISTRICT_SCOPE)
    assert (await plan_write(env.deps, U, "Urlop", None)).kind is None


async def test_invalid_target_is_a_clear_error():
    env = connect(make_deps(), U)
    with pytest.raises(SecondaryError) as err:
        await plan_write(env.deps, U, WHISTLE, "kosmos")
    assert err.value.code == "invalid_target"


async def test_matches_level_cannot_read_primary_district_and_legacy_can():
    env = connect(make_deps(), U)
    with pytest.raises(SecondaryError) as err:
        await require_primary_read(env.deps, U)
    assert err.value.code == "district_access_required"
    connect(env, U, scope=DISTRICT_SCOPE)
    await require_primary_read(env.deps, U)


# ── zapis wydarzeń ─────────────────────────────────────────────────────────
async def test_first_write_creates_named_calendar_with_color_and_maps_it():
    env = connect(make_deps(), U)
    out = await post(env, "211647")
    cals = env.world.calendars
    new = [c for c in cals if c != "primary"]
    assert len(new) == 1 and cals[new[0]]["summary"] == "BAZA - Boiskowy"
    # kolor: dowolny hex + napis wg jasności (zielony domyślny = biały)
    assert cals[new[0]]["backgroundColor"] == "#33b679"
    assert cals[new[0]]["foregroundColor"] in ("#000000", "#ffffff")
    row = env.store.maps[(U, "211647")]
    assert row["calendar_id"] == new[0] and row["event_id"] == out["eventId"]
    assert out["eventId"] == google_event_id(U, "211647")
    body = env.world.events[(new[0], out["eventId"])]
    assert "colorId" not in body and "eventLabelId" not in body
    assert body["transparency"] == "opaque"
    assert body["reminders"] == {"useDefault": False, "overrides": [{"method": "popup", "minutes": 180}]}
    # nic nie trafia do kalendarza głównego
    assert not env.world.events_in("primary")


async def test_second_post_updates_without_duplicate_and_busy_maps_to_transparency():
    env = connect(make_deps(), U)
    await post(env, "1")
    env.store.setups[U]["busy"] = False
    await post(env, "1")
    cal = env.store.maps[(U, "1")]["calendar_id"]
    assert len(env.world.events_in(cal)) == 1
    assert env.world.events_in(cal)[google_event_id(U, "1")]["transparency"] == "transparent"
    assert len(env.world.calendar_ids()) == 1


async def test_two_kinds_go_to_two_calendars_and_shared_mode_to_one():
    env = connect(make_deps(), U)
    await post(env, "1", WHISTLE)
    await post(env, "2", STOPWATCH)
    names = sorted(c["summary"] for k, c in env.world.calendars.items() if k != "primary")
    assert names == ["BAZA - Boiskowy", "BAZA - Stolikowy"]
    env2 = connect(make_deps(), U)
    env2.store.setups[U]["mode"] = "one"
    await post(env2, "1", WHISTLE)
    await post(env2, "2", STOPWATCH)
    assert [c["summary"] for k, c in env2.world.calendars.items() if k != "primary"] == ["BAZA - Mecze"]


async def test_reminders_accept_email_and_cap_at_five():
    env = connect(make_deps(), U)
    mixed = [{"method": "email", "minutes": 1440}, {"method": "popup", "minutes": 60}]
    out = await post(env, "1", reminders=mixed)
    cal = env.store.maps[(U, "1")]["calendar_id"]
    assert env.world.events[(cal, out["eventId"])]["reminders"]["overrides"] == mixed
    with pytest.raises(SecondaryError) as err:
        await post(env, "2", reminders=[{"method": "popup", "minutes": m} for m in range(6)])
    assert err.value.code == "invalid_reminders"
    with pytest.raises(SecondaryError):
        await post(env, "3", reminders=[{"method": "sms", "minutes": 5}])
    assert await post(env, "4", reminders=[])  # "bez przypomnień" to stan pełnoprawny


async def test_changing_target_inserts_in_new_calendar_first_then_deletes_old():
    env = connect(make_deps(), U)
    await post(env, "1", WHISTLE)
    old_cal = env.store.maps[(U, "1")]["calendar_id"]
    env.world.log.clear()
    await post(env, "1", STOPWATCH)
    new_cal = env.store.maps[(U, "1")]["calendar_id"]
    assert new_cal != old_cal
    ops = [e[:2] for e in env.world.log if e[0] in ("insert_event", "delete_event")]
    assert ops == [("insert_event", new_cal), ("delete_event", old_cal)]
    assert not env.world.events_in(old_cal)
    assert len(env.world.events_in(new_cal)) == 1


async def test_manually_deleted_calendar_is_recreated_and_marked_for_refill():
    env = connect(make_deps(), U)
    await post(env, "1")
    await post(env, "2")
    dead = env.store.maps[(U, "1")]["calendar_id"]
    del env.world.calendars[dead]  # użytkownik usunął kalendarz w Google
    out = await post(env, "1")
    fresh = env.store.setups[U]["whistle_id"]
    assert fresh != dead and fresh in env.world.calendars
    assert env.store.maps[(U, "1")]["calendar_id"] == fresh
    assert out["eventId"] in env.world.events_in(fresh)
    # druga pozycja wskazywała zniszczony kalendarz: mapowanie zniknęło, aplikacja ma uzupełnić
    assert (U, "2") not in env.store.maps
    view = await setup_view(env.deps, U)
    assert [c["missing"] for c in view["calendars"] if c["kind"] == "whistle"] == [True]
    # odtworzony kalendarz dostaje kolor zapamiętany w ustawieniach
    assert env.world.calendars[fresh]["backgroundColor"] == "#33b679"
    view, _, _ = await put_setup(env.deps, U, {"refilled": ["whistle"]})
    assert [c["missing"] for c in view["calendars"]] == [False, False]


async def test_missing_event_in_existing_calendar_is_inserted_not_failed():
    env = connect(make_deps(), U)
    await post(env, "1")
    cal = env.store.maps[(U, "1")]["calendar_id"]
    del env.world.events[(cal, google_event_id(U, "1"))]
    await post(env, "1")
    assert len(env.world.events_in(cal)) == 1


async def test_google_failure_is_a_polish_error_with_code():
    env = connect(make_deps(), U)
    await post(env, "1")
    env.world.fail.append(("insert_event", 500))
    with pytest.raises(SecondaryError) as err:
        await post(env, "2")
    assert err.value.status == 502 and err.value.code == "google_write_failed"
    assert "Google" in err.value.message


async def test_delete_removes_from_the_mapped_calendar_and_is_idempotent():
    env = connect(make_deps(), U)
    await post(env, "1")
    cal = env.store.maps[(U, "1")]["calendar_id"]
    await remove_event(env.deps, U, "1")
    assert not env.world.events_in(cal) and (U, "1") not in env.store.maps
    await remove_event(env.deps, U, "1")  # brak mapowania: nic się nie dzieje
    await post(env, "1")
    del env.world.events[(cal, google_event_id(U, "1"))]
    await remove_event(env.deps, U, "1")  # wpis usunięty ręcznie w Google
    assert (U, "1") not in env.store.maps


async def test_delete_of_primary_entry_without_access_is_403_and_mapping_stays():
    env = connect(make_deps(), U)
    env.store.maps[(U, "9")] = {"user_login": U, "match_id": "9", "event_id": "old", "calendar_id": None}
    with pytest.raises(SecondaryError) as err:
        await remove_event(env.deps, U, "9")
    assert err.value.status == 403 and err.value.code == "district_access_required"
    assert (U, "9") in env.store.maps


# ── widok i ustawienia ─────────────────────────────────────────────────────
async def test_setup_view_contract_shape_for_flag_on_and_off():
    env = connect(make_deps(), U)
    view = await setup_view(env.deps, U)
    assert set(view) == {
        "feature_enabled", "connected", "email", "needs_migration",
        "mode", "busy", "district_access", "calendars", "job",
    }
    assert view["feature_enabled"] and view["connected"] and view["mode"] == "two" and view["busy"]
    assert [c["kind"] for c in view["calendars"]] == ["whistle", "stopwatch"]
    assert set(view["calendars"][0]) == {"kind", "name", "color", "missing"}
    assert view["district_access"] is False and view["job"] is None
    off = make_deps(flag=False)
    connect(off, U, scope=None)
    v = await setup_view(off.deps, U)
    assert v["feature_enabled"] is False and v["needs_migration"] is False and v["calendars"] == []
    assert v["connected"] and v["district_access"]


async def test_needs_migration_rules():
    env = make_deps()
    env.store.tokens[U] = {"access_token": "a", "refresh_token": "r", "expires_at": "x", "scope": None}
    assert (await setup_view(env.deps, U))["needs_migration"] is True
    assert (await setup_view(env.deps, "nobody"))["needs_migration"] is False  # brak tokenu
    env.store.tokens["beach:1"] = dict(env.store.tokens[U])
    assert (await setup_view(env.deps, "beach:1"))["needs_migration"] is False  # Beach nie jest legacy
    env.store.setups[U] = {"migrated": True}
    assert (await setup_view(env.deps, U))["needs_migration"] is False


async def test_put_setup_saves_choices_before_connection_and_validates():
    env = make_deps()
    view, warnings, start = await put_setup(
        env.deps, U, {"mode": "one", "colors": {"shared": "#ABCDEF"}, "busy": False}
    )
    assert view["mode"] == "one" and view["busy"] is False and not start
    assert view["calendars"] == [
        {"kind": "shared", "name": "BAZA - Mecze", "color": "#abcdef", "missing": False}
    ]
    assert not env.world.calendar_ids()  # bez tokenu nic nie zakładamy
    for bad in ({"mode": "trzy"}, {"colors": {"shared": "zielony"}}, {"colors": {"x": "#000000"}}):
        with pytest.raises(SecondaryError) as err:
            await put_setup(env.deps, U, bad)
        assert err.value.status == 400
    off = make_deps(flag=False)
    with pytest.raises(SecondaryError) as err:
        await put_setup(off.deps, U, {"mode": "one"})
    assert err.value.status == 404


async def test_put_setup_creates_calendars_and_patches_colors_when_connected():
    env = connect(make_deps(), U)
    view, warnings, start = await put_setup(
        env.deps, U, {"colors": {"whistle": "#112233", "stopwatch": "#fff200"}}
    )
    by_name = {c["summary"]: c for k, c in env.world.calendars.items() if k != "primary"}
    assert by_name["BAZA - Boiskowy"]["backgroundColor"] == "#112233"
    assert by_name["BAZA - Boiskowy"]["foregroundColor"] == "#ffffff"
    assert by_name["BAZA - Stolikowy"]["backgroundColor"] == "#fff200"
    assert by_name["BAZA - Stolikowy"]["foregroundColor"] == "#000000"  # jasny kolor: czarny napis
    assert warnings == [] and not start


async def test_color_failure_is_reported_not_swallowed():
    env = connect(make_deps(), U)
    await put_setup(env.deps, U, {})
    env.world.fail.append(("patch_calendar_list", 403, None))
    _, warnings, _ = await put_setup(env.deps, U, {"colors": {"whistle": "#123456"}})
    assert warnings and "koloru" in warnings[0]
    assert env.store.setups[U]["whistle_color"] == "#123456"


# ── połączenie, przejęcie, rozłączenie ─────────────────────────────────────
NEW = {"access_token": "n", "refresh_token": "nr", "expires_at": "2030-01-01T00:00:00", "scope": MATCHES_SCOPE}


async def test_first_connection_has_nothing_to_migrate_and_creates_calendars():
    env = make_deps()
    start, warnings = await after_connect(env.deps, U, previous=None, new_tokens=NEW, email="a@b.pl")
    assert start is False and env.store.setups[U]["migrated"] is True
    assert env.store.setups[U]["email"] == "a@b.pl"
    assert len(env.world.calendar_ids()) == 2
    assert env.store.tokens[U]["scope"] == MATCHES_SCOPE


async def test_reconnect_adopts_remembered_calendar_without_duplicate():
    env = make_deps()
    await after_connect(env.deps, U, previous=None, new_tokens=NEW, email=None)
    ids = dict(whistle=env.store.setups[U]["whistle_id"], stopwatch=env.store.setups[U]["stopwatch_id"])
    _, warnings = await disconnect(env.deps, U, remove_calendars=False)
    assert U not in env.store.tokens and env.store.setups[U]["whistle_id"] == ids["whistle"]
    start, _ = await after_connect(env.deps, U, previous=None, new_tokens=NEW, email=None)
    assert len(env.world.calendar_ids()) == 2  # zero duplikatów
    assert env.store.setups[U]["whistle_id"] == ids["whistle"]
    assert env.store.setups[U]["stopwatch_id"] == ids["stopwatch"]


async def test_reconnect_after_losing_access_to_remembered_calendar_makes_new_one():
    env = make_deps()
    await after_connect(env.deps, U, previous=None, new_tokens=NEW, email=None)
    old = env.store.setups[U]["whistle_id"]
    await disconnect(env.deps, U, remove_calendars=False)
    del env.world.calendars[old]  # w międzyczasie ktoś go skasował
    await after_connect(env.deps, U, previous=None, new_tokens=NEW, email=None)
    assert env.store.setups[U]["whistle_id"] not in (None, old)
    assert len(env.world.calendar_ids()) == 2


async def test_disconnect_with_removal_deletes_calendars_and_forgets_them():
    env = make_deps()
    await after_connect(env.deps, U, previous=None, new_tokens=NEW, email=None)
    await post(env, "1")
    was, warnings = await disconnect(env.deps, U, remove_calendars=True)
    assert was and not warnings
    assert not env.world.calendar_ids()
    assert env.store.setups[U]["whistle_id"] is None and (U, "1") not in env.store.maps
    assert U not in env.store.tokens
    assert await disconnect(env.deps, U, remove_calendars=True) == (False, [])


async def test_disconnect_removal_failure_keeps_id_and_warns():
    env = make_deps()
    await after_connect(env.deps, U, previous=None, new_tokens=NEW, email=None)
    kept = env.store.setups[U]["whistle_id"]
    env.world.fail.append(("delete_calendar", 500, kept))
    _, warnings = await disconnect(env.deps, U, remove_calendars=True)
    assert warnings and env.store.setups[U]["whistle_id"] == kept


# ── przenoszenie ───────────────────────────────────────────────────────────
def legacy_account(env, extra_primary=True):
    """Konto legacy z wpisami w kalendarzu głównym i mapowaniami."""
    env.store.tokens[U] = {"access_token": "old", "refresh_token": "oldr", "expires_at": "2030-01-01T00:00:00", "scope": None}
    w = env.world
    rows = {
        "m-whistle": (WHISTLE, FUTURE),
        "m-stop": (STOPWATCH, FUTURE),
        "m-past": (WHISTLE, PAST),
        "m-unavail": ("Urlop", FUTURE),
        "m-gone": (WHISTLE, FUTURE),
    }
    for match, (title, start) in rows.items():
        eid = f"ev-{match}"
        if match != "m-gone":
            w.add_primary_event(eid, title, start=start)
        env.store.maps[(U, match)] = {"user_login": U, "match_id": match, "event_id": eid, "calendar_id": None}


async def reconnect_matches(env):
    prev = await env.store.get_tokens(U)
    return await after_connect(env.deps, U, previous=prev, new_tokens=NEW, email="x@y.pl")


async def test_reconnect_of_legacy_account_parks_old_token_and_asks_for_migration():
    env = make_deps()
    legacy_account(env)
    start, _ = await reconnect_matches(env)
    row = env.store.setups[U]
    assert start is True and row["park_access"] == "old" and not row.get("migrated")
    assert row["job_state"] == "running" and row["job_kind"] == "migrate"
    assert env.store.tokens[U]["scope"] == MATCHES_SCOPE
    view = await setup_view(env.deps, U)
    assert view["needs_migration"] is True and view["district_access"] is False


async def test_migration_moves_only_future_match_events_and_leaves_unavailability():
    env = make_deps()
    legacy_account(env)
    await reconnect_matches(env)
    job = await run_job(env.deps, U)
    # liczniki: tylko przyszłe mecze (niedyspozycja, historia i wpis usunięty ręcznie nie wchodzą)
    assert job == {"kind": "migrate", "state": "done", "total": 2, "done": 2, "skipped": 0, "failed": 0,
                   "error": None, "kept_calendars": [], "note": None}
    assert not [e for e in env.world.log if e[0] == "get_event" and e[1] == "primary"]  # zero events.get
    prim = env.world.events_in("primary")
    # niedyspozycja i wpis historyczny nietknięte
    assert set(prim) == {"ev-m-unavail", "ev-m-past"}
    assert env.store.maps[(U, "m-unavail")]["calendar_id"] is None
    assert env.store.maps[(U, "m-past")]["calendar_id"] is None
    # mecze trafiły do właściwych kalendarzy (po prefiksie), bez koloru
    for match, name in (("m-whistle", "BAZA - Boiskowy"), ("m-stop", "BAZA - Stolikowy")):
        cal = env.store.maps[(U, match)]["calendar_id"]
        assert env.world.calendars[cal]["summary"] == name
        body = env.world.events[(cal, env.store.maps[(U, match)]["event_id"])]
        assert "colorId" not in body
    # wpis usunięty ręcznie: nic nie wskrzeszone
    assert not any(e[2] == "ev-m-gone" for e in env.world.log if e[0] == "insert_event")
    row = env.store.setups[U]
    assert row["migrated"] is True and row["park_access"] is None
    assert (await setup_view(env.deps, U))["needs_migration"] is False


async def test_migration_inserts_before_it_deletes_from_primary():
    env = make_deps()
    legacy_account(env)
    await reconnect_matches(env)
    env.world.log.clear()
    await run_job(env.deps, U)
    ops = [e for e in env.world.log if e[0] in ("insert_event", "delete_event")]
    for i, op in enumerate(ops):
        if op[0] == "delete_event":
            assert any(o[0] == "insert_event" for o in ops[:i])
    first_delete = next(i for i, o in enumerate(ops) if o[0] == "delete_event")
    assert ops[first_delete - 1][0] == "insert_event"


async def test_interrupted_migration_resumes_without_duplicates():
    env = make_deps()
    legacy_account(env)
    await reconnect_matches(env)
    env.world.fail.append(("delete_event", 500, "primary"))  # pierwsze kasowanie z primary pada
    job = await run_job(env.deps, U)
    assert job["state"] == "failed" and job["failed"] == 1 and job["error"]
    assert env.store.setups[U]["park_access"] == "old"  # token czeka na wznowienie
    assert not env.store.setups[U].get("migrated")
    job, started = await start_migration(env.deps, U)
    assert started is True
    job = await run_job(env.deps, U)
    assert job["state"] == "done" and job["failed"] == 0
    assert job["done"] == 2  # licznik skumulowany, bez dubli
    total_match_events = [
        e for cal in env.world.calendar_ids() for e in env.world.events_in(cal).values()
    ]
    assert len(total_match_events) == 2
    assert set(env.world.events_in("primary")) == {"ev-m-unavail", "ev-m-past"}


async def test_crash_between_primary_delete_and_mapping_save_is_recovered():
    env = make_deps()
    legacy_account(env)
    await reconnect_matches(env)
    env.store.fail_save_mapping = 1  # insert i delete poszły, zapis mapowania nie
    job = await run_job(env.deps, U)
    assert job["state"] == "failed" and job["failed"] == 1
    await start_migration(env.deps, U)
    job = await run_job(env.deps, U)
    assert job["state"] == "done" and job["failed"] == 0
    moved = [(k, v) for k, v in env.store.maps.items() if v["calendar_id"]]
    assert len(moved) == 2
    assert len([e for c in env.world.calendar_ids() for e in env.world.events_in(c)]) == 2


async def test_authorization_error_stops_job_with_a_clear_message():
    env = make_deps()
    legacy_account(env)
    await reconnect_matches(env)
    env.world.fail.append(("list_events", 401, "primary"))
    job = await run_job(env.deps, U)
    assert job["state"] == "failed" and "Połącz konto Google ponownie" in job["error"]


async def test_migrate_route_logic_guards():
    env = make_deps()
    with pytest.raises(SecondaryError) as err:
        await start_migration(env.deps, U)
    assert err.value.code == "calendar_not_connected"
    env.store.tokens[U] = {"access_token": "a", "refresh_token": "r", "expires_at": "x", "scope": None}
    with pytest.raises(SecondaryError) as err:
        await start_migration(env.deps, U)
    assert err.value.code == "reconnect_required"
    off = make_deps(flag=False)
    with pytest.raises(SecondaryError) as err:
        await start_migration(off.deps, U)
    assert err.value.status == 404


async def test_second_start_while_running_does_not_launch_second_worker():
    env = make_deps()
    legacy_account(env)
    await reconnect_matches(env)  # zadanie już biegnie (świeże bicie serca)
    job, started = await start_migration(env.deps, U)
    assert started is False and job["state"] == "running"
    env.store.setups[U]["job_heartbeat"] = NOW - datetime.timedelta(minutes=10)
    _, started = await start_migration(env.deps, U)
    assert started is True  # porzucone zadanie można przejąć


async def test_migration_without_access_to_primary_reports_instead_of_hiding():
    env = make_deps()
    legacy_account(env)
    env.store.tokens[U]["scope"] = None
    await reconnect_matches(env)
    env.store.setups[U]["park_access"] = None  # stary token przepadł
    job = await run_job(env.deps, U)
    assert job["state"] == "done" and job["total"] == 0 and job["error"] is None
    assert "mogły zostać" in job["note"]


async def test_new_writes_during_migration_leave_no_orphan_in_primary():
    env = make_deps()
    legacy_account(env)
    await reconnect_matches(env)  # zadanie wystartowało, jeszcze nie ruszyło
    await post(env, "m-whistle")  # aplikacja ponawia mecz w trakcie
    assert "ev-m-whistle" not in env.world.events_in("primary")  # skasowany starym tokenem
    cal = env.store.maps[(U, "m-whistle")]["calendar_id"]
    assert cal and len(env.world.events_in(cal)) == 1
    await run_job(env.deps, U)
    assert len([e for c in env.world.calendar_ids() for e in env.world.events_in(c)]) == 2


# ── zmiana układu ──────────────────────────────────────────────────────────
async def test_mode_change_moves_events_and_drops_empty_old_calendars():
    env = connect(make_deps(), U)
    await post(env, "1", WHISTLE)
    await post(env, "2", STOPWATCH)
    old = list(env.world.calendar_ids())
    view, _, start = await put_setup(env.deps, U, {"mode": "one"})
    assert start is True and view["job"]["kind"] == "mode"
    job = await run_job(env.deps, U)
    assert job["state"] == "done" and job["done"] == 2
    cals = env.world.calendar_ids()
    assert [env.world.calendars[c]["summary"] for c in cals if c not in old] == ["BAZA - Mecze"]
    assert all(c not in env.world.calendars for c in old)  # puste, więc skasowane
    shared = env.store.setups[U]["shared_id"]
    assert {v["calendar_id"] for v in env.store.maps.values()} == {shared}
    assert len(env.world.events_in(shared)) == 2
    # i z powrotem
    _, _, start = await put_setup(env.deps, U, {"mode": "two"})
    job = await run_job(env.deps, U)
    assert job["state"] == "done"
    assert {env.world.calendars[v["calendar_id"]]["summary"] for v in env.store.maps.values()} == {
        "BAZA - Boiskowy", "BAZA - Stolikowy"
    }


async def test_mode_change_keeps_old_calendar_with_foreign_entries():
    env = connect(make_deps(), U)
    await post(env, "1", WHISTLE)
    cal = env.store.setups[U]["whistle_id"]
    env.world.events[(cal, "reczny")] = {"id": "reczny", "summary": "Moje"}
    await put_setup(env.deps, U, {"mode": "one"})
    await run_job(env.deps, U)
    assert cal in env.world.calendars and "reczny" in env.world.events_in(cal)


async def test_mode_change_refused_while_job_runs_and_noop_for_same_mode():
    env = make_deps()
    legacy_account(env)
    await reconnect_matches(env)
    with pytest.raises(SecondaryError) as err:
        await put_setup(env.deps, U, {"mode": "one"})
    assert err.value.status == 409 and err.value.code == "job_running"
    _, _, start = await put_setup(env.deps, U, {"mode": "two"})
    assert start is False


async def test_mode_change_before_migration_only_changes_preference():
    env = make_deps()
    legacy_account(env)
    await reconnect_matches(env)
    await run_job(env.deps, U)
    env2 = make_deps()
    legacy_account(env2)
    await put_setup(env2.deps, U, {"mode": "one"})  # jeszcze bez zgody
    await reconnect_matches(env2)
    await run_job(env2.deps, U)
    assert [c["summary"] for k, c in env2.world.calendars.items() if k != "primary"] == ["BAZA - Mecze"]


async def test_abandoned_mode_job_is_resumed_as_mode_by_migrate_call():
    env = connect(make_deps(), U)
    await post(env, "1", WHISTLE)
    await post(env, "2", STOPWATCH)
    await put_setup(env.deps, U, {"mode": "one"})  # zadanie "mode" wystartowało, nikt go nie uruchomił
    env.store.setups[U]["job_heartbeat"] = NOW - datetime.timedelta(minutes=10)
    job, started = await start_migration(env.deps, U)  # migrated=True, a mimo to wznawia
    assert started is True and job["kind"] == "mode"
    job = await run_job(env.deps, U)
    assert job["kind"] == "mode" and job["state"] == "done" and job["done"] == 2
    # świeże zadanie nie jest przejmowane
    await put_setup(env.deps, U, {"mode": "two"})
    job, started = await start_migration(env.deps, U)
    assert started is False and job["state"] == "running"


async def test_kept_calendars_are_reported_in_job_and_setup():
    env = connect(make_deps(), U)
    await post(env, "1", WHISTLE)
    await post(env, "2", STOPWATCH)
    cal = env.store.setups[U]["whistle_id"]
    env.world.events[(cal, "reczny")] = {"id": "reczny", "summary": "Moje"}
    await put_setup(env.deps, U, {"mode": "one"})
    job = await run_job(env.deps, U)
    assert job["state"] == "done"
    assert job["kept_calendars"] == [{"kind": "whistle", "name": "BAZA - Boiskowy"}]
    assert (await setup_view(env.deps, U))["job"]["kept_calendars"] == job["kept_calendars"]
    # czysta zmiana układu: pusta lista
    env2 = connect(make_deps(), U)
    await post(env2, "1", WHISTLE)
    await put_setup(env2.deps, U, {"mode": "one"})
    assert (await run_job(env2.deps, U))["kept_calendars"] == []

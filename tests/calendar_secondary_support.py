"""Atrapy do testów kalendarzy drugorzędnych: Google w pamięci i baza w pamięci.

Bez sieci, bez Postgresa, bez bibliotek Google.
"""

from __future__ import annotations

import datetime
import itertools
from types import SimpleNamespace

from app.calendar_secondary_engine import SETUP_DEFAULTS, Deps
from app.calendar_secondary_rules import (
    SCOPE_APP_CREATED,
    SCOPE_CALENDARLIST,
    SCOPE_EVENTS,
    GoogleError,
)

NOW = datetime.datetime(2026, 11, 2, 12, 0, tzinfo=datetime.timezone.utc)
FUTURE = "2026-12-01T18:00:00+01:00"
FUTURE_END = "2026-12-01T20:00:00+01:00"
PAST = "2026-09-01T18:00:00+02:00"

MATCHES_SCOPE = f"{SCOPE_APP_CREATED} {SCOPE_CALENDARLIST} openid"
DISTRICT_SCOPE = f"{SCOPE_APP_CREATED} {SCOPE_CALENDARLIST} {SCOPE_EVENTS} openid"


class World:
    """Konto Google: kalendarze, wydarzenia, dziennik wywołań i wstrzykiwane awarie."""

    def __init__(self):
        self.calendars: dict[str, dict] = {"primary": {"summary": "primary"}}
        self.events: dict[tuple[str, str], dict] = {}
        self.log: list[tuple] = []
        self.fail: list[tuple] = []  # (metoda, status, [kalendarz]) jednorazowe
        self.list_color_fail = False
        self._ids = itertools.count(1)

    def add_primary_event(self, event_id, summary, start=FUTURE, end=FUTURE_END, **extra):
        self.events[("primary", event_id)] = {
            "id": event_id,
            "summary": summary,
            "start": {"dateTime": start},
            "end": {"dateTime": end},
            "location": "Hala",
            "reminders": {"useDefault": False, "overrides": [{"method": "popup", "minutes": 180}]},
            **extra,
        }

    def events_in(self, cal: str) -> dict[str, dict]:
        return {k[1]: v for k, v in self.events.items() if k[0] == cal}

    def calendar_ids(self) -> list[str]:
        return [c for c in self.calendars if c != "primary"]

    def _maybe_fail(self, method: str, cal: str | None = None):
        for i, spec in enumerate(self.fail):
            if spec[0] == method and (len(spec) < 3 or spec[2] in (None, cal)):
                self.fail.pop(i)
                raise GoogleError(spec[1])


class FakeApi:
    def __init__(self, world: World, primary: bool = True):
        self.w = world
        self.primary = primary

    def _cal(self, cal: str):
        if cal == "primary" and not self.primary:
            raise GoogleError(403)
        if cal not in self.w.calendars:
            raise GoogleError(404)

    async def get_calendar(self, calendar_id):
        self.w.log.append(("get_calendar", calendar_id))
        self.w._maybe_fail("get_calendar", calendar_id)
        self._cal(calendar_id)
        return {"id": calendar_id, **self.w.calendars[calendar_id]}

    async def insert_calendar(self, body):
        self.w.log.append(("insert_calendar", body["summary"]))
        self.w._maybe_fail("insert_calendar")
        cid = f"cal{next(self.w._ids)}@group.calendar.google.com"
        self.w.calendars[cid] = dict(body)
        return {"id": cid}

    async def delete_calendar(self, calendar_id):
        self.w.log.append(("delete_calendar", calendar_id))
        self.w._maybe_fail("delete_calendar", calendar_id)
        self._cal(calendar_id)
        del self.w.calendars[calendar_id]
        for key in [k for k in self.w.events if k[0] == calendar_id]:
            del self.w.events[key]

    async def patch_calendar_list(self, calendar_id, body):
        self.w.log.append(("patch_calendar_list", calendar_id, body))
        self.w._maybe_fail("patch_calendar_list", calendar_id)
        self._cal(calendar_id)
        self.w.calendars[calendar_id].update(body)
        return body

    async def get_event(self, calendar_id, event_id):
        self.w.log.append(("get_event", calendar_id, event_id))
        self.w._maybe_fail("get_event", calendar_id)
        self._cal(calendar_id)
        ev = self.w.events.get((calendar_id, event_id))
        if ev is None:
            raise GoogleError(404)
        return dict(ev)

    async def insert_event(self, calendar_id, body):
        self.w.log.append(("insert_event", calendar_id, body.get("id")))
        self.w._maybe_fail("insert_event", calendar_id)
        self._cal(calendar_id)
        key = (calendar_id, body["id"])
        if key in self.w.events:
            raise GoogleError(409)
        self.w.events[key] = dict(body)
        return {"id": body["id"]}

    async def update_event(self, calendar_id, event_id, body):
        self.w.log.append(("update_event", calendar_id, event_id))
        self.w._maybe_fail("update_event", calendar_id)
        self._cal(calendar_id)
        key = (calendar_id, event_id)
        if key not in self.w.events:
            raise GoogleError(404)
        self.w.events[key] = {**body, "id": event_id}
        return {"id": event_id}

    async def delete_event(self, calendar_id, event_id):
        self.w.log.append(("delete_event", calendar_id, event_id))
        self.w._maybe_fail("delete_event", calendar_id)
        self._cal(calendar_id)
        if (calendar_id, event_id) not in self.w.events:
            raise GoogleError(404)
        del self.w.events[(calendar_id, event_id)]

    async def list_events(self, calendar_id, max_results=1, time_min=None):
        self.w.log.append(("list_events", calendar_id))
        self.w._maybe_fail("list_events", calendar_id)
        self._cal(calendar_id)
        items = [v for k, v in self.w.events.items() if k[0] == calendar_id]
        if time_min is not None:
            from app.calendar_secondary_rules import _parse_moment, event_start

            floor = _parse_moment(time_min)
            items = [e for e in items if (event_start(e) or floor) > floor]
        return items[:max_results]


class FakeStore:
    def __init__(self):
        self.setups: dict[str, dict] = {}
        self.tokens: dict[str, dict] = {}
        self.maps: dict[tuple[str, str], dict] = {}
        self.fail_save_mapping = 0

    async def get_setup(self, user):
        row = self.setups.get(user)
        return dict(row) if row else None

    async def upsert_setup(self, user, **fields):
        self.setups.setdefault(user, {}).update(fields)

    async def set_calendar_id(self, user, kind, new_id, expect_old):
        row = self.setups.setdefault(user, {})
        if row.get(f"{kind}_id") != expect_old:
            return False
        row[f"{kind}_id"] = new_id
        return True

    async def get_tokens(self, user):
        row = self.tokens.get(user)
        return dict(row) if row else None

    async def save_tokens(self, user, access, refresh, expires_at, scope):
        self.tokens[user] = {
            "access_token": access,
            "refresh_token": refresh,
            "expires_at": expires_at,
            "scope": scope,
        }

    async def delete_tokens(self, user):
        self.tokens.pop(user, None)

    async def park_tokens(self, user, *, access, refresh, expires_at, scope):
        await self.upsert_setup(
            user, park_access=access, park_refresh=refresh, park_expires=expires_at, park_scope=scope
        )

    async def clear_park(self, user):
        await self.upsert_setup(
            user, park_access=None, park_refresh=None, park_expires=None, park_scope=None
        )

    async def list_mappings(self, user):
        return [dict(v) for (u, _), v in self.maps.items() if u == user]

    async def get_mapping(self, user, match_id):
        row = self.maps.get((user, match_id))
        return dict(row) if row else None

    async def save_mapping(self, user, match_id, event_id, calendar_id):
        if self.fail_save_mapping:
            self.fail_save_mapping -= 1
            raise RuntimeError("baza chwilowo niedostępna")
        self.maps[(user, match_id)] = {
            "user_login": user,
            "match_id": match_id,
            "event_id": event_id,
            "calendar_id": calendar_id,
        }

    async def delete_mapping(self, user, match_id):
        self.maps.pop((user, match_id), None)

    async def delete_mappings_for_calendar(self, user, calendar_id):
        for key in [k for k, v in self.maps.items() if k[0] == user and v["calendar_id"] == calendar_id]:
            del self.maps[key]

    async def try_start_job(self, user, kind, now, stale_seconds, carry_done):
        row = self.setups.setdefault(user, {})
        if row.get("job_state") == "running":
            beat = row.get("job_heartbeat")
            if beat and (now - beat).total_seconds() <= stale_seconds:
                return False
        row.update(
            job_kind=kind,
            job_state="running",
            job_done=carry_done,
            job_skipped=0,
            job_failed=0,
            job_error=None,
            job_heartbeat=now,
        )
        return True

    async def update_job(self, user, **fields):
        self.setups.setdefault(user, {}).update(fields)


def make_deps(world: World | None = None, store: FakeStore | None = None, flag: bool = True):
    world = world or World()
    store = store or FakeStore()
    current = FakeApi(world, primary=True)
    parked = FakeApi(world, primary=True)

    async def api_current(user):
        tok = await store.get_tokens(user)
        # Token matches nie ma dostępu do kalendarza głównego (jak w Google).
        has_primary = not tok or not tok.get("scope") or SCOPE_EVENTS in tok["scope"]
        return FakeApi(world, primary=has_primary)

    async def api_parked(user):
        setup = await store.get_setup(user)
        return parked if setup and setup.get("park_access") else None

    deps = Deps(store=store, flag=flag, api_current=api_current, api_parked=api_parked, now=lambda: NOW)
    return SimpleNamespace(deps=deps, world=world, store=store, current=current)


def connect(env, user, scope=MATCHES_SCOPE):
    """Zakłada token konta bez przechodzenia przez OAuth."""
    env.store.tokens[user] = {
        "access_token": "a",
        "refresh_token": "r",
        "expires_at": "2030-01-01T00:00:00",
        "scope": scope,
    }
    env.store.setups.setdefault(user, {}).setdefault("migrated", True)
    return env


__all__ = ["SETUP_DEFAULTS"]

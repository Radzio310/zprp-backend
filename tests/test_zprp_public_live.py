"""Publiczne LIVE i przebieg meczu z ProEla - trasy na małej bazie SQLite."""

import asyncio
import importlib
import json
import sys
import types
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from zoneinfo import ZoneInfo

import pytest
import sqlalchemy
from databases import Database
from sqlalchemy import JSON, BigInteger, Column, DateTime, Integer, String, Table, insert

from app.zprp_public_tables import define_tables as define_public
from app.national_distance_tables import define_tables as define_national

MODULES = ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.enrich", "app.zprp_public.api",
           "app.zprp_public.portal", "app.zprp_public.extras", "app.zprp_public.live")
WARSAW = ZoneInfo("Europe/Warsaw")


def _proel_tables(metadata):
    saved = Table(
        "proel_matches", metadata,
        Column("match_number", String, primary_key=True), Column("data_json", JSON), Column("status", String),
        Column("zprp_match_id", String), Column("updated_at", DateTime(timezone=True)),
    )
    state = Table(
        "proel_match_state", metadata,
        Column("match_number", String, primary_key=True), Column("zprp_match_id", String),
        Column("rev", BigInteger), Column("live_started_at", DateTime(timezone=True)),
        Column("lease_until", DateTime(timezone=True)), Column("lease_epoch", Integer),
        Column("updated_at", DateTime(timezone=True)),
    )
    return saved, state


@pytest.fixture
def env(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    pub = define_public(metadata)
    nat = define_national(metadata)
    saved, state = _proel_tables(metadata)
    url = f"sqlite:///{tmp_path / 'live.db'}"
    metadata.create_all(sqlalchemy.create_engine(url))
    fake = types.ModuleType("app.db")
    fake.database = Database(url.replace("sqlite://", "sqlite+aiosqlite://"))
    fake.DATABASE_URL = url
    for table in list(pub) + list(nat):
        setattr(fake, table.name, table)
    fake.saved_matches = saved
    fake.proel_match_state = state
    fake.__getattr__ = lambda name: MagicMock()
    monkeypatch.setitem(sys.modules, "app.db", fake)
    for name in MODULES:
        sys.modules.pop(name, None)
    live = importlib.import_module("app.zprp_public.live")
    importlib.import_module("app.zprp_public.enrich").invalidate()
    yield live, fake.database, {t.name: t for t in list(pub) + list(nat) + [saved, state]}
    for name in MODULES:
        sys.modules.pop(name, None)


def _h(**extra):
    return {"source_hash": "h", "source_json": {}, **extra}


def _blob(match_id, host, guest, **over):
    blob = {
        "matchConfig": {"matchNumber": "X", "matchId": match_id, "hostTeamName": host, "guestTeamName": guest, "halfTime": 30,
                        "hostPlayerCards": [{"number": 7, "fullName": "Tajne Dane"}], "referee1": "Sędzia Stolikowy"},
        "scoreHost": 1, "scoreGuest": 0, "mainTime": 300_000, "isFirstHalf": True, "isGameRunning": True,
        "savedAtMs": 1_700_000_000_000,
        "protocol": [{"type": "goal", "team": "host", "player": 7, "time": 120_000, "half": 1}],
    }
    blob.update(over)
    return blob


async def _seed(db, T):
    local = datetime.now(WARSAW).replace(tzinfo=None, microsecond=0)
    utc = datetime.now(timezone.utc)

    def ins(table, /, **v):
        return db.execute(insert(T[table]).values(**v))

    await ins("zprp_public_seasons", season_id="S1", start_year=2026, name="2026/27", active=True, **_h())
    for cid, name in (("c1", "SMS Enea Gniezno"), ("c2", "KS Pyrki Poznań")):
        await ins("zprp_public_clubs", club_id=cid, name=name, city="X", archived=False, logo_url=f"https://l/{cid}.png", **_h())
    base = dict(season_id="S1", competition_id="K1", competition_name="Wielkopolska Liga Juniorek", **_h())

    def match(mid, code, h, a, minutes_ago, **kw):
        return dict(match_id=mid, match_code=code, home_team_id=h, away_team_id=a, home_club_id=h, away_club_id=a,
                    home_team_name={"c1": "SMS Enea Gniezno", "c2": "KS Pyrki Poznań"}[h],
                    away_team_name={"c1": "SMS Enea Gniezno", "c2": "KS Pyrki Poznań"}[a],
                    scheduled_at=local - timedelta(minutes=minutes_ago), **base, **kw)

    # m1: trwa w ProElu; ZPRP ma gospodarzy odwrotnie niż protokół (zamiana stron po nazwach).
    await ins("zprp_public_matches", **match("m1", "P/JK/6", "c2", "c1", 20))
    # m2: powinien trwać (godzina minęła), ProEl milczy.
    await ins("zprp_public_matches", **match("m2", "P/JK/7", "c1", "c2", 30))
    # m3: za godzinę.
    await ins("zprp_public_matches", **match("m3", "P/JK/8", "c1", "c2", -60))
    # m4: testowy protokół ProEl - nigdy publicznie.
    await ins("zprp_public_matches", **match("m4", "P/JK/9", "c1", "c2", 10))

    await ins("proel_matches", match_number="P/JK/6", zprp_match_id="m1", status="in_progress",
              updated_at=utc - timedelta(seconds=30), data_json=_blob("m1", "SMS Enea Gniezno", "KS Pyrki Poznań"))
    await ins("proel_match_state", match_number="P/JK/6", zprp_match_id="m1", rev=5, live_started_at=utc - timedelta(minutes=10),
              lease_until=utc + timedelta(seconds=60), updated_at=utc)
    await ins("proel_matches", match_number="P/JK/9", zprp_match_id="m4", status="in_progress", updated_at=utc,
              data_json=_blob("m4", "SMS Enea Gniezno", "KS Pyrki Poznań", matchConfig={"isTest": True, "matchNumber": "T"}))
    await ins("proel_match_state", match_number="P/JK/9", zprp_match_id="m4", rev=1, live_started_at=utc,
              lease_until=utc + timedelta(seconds=60), updated_at=utc)


def run(env, factory):
    module, db, T = env

    async def go():
        await db.connect()
        try:
            await _seed(db, T)
            return await factory(module, db, T)
        finally:
            await db.disconnect()

    return asyncio.run(go())


def test_live_tylko_ze_zrodla_i_bez_danych_osobowych(env):
    async def go(live, db, T):
        return await live.live_matches(since="", wait=0)

    out = run(env, go)
    assert [c["match_id"] for c in out["live"]] == ["m1"]
    card = out["live"][0]
    assert card["status"] == "live"
    # protokół: SMS (host) 1:0; w ZPRP SMS jest gościem -> wynik po stronie away
    assert card["live"]["score"] == {"home": 0, "away": 1}
    assert card["live"]["last_events"][0]["side"] == "away"
    assert card["live"]["clock"]["running"] is True
    # m4 ma tylko testowy protokół - dla portalu to zwykły mecz z terminarza
    assert [c["match_id"] for c in out["window"]] == ["m2", "m4"]
    assert [c["match_id"] for c in out["soon"]] == ["m3"]
    assert "m4" not in json.dumps(out["live"], default=str)  # test ProEla
    text = json.dumps(out, default=str)
    assert "Tajne" not in text and "Stolikowy" not in text
    assert out["token"]


def test_long_poll_wraca_po_zmianie(env):
    async def go(live, db, T):
        first = await live.live_matches(since="", wait=0)
        live.TICK_S = 0.05
        live._live_rows_memo.ttl = 0.0

        async def bump():
            await asyncio.sleep(0.2)
            await db.execute(T["proel_match_state"].update().where(T["proel_match_state"].c.match_number == "P/JK/6").values(rev=6))

        task = asyncio.create_task(bump())
        second = await live.live_matches(since=first["token"], wait=5)
        await task
        same = await live.live_matches(since=second["token"], wait=0)
        return first, second, same

    first, second, same = run(env, go)
    assert second["token"] != first["token"] and second["changed"] is True
    assert same["changed"] is False


def test_przebieg_meczu(env):
    async def go(live, db, T):
        return await live.match_timeline("m1", since="", wait=0), await live.match_timeline("m2", since="", wait=0)

    tl, empty = run(env, go)
    assert tl["available"] is True and tl["phase"] == "live" and tl["sides"] == "swapped"
    assert tl["events"][0] == {"t": 120_000, "half": 1, "side": "away", "kind": "goal", "number": 7, "staff": None,
                               "score": {"home": 0, "away": 1}}
    assert tl["board"]["score"] == {"home": 0, "away": 1}
    assert empty["available"] is False and empty["events"] == []

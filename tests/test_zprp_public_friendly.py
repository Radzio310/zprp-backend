"""Mecze towarzyskie z ProEla w Pod Ręką: identyfikator, LIVE, historia, przegląd, przebieg."""

import asyncio
import importlib
import sys
import types
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
import sqlalchemy
from databases import Database
from sqlalchemy import JSON, BigInteger, Column, DateTime, Integer, String, Table, insert

from app.zprp_public import friendly_rules as FR
from app.zprp_public_tables import define_tables as define_public
from app.national_distance_tables import define_tables as define_national

MODULES = ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.enrich", "app.zprp_public.api",
           "app.zprp_public.portal", "app.zprp_public.extras", "app.zprp_public.live", "app.zprp_public.friendly")


def test_identyfikator_jest_odwracalny():
    for key in ("M-ABC12345/EHF/1", "EHF/1", "M-ZZ9988AA/Łódź 7"):
        fid = FR.friendly_id(key)
        assert fid.startswith("tow-") and FR.key_of_id(fid) == key and FR.is_friendly_id(fid)
    assert not FR.is_friendly_id("212530") and not FR.is_friendly_id("tow-") and not FR.is_friendly_id("tow-!!!")
    assert FR.key_of_id("tow-QUJD=") == ""  # nieznormalizowany zapis


def test_blob_towarzyski():
    cfg = {"hostTeamName": "Polska", "guestTeamName": "Słowenia"}
    assert FR.is_friendly_blob({"matchConfig": cfg})
    assert not FR.is_friendly_blob({"matchConfig": {**cfg, "matchId": "123456"}})
    assert FR.is_friendly_blob({"matchConfig": {**cfg, "matchId": "Date.now()-1"}})
    assert not FR.is_friendly_blob({"matchConfig": {**cfg, "isTest": True}})
    assert not FR.is_friendly_blob({"matchConfig": {**cfg, "training": {"x": 1}}})
    assert not FR.is_friendly_blob({"matchConfig": {"hostTeamName": "Polska"}})


def _proel_tables(metadata):
    saved = Table("proel_matches", metadata, Column("match_number", String, primary_key=True), Column("data_json", JSON),
                  Column("status", String), Column("zprp_match_id", String), Column("updated_at", DateTime(timezone=True)))
    state = Table("proel_match_state", metadata, Column("match_number", String, primary_key=True),
                  Column("zprp_match_id", String), Column("rev", BigInteger), Column("live_started_at", DateTime(timezone=True)),
                  Column("lease_until", DateTime(timezone=True)), Column("lease_epoch", Integer),
                  Column("updated_at", DateTime(timezone=True)))
    return saved, state


@pytest.fixture
def env(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    pub = define_public(metadata)
    nat = define_national(metadata)
    saved, state = _proel_tables(metadata)
    url = f"sqlite:///{tmp_path / 'fr.db'}"
    metadata.create_all(sqlalchemy.create_engine(url))
    fake = types.ModuleType("app.db")
    fake.database = Database(url.replace("sqlite://", "sqlite+aiosqlite://"))
    fake.DATABASE_URL = url
    for table in list(pub) + list(nat):
        setattr(fake, table.name, table)
    fake.saved_matches, fake.proel_match_state = saved, state
    fake.__getattr__ = lambda name: MagicMock()
    monkeypatch.setitem(sys.modules, "app.db", fake)
    for name in MODULES:
        sys.modules.pop(name, None)
    live = importlib.import_module("app.zprp_public.live")
    friendly = importlib.import_module("app.zprp_public.friendly")
    portal = importlib.import_module("app.zprp_public.portal")
    importlib.import_module("app.zprp_public.enrich").invalidate()
    yield live, friendly, portal, fake.database, {t.name: t for t in list(pub) + list(nat) + [saved, state]}
    for name in MODULES:
        sys.modules.pop(name, None)


def _blob(host="Polska", guest="Słowenia", **cfg):
    return {
        "matchConfig": {"matchNumber": "EHF/1", "hostTeamName": host, "guestTeamName": guest, "halfTime": 30,
                        "referee1": "Kowalski Jan", "referee2": "--- ---", "venueCity": "Gliwice",
                        "extras": {"matchDate": "2026-11-06", "matchTime": "18:30"},
                        "hostPlayerCards": [{"number": 7, "fullName": "Nowak Adam"}],
                        "guestPlayerCards": [{"number": 3, "fullName": "Horvat Luka"}],
                        **cfg},
        "scoreHost": 1, "scoreGuest": 0, "mainTime": 300_000, "isFirstHalf": True, "isGameRunning": True,
        "savedAtMs": 1_700_000_000_000,
        "protocol": [{"type": "goal", "team": "host", "player": 7, "time": 120_000, "half": 1}],
    }


KEY = "M-ABCDEF12/EHF/1"


def run(env, factory):
    live, friendly, portal, db, T = env

    async def go():
        await db.connect()
        try:
            utc = datetime.now(timezone.utc)

            def ins(table, **v):
                return db.execute(insert(T[table]).values(**v))

            await ins("proel_matches", match_number=KEY, status="in_progress", updated_at=utc - timedelta(seconds=20), data_json=_blob())
            await ins("proel_match_state", match_number=KEY, rev=3, live_started_at=utc - timedelta(minutes=9),
                      lease_until=utc + timedelta(seconds=60), updated_at=utc)
            # numer znany w terminarzu ZPRP -> to mecz rozgrywek, nie towarzyski
            await ins("zprp_public_matches", match_id="z1", match_code="S/JK/6", season_id="S", competition_id="K",
                      competition_name="L", source_hash="h", source_json={})
            await ins("proel_matches", match_number="S/JK/6", status="finished", updated_at=utc, data_json=_blob("A", "B"))
            await ins("proel_match_state", match_number="S/JK/6", rev=1, live_started_at=utc, updated_at=utc)
            # zakończony towarzyski sprzed 3 dni, szkoleniowy, przedmeczowy
            await ins("proel_matches", match_number="M-ZZZZ1111/EHF/2", status="approved", updated_at=utc - timedelta(days=3),
                      data_json={**_blob("Niemcy", "Dania"), "scoreHost": 20, "scoreGuest": 18})
            await ins("proel_match_state", match_number="M-ZZZZ1111/EHF/2", rev=9,
                      live_started_at=utc - timedelta(days=3), updated_at=utc)
            await ins("proel_matches", match_number="T-K3N8P2WQ/EHF/1", status="finished", updated_at=utc, data_json=_blob())
            await ins("proel_matches", match_number="M-PRE00000/EHF/3", status="in_progress", updated_at=utc, data_json=_blob())
            await ins("proel_match_state", match_number="M-PRE00000/EHF/3", rev=1, updated_at=utc)
            return await factory(live, friendly, portal)
        finally:
            await db.disconnect()

    return asyncio.run(go())


def test_live_i_historia(env):
    async def go(live, friendly, portal):
        return await live.live_matches(since="", wait=0), await friendly.friendlies(limit=20, offset=0)

    feed, hist = run(env, go)
    assert [c["match_id"] for c in feed["live"]] == [FR.friendly_id(KEY)]
    card = feed["live"][0]
    assert card["friendly"] is True and card["status"] == "live" and card["home_team_name"] == "Polska"
    assert card["live"]["score"] == {"home": 1, "away": 0}
    # historia: tylko zakończone; bez T-, bez numeru znanego w ZPRP, bez przedmeczowego
    assert [c["match_code"] for c in hist["items"]] == ["EHF/2"]
    assert hist["items"][0]["score_home"] == 20 and hist["items"][0]["status"] == "finished"
    assert all(c["match_id"] != FR.friendly_id("S/JK/6") for c in feed["finished"])


def test_przeglad_i_przebieg(env):
    fid = FR.friendly_id(KEY)

    async def go(live, friendly, portal):
        return await portal.match_overview(fid), await live.match_timeline(fid, since="", wait=0)

    over, tl = run(env, go)
    assert over["friendly"] is True and over["match"]["competition_name"] == "Mecz towarzyski"
    assert over["match"]["venue_city"] == "Gliwice" and over["match"]["scheduled_at"] == datetime(2026, 11, 6, 18, 30)
    assert over["officials"] == [{"role": "Sędzia", "id": None, "name": "Kowalski Jan"}]
    home = {p["shirt_number"]: p for p in over["lineups"]["home"]}
    assert home["7"]["last_name"] == "Nowak" and home["7"]["goals"] == 1
    assert over["lineups"]["away"][0]["last_name"] == "Horvat"
    assert tl["available"] is True and tl["phase"] == "live" and tl["sides"] == "direct"
    assert tl["events"][0]["score"] == {"home": 1, "away": 0}


def test_obcy_klucz_i_szkoleniowy_to_404(env):
    from fastapi import HTTPException

    async def go(live, friendly, portal):
        out = []
        for key in ("T-K3N8P2WQ/EHF/1", "S/JK/6", "M-NIEMA000/X/1"):
            try:
                await portal.match_overview(FR.friendly_id(key))
                out.append("ok")
            except HTTPException as e:
                out.append(e.status_code)
        return out

    assert run(env, go) == [404, 404, 404]

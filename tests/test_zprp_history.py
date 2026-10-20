"""Pobieranie minionych sezonów: kolejność, wznawianie po restarcie, zatrzymanie.

`app.db` łączy się z Postgresem przy imporcie, więc podmieniamy go modułem z
tabelami hurtowni na SQLite (stan pętli i zapytania o braki działają naprawdę).
"""

import asyncio
import importlib
import sys
import types
from datetime import datetime
from unittest.mock import MagicMock

import pytest
import sqlalchemy
from databases import Database
from sqlalchemy import insert

from app.zprp_public_tables import define_tables as define_public

SEASONS = {
    "1": {"ID_sezon": "195", "Rok_rozpoczecia": "2026", "Nazwa": "2026/2027", "Stan": "1"},
    "2": {"ID_sezon": "194", "Rok_rozpoczecia": "2025", "Nazwa": "2025/2026", "Stan": "0"},
    "3": {"ID_sezon": "188", "Rok_rozpoczecia": "2020", "Nazwa": "2020/2021", "Stan": "0"},
    "4": {"ID_sezon": "187", "Rok_rozpoczecia": "2019", "Nazwa": "2019/2020", "Stan": "0"},
}
COMPETITIONS = {
    "194": {"1": {"Id_rozgrywki": "a"}, "2": {"Id_rozgrywki": "b"}, "3": {"Id_rozgrywki": "c"}},
    "188": {"1": {"Id_rozgrywki": "d"}},
    "187": {"1": {"Id_rozgrywki": "e"}},
}


class FakeClient:
    requests = 0

    async def get(self, path):
        if path.startswith("pokaz_sezony"):
            return SEASONS
        return COMPETITIONS[path.split("Sezon=")[1]]

    async def close(self):
        pass


@pytest.fixture
async def world(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    pub = define_public(metadata)
    url = f"sqlite:///{tmp_path / 'history.db'}"
    metadata.create_all(sqlalchemy.create_engine(url))
    fake = types.ModuleType("app.db")
    fake.database = Database(url.replace("sqlite://", "sqlite+aiosqlite://"))
    fake.DATABASE_URL = url
    for table in pub:
        setattr(fake, table.name, table)
    fake.__getattr__ = lambda name: MagicMock()
    monkeypatch.setitem(sys.modules, "app.db", fake)
    names = [n for n in list(sys.modules) if n.startswith("app.zprp_public.")]
    for name in names:
        monkeypatch.delitem(sys.modules, name, raising=False)
    H = importlib.import_module("app.zprp_public.history")
    await fake.database.connect()

    box = {"H": H, "db": fake.database, "T": {t.name: t for t in pub}, "tree": [], "rosters": [], "details": [], "die_on": None}

    async def tree(client, item, counters, include_stats):
        cid = item["Id_rozgrywki"]
        if box["die_on"] == cid:
            box["die_on"] = None
            raise asyncio.CancelledError()
        box["tree"].append(cid)

    async def competition(item, season_id, counters):
        return item["Id_rozgrywki"]

    teams = {"194": ["t1", "t2"], "188": ["t3"], "187": []}
    todo = {"194": ["m1", "m2", "m3"], "188": ["m4"], "187": []}

    async def pending_rosters(season_id):
        return [t for t in teams[season_id] if t not in box["rosters"]]

    async def pending_details(season_id, limit):
        return [m for m in todo[season_id] if m not in box["details"]][:limit]

    async def roster(client, team_id, season_id, counters):
        box["rosters"].append(team_id)

    async def details(client, match_id, counters):
        box["details"].append(match_id)
        return "comp"

    monkeypatch.setattr(H.sync_mod, "_sync_competition_tree", tree)
    monkeypatch.setattr(H.sync_mod, "_store_competition", competition)
    monkeypatch.setattr(H.sync_mod, "_sync_roster", roster)
    monkeypatch.setattr(H.sync_mod, "_sync_match_details", details)
    monkeypatch.setattr(H, "_pending_rosters", pending_rosters)
    monkeypatch.setattr(H, "_pending_details", pending_details)
    yield box
    await fake.database.disconnect()


async def test_past_seasons_come_from_api_list_newest_first(world):
    H = world["H"]
    result = H.past_seasons(list(SEASONS.values()))
    assert [s["ID_sezon"] for s in result] == ["194", "188", "187"]


async def test_full_run_visits_every_past_season_and_completes(world):
    H = world["H"]
    await H.start()
    state = await H.run_history(client=FakeClient())
    assert world["tree"] == ["a", "b", "c", "d", "e"]
    assert world["rosters"] == ["t1", "t2", "t3"]
    assert world["details"] == ["m1", "m2", "m3", "m4"]
    assert all(state["seasons"][s]["status"] == "done" for s in ("194", "188", "187"))
    assert state["completed_at"] and state["enabled"] is False


async def test_resume_after_restart_skips_finished_competitions(world):
    H = world["H"]
    await H.start()
    world["die_on"] = "c"
    with pytest.raises(asyncio.CancelledError):
        await H.run_history(client=FakeClient())
    assert world["tree"] == ["a", "b"]
    saved = await H.load_state()
    assert saved["seasons"]["194"]["competitions_done"] == ["a", "b"]
    assert saved["lease"] is None

    await H.run_history(client=FakeClient())
    assert world["tree"] == ["a", "b", "c", "d", "e"]  # a i b nie powtórzone
    assert (await H.load_state())["seasons"]["194"]["status"] == "done"


async def test_stop_request_halts_after_current_step_and_is_remembered(world):
    H = world["H"]
    await H.start()
    original = H.sync_mod._sync_competition_tree

    async def stop_after_first(client, item, counters, include_stats):
        await original(client, item, counters, include_stats)
        await H.stop()

    H.sync_mod._sync_competition_tree = stop_after_first
    try:
        await H.run_history(client=FakeClient())
    finally:
        H.sync_mod._sync_competition_tree = original
    assert world["tree"] == ["a"]
    saved = await H.load_state()
    assert saved["enabled"] is False
    assert saved["user_stopped"] is True


async def test_autostart_only_on_production_by_default(world, monkeypatch):
    H = world["H"]
    monkeypatch.delenv("ZPRP_HISTORY_AUTOSTART", raising=False)
    monkeypatch.delenv("RAILWAY_ENVIRONMENT_NAME", raising=False)
    assert H.autostart_enabled() is False
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    assert H.autostart_enabled() is True
    monkeypatch.setenv("ZPRP_HISTORY_AUTOSTART", "0")
    assert H.autostart_enabled() is False


async def test_pending_queries_use_real_tables_and_close_empty_details(world):
    H, db, T = world["H"], world["db"], world["T"]
    h = {"source_hash": "h", "source_json": {}}
    base = dict(season_id="194", competition_id="a", **h)
    await db.execute(insert(T["zprp_public_matches"]).values(match_id="m1", home_team_id="t1", away_team_id="t2", **base))
    await db.execute(insert(T["zprp_public_matches"]).values(match_id="m2", home_team_id="t2", away_team_id="t3", details_fetched_at=datetime(2026, 1, 1), **base))
    await db.execute(insert(T["zprp_public_teams"]).values(team_id="t1", season_id="194", name="A", roster_fetched_at=datetime(2026, 1, 1), **h))
    # prawdziwe zapytania (bez atrap) - odtwarzamy je z modułu przed podmianą
    importlib.reload(H)
    assert await H._pending_rosters("194") == ["t2", "t3"]
    assert await H._pending_details("194", 10) == ["m1"]

"""Exercise live writes against a local SQL store, without importing production DB."""
import ast
import importlib.util
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import (Boolean, Column, DateTime, Float, JSON, MetaData, String,
                        Table, create_engine, select, update)

from app import settlement_origin as O, settlement_rates as R
from app.settlement_distances import VersionedDistanceIndex
from app.settlement_seasons import in_scope, season_of
from app.settlement_sync_rules import STORE_BATCH, upsert_batches
from app.settlement_venues import looks_like_city, pretty_city

APP = Path(__file__).resolve().parents[1] / "app"
NOW = datetime(2026, 10, 31, 12, tzinfo=timezone.utc)


def functions(*names):
    tree = ast.parse((APP / "province_settlement_sync.py").read_text(encoding="utf-8"))
    return ast.Module(body=[n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and n.name in names], type_ignores=[])


class LocalDB:
    def __init__(self, conn):
        self.conn, self.depth = conn, 0

    def normalize(self, row):
        return {k: v.replace(tzinfo=timezone.utc) if isinstance(v, datetime) and v.tzinfo is None else v
                for k, v in row.items()}

    async def fetch_all(self, query):
        rows = [self.normalize(r) for r in self.conn.execute(query).mappings()]
        if not self.depth:
            self.conn.commit()
        return rows

    async def fetch_one(self, query):
        rows = await self.fetch_all(query)
        return rows[0] if rows else None

    async def fetch_val(self, query):
        row = await self.fetch_one(query)
        return next(iter(row.values())) if row else None

    async def execute(self, query):
        self.conn.execute(query)
        if not self.depth:
            self.conn.commit()

    @asynccontextmanager
    async def transaction(self):
        self.depth += 1
        try:
            yield
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise
        finally:
            self.depth -= 1


@pytest.fixture
def world(monkeypatch):
    meta = MetaData()
    def table(name, fields):
        return Table(name, meta, *(Column(key, typ, primary_key=pk) for key, typ, pk in fields))
    matches = table("province_matches", [("province", String, True), ("match_id", String, True),
        ("state_json", JSON, False), ("active", Boolean, False), ("match_code", String, False),
        ("match_at", DateTime, False), ("season", String, False), ("approved", Boolean, False)])
    table("province_judges", [("province", String, True), ("judge_id", String, True), ("full_name", String, False)])
    judges = table("province_settlement_judges", [("province", String, True), ("judge_id", String, True),
        ("full_name", String, False), ("home_city", String, False)])
    modules = table("province_modules", [("province", String, True), ("module", String, True), ("enabled", Boolean, False)])
    table("okreg_distances", [("province", String, True), ("content", JSON, False)])
    settlements = table("province_settlement_matches", [
        (key, String, key in {"province", "judge_id", "match_key"}) for key in
        ["province", "judge_id", "match_key", "season", "match_code", "role", "level", "origin", "city",
         "hall", "home_city", "teams", "round_text", "series_text", "distance_source"]] +
        [("match_at", DateTime, False), ("last_seen_at", DateTime, False), ("updated_at", DateTime, False),
         ("distance_km", Float, False), ("active", Boolean, False), ("approved", Boolean, False)])
    engine = create_engine("sqlite://")
    meta.create_all(engine)
    conn = engine.connect()
    conn.connection.create_function("pg_advisory_xact_lock", 1, lambda key: 0)
    db = LocalDB(conn)
    fake_db = ModuleType("app.db")
    for t in meta.tables.values():
        setattr(fake_db, t.name, t)
    fake_db.database = db
    # The live module has no DB-importing transitive dependencies.
    monkeypatch.setitem(sys.modules, "app.db", fake_db)
    spec = importlib.util.spec_from_file_location("live_under_test", APP / "settlement_live.py")
    live = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(live)
    source = ModuleType("app.province_settlement_sync")
    source.__dict__.update({"R": R, "O": O, "season_of": season_of, "in_scope": in_scope,
        "_now": lambda: NOW, "_s": lambda v: str(v or "").strip(), "_state": lambda v: v or {},
        "_parse_when": lambda v: datetime.fromisoformat(v) if v else None,
        "database": db, "province_settlement_matches": settlements, "STORE_BATCH": STORE_BATCH,
        "tuple_": __import__("sqlalchemy").tuple_, "select": select, "update": update,
        "and_": __import__("sqlalchemy").and_, "VersionedDistanceIndex": VersionedDistanceIndex,
        "pretty_city": pretty_city, "looks_like_city": looks_like_city,
        "load_national_pairs": AsyncMock(return_value={}), "judge_cities": AsyncMock(return_value={}),
        "_own_prefixes": AsyncMock(return_value=set())})
    exec(compile(functions("_district_assignments", "_district_rows", "_store_locked"), "projection", "exec"), source.__dict__)
    async def upsert(rows):
        await upsert_batches(db, settlements, rows, ["province", "judge_id", "match_key"])
    source._upsert_matches = upsert
    import app
    monkeypatch.setitem(sys.modules, "app.province_settlement_sync", source)
    monkeypatch.setattr(app, "province_settlement_sync", source, raising=False)
    conn.execute(modules.insert().values(province="SLASKIE", module="settlements", enabled=True))
    for number in ("1", "2", "3"):
        conn.execute(judges.insert().values(province="SLASKIE", judge_id=number, full_name=f"Judge {number}", home_city="Katowice"))
    conn.commit()
    yield SimpleNamespace(live=live, db=db, matches=matches, settlements=settlements, source=source)
    conn.close()
    engine.dispose()


def state(secretary):
    return {"NrSedzia_sekretarz": secretary, "NrSedzia_sekretarz_nazwisko": f"Judge {secretary}",
            "NrSedzia_czas": "2", "NrSedzia_czas_nazwisko": "Judge 2", "RozgrywkiCode": "OSM/12",
            "Hala_miasto": "Katowice", "Hala_nazwa": "Hala", "season": "2026/2027"}


async def put_match(w, match_id, crew):
    await w.db.execute(w.matches.insert().values(province="SLASKIE", match_id=match_id, state_json=crew,
        active=True, match_code="OSM/12", match_at=NOW, season="2026/2027", approved=False))


@pytest.mark.asyncio
async def test_exchange_moves_only_one_match_and_full_run_cannot_undo_it(world):
    w = world
    await put_match(w, "42", state("1"))
    await put_match(w, "43", state("1"))
    await w.live._sync_match("ŚLĄSKIE", "42", enrich=False)
    await w.live._sync_match("SLASKIE", "43", enrich=False)
    old_batch = {(r["judge_id"], r["match_key"]): r for r in await w.db.fetch_all(select(w.settlements))}
    await w.db.execute(update(w.matches).where(w.matches.c.match_id == "42").values(state_json=state("3")))
    started_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await w.live._sync_match("SLASKIE", "42", previous_state=state("1"), enrich=False)
    rows = {(r["judge_id"], r["match_key"]): r for r in await w.db.fetch_all(select(w.settlements))}
    assert rows["1", "d:42"]["active"] is False
    assert rows["3", "d:42"]["active"] is True
    assert rows["2", "d:42"]["active"] is True
    assert rows["1", "d:43"]["active"] is True
    assert rows["3", "d:42"]["distance_km"] == 0
    old_batch["1", "o:42"] = {**old_batch["1", "d:42"], "match_key": "o:42", "origin": "outside"}
    # A scrape collected before the exchange reaches its final commit afterwards.
    await w.source._store_locked("SLASKIE", old_batch, set(old_batch), NOW,
                                 {"2026/2027"}, "2026/2027", started_at)
    rows = {(r["judge_id"], r["match_key"]): r for r in await w.db.fetch_all(select(w.settlements))}
    assert rows["1", "d:42"]["active"] is False
    assert rows["3", "d:42"]["active"] is True
    assert ("1", "o:42") not in rows


@pytest.mark.asyncio
async def test_removal_before_first_full_run_leaves_receipt_and_readding_restores(world):
    w = world
    await put_match(w, "42", state("3"))
    await w.live._sync_match("SLASKIE", "42", previous_state=state("1"), enrich=False)
    rows = {r["judge_id"]: r for r in await w.db.fetch_all(select(w.settlements))}
    assert rows["1"]["active"] is False  # prevents stale phone forecast resurrecting it
    await w.db.execute(update(w.matches).where(w.matches.c.match_id == "42").values(state_json=state("1")))
    await w.live._sync_match("SLASKIE", "42", previous_state=state("3"), enrich=False)
    rows = {r["judge_id"]: r for r in await w.db.fetch_all(select(w.settlements))}
    assert rows["1"]["active"] is True
    assert rows["3"]["active"] is False
    assert len([r for r in rows.values() if r["active"]]) == 2

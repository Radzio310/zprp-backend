"""Rules of the home city frozen at the moment of settlement (06.11.2026)."""
from types import SimpleNamespace

import pytest

from app import settlement_home_lock as HL


def test_apply_locks_restores_frozen_fields_only_for_locked_rows():
    batch = {
        ("1", "d:42"): {"home_city": "Gliwice", "distance_km": 27.0, "distance_source": "google", "city": "Bytom"},
        ("1", "d:43"): {"home_city": "Gliwice", "distance_km": 12.0, "distance_source": "table", "city": "Zabrze"},
    }
    locked = {("1", "d:42"): {"home_city": "Katowice", "distance_km": 14.0, "distance_source": "table"}}
    assert HL.apply_locks(batch, locked) == 1
    assert batch["1", "d:42"] == {"home_city": "Katowice", "distance_km": 14.0, "distance_source": "table", "city": "Bytom"}
    assert batch["1", "d:43"]["home_city"] == "Gliwice"
    # Second pass changes nothing.
    assert HL.apply_locks(batch, locked) == 0


def test_lock_keys_of_skips_empty_and_duplicates():
    matches = [SimpleNamespace(match_key="d:1"), SimpleNamespace(match_key="d:1"), SimpleNamespace(match_key=""), {"match_key": "o:2"}]
    assert HL.lock_keys_of(matches) == ["d:1", "o:2"]


def test_home_story_period_settled_from_previous_city():
    rows = [
        {"home_city": "Katowice", "home_locked": "7/S/2026"},
        {"home_city": "katowice ", "home_locked": "7/S/2026"},
        {"home_city": "", "home_locked": None},
    ]
    story = HL.home_story(rows, "Gliwice")
    assert story["changed"] is True
    assert story["settled"] == "all"
    assert story["current"] == "Gliwice"
    assert story["cities"] == [
        {"city": "Katowice", "matches": 2, "locked": 2, "documents": ["7/S/2026"], "current": False}
    ]


def test_home_story_mixed_period_and_unchanged_city():
    mixed = HL.home_story(
        [{"home_city": "Katowice", "home_locked": "7/S/2026"}, {"home_city": "Gliwice", "home_locked": None}],
        "Gliwice",
    )
    assert mixed["changed"] is True and mixed["settled"] == "some"
    assert [c["current"] for c in mixed["cities"]] == [False, True]

    same = HL.home_story([{"home_city": "Gliwice", "home_locked": None}], "gliwice")
    assert same["changed"] is False and same["settled"] == "none"

    assert HL.home_story([{"home_city": ""}], "Gliwice") is None
    # Unknown current city: nothing to compare, nothing "changed".
    assert HL.home_story([{"home_city": "Katowice"}], "")["changed"] is False


def test_register_window_uses_polish_days_and_issue_moment():
    from datetime import date, datetime, timezone

    start, end = HL.register_window(date(2026, 10, 1), date(2026, 10, 31), datetime(2026, 11, 3, 9, tzinfo=timezone.utc), False)
    assert start == datetime(2026, 9, 30, 22, tzinfo=timezone.utc)
    assert end == datetime(2026, 10, 31, 23, tzinfo=timezone.utc)
    # Issued mid-period without future matches: later matches were not on the document.
    _, end = HL.register_window(date(2026, 10, 1), date(2026, 10, 31), datetime(2026, 10, 20, 12, tzinfo=timezone.utc), False)
    assert end == datetime(2026, 10, 20, 12, tzinfo=timezone.utc)
    _, end = HL.register_window(date(2026, 10, 1), date(2026, 10, 31), datetime(2026, 10, 20, 12, tzinfo=timezone.utc), True)
    assert end == datetime(2026, 10, 31, 23, tzinfo=timezone.utc)
    assert HL.register_window(None, date(2026, 10, 31), None, False) is None


@pytest.mark.asyncio
async def test_backfill_from_register_locks_oldest_document_first(monkeypatch):
    import json
    import sys
    from datetime import date, datetime, timezone
    from types import ModuleType

    from sqlalchemy import (
        Boolean,
        Column,
        Date,
        DateTime,
        Float,
        Integer,
        MetaData,
        String,
        Table,
        Text,
        create_engine,
        select,
    )

    meta = MetaData()
    matches = Table("province_settlement_matches", meta,
        Column("province", String, primary_key=True), Column("judge_id", String, primary_key=True),
        Column("match_key", String, primary_key=True), Column("match_at", DateTime(timezone=True)),
        Column("home_city", String), Column("distance_km", Float), Column("distance_source", String),
        Column("home_locked_doc", String), Column("home_locked_at", DateTime(timezone=True)))
    register = Table("province_settlement_register", meta,
        Column("id", Integer, primary_key=True), Column("province", String), Column("number", String),
        Column("date_from", Date), Column("date_to", Date), Column("include_future", Boolean),
        Column("items_json", Text), Column("created_at", DateTime(timezone=True)))
    engine = create_engine("sqlite://")
    meta.create_all(engine)
    conn = engine.connect()

    class DB:
        async def fetch_all(self, query):
            return list(conn.execute(query).mappings())

        async def execute(self, query):
            conn.execute(query)

    fake = ModuleType("app.db")
    fake.database, fake.province_settlement_matches, fake.province_settlement_register = DB(), matches, register
    monkeypatch.setitem(sys.modules, "app.db", fake)

    utc = timezone.utc
    conn.execute(matches.insert(), [
        {"province": "SLASKIE", "judge_id": "1", "match_key": "d:1", "match_at": datetime(2026, 10, 5, 16, tzinfo=utc)},
        {"province": "SLASKIE", "judge_id": "1", "match_key": "d:2", "match_at": datetime(2026, 10, 25, 16, tzinfo=utc)},
        {"province": "SLASKIE", "judge_id": "2", "match_key": "d:3", "match_at": datetime(2026, 10, 6, 16, tzinfo=utc)},
        {"province": "SLASKIE", "judge_id": "1", "match_key": "d:4", "match_at": datetime(2026, 11, 2, 16, tzinfo=utc)},
    ])
    items = json.dumps([{"judge_id": "1", "part": ""}])
    conn.execute(register.insert(), [
        {"id": 2, "province": "SLASKIE", "number": "9/S/2026", "date_from": date(2026, 10, 1), "date_to": date(2026, 10, 31),
         "include_future": False, "items_json": items, "created_at": datetime(2026, 11, 4, tzinfo=utc)},
        {"id": 1, "province": "SLASKIE", "number": "7/S/2026", "date_from": date(2026, 10, 1), "date_to": date(2026, 10, 31),
         "include_future": False, "items_json": items, "created_at": datetime(2026, 10, 20, tzinfo=utc)},
    ])
    await HL.backfill_from_register("SLASKIE")
    rows = {r["match_key"]: r["home_locked_doc"] for r in conn.execute(select(matches)).mappings()}
    # d:1 was on the first document; d:2 (played after it) only on the second.
    assert rows == {"d:1": "7/S/2026", "d:2": "9/S/2026", "d:3": None, "d:4": None}

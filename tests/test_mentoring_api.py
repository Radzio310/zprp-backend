"""Endpoint tests with isolated schema and async mocks: never import app.db."""
import importlib.util
import sys
import types
import unittest
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch
from sqlalchemy import MetaData, Table, Column, String, JSON, DateTime, Boolean
from sqlalchemy.dialects.postgresql import insert as pg_insert
from fastapi import HTTPException
from app.mentoring_tables import define_tables


def load_api():
    metadata = MetaData()
    fake_db = types.ModuleType("app.db")
    names = ("mentoring_config", "mentoring_pairs", "mentoring_members", "mentoring_assignments", "mentoring_audit")
    for name, table in zip(names, define_tables(metadata)):
        setattr(fake_db, name, table)
    fake_db.province_judges = Table("province_judges", metadata, Column("judge_id", String, primary_key=True), Column("province", String), Column("full_name", String), Column("photo_url", String))
    fake_db.province_matches = Table("province_matches", metadata, Column("match_id", String), Column("province", String), Column("state_json", JSON), Column("match_at", DateTime), Column("updated_at", DateTime), Column("active", Boolean))
    fake_db.database = AsyncMock()
    transaction = AsyncMock()
    fake_db.database.transaction = lambda: transaction
    fake_market = types.ModuleType("app.match_market")
    fake_market.Actor = type("Actor", (), {})
    fake_market.market_actor = lambda: None
    spec = importlib.util.spec_from_file_location("mentoring_isolated_test", Path(__file__).parents[1] / "app" / "mentoring.py")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"app.db": fake_db, "app.match_market": fake_market}):
        spec.loader.exec_module(module)
    return module, fake_db


class MentoringApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.api, self.db = load_api()
        self.actor = types.SimpleNamespace(judge_id="admin", is_admin=True, province="ŚLĄSKIE", badges={})
        self.people = [{"judge_id": j, "province": "ŚLĄSKIE"} for j in ["1", "2", "3"]]

    async def test_conflict_does_not_write_pair(self):
        self.db.database.fetch_one.side_effect = [None, {"judge_id": "1", "pair_id": "existing"}]
        self.db.database.fetch_all.return_value = self.people
        with self.assertRaises(HTTPException) as error:
            await self.api.create_pair(self.api.PairRequest(province="ŚLĄSKIE", judge_ids=["1", "2"], mentor_ids=["3"]), self.actor)
        self.assertEqual(error.exception.status_code, 409)
        # Only the transaction lock; no insert before validation completes.
        self.assertEqual(self.db.database.execute.await_count, 1)
        self.assertEqual([c.name for c in self.db.mentoring_members.primary_key], ["judge_id"])

    async def test_commission_cannot_select_foreign_mentor(self):
        self.actor.is_admin = False
        self.db.database.fetch_all.return_value = [*self.people[:2], {"judge_id": "3", "province": "OPOLSKIE"}]
        with self.assertRaises(HTTPException) as error:
            await self.api.validate_people(self.actor, "ŚLĄSKIE", ["1", "2"], ["3"])
        self.assertEqual(error.exception.status_code, 403)

    async def test_admin_can_mix_provinces(self):
        self.db.database.fetch_all.return_value = [*self.people[:2], {"judge_id": "3", "province": "OPOLSKIE"}]
        await self.api.validate_people(self.actor, "ŚLĄSKIE", ["1", "2"], ["3"])

    def test_pair_scope_uses_admin_only_bucket_for_two_judge_provinces(self):
        people = [
            {"judge_id": "1", "province": "MAZOWIECKIE"},
            {"judge_id": "2", "province": "LUBELSKIE"},
            {"judge_id": "3", "province": "MAZOWIECKIE"},
        ]
        self.assertEqual(self.api.pair_scope(["1", "2"], people), self.api.CROSS_PROVINCE)
        self.assertEqual(self.api.pair_scope(["1", "3"], people), "MAZOWIECKIE")

    def test_pair_scope_rejects_judge_without_province(self):
        with self.assertRaises(HTTPException) as error:
            self.api.pair_scope(
                ["1", "2"],
                [
                    {"judge_id": "1", "province": "MAZOWIECKIE"},
                    {"judge_id": "2", "province": ""},
                ],
            )
        self.assertEqual(error.exception.status_code, 422)

    async def test_country_overview_is_admin_only(self):
        self.actor.is_admin = False
        with self.assertRaises(HTTPException) as error:
            await self.api.admin_overview(self.actor)
        self.assertEqual(error.exception.status_code, 403)
        self.db.database.fetch_all.assert_not_awaited()

    async def test_country_overview_contains_empty_and_active_provinces(self):
        self.db.database.fetch_all.side_effect = [
            [{"province": "ŚLĄSKIE", "enabled": True, "manager_ids": ["3"]}],
            [{"province": "ŚLĄSKIE", "count": 2}],
            [{"province": "ŚLĄSKIE", "count": 3}],
        ]
        result = await self.api.admin_overview(self.actor)
        slaskie = next(row for row in result["provinces"] if row["province"] == "ŚLĄSKIE")
        opolskie = next(row for row in result["provinces"] if row["province"] == "OPOLSKIE")
        cross = next(row for row in result["provinces"] if row["province"] == self.api.CROSS_PROVINCE)
        self.assertEqual((slaskie["enabled"], slaskie["active_pairs"], slaskie["active_mentors"]), (True, 2, 3))
        self.assertEqual((opolskie["enabled"], opolskie["active_pairs"]), (False, 0))
        self.assertEqual((cross["enabled"], cross["admin_only"]), (False, True))

    async def test_self_mentoring_rejected(self):
        with self.assertRaises(HTTPException) as error:
            await self.api.validate_people(self.actor, "ŚLĄSKIE", ["1", "2"], ["1"])
        self.assertEqual(error.exception.status_code, 422)

    async def test_judge_can_read_own_pair_and_active_mentors(self):
        self.actor.judge_id = "1"
        self.db.database.fetch_one.side_effect = [
            {"judge_id": "1", "pair_id": "pair"},
            {
                "id": "pair",
                "province": "MAZOWIECKIE",
                "judge_ids": '["1", "2"]',
                "created_by": "admin",
                "created_at": "date",
                "ended_at": None,
            },
        ]
        self.db.database.fetch_all.side_effect = [
            [{"mentor_id": "3"}],
            [
                {"judge_id": "2", "full_name": "Drugi Sędzia", "province": "MAZOWIECKIE", "photo_url": "judge.jpg"},
                {"judge_id": "1", "full_name": "Pierwszy Sędzia", "province": "MAZOWIECKIE", "photo_url": "first.jpg"},
                {"judge_id": "3", "full_name": "Mentor", "province": "ŚLĄSKIE", "photo_url": "mentor.jpg"},
            ],
        ]
        result = await self.api.my_pair(self.actor)
        self.assertEqual([person["judge_id"] for person in result["pair"]["judges"]], ["1", "2"])
        self.assertEqual(result["pair"]["mentors"][0]["full_name"], "Mentor")
        self.assertNotIn("show_home", result["pair"]["mentors"][0])

    async def test_judge_without_pair_gets_empty_relation(self):
        self.db.database.fetch_one.return_value = None
        self.assertEqual(await self.api.my_pair(self.actor), {"pair": None})
        self.db.database.fetch_all.assert_not_awaited()

    async def test_revoked_link_cannot_read_or_change_preferences(self):
        self.db.database.fetch_one.side_effect = [{"id": "pair", "judge_ids": ["1", "2"], "province": "ŚLĄSKIE"}, None]
        with self.assertRaises(HTTPException) as error:
            await self.api.preferences("pair", self.api.Preferences(show_home=True, notify=True), self.actor)
        self.assertEqual(error.exception.status_code, 403)
        self.db.database.execute.assert_not_awaited()

    async def test_end_preserves_audit_but_frees_members(self):
        self.db.database.fetch_one.side_effect = [{"id": "pair", "province": "ŚLĄSKIE", "judge_ids": ["1", "2"]}, None]
        await self.api.end_pair("pair", self.actor)
        statements = [str(call.args[0]) for call in self.db.database.execute.await_args_list]
        self.assertTrue(any("DELETE FROM mentoring_active_members" in sql for sql in statements))
        self.assertTrue(any("INSERT INTO mentoring_audit" in sql for sql in statements))
        self.assertFalse(any("DELETE FROM mentoring_pairs" in sql for sql in statements))

    async def test_management_keeps_ended_pairs_and_mentor_history(self):
        self.db.database.fetch_all.side_effect = [
            self.people,
            [{"id": "ended", "province": "ŚLĄSKIE", "judge_ids": ["1", "2"], "ended_at": "date"}],
            [{"pair_id": "ended", "mentor_id": "3", "ended_at": "date"}],
            [],
        ]
        self.db.database.fetch_one.return_value = None
        result = await self.api.management("ŚLĄSKIE", self.actor)
        self.assertEqual(result["pairs"][0]["mentor_ids"], [])
        self.assertEqual(result["pairs"][0]["mentor_history_ids"], ["3"])
        query = str(self.db.database.fetch_all.await_args_list[1].args[0])
        self.assertNotIn("ended_at IS NULL", query)

    async def test_feed_is_read_only_and_handles_database_json_strings(self):
        self.db.database.fetch_one.side_effect = [{"id": "pair", "judge_ids": '["1", "2"]'}, {"mentor_id": "admin"}]
        state = {"NrSedzia_pierwszy": "1", "NrSedzia_drugi": "2", "data_fakt": "2026-10-10", "Link": "private-action-url", "delegate_note": "private", "token": "secret", "roster_gosp": {"medical": "private"}}
        self.db.database.fetch_all.return_value = [{"match_id": "123", "province": "ŚLĄSKIE", "state_json": json.dumps(state)}]
        result = await self.api.matches("pair", self.actor)
        item = result["matches"][0]
        self.assertEqual(item["type"], "mentoring")
        self.assertFalse(item["isMyMatch"])
        self.assertNotIn("delegate_note", item)
        self.assertNotIn("token", item)
        self.assertNotIn("Link", item)
        self.assertNotIn("roster_gosp", item)

    async def test_latest_snapshot_wins_after_province_transfer(self):
        self.db.database.fetch_one.side_effect = [{"id": "pair", "judge_ids": ["1", "2"]}, {"mentor_id": "admin"}]
        self.db.database.fetch_all.return_value = [
            {"match_id": "123", "province": "OPOLSKIE", "state_json": {"NrSedzia_pierwszy": "1", "NrSedzia_drugi": "3"}},
            {"match_id": "123", "province": "ŚLĄSKIE", "state_json": {"NrSedzia_pierwszy": "1", "NrSedzia_drugi": "2"}},
        ]
        result = await self.api.matches("pair", self.actor)
        self.assertEqual(result["matches"], [])


if __name__ == "__main__":
    unittest.main()

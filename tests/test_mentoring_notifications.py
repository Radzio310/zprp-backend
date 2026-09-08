import importlib.util
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch
from sqlalchemy import MetaData, Table, Column, String, JSON, DateTime, Integer
from sqlalchemy.dialects.postgresql import insert as pg_insert
from app.mentoring_tables import define_tables


class MentoringNotificationsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        metadata = MetaData()
        db = types.ModuleType("app.db")
        for name, table in zip(("mentoring_config", "mentoring_pairs", "mentoring_members", "mentoring_assignments", "mentoring_audit"), define_tables(metadata)):
            setattr(db, name, table)
        db.province_judges = Table("province_judges", metadata, Column("judge_id", String), Column("province", String))
        db.province_matches = Table("province_matches", metadata, Column("match_id", String), Column("province", String))
        db.province_match_events = Table("province_match_events", metadata, Column("id", Integer), Column("match_id", String), Column("province", String), Column("created_at", DateTime))
        db.province_match_notifications = Table("province_match_notifications", metadata, Column("event_id", Integer), Column("installation_id", String), Column("judge_id", String), Column("title", String), Column("body", String), Column("data_json", JSON), Column("status", String))
        db.push_tokens = Table("push_tokens", metadata, Column("judge_id", String), Column("app_variant", String))
        db.database = AsyncMock()
        monitor = types.ModuleType("app.province_match_monitor")
        monitor._prefs_allow = lambda prefs, event: True
        self.modules = patch.dict(sys.modules, {"app.db": db, "app.province_match_monitor": monitor})
        self.modules.start()
        self.addCleanup(self.modules.stop)
        spec = importlib.util.spec_from_file_location("mentoring_notifications_isolated", Path(__file__).parents[1] / "app" / "mentoring_notifications.py")
        self.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.api)
        self.db = db.database
        moment = datetime(2026, 10, 1, tzinfo=timezone.utc)
        self.event = {"id": 1, "province": "ŚLĄSKIE", "match_id": "123", "created_at": moment, "data_json": {}, "target_judge_ids": ["1", "2"], "title": "Zmiana terminu", "body": "Zmiana", "event_type": "match_date_changed"}
        self.match = {"match_at": moment + timedelta(days=2), "state_json": {"NrSedzia_pierwszy": "1", "NrSedzia_drugi": "2"}}
        self.api.season_bounds = lambda: (moment - timedelta(days=30), moment + timedelta(days=335))

    async def test_multiple_mentors_and_one_delivery_per_device(self):
        self.db.fetch_one.side_effect = [self.event, self.match]
        self.db.fetch_all.side_effect = [
            [{"id": "pair", "judge_ids": ["1", "2"], "mentor_id": m} for m in ["3", "4"]],
            [{"judge_id": m, "installation_id": "phone-" + m, "notification_prefs": {}} for m in ["3", "4"]],
        ]
        await self.api.enqueue(1)
        self.assertEqual(self.db.execute.await_count, 2)
        for call in self.db.execute.await_args_list:
            statement = call.args[0]
            data = statement.compile().params["data_json"]
            self.assertEqual(data["kind"], "mentoring_match_change")
            self.assertEqual(data["mentoring_pair_ids"], ["pair"])
            self.assertIn("ON CONFLICT", str(statement))
        eligibility_query = str(self.db.fetch_all.await_args_list[0].args[0])
        self.assertIn("baseline_at <", eligibility_query)
        self.assertIn("started_at <", eligibility_query)

    async def test_native_assignment_is_not_duplicated(self):
        self.match["state_json"]["NrSedzia_delegat"] = "3"
        self.db.fetch_one.side_effect = [self.event, self.match]
        self.db.fetch_all.return_value = [{"id": "pair", "judge_ids": ["1", "2"], "mentor_id": "3"}]
        await self.api.enqueue(1)
        self.db.execute.assert_not_awaited()

    async def test_changed_account_never_receives_queued_push(self):
        self.assertFalse(await self.api.delivery_allowed({"kind": "mentoring_match_change", "mentoring_mentor_id": "3"}, {"judge_id": "4"}))
        self.db.fetch_one.assert_not_awaited()

    async def test_revoked_or_muted_assignment_is_checked_at_delivery(self):
        self.db.fetch_one.return_value = None
        self.assertFalse(await self.api.delivery_allowed({"kind": "mentoring_match_change", "mentoring_mentor_id": "3", "mentoring_pair_ids": ["pair"], "mentoring_event_at": self.event["created_at"].isoformat()}, {"judge_id": "3"}))
        query = str(self.db.fetch_one.await_args.args[0])
        self.assertIn("ended_at IS NULL", query)
        self.assertIn("notify IS true", query)
        self.assertIn("started_at <", query)


if __name__ == "__main__":
    unittest.main()

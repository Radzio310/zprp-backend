"""Nie wysyłamy starych rewizji po nowszych ani wygasłych powiadomień."""
import importlib
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest


def load_scheduler():
    name = "app.push.scheduler"
    saved_db, saved_module = sys.modules.get("app.db"), sys.modules.get(name)
    cleanup_name = "app.push.token_cleanup"
    saved_cleanup = sys.modules.get(cleanup_name)
    sys.modules["app.db"] = MagicMock()
    try:
        sys.modules.pop(name, None)
        return importlib.import_module(name)
    finally:
        if saved_db is None:
            sys.modules.pop("app.db", None)
        else:
            sys.modules["app.db"] = saved_db
        if saved_module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = saved_module
        # Ten moduł również wiąże database przy imporcie. Nie zostawiamy
        # w globalnym cache zależności trzymającej atrapę app.db.
        if saved_cleanup is None:
            sys.modules.pop(cleanup_name, None)
            package = sys.modules.get("app.push")
            if package is not None and hasattr(package, "token_cleanup"):
                delattr(package, "token_cleanup")
        else:
            sys.modules[cleanup_name] = saved_cleanup


scheduler = load_scheduler()
NOW = datetime(2026, 10, 24, 10, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_expired_revision_is_not_sent(monkeypatch):
    monkeypatch.setattr(scheduler, "_utc_now", lambda: NOW)
    reason = await scheduler._match_notification_stale_reason(
        {"created_at": NOW - timedelta(days=2)}, {"kind": "province_match_change", "event_type": "match_updated"})
    assert "Expired" in reason


@pytest.mark.asyncio
async def test_new_assignment_is_not_superseded_by_later_changes(monkeypatch):
    monkeypatch.setattr(scheduler, "_utc_now", lambda: NOW)
    reason = await scheduler._match_notification_stale_reason(
        {"created_at": NOW - timedelta(days=2)}, {"kind": "province_match_change", "event_type": "match_added"})
    assert reason is None


@pytest.mark.asyncio
async def test_unrelated_notifications_keep_their_delivery_policy():
    assert await scheduler._match_notification_stale_reason({}, {"kind": "mentor_evaluation_request"}) is None


@pytest.mark.asyncio
async def test_newer_important_revision_supersedes_retry(monkeypatch):
    from sqlalchemy import Column, Integer, JSON, MetaData, String, Table
    meta = MetaData()
    notifications = Table("notifications", meta, Column("id", Integer), Column("installation_id", String),
                          Column("event_id", Integer), Column("status", String))
    events = Table("events", meta, Column("id", Integer), Column("province", String),
                   Column("match_id", String), Column("event_type", String), Column("data_json", JSON))
    monkeypatch.setattr(scheduler, "province_match_notifications", notifications)
    monkeypatch.setattr(scheduler, "province_match_events", events)
    monkeypatch.setattr(scheduler, "_utc_now", lambda: NOW)
    db = MagicMock(fetch_val=AsyncMock(return_value=99))
    monkeypatch.setattr(scheduler, "database", db)
    row = {"created_at": NOW, "installation_id": "iphone", "event_id": 10}
    reason = await scheduler._match_notification_stale_reason(row,
        {"kind": "province_match_change", "event_type": "match_updated", "province": "SLASKIE", "match_id": "42"})
    assert "Superseded" in reason
    # Zapytanie musi wykluczać nowy przydział oraz zmiany informacyjne.
    from sqlalchemy.dialects import postgresql
    query = db.fetch_val.call_args.args[0].compile(dialect=postgresql.dialect())
    assert "match_added" in str(query.params) and "match_info_updated" in str(query.params)
    assert 10 in query.params.values()
    assert "events.event_type =" in str(query)
    assert "change_types" in query.params.values()


@pytest.mark.asyncio
async def test_delivery_rechecks_account_and_preferences(monkeypatch):
    db = MagicMock(fetch_val=AsyncMock(return_value="iphone"))
    monkeypatch.setattr(scheduler, "database", db)
    # Only the table used by the token-owner lookup is needed for these tests.
    from sqlalchemy import Column, DateTime, MetaData, String, Table
    tokens = Table("tokens", MetaData(), Column("installation_id", String), Column("token", String),
                   Column("token_type", String), Column("updated_at", DateTime))
    monkeypatch.setattr(scheduler, "push_tokens", tokens)
    row = {"judge_id": "865", "installation_id": "iphone"}
    token = {"judge_id": "999", "token": "fcm", "token_type": "device_fcm", "notification_prefs": {}}
    assert "identity changed" in await scheduler._match_delivery_reason(row, {}, token)
    token["judge_id"] = "865"
    token["notification_prefs"] = {"notificationTypes": {"protocolStatus": False}}
    data = {"kind": "province_match_change", "event_type": "protocol_approved"}
    assert "preference changed" in await scheduler._match_delivery_reason(row, data, token)
    token["notification_prefs"] = {}
    assert await scheduler._match_delivery_reason(row, data, token) is None
    db.fetch_val.return_value = "new-installation-same-iphone"
    assert "Superseded installation" in await scheduler._match_delivery_reason(row, data, token)


@pytest.mark.asyncio
@pytest.mark.parametrize("removed, expected", [(None, "already presented"), (99, None)])
async def test_local_receipt_suppresses_delayed_server_push_until_next_assignment(monkeypatch, removed, expected):
    from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table
    meta = MetaData()
    receipts = Table("receipts", meta, Column("installation_id", String), Column("judge_id", String),
                     Column("match_id", String), Column("observed_at", DateTime(timezone=True)))
    notifications = Table("notifications", meta, Column("id", Integer), Column("installation_id", String),
                          Column("judge_id", String), Column("event_id", Integer))
    events = Table("events", meta, Column("id", Integer), Column("match_id", String),
                   Column("event_type", String), Column("created_at", DateTime(timezone=True)))
    monkeypatch.setattr(scheduler, "push_local_match_receipts", receipts)
    monkeypatch.setattr(scheduler, "province_match_notifications", notifications)
    monkeypatch.setattr(scheduler, "province_match_events", events)
    db = MagicMock(fetch_val=AsyncMock(side_effect=[NOW - timedelta(minutes=10), removed]))
    monkeypatch.setattr(scheduler, "database", db)
    reason = await scheduler._local_match_receipt_reason(
        {"installation_id": "iphone", "judge_id": "865", "event_id": 100}, {"match_id": "42"}, NOW)
    if expected:
        assert expected in reason
    else:
        assert reason is None

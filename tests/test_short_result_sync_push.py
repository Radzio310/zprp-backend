"""Cichy push danych po zapisie wyniku skróconego."""
from __future__ import annotations

import json

import pytest

import app.short_result_sync_push as sp
from app.push.fcm import fcm_message_payload

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


def test_data_only_message_has_no_notification_block():
    msg = fcm_message_payload("tok", "", "", {"kind": sp.KIND, "dataOnly": "1", "matchId": "5"})["message"]
    assert "notification" not in msg
    assert "notification" not in msg["android"]
    assert msg["data"] == {"kind": sp.KIND, "matchId": "5"}
    assert msg["apns"]["payload"]["aps"] == {"content-available": 1}


def test_regular_message_still_has_notification():
    msg = fcm_message_payload("tok", "T", "B", {"kind": "x"})["message"]
    assert msg["notification"] == {"title": "T", "body": "B"}


def test_pushable_fields_drops_everything_but_result():
    out = sp.pushable_fields(
        {"wynik_gosp_full": "24", "timeout1_gosp_ii": "", "widzowie": 10, "data_fakt": "2026-01-01", "x": "1"}
    )
    assert out == {"wynik_gosp_full": "24", "timeout1_gosp_ii": "", "widzowie": "10"}


async def test_notify_sends_to_recipients(monkeypatch):
    calls = []

    async def fake_recipients(id_zawody, actor):
        return ["1", "2"]

    async def fake_send(judges, title, body, data=None, **kw):
        calls.append((judges, data, kw))

    monkeypatch.setattr(sp, "recipients", fake_recipients)
    import sys
    import types

    fake_mod = types.ModuleType("app.push.push")
    fake_mod.send_push_to_judges_report = fake_send
    monkeypatch.setitem(sys.modules, "app.push.push", fake_mod)
    await sp.notify_short_result_saved(77, {"wynik_gosp_full": "3", "data_fakt": "x"}, "1")
    judges, data, kw = calls[0]
    assert judges == ["1", "2"]
    assert data["dataOnly"] == "1" and data["matchId"] == "77" and data["kind"] == sp.KIND
    assert json.loads(data["fields"]) == {"wynik_gosp_full": "3"}
    assert kw["app_variant"] == "baza"


async def test_notify_never_raises(monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("x")

    monkeypatch.setattr(sp, "recipients", boom)
    await sp.notify_short_result_saved(1, {"wynik_gosp_full": "3"}, None)

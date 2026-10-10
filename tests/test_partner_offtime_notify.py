"""Powiadomienie partnera o nowej niedyspozycji: reguły i decyzja o wysyłce."""
from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from datetime import date, timedelta
from pathlib import Path

import pytest
from sqlalchemy import JSON, Column, MetaData, String, Table

from app.partner_offtime_notify_rules import (
    event_key,
    new_future_offtimes,
    notification_text,
    parse_offtime_date,
)
from app.push.preferences import notification_type_allowed

TODAY = date.today()


def _iso(d: date) -> str:
    return d.isoformat()


def _entry(start: date, end: date, info: str = "Urlop", entry_id: str = "") -> dict:
    return {"lp": 1, "id": entry_id, "dateFrom": _iso(start), "dateTo": _iso(end), "info": info}


def test_parse_dates_in_all_three_shapes():
    assert parse_offtime_date("2026-10-12") == date(2026, 10, 12)
    assert parse_offtime_date("12.10.2026") == date(2026, 10, 12)
    # Lokalna północ 12.10 w Polsce zapisana przez toISOString().
    assert parse_offtime_date("2026-10-11T22:00:00.000Z") == date(2026, 10, 12)
    assert parse_offtime_date("") is None
    assert parse_offtime_date("0000-00-00") is None
    assert parse_offtime_date("bzdura") is None


def test_new_entry_is_reported():
    a = TODAY + timedelta(days=3)
    b = TODAY + timedelta(days=10)
    old = [_entry(a, a, entry_id="1")]
    new = [_entry(a, a, entry_id="1"), _entry(b, b + timedelta(days=2), "Wesele", "2")]
    fresh = new_future_offtimes(old, new, TODAY)
    assert [(e["from"], e["to"], e["info"]) for e in fresh] == [(b, b + timedelta(days=2), "Wesele")]


def test_same_dates_in_other_notation_are_not_new():
    a = TODAY + timedelta(days=3)
    old = [{"dateFrom": a.strftime("%d.%m.%Y"), "dateTo": a.strftime("%d.%m.%Y"), "info": "x"}]
    new = [_entry(a, a, "inny opis", "77")]
    assert new_future_offtimes(old, new, TODAY) == []


def test_past_and_deleted_entries_are_ignored():
    past = TODAY - timedelta(days=5)
    a = TODAY + timedelta(days=3)
    assert new_future_offtimes([], [_entry(past, past)], TODAY) == []
    assert new_future_offtimes([_entry(a, a)], [], TODAY) == []
    # Termin trwający dziś jeszcze się liczy.
    assert len(new_future_offtimes([], [_entry(past, TODAY)], TODAY)) == 1


def test_unknown_baseline_sends_nothing():
    a = TODAY + timedelta(days=3)
    assert new_future_offtimes({}, [_entry(a, a)], TODAY) == []
    assert new_future_offtimes(None, [_entry(a, a)], TODAY) == []
    assert new_future_offtimes([], {}, TODAY) == []


def test_json_string_is_read_as_list():
    a = TODAY + timedelta(days=3)
    assert len(new_future_offtimes("[]", [_entry(a, a)], TODAY)) == 1


def test_duplicate_ranges_count_once():
    a = TODAY + timedelta(days=3)
    assert len(new_future_offtimes([], [_entry(a, a), _entry(a, a)], TODAY)) == 1


def test_text_single_and_many():
    one = [{"from": date(2026, 10, 12), "to": date(2026, 10, 14), "info": "Wyjazd służbowy"}]
    title, body = notification_text("Jan Kowalski", one)
    assert title == "Twój partner zgłosił niedyspozycję"
    assert body == "Jan Kowalski: 12.10–14.10.2026 · Wyjazd służbowy"

    many = [
        {"from": date(2026, 10, d), "to": date(2026, 10, d), "info": "x"}
        for d in (1, 5, 9, 20)
    ]
    title, body = notification_text("Jan Kowalski", many)
    assert title == "Twój partner zgłosił niedyspozycje"
    assert body == "Jan Kowalski: 01.10.2026, 05.10.2026, 09.10.2026 (+1)"


def test_text_across_years():
    entry = [{"from": date(2026, 12, 30), "to": date(2027, 1, 2), "info": ""}]
    assert notification_text("A", entry)[1] == "A: 30.12.2026–02.01.2027"


def test_event_key_is_stable_and_fits_tag():
    entries = [{"from": date(2026, 10, 12), "to": date(2026, 10, 12), "info": ""}]
    key = event_key("123", entries)
    assert key == event_key("123", entries)
    assert key != event_key("124", entries)
    assert len(key) <= 32


def test_preference_switch_defaults_to_on():
    assert notification_type_allowed({}, "partnerOfftimes")
    assert notification_type_allowed({"notificationTypes": {}}, "partnerOfftimes")
    assert not notification_type_allowed(
        {"notificationTypes": {"partnerOfftimes": False}}, "partnerOfftimes"
    )


# ── decyzja o wysyłce (baza i push podmienione) ─────────────────────────────
# `app.db` przy imporcie stawia schemat Postgresa, więc jak w pozostałych
# testach powiadomień moduł ładujemy z atrapą bazy i atrapą wysyłki.


class _FakeDb:
    def __init__(self, partner_row=None, error=None):
        self.partner_row = partner_row
        self.error = error

    async def fetch_one(self, _query):
        if self.error:
            raise self.error
        return self.partner_row


@pytest.fixture
def harness(monkeypatch):
    calls = []

    async def fake_send(judge_ids, title, body, data=None, **kwargs):
        calls.append({"ids": judge_ids, "title": title, "body": body, "data": data, **kwargs})
        return 1

    db = types.ModuleType("app.db")
    db.partner_offtimes = Table(
        "partner_offtimes", MetaData(),
        Column("judge_id", String), Column("partner_id", String), Column("data_json", JSON),
    )
    db.database = _FakeDb()
    push = types.ModuleType("app.push.push")
    push.send_push_to_judges = fake_send
    monkeypatch.setitem(sys.modules, "app.db", db)
    monkeypatch.setitem(sys.modules, "app.push.push", push)
    spec = importlib.util.spec_from_file_location(
        "partner_offtime_notify_isolated",
        Path(__file__).parents[1] / "app" / "partner_offtime_notify.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def run(partner_row=None, error=None, **overrides):
        module.database = _FakeDb(partner_row, error)
        a = TODAY + timedelta(days=4)
        kwargs = dict(
            judge_id="100",
            full_name="Jan Kowalski",
            old_partner_id="200",
            new_partner_id="200",
            old_data=[],
            new_data=[_entry(a, a, "Urlop", "9")],
        )
        kwargs.update(overrides)
        return asyncio.run(module.notify_partner_about_new_offtimes(**kwargs))

    run.calls = calls
    return run


def test_mutual_pair_gets_push(harness):
    assert harness({"partner_id": "100"}) == 1
    assert len(harness.calls) == 1
    call = harness.calls[0]
    assert call["ids"] == ["200"]
    assert call["title"] == "Twój partner zgłosił niedyspozycję"
    assert call["data"]["type"] == "more_screen"
    assert call["data"]["screen"] == "niedyspozycznosc"
    assert call["data"]["kind"] == "partner_offtime"
    assert call["preference_key"] == "partnerOfftimes"
    assert call["app_variant"] == "baza"


def test_one_sided_invite_gets_nothing(harness):
    assert harness({"partner_id": None}) == 0
    assert harness({"partner_id": "999"}) == 0
    assert harness(None) == 0
    assert harness.calls == []


def test_pairing_change_in_same_write_is_silent(harness):
    assert harness({"partner_id": "100"}, old_partner_id=None) == 0
    assert harness({"partner_id": "100"}, new_partner_id=None) == 0
    assert harness.calls == []


def test_nothing_new_is_silent(harness):
    a = TODAY + timedelta(days=4)
    same = [_entry(a, a, "Urlop", "9")]
    assert harness({"partner_id": "100"}, old_data=same, new_data=same) == 0
    assert harness.calls == []


def test_errors_never_escape(harness):
    assert harness(error=RuntimeError("db down")) == 0
    assert harness.calls == []

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

from app.partner_offtime_access import caller_judge_id, write_allowed
from app.partner_offtime_notify_rules import (
    OfftimeChange,
    diff_future_offtimes,
    event_key,
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


def _spans(entries):
    return [(e["from"], e["to"]) for e in entries]


def _e(start: date, end: date, info: str = "") -> dict:
    return {"from": start, "to": end, "info": info}


def test_new_entry_is_reported():
    a = TODAY + timedelta(days=3)
    b = TODAY + timedelta(days=10)
    old = [_entry(a, a, entry_id="1")]
    new = [_entry(a, a, entry_id="1"), _entry(b, b + timedelta(days=2), "Wesele", "2")]
    change = diff_future_offtimes(old, new, TODAY)
    assert _spans(change.added) == [(b, b + timedelta(days=2))]
    assert change.added[0]["info"] == "Wesele"
    assert change.removed == []


def test_removed_entry_is_reported():
    a = TODAY + timedelta(days=3)
    b = TODAY + timedelta(days=10)
    change = diff_future_offtimes([_entry(a, a), _entry(b, b)], [_entry(a, a)], TODAY)
    assert change.added == []
    assert _spans(change.removed) == [(b, b)]


def test_date_shift_is_one_add_and_one_remove():
    a = TODAY + timedelta(days=3)
    b = TODAY + timedelta(days=4)
    change = diff_future_offtimes([_entry(a, a, "x", "5")], [_entry(b, b, "x", "5")], TODAY)
    assert _spans(change.added) == [(b, b)]
    assert _spans(change.removed) == [(a, a)]


def test_same_dates_in_other_notation_are_not_a_change():
    a = TODAY + timedelta(days=3)
    old = [{"dateFrom": a.strftime("%d.%m.%Y"), "dateTo": a.strftime("%d.%m.%Y"), "info": "x"}]
    new = [_entry(a, a, "inny opis", "77")]
    assert not diff_future_offtimes(old, new, TODAY)


def test_past_entries_are_ignored_both_ways():
    past = TODAY - timedelta(days=5)
    assert not diff_future_offtimes([], [_entry(past, past)], TODAY)
    assert not diff_future_offtimes([_entry(past, past)], [], TODAY)
    # Termin trwający dziś jeszcze się liczy.
    assert len(diff_future_offtimes([], [_entry(past, TODAY)], TODAY).added) == 1


def test_empty_list_after_many_is_not_a_cancellation():
    # Nieudany odczyt z ZPRP daje pustą listę - nie ogłaszamy „wszystko odwołane".
    a = TODAY + timedelta(days=3)
    b = TODAY + timedelta(days=9)
    assert not diff_future_offtimes([_entry(a, a), _entry(b, b)], [], TODAY)
    # Jeden jedyny termin usunięty do zera - to zwykłe odwołanie.
    assert len(diff_future_offtimes([_entry(a, a)], [], TODAY).removed) == 1


def test_unknown_baseline_sends_nothing():
    a = TODAY + timedelta(days=3)
    assert not diff_future_offtimes({}, [_entry(a, a)], TODAY)
    assert not diff_future_offtimes(None, [_entry(a, a)], TODAY)
    assert not diff_future_offtimes([_entry(a, a)], {}, TODAY)


def test_json_string_is_read_as_list():
    a = TODAY + timedelta(days=3)
    assert len(diff_future_offtimes("[]", [_entry(a, a)], TODAY).added) == 1


def test_duplicate_ranges_count_once():
    a = TODAY + timedelta(days=3)
    assert len(diff_future_offtimes([], [_entry(a, a), _entry(a, a)], TODAY).added) == 1


def test_text_added():
    one = OfftimeChange([_e(date(2026, 10, 12), date(2026, 10, 14), "Wyjazd służbowy")], [])
    assert notification_text("Jan Kowalski", one) == (
        "Twój partner zgłosił niedyspozycję",
        "Jan Kowalski: 12.10–14.10.2026 · Wyjazd służbowy",
    )
    many = OfftimeChange([_e(date(2026, 10, d), date(2026, 10, d), "x") for d in (1, 5, 9, 20)], [])
    assert notification_text("Jan Kowalski", many) == (
        "Twój partner zgłosił niedyspozycje",
        "Jan Kowalski: 01.10.2026, 05.10.2026, 09.10.2026 (+1)",
    )


def test_text_removed():
    one = OfftimeChange([], [_e(date(2026, 10, 12), date(2026, 10, 12), "x")])
    assert notification_text("Jan Kowalski", one) == (
        "Twój partner odwołał niedyspozycję",
        "Jan Kowalski: 12.10.2026 – termin odwołany",
    )
    two = OfftimeChange([], [_e(date(2026, 10, 12), date(2026, 10, 12)), _e(date(2026, 11, 2), date(2026, 11, 3))])
    assert notification_text("Jan Kowalski", two) == (
        "Twój partner odwołał niedyspozycje",
        "Jan Kowalski: 12.10.2026, 02.11–03.11.2026 – terminy odwołane",
    )


def test_text_changed():
    shift = OfftimeChange([_e(date(2026, 10, 14), date(2026, 10, 15), "Urlop")], [_e(date(2026, 10, 12), date(2026, 10, 12))])
    assert notification_text("Jan Kowalski", shift) == (
        "Twój partner zmienił niedyspozycję",
        "Jan Kowalski: 12.10.2026 → 14.10–15.10.2026 · Urlop",
    )
    mixed = OfftimeChange(
        [_e(date(2026, 10, 1), date(2026, 10, 1)), _e(date(2026, 10, 2), date(2026, 10, 2))],
        [_e(date(2026, 10, 9), date(2026, 10, 9))],
    )
    assert notification_text("A", mixed) == (
        "Twój partner zmienił niedyspozycje",
        "A: nowe 01.10.2026, 02.10.2026; odwołane 09.10.2026",
    )


def test_text_across_years():
    entry = OfftimeChange([_e(date(2026, 12, 30), date(2027, 1, 2))], [])
    assert notification_text("A", entry)[1] == "A: 30.12.2026–02.01.2027"


def test_event_key_is_stable_and_fits_tag():
    d = date(2026, 10, 12)
    added = OfftimeChange([_e(d, d)], [])
    removed = OfftimeChange([], [_e(d, d)])
    key = event_key("123", added)
    assert key == event_key("123", added)
    assert key != event_key("124", added)
    assert key != event_key("123", removed)
    assert len(key) <= 32


def test_preference_switch_defaults_to_on():
    assert notification_type_allowed({}, "partnerOfftimes")
    assert notification_type_allowed({"notificationTypes": {}}, "partnerOfftimes")
    assert not notification_type_allowed(
        {"notificationTypes": {"partnerOfftimes": False}}, "partnerOfftimes"
    )


# ── kto może zapisać wpis ───────────────────────────────────────────────────


def test_caller_id_comes_from_token():
    assert caller_judge_id({"judge_id": " 100 "}) == "100"
    assert caller_judge_id({"sub": "login"}) == ""


def test_own_row_is_writable():
    assert write_allowed("100", "100")
    assert write_allowed("100", "100", {"data_json": [], "partner_id": "200"}, "200")


def test_foreign_row_is_not_writable():
    assert not write_allowed("100", "200")
    assert not write_allowed("100", "200", {"data_json": []}, "100")
    assert not write_allowed("100", "200", {"partner_id": "100"}, "100")


def test_account_without_judge_number_writes_nothing():
    assert not write_allowed("", "")
    assert not write_allowed("", "200", {"partner_id": None}, "")


def test_unlinking_clears_partner_field_pointing_at_me_only():
    assert write_allowed("100", "200", {"partner_id": None}, "100")
    assert not write_allowed("100", "200", {"partner_id": None}, "300")
    assert not write_allowed("100", "200", {"partner_id": None, "full_name": "X"}, "100")


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


def test_cancellation_gets_push(harness):
    a = TODAY + timedelta(days=4)
    assert harness({"partner_id": "100"}, old_data=[_entry(a, a, "Urlop", "9")], new_data=[]) == 1
    assert harness.calls[0]["title"] == "Twój partner odwołał niedyspozycję"


def test_nothing_new_is_silent(harness):
    a = TODAY + timedelta(days=4)
    same = [_entry(a, a, "Urlop", "9")]
    assert harness({"partner_id": "100"}, old_data=same, new_data=same) == 0
    assert harness.calls == []


def test_errors_never_escape(harness):
    assert harness(error=RuntimeError("db down")) == 0
    assert harness.calls == []

"""Werdykty wspolnego dojazdu dla statystyk (liść `verdicts_from_entries`, 25.11.2026)."""

import asyncio
import dataclasses

import pytest

from app import settlement_rates as R
from tests.test_settlement_engine import at, make
from tests.test_settlement_forecast_trips import db  # noqa: F401  (atrapa bazy bez Postgresa)
from tests.test_settlement_trip_share import run


@pytest.fixture
def T(db):  # noqa: F811
    import tests.test_settlement_forecast_trips as base

    return base._T


def two(payer_a="OKREG", payer_b="OKREG", day="2026-11-07", mode_a=None, mode_b=None):
    a = dataclasses.replace(make("a", "S/JMM/7", R.ROLE_FIELD, at(f"{day}T09:00")), payer=payer_a, trip_mode=mode_a)
    b = dataclasses.replace(make("b", "S/JMM/8", R.ROLE_FIELD, at(f"{day}T14:00")), payer=payer_b, trip_mode=mode_b)
    return [a, b]


def verdicts(T, assignments):
    _, entry = run(assignments)
    return {v["match_key"]: v["result"] for v in T.verdicts_from_entries([entry])}


def test_ten_sam_platnik_drugi_wspolny(T):
    assert verdicts(T, two()) == {"a": "own", "b": "shared"}


def test_rozni_platnicy_obaj_wlasny(T):
    assert verdicts(T, two(payer_b="1234")) == {"a": "own", "b": "own"}


def test_wspolny_budzet_o_roznych_nazwach_to_jeden_platnik(T, monkeypatch):
    """Kluby jednego budzetu: `_payers` sprowadza je do klubu glownego."""
    items = two(payer_a=None, payer_b=None)

    async def fake_scope(province, by_season, **kwargs):
        return {"payer_of": {"a": "pogon-a", "b": "pogon-b"}}

    async def fake_owner(province):
        return {"pogon-a": "pogon", "pogon-b": "pogon"}

    import sys

    CS = sys.modules["app.settlement_club_scope"]

    monkeypatch.setattr(CS, "club_scope_many", fake_scope)
    monkeypatch.setattr(T, "_budget_owner", fake_owner)
    payers = asyncio.run(
        T._payers("ŚLĄSKIE", items, central_versions=[], province_versions=[], now=T._now())
    )
    assert payers == {"a": "pogon", "b": "pogon"}
    items = [dataclasses.replace(i, payer=payers[i.match_key]) for i in items]
    assert verdicts(T, items) == {"a": "own", "b": "shared"}


def test_reczne_razem_i_osobno(T):
    assert verdicts(T, two(payer_b="1234", mode_b="together")) == {"a": "own", "b": "shared"}
    assert verdicts(T, two(mode_b="separate")) == {"a": "own", "b": "own"}


def test_przed_01_11_bez_werdyktow(T):
    assert verdicts(T, two(day="2026-10-31")) == {}


def test_mecz_samotny_nie_ma_werdyktu(T):
    assert verdicts(T, two()[:1]) == {}

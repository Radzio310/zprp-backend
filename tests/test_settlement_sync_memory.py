"""Pamiec porazek pomiaru, puste hale po meczu i zapis paczkami (sync rozliczen okregu)."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import Column, DateTime, MetaData, String, Table
from sqlalchemy.dialects import postgresql

from app import settlement_sync_rules as R

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)


def test_porazka_zyje_zgodnie_z_terminem():
    assert R.failure_alive("nokm", NOW - timedelta(days=6), NOW)
    assert not R.failure_alive("nokm", NOW - timedelta(days=8), NOW)
    assert R.failure_alive("noshape", NOW - timedelta(days=29), NOW)
    assert not R.failure_alive("noshape", NOW - timedelta(days=31), NOW)
    assert not R.failure_alive("inne", NOW, NOW)
    assert not R.failure_alive("nokm", None, NOW)


def test_klasyfikacja_porazek():
    cache = {("a", "x"): None, ("a", "y"): 12.0, ("a", "z"): 5.0, ("old", "q"): None}
    failed, healed = R.classify_failures(
        cache, {("old", "q")}, {("a", "z"): "poly"}, google_on=True, no_route={("a", "x")}
    )
    assert failed == {("a", "x"): "nokm", ("a", "y"): "noshape"}
    assert healed == {("a", "z")}


def test_bez_klucza_google_brak_wyniku_nie_jest_porazka():
    failed, _ = R.classify_failures({("a", "x"): None}, set(), {}, google_on=False)
    assert failed == {}


def test_hala_pusta_po_meczu_pytana_dopiero_po_kilku_dniach():
    played = NOW - timedelta(days=10)
    fresh = {"city": "", "fetched_at": NOW - timedelta(days=2)}
    old = {"city": "", "fetched_at": NOW - timedelta(days=6)}
    assert not R.venue_needs_refresh(fresh, played, NOW)
    assert R.venue_needs_refresh(old, played, NOW)
    before_match = {"city": None, "fetched_at": played - timedelta(days=1)}
    assert R.venue_needs_refresh(before_match, played, NOW)
    assert R.venue_needs_refresh(None, played, NOW)


def test_hala_z_miastem_bez_zmian():
    hit = {"city": "Gliwice", "fetched_at": NOW - timedelta(days=20)}
    assert R.venue_needs_refresh(hit, NOW + timedelta(days=3), NOW)
    assert not R.venue_needs_refresh(hit, NOW - timedelta(days=30), NOW)


class Recorder:
    def __init__(self):
        self.queries = []

    async def execute(self, query):
        self.queries.append(query)


def _table():
    return Table(
        "t", MetaData(),
        Column("a", String, primary_key=True),
        Column("b", String, primary_key=True),
        Column("kind", String),
        Column("at", DateTime(timezone=True)),
    )


def test_upsert_paczkami_scala_duplikaty_i_kompiluje_sie_na_postgresie():
    table, db = _table(), Recorder()
    rows = [{"a": str(i), "b": "x", "kind": "nokm", "at": NOW} for i in range(R.STORE_BATCH + 10)]
    rows.append({"a": "0", "b": "x", "kind": "noshape", "at": NOW})  # duplikat klucza
    count = asyncio.run(R.upsert_batches(db, table, rows, ["a", "b"]))
    assert count == 2 and len(db.queries) == 2
    sql = str(db.queries[0].compile(dialect=postgresql.dialect()))
    assert "ON CONFLICT (a, b) DO UPDATE SET kind = excluded.kind, at = excluded.at" in sql
    # ostatni wygrywa
    params = db.queries[0].compile(dialect=postgresql.dialect()).params
    assert params["kind_m0"] == "noshape"


def test_upsert_pustej_listy_nic_nie_wysyla():
    db = Recorder()
    assert asyncio.run(R.upsert_batches(db, _table(), [], ["a", "b"])) == 0
    assert db.queries == []


def test_nieznany_wynik_nie_jest_porazka_tylko_jednoznaczny_brak_trasy():
    cache = {("a", "x"): None, ("a", "w"): None}
    failed, _ = R.classify_failures(cache, set(), {}, google_on=True, no_route={("a", "x")})
    assert failed == {("a", "x"): "nokm"}  # ("a", "w") = wyjatek/limit: bez pamieci


class _Resp:
    def __init__(self, data=None, code=200):
        self._d, self.status_code = data or {}, code

    def json(self):
        return self._d


class _Client:
    def __init__(self, behaviour):
        self.behaviour = behaviour

    async def get(self, url, params=None):
        if isinstance(self.behaviour, Exception):
            raise self.behaviour
        return self.behaviour


def _verdict(behaviour, monkeypatch):
    from app import settlement_distances as SD

    monkeypatch.setattr(SD, "GOOGLE_MAPS_API_KEY", "k")
    return asyncio.run(SD.google_route_verdict(_Client(behaviour), "A", "B"))


def test_zero_results_to_jednoznaczny_brak_trasy(monkeypatch):
    assert _verdict(_Resp({"status": "ZERO_RESULTS", "routes": []}), monkeypatch) == (None, "", True)
    assert _verdict(_Resp({"status": "NOT_FOUND", "routes": []}), monkeypatch)[2] is True


def test_bledy_nie_sa_brakiem_trasy(monkeypatch):
    for behaviour in (
        TimeoutError("t"),
        _Resp({"status": "OVER_QUERY_LIMIT", "routes": []}),
        _Resp({"status": "REQUEST_DENIED", "routes": []}),
        _Resp({}, code=503),
        _Resp({"status": "OK", "routes": []}),
    ):
        km, enc, definitive = _verdict(behaviour, monkeypatch)
        assert km is None and definitive is False


def test_trasa_znaleziona(monkeypatch):
    route = {"legs": [{"distance": {"value": 12000}}], "overview_polyline": {"points": "xyz"}}
    ok = _Resp({"status": "OK", "routes": [route]})
    assert _verdict(ok, monkeypatch) == (12.0, "xyz", False)

"""
Prognoza z telefonu skleja dojazdy ta sama regula co obsady z bazy (25.11.2026):
platnik dosylanego meczu wynika z klubu gospodarza (`club_scope_many`), a reczna
decyzja z `province_trip_decisions` obejmuje takze mecze `f:<id>`.
"""

from datetime import datetime, timezone

import importlib
import pathlib
import re
import sys
import types
from unittest import mock

import pytest
import sqlalchemy as sa

from app import settlement_engine as E
from app import settlement_forecast_rules as F
from app import settlement_rates as R
from tests.test_settlement_engine import CENTRAL_VERSIONS, PROV_VERSIONS, at

ROOT = pathlib.Path(__file__).resolve().parents[1]

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)


class FakeDb:
    def __init__(self, decisions=()):
        self.decisions = list(decisions)

    async def fetch_all(self, query):
        text = str(query)
        if "FROM province_club_teams" in text:
            return [
                {"season": "2026/2027", "team_id": "t1", "club_id": "c1", "team_name": "KS Alfa",
                 "category": "Seniorzy", "gender": "M", "name_key": "", "team_province": "ŚLĄSKIE",
                 "competition_code": "S/JMM/7"},
                {"season": "2026/2027", "team_id": "t2", "club_id": "c2", "team_name": "KS Beta",
                 "category": "Seniorzy", "gender": "M", "name_key": "", "team_province": "ŚLĄSKIE",
                 "competition_code": "S/JMM/7"},
            ]
        if "FROM province_clubs" in text:
            return [
                {"club_id": "c1", "display_name": "Alfa", "settles_via_district": False, "settles_since": None},
                {"club_id": "c2", "display_name": "Beta", "settles_via_district": False, "settles_since": None},
            ]
        if "FROM province_trip_decisions" in text:
            return self.decisions
        if "FROM province_matches" in text:
            raise AssertionError("prognoza nie moze czytac stanow wszystkich meczow okregu")
        return []


def _fake_db_module(fake):
    """`app.db` laczy sie z Postgresem juz przy imporcie - tu podstawiamy atrape z samymi tabelami."""
    module = types.ModuleType("app.db")
    meta = sa.MetaData()
    columns = (
        "id province season club_id team_id match_key judge_id mode match_id state_json active "
        "updated_by updated_at team_name team_province competition_code category gender name_key "
        "display_name settles_via_district settles_since excluded triple_table tournament_key"
    ).split()
    tables = {}

    def table(name):
        if name not in tables:
            tables[name] = sa.Table(name, meta, *[sa.Column(c, sa.String) for c in columns])
        return tables[name]

    module.database = fake
    module.__getattr__ = table
    return module


@pytest.fixture
def db(monkeypatch):
    fake = FakeDb()
    before = set(sys.modules)
    monkeypatch.setitem(sys.modules, "app.db", _fake_db_module(fake))
    # Ciezki ekran rozliczen (setki tabel) nie jest tu potrzebny - trasy sa osobno.
    stub = types.ModuleType("app.province_settlements")
    stub.__getattr__ = lambda name: mock.MagicMock()
    monkeypatch.setitem(sys.modules, "app.province_settlements", stub)
    for name in ("app.province_settlement_trips", "app.settlement_club_scope", "app.province_club_splits"):
        sys.modules.pop(name, None)
    T = importlib.import_module("app.province_settlement_trips")
    SCOPE = importlib.import_module("app.settlement_club_scope")
    SPL = importlib.import_module("app.province_club_splits")
    global _T
    _T = T

    async def no_splits(province):
        return [], []

    async def no_budgets(province):
        return {}

    monkeypatch.setattr(SPL, "overlay", no_splits)
    monkeypatch.setattr(T, "_budget_owner", no_budgets)
    yield fake
    for name in set(sys.modules) - before:
        if name.startswith("app."):
            sys.modules.pop(name, None)


def item(match_id, when, teams="KS Alfa - KS Beta", host=None, code="S/JMM/7", city="Zabrze"):
    return {
        "match_id": match_id, "code": code, "when": when, "role": "Sędzia boiskowy",
        "city": city, "hall": "", "teams": teams, "host": host,
    }


def forecast(items):
    picked = F.pick_forecast(items, known_ids=set(), own_prefixes={"S"}, now=NOW)
    out = [
        E.Assignment(
            match_key=p["match_key"], judge_id="5124", match_at=p["match_at"], match_code=p["code"],
            role=p["role"], origin=F.FORECAST_ORIGIN, city=p["city"], hall=p["hall"], home_city="Bystra",
            teams=p["teams"], distance_km=20.0, distance_source="table",
        )
        for p in picked
    ]
    return picked, out


async def annotate(picked, out):
    await _T.annotate_forecast(
        "ŚLĄSKIE", "5124", out,
        central_versions=CENTRAL_VERSIONS, province_versions=PROV_VERSIONS, now=NOW,
        hosts={p["match_key"]: p["host"] for p in picked if p.get("host")},
        guests={p["match_key"]: p["guest"] for p in picked if p.get("guest")},
    )


def travels(assignments):
    [entry] = E.settle_judges(
        assignments, province="ŚLĄSKIE", central_versions=CENTRAL_VERSIONS,
        province_versions=PROV_VERSIONS, now=NOW, include_future=True, names={"5124": "K"},
    )
    return {m.match_key: m.travel for m in entry.matches}


async def test_dwa_doslane_u_tego_samego_klubu_jeden_dojazd(db):
    picked, out = forecast([item("1", "2026-12-05T08:00:00Z"), item("2", "2026-12-05T13:00:00Z")])
    await annotate(picked, out)
    assert [a.payer for a in out] == ["c1", "c1"]
    got = travels(out)
    assert got["f:1"] > 0 and got["f:2"] == 0


async def test_dwa_doslane_u_roznych_klubow_dwa_dojazdy(db):
    picked, out = forecast([
        item("1", "2026-12-05T08:00:00Z"),
        item("2", "2026-12-05T13:00:00Z", teams="KS Beta - KS Alfa"),
    ])
    await annotate(picked, out)
    assert [a.payer for a in out] == ["c1", "c2"]
    got = travels(out)
    assert got["f:1"] > 0 and got["f:2"] > 0


async def test_znany_plus_doslany_jak_gdyby_oba_w_bazie(db):
    known = E.Assignment(
        match_key="d:1", judge_id="5124", match_at=at("2026-12-05T08:00"), match_code="S/JMM/7",
        role=R.ROLE_FIELD, origin="district", city="Zabrze", home_city="Bystra",
        distance_km=20.0, distance_source="table", payer="c1",
    )
    picked, out = forecast([item("2", "2026-12-05T13:00:00Z")])
    await annotate(picked, out)
    got = travels([known, *out])
    assert got["d:1"] > 0 and got["f:2"] == 0
    # odwrotnie: doslany jest wczesniejszy, wiec to on bierze dojazd
    picked, out = forecast([item("3", "2026-12-05T07:00:00Z")])
    await annotate(picked, out)
    got = travels([known, *out])
    assert got["f:3"] > 0 and got["d:1"] == 0


async def test_doslany_sprzed_listopada_bez_zmian(db):
    early = [
        E.Assignment(match_key=f"f:{n}", judge_id="5124", match_at=at(f"2026-10-20T{h}:00"),
                     match_code="S/JMM/7", role=R.ROLE_FIELD, origin="forecast", city="Zabrze",
                     home_city="Bystra", teams="KS Alfa - KS Beta", distance_km=20.0,
                     distance_source="table")
        for n, h in ((7, "08"), (8, "14"))
    ]
    await annotate([], early)
    assert [a.payer for a in early] == [None, None]
    got = travels(early)
    assert got["f:7"] > 0 and got["f:8"] > 0


async def test_doslany_z_reczna_decyzja(db):
    db.decisions = [
        {"mode": "separate", "match_key": "d:2", "judge_id": "5124"},
        {"mode": "bogus", "match_key": "d:1", "judge_id": "5124"},
    ]
    picked, out = forecast([item("1", "2026-12-05T08:00:00Z"), item("2", "2026-12-05T13:00:00Z")])
    await annotate(picked, out)
    assert [a.trip_mode for a in out] == [None, "separate"]
    got = travels(out)
    assert got["f:1"] > 0 and got["f:2"] > 0

    db.decisions = [{"mode": "together", "match_key": "f:1", "judge_id": "5124"}]
    picked, out = forecast([
        item("1", "2026-12-05T08:00:00Z"),
        item("2", "2026-12-05T13:00:00Z", teams="KS Beta - KS Alfa"),
    ])
    await annotate(picked, out)
    got = travels(out)
    assert got["f:1"] == 0 and got["f:2"] > 0


async def test_stary_klient_bez_pola_host_uzywa_napisu_teams(db):
    raw = item("1", "2026-12-05T08:00:00Z")
    raw.pop("host")
    picked, out = forecast([raw, item("2", "2026-12-05T13:00:00Z")])
    assert picked[0]["host"] == ""
    await annotate(picked, out)
    assert out[0].payer == "c1"


async def test_nowy_klient_host_po_zamianie_stron_wygrywa_z_napisem(db):
    # nominalnie Alfa - Beta, po zamianie gospodarzem jest Beta
    picked, out = forecast([
        item("1", "2026-12-05T08:00:00Z", host="KS Beta"),
        item("2", "2026-12-05T13:00:00Z", teams="KS Beta - KS Alfa"),
    ])
    await annotate(picked, out)
    assert [a.payer for a in out] == ["c2", "c2"]


async def test_nieznany_gospodarz_to_nieznany_platnik(db):
    picked, out = forecast([
        item("1", "2026-12-05T08:00:00Z", teams="Obcy - Ktos"),
        item("2", "2026-12-05T13:00:00Z", teams=""),
    ])
    await annotate(picked, out)
    assert out[0].payer is None and out[1].payer is None
    got = travels(out)
    assert got["f:1"] > 0 and got["f:2"] > 0


async def test_blad_bazy_zostawia_stara_regule(db, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("baza")

    monkeypatch.setattr(sys.modules["app.settlement_club_scope"], "club_scope_many", boom)
    picked, out = forecast([item("1", "2026-12-05T08:00:00Z"), item("2", "2026-12-05T13:00:00Z")])
    await annotate(picked, out)
    assert [a.payer for a in out] == [None, None]


def test_model_przyjmuje_stare_i_nowe_pole():
    """Pola `host`/`guest` sa opcjonalne: stary telefon ich nie wysyla."""
    source = (ROOT / "app" / "province_settlements.py").read_text(encoding="utf-8")
    body = source[source.index("class ForecastMatch"):source.index("class ForecastRequest")]
    assert "host: Optional[str] = None" in body and "guest: Optional[str] = None" in body
    assert "annotate_forecast(" in source

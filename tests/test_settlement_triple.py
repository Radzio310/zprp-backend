"""
Potrojny ryczalt stolikowego - gdy stolikowy z klubu sie nie stawil.

Regula (decyzja uzytkownika z 10.09.2026): tylko stoliki OKREGOWE i tylko
w okregach, ktore maja te opcje wlaczona (na razie Slask). Dojazd zostaje
normalny, a klub gospodarza placi te sama trzykrotnosc.
"""

import io
import json
from datetime import datetime, timezone
from pathlib import Path

from app import settlement_engine as E
from app import settlement_rates as R

ROOT = Path(__file__).resolve().parent.parent
SEED = json.loads(io.open(ROOT / "app" / "data" / "central_rates_seed.json", encoding="utf-8").read())
CENTRAL_VERSIONS = [
    {"id": 1, "valid_from": None, "valid_to": "2026-08-31", "enabled": True, "content": SEED["versions"][0]["content"]},
    {"id": 2, "valid_from": "2026-09-01", "valid_to": None, "enabled": True, "content": SEED["versions"][1]["content"]},
]
PROV_RAW = json.loads(
    io.open(ROOT.parent / "BAZA" / "assets" / "data" / "okregowe" / "slaskieCalcRates.json", encoding="utf-8").read()
)
PROV_VERSIONS = [
    {"id": 10, "valid_from": "2026-09-01", "valid_to": None, "enabled": True,
     "content": {**PROV_RAW, "kilometrowka": {"ŚLĄSKIE": 0.7}}},
]
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def at(iso: str) -> datetime:
    return datetime.fromisoformat(iso).replace(tzinfo=timezone.utc)


def make(key, code, role, when, *, km=20.0, triple=False):
    return E.Assignment(
        match_key=key, judge_id="5124", judge_name="KOWALSKI Jan",
        match_at=when, match_code=code, role=role,
        city="Zabrze", home_city="Bystra", distance_km=km, distance_source="table",
        triple_table=triple,
    )


def settle(assignments, province="ŚLĄSKIE", **kwargs):
    return E.settle_judges(
        assignments,
        province=province,
        central_versions=CENTRAL_VERSIONS,
        province_versions=PROV_VERSIONS,
        now=NOW,
        names={"5124": "KOWALSKI Jan"},
        **kwargs,
    )


# ------------------------------------------------------------------ regula

def test_potrojny_tylko_na_stoliku_okregowym():
    assert R.triple_table_allowed("S/JMM/7", R.ROLE_TABLE, "ŚLĄSKIE") is True
    assert R.triple_table_allowed("S/DZM/1", R.ROLE_TABLE, "SLASKIE") is True
    # Boiskowy stoi na boisku, nie przy stoliku.
    assert R.triple_table_allowed("S/JMM/7", R.ROLE_FIELD, "ŚLĄSKIE") is False
    # Stoliki ligowe (II liga w gore) i puchar wojewodzki - bez tej opcji.
    assert R.triple_table_allowed("IIM4/12", R.ROLE_TABLE, "ŚLĄSKIE") is False
    assert R.triple_table_allowed("S/PPK/2", R.ROLE_TABLE, "ŚLĄSKIE") is False
    # Okreg, ktory tej opcji nie ma wlaczonej.
    assert R.triple_table_allowed("S/JMM/7", R.ROLE_TABLE, "MAZOWIECKIE") is False


# ------------------------------------------------------------------ rachunek

def test_ryczalt_x3_a_dojazd_bez_zmian():
    [plain] = settle([make("m1", "S/JMM/7", R.ROLE_TABLE, at("2026-10-04T10:00"))])
    [triple] = settle([make("m1", "S/JMM/7", R.ROLE_TABLE, at("2026-10-04T10:00"), triple=True)])

    assert plain.matches[0].triple_table is False
    assert triple.matches[0].triple_table is True
    assert triple.matches[0].gross == 3 * plain.matches[0].gross
    assert triple.matches[0].travel == plain.matches[0].travel
    # Podatek liczy sie od sumy miesiaca, wiec potrojna kwota podnosi tez podatek.
    assert triple.gross == 3 * plain.gross


def test_znacznik_bez_pokrycia_w_regule_nic_nie_zmienia():
    [plain] = settle([make("l1", "IIM4/12", R.ROLE_TABLE, at("2026-10-10T18:00"), km=50)])
    [marked] = settle([make("l1", "IIM4/12", R.ROLE_TABLE, at("2026-10-10T18:00"), km=50, triple=True)])
    assert marked.matches[0].gross == plain.matches[0].gross
    assert marked.matches[0].triple_table is False


def test_okreg_bez_opcji_nie_mnozy():
    [marked] = settle(
        [make("m1", "S/JMM/7", R.ROLE_TABLE, at("2026-10-04T10:00"), triple=True)],
        province="MAZOWIECKIE",
    )
    # Stawki mazowieckiej nie mamy, ale znacznik i tak nie ma prawa zadzialac.
    assert marked.matches[0].triple_table is False


def test_mecz_bez_odleglosci_nie_mnozy_zera():
    [entry] = settle([make("m1", "S/JMM/7", R.ROLE_TABLE, at("2026-10-04T10:00"), km=None, triple=True)])
    assert entry.matches[0].status == "missing-distance"
    assert entry.matches[0].gross == 0

"""
Obsady rozliczane przez ZPRP - poza rozliczeniem okregu (decyzja z 10.09.2026).

Z rozliczenia okregu wypada wszystko, co obsadza ZPRP (boiskowi i delegaci na
meczach centralnych), oraz stoliki Mistrzostw Polski. Panel webowy moze je
doliczyc przelacznikiem, aplikacja sedziego - nigdy.
"""

import io
import json
from datetime import date, datetime, timezone
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
OCTOBER = {"date_from": date(2026, 10, 1), "date_to": date(2026, 10, 31)}


def at(iso: str) -> datetime:
    return datetime.fromisoformat(iso).replace(tzinfo=timezone.utc)


def make(key, code, role, when, *, km=20.0, city="Zabrze", judge="5124"):
    return E.Assignment(
        match_key=key, judge_id=judge, judge_name="KOWALSKI Jan",
        match_at=when, match_code=code, role=role,
        city=city, home_city="Bystra", distance_km=km, distance_source="table",
    )


def settle(assignments, **kwargs):
    return E.settle_judges(
        assignments,
        province="ŚLĄSKIE",
        central_versions=CENTRAL_VERSIONS,
        province_versions=PROV_VERSIONS,
        now=NOW,
        names={"5124": "KOWALSKI Jan"},
        **kwargs,
    )


def months(assignments, **kwargs):
    return E.monthly_totals(
        assignments,
        province="ŚLĄSKIE",
        central_versions=CENTRAL_VERSIONS,
        province_versions=PROV_VERSIONS,
        now=NOW,
        **kwargs,
    )


# ---------------------------------------------------------------- kto rozlicza

def test_boiskowy_na_meczu_centralnym_rozlicza_zprp():
    for code in ("SM/8", "IMD/3", "IIM4/12", "LCM/5", "BSM/2"):
        assert R.zprp_settlement_reason(code, R.ROLE_FIELD) == R.ZPRP_FIELD, code


def test_delegat_na_meczu_centralnym_rozlicza_zprp():
    assert R.zprp_settlement_reason("SM/8", R.ROLE_DELEGATE) == R.ZPRP_DELEGATE
    assert R.zprp_settlement_reason("PPM/23", R.ROLE_DELEGATE) == R.ZPRP_DELEGATE


def test_mistrzostwa_i_puchar_polski():
    assert R.zprp_settlement_reason("MPJMM/19", R.ROLE_FIELD) == R.ZPRP_FIELD
    assert R.zprp_settlement_reason("PPM/23", R.ROLE_FIELD) == R.ZPRP_FIELD
    # Stoliki MP rozlicza ZPRP osobno; stoliki Pucharu Polski - okreg.
    assert R.zprp_settlement_reason("MPJMM/19", R.ROLE_TABLE) == R.ZPRP_MP_TABLE
    assert R.zprp_settlement_reason("PPM/23", R.ROLE_TABLE) is None


def test_stolik_ligowy_zostaje_w_okregu():
    for code in ("SM/8", "IMD/3", "IIM4/12"):
        assert R.zprp_settlement_reason(code, R.ROLE_TABLE) is None, code


def test_mecze_okregowe_zostaja_w_kazdej_roli():
    for code in ("S/JMM/7", "S/IIIM/4", "S/DZM/1", "S/MLK/2"):
        for role in (R.ROLE_FIELD, R.ROLE_TABLE, R.ROLE_DELEGATE):
            assert R.zprp_settlement_reason(code, role) is None, (code, role)


def test_puchar_wojewodzki_to_mecz_okregu_mimo_stawek_ii_ligi():
    # Stawki II ligi...
    assert R.match_level("S/PPK/2") == "central"
    # ...ale rozlicza go okreg, w kazdej roli.
    assert R.zprp_settlement_reason("S/PPK/2", R.ROLE_FIELD) is None
    assert R.zprp_settlement_reason("S/PPK/2", R.ROLE_DELEGATE) is None


def test_superpuchar_i_ehf_obsadza_centrala():
    assert R.zprp_settlement_reason("SPM/1", R.ROLE_FIELD) == R.ZPRP_FIELD
    assert R.zprp_settlement_reason("EHF/5", R.ROLE_DELEGATE) == R.ZPRP_DELEGATE
    assert R.zprp_settlement_reason("EHF/5", R.ROLE_TABLE) is None


def test_kazdy_powod_ma_opis_dla_czlowieka():
    for reason in (R.ZPRP_FIELD, R.ZPRP_DELEGATE, R.ZPRP_MP_TABLE):
        assert R.ZPRP_REASONS[reason]


# ---------------------------------------------------------------- rachunek

def _district_and_league():
    return [
        make("d", "S/JMM/7", R.ROLE_FIELD, at("2026-10-04T10:00")),
        make("l", "SM/8", R.ROLE_FIELD, at("2026-10-09T18:00"), km=486, city="Kwidzyn"),
    ]


def test_boiskowy_superligi_nie_wchodzi_do_sumy_ani_do_podatku():
    [entry] = settle(_district_and_league())
    assert [m.match_key for m in entry.matches] == ["d"]
    assert entry.gross == 132
    # Superliga nie podbila sumy ponad prog 200 zl.
    assert entry.costs == 0
    assert entry.travel == round(20 * 0.7 * 2)


def test_przelacznik_przywraca_obsady_zprp_ze_znacznikiem():
    [entry] = settle(_district_and_league(), include_zprp=True)
    assert [m.match_key for m in entry.matches] == ["d", "l"]
    league = entry.matches[1]
    assert league.zprp_reason == R.ZPRP_FIELD
    assert entry.matches[0].zprp_reason is None
    assert entry.gross > 132


def test_sedzia_z_samymi_obsadami_zprp_znika_z_zestawienia():
    assert settle([make("l", "SM/8", R.ROLE_FIELD, at("2026-10-09T18:00"))]) == []


def test_przejazd_na_obsade_zprp_nie_trafia_na_liste():
    rows = E.travel_rows(settle(_district_and_league()))
    assert [r.route for r in rows] == ["Bystra-Zabrze-Bystra"]


def test_obsady_zprp_tlumacza_sie_zamiast_znikac():
    items = _district_and_league() + [
        make("f", "SM/9", R.ROLE_FIELD, at("2026-10-25T18:00")),
        make("n", "SM/10", R.ROLE_FIELD, at("2026-11-02T18:00")),
    ]
    played = E.zprp_matches(items, now=NOW, **OCTOBER)
    assert [m.match_key for m in played] == ["l"]
    assert played[0].reason == R.ZPRP_FIELD
    assert played[0].category == "SM"

    with_future = E.zprp_matches(items, now=NOW, include_future=True, **OCTOBER)
    assert [m.match_key for m in with_future] == ["l", "f"]
    assert with_future[1].future is True


# ---------------------------------------------------------------- miesiace

def test_sumy_miesieczne_to_te_same_kwoty_co_po_kliknieciu_w_miesiac():
    items = _district_and_league() + [
        make("s", "S/JMM/7", R.ROLE_FIELD, at("2026-09-06T10:00"), city="Bytom"),
        make("o", "S/JMM/7", R.ROLE_FIELD, at("2026-10-11T10:00"), city="Gliwice"),
    ]
    rows = months(items)
    assert [(r["year"], r["month"]) for r in rows] == [(2026, 9), (2026, 10)]

    october = E.totals_of(settle(items, **OCTOBER))
    assert rows[1]["total"] == october["total"]
    assert rows[1]["tax"] == october["tax"]
    # Superliga poza rozliczeniem okregu.
    assert rows[1]["matches"] == 2


def test_sumy_miesieczne_z_przelacznikiem_zprp():
    rows = months(_district_and_league(), include_zprp=True)
    assert rows[0]["matches"] == 2


def test_sumy_miesieczne_pomijaja_przyszle_i_puste_miesiace():
    items = [
        make("p", "S/JMM/7", R.ROLE_FIELD, at("2026-11-08T10:00")),
        make("l", "SM/8", R.ROLE_FIELD, at("2026-10-09T18:00")),
    ]
    assert months(items) == []
    assert [(r["year"], r["month"]) for r in months(items, include_future=True)] == [(2026, 11)]

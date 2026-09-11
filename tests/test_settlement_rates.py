"""
Silnik rozliczen liczy PIENIADZE, wiec kazda regula ma tu swoj przypadek.

Kwoty sprawdzane sa wprost wobec tabeli z `app/data/central_rates_seed.json`
i wobec wzorcowej tabeli slaskiej - te same liczby, ktore widzi sedzia
w aplikacji.
"""

import io
import json
from datetime import date
from pathlib import Path

import pytest

from app import settlement_rates as R

ROOT = Path(__file__).resolve().parent.parent
SEED = json.loads(io.open(ROOT / "app" / "data" / "central_rates_seed.json", encoding="utf-8").read())
BOOK_OLD = SEED["versions"][0]["content"]
BOOK_NEW = SEED["versions"][1]["content"]

OKREGOWE = ROOT.parent / "BAZA" / "assets" / "data" / "okregowe"
# Wersja od 01.09.2026 (kopia serwera): stala stawka za mecz + kilometrowka.
PROV_SLASKIE = json.loads(io.open(OKREGOWE / "slaskieCalcRates.json", encoding="utf-8").read())
# Wersja 01.01-31.08.2026: ryczalt rosl progami odleglosci, kilometrowka 0.
PROV_SLASKIE_PROGI = json.loads(
    io.open(OKREGOWE / "STAWKI - wersjonowanie" / "slaskie wersje" / "slaskie_do_31_08_2026.json", encoding="utf-8").read()
)

SOBOTA_STARA = date(2026, 3, 7)
SOBOTA_NOWA = date(2026, 9, 5)


# ---------------------------------------------------------------- rozpoznanie

@pytest.mark.parametrize(
    "code,expected",
    [
        # Numer mistrzostw niesie w sobie litere kategorii - „MPJMM/19" zawiera
        # „JMM" i bez pierwszenstwa pucharu rozliczalby sie jak mecz juniorski.
        ("MPJMM/19", "cup"),
        ("PPM/23", "cup"),
        # Puchar WOJEWODZKI placi stawkami II ligi, wiec liczy sie jak centralny.
        ("S/PPK/2", "central"),
        # II liga jest centralna takze w wojewodzkiej grupie IIM4.
        ("IIM4/12", "central"),
        ("S/JMM/7", "district"),
        ("DZM/3", "district"),
        ("OSM/3", "central"),
        # Mecz miedzypanstwowy - stawki nie ma w zadnej tabeli ZPRP.
        ("EHF/1", "unknown"),
    ],
)
def test_match_level(code, expected):
    assert R.match_level(code) == expected


def test_baraz_placi_stawka_superligi_o_ktora_gra():
    # „BSK/1" zawiera „SK", wiec wczesniej trafial do Superligi przez przypadek.
    assert R.competition_prefix("BSK/1") == "BSK"
    assert R.central_category("BSK/1") == "OSK"


def test_kategorie_okregowe():
    assert R.district_category("S/MLM1213/2") == "Młodzik mł."
    assert R.district_category("S/JMM/7") == "Junior mł."
    assert R.district_category("S/JM/7") == "Junior"
    assert R.district_category("S/IIIM/4") == "III liga"


def test_turniej_dzieci_ma_wlasna_kategorie():
    assert R.district_category("S/DZM/3") == "Dzieci"
    assert R.district_category("S/DZK/1") == "Dzieci"
    assert R.category_label("S/DZM/3") == "Dzieci"


# --------------------------------------------------------------------- etapy

@pytest.mark.parametrize(
    "kind,text,stage,detected",
    [
        ("MP", "1/16 MPJMM gr. E Zabrze", "1/16 i 1/8MP", True),
        ("MP", "1/8 MPJMM", "1/16 i 1/8MP", True),
        # 1/12 to etap mlodzikow z regulaminu - prog najnizszy.
        ("MP", "1/12 MPMLM gr. A", "1/16 i 1/8MP", True),
        ("MP", "1/4 MPJMM", "1/4MP", True),
        # „Final" po zdjeciu ogonka; „l" NFD nie rozklada, stad osobna podmiana.
        ("MP", "Finał MPJMM", "Finał MP", True),
        ("PP", "1/4 finału", "1/4 i 1/2PP", True),
        # Polfinal PP ma WLASNY prog od 01.09.2026.
        ("PP", "1/2 finału", "1/2PP", True),
        ("PP", "Finał", "Finał PP", True),
    ],
)
def test_cup_stage_rozpoznany(kind, text, stage, detected):
    assert R.cup_stage_from_text(kind, text, "") == (stage, detected)


def test_cup_stage_bez_rundy_bierze_najnizszy_prog():
    # Zawyzona kwota w zestawieniu okregu wyglada jak zobowiazanie, ktorego nie ma.
    assert R.cup_stage_from_text("MP", "", "") == ("1/16 i 1/8MP", False)
    assert R.cup_stage_from_text("PP", None, None) == ("1/16 i 1/8PP", False)


def test_puchar_wojewodzki_nie_jest_turniejem_centralnym():
    assert R.cup_stage("S/PPK/2", "1/4 finału", "") is None


# --------------------------------------------------------------------- kwoty

def _gross(code, role, km, when, book, prov=PROV_SLASKIE, runda=None):
    return R.calculate_gross(
        code=code, role=role, distance_km=km, when=when,
        central_book=book, province_content=prov, round_text=runda,
    )


def test_stolik_centralny_rosnie_od_uchwaly_44_26():
    assert _gross("IIM4/12", R.ROLE_TABLE, 0, SOBOTA_STARA, BOOK_OLD) == 63
    assert _gross("IIM4/12", R.ROLE_TABLE, 0, SOBOTA_NOWA, BOOK_NEW) == 110


def test_superliga_zostaje_przy_swojej_stawce_stolikowej():
    # Osobna tabela ORLEN, nietknieta uchwala 44/26.
    assert _gross("OSM/3", R.ROLE_TABLE, 0, SOBOTA_NOWA, BOOK_NEW) == 120


def test_polfinal_pp_placi_jak_final_dopiero_od_nowej_tabeli():
    assert _gross("PPM/23", R.ROLE_FIELD, 50, SOBOTA_STARA, BOOK_OLD, runda="1/2 finału") == 339
    assert _gross("PPM/23", R.ROLE_FIELD, 50, SOBOTA_NOWA, BOOK_NEW, runda="1/2 finału") == 529
    # Cwiercfinal zostaje na swoim progu w obu tabelach.
    assert _gross("PPM/23", R.ROLE_FIELD, 50, SOBOTA_NOWA, BOOK_NEW, runda="1/4 finału") == 339


def test_puchar_wojewodzki_placi_stawka_ii_ligi():
    assert _gross("S/PPK/2", R.ROLE_FIELD, 50, SOBOTA_NOWA, BOOK_NEW) == 195


def test_okregowy_od_01_09_2026_to_stala_stawka():
    # Od 01.09.2026 odleglosc nie zmienia ryczaltu - dojazd idzie kilometrowka.
    for km in (0, 20, 150):
        assert _gross("S/JMM/7", R.ROLE_FIELD, km, SOBOTA_NOWA, BOOK_NEW) == 117
        assert _gross("S/JMM/7", R.ROLE_TABLE, km, SOBOTA_NOWA, BOOK_NEW) == 77
    assert _gross("S/IIIM/4", R.ROLE_FIELD, 20, SOBOTA_NOWA, BOOK_NEW) == 131


def test_delegat_okregowy_weekend_tanszy_i_doplata_za_100_km():
    sroda = date(2026, 9, 9)
    assert _gross("S/JMM/7", R.ROLE_DELEGATE, 20, sroda, BOOK_NEW) == 356
    assert _gross("S/JMM/7", R.ROLE_DELEGATE, 20, SOBOTA_NOWA, BOOK_NEW) == 264
    assert _gross("S/JMM/7", R.ROLE_DELEGATE, 120, SOBOTA_NOWA, BOOK_NEW) == 314


def test_okregowy_do_31_08_2026_rosl_progami():
    # Junior ml., prog 15-30 km = 152 zl; mecz na miejscu ma wlasny prog [0,0].
    assert _gross("S/JMM/7", R.ROLE_FIELD, 20, SOBOTA_STARA, BOOK_OLD, prov=PROV_SLASKIE_PROGI) == 152
    assert _gross("S/JMM/7", R.ROLE_FIELD, 0, SOBOTA_STARA, BOOK_OLD, prov=PROV_SLASKIE_PROGI) == 117
    assert _gross("S/JMM/7", R.ROLE_TABLE, 50, SOBOTA_STARA, BOOK_OLD, prov=PROV_SLASKIE_PROGI) == 132
    # Mlodzik ml. na miejscu 117 jak w aplikacji - sekcja "mecze" miala tu 119.
    assert _gross("S/MLM1213/2", R.ROLE_FIELD, 0, SOBOTA_STARA, BOOK_OLD, prov=PROV_SLASKIE_PROGI) == 117


def test_turniej_dzieci_40_zl_za_mecz_od_01_09_2026():
    for km in (0, 20, 150):
        assert _gross("S/DZM/3", R.ROLE_FIELD, km, SOBOTA_NOWA, BOOK_NEW) == 40
        assert _gross("S/DZK/1", R.ROLE_FIELD, km, SOBOTA_NOWA, BOOK_NEW) == 40
    # Stawka turnieju dotyczy boiskowego (tak jak kalkulator w BAZA) - stolikowy
    # na meczu dzieci zostaje przy zwyklej stawce okregowej.
    assert _gross("S/DZM/3", R.ROLE_TABLE, 20, SOBOTA_NOWA, BOOK_NEW) == 77


def test_turniej_dzieci_przed_01_09_2026_liczy_sie_jak_inne():
    # Zasada 40 zl obowiazuje od 01.09.2026. Wersja do 31.08.2026 nie ma
    # kategorii "Dzieci", wiec mecz dzieci idzie progami "Inne" jak dotad.
    assert _gross("S/DZM/3", R.ROLE_FIELD, 20, SOBOTA_STARA, BOOK_OLD, prov=PROV_SLASKIE_PROGI) == 152
    assert _gross("S/DZM/3", R.ROLE_TABLE, 20, SOBOTA_STARA, BOOK_OLD, prov=PROV_SLASKIE_PROGI) == 105


def test_delegat_do_31_08_2026_jak_tabela_c_zprp():
    # Tabela C: 264 zl w sobote i niedziele, 356 w dni robocze, +50 zl powyzej
    # 100 km. Serwer czytal "mecze" (356 na kazdy dzien), aplikacja - sekcje dni.
    sroda = date(2026, 3, 4)
    assert _gross("S/JMM/7", R.ROLE_DELEGATE, 20, SOBOTA_STARA, BOOK_OLD, prov=PROV_SLASKIE_PROGI) == 264
    assert _gross("S/JMM/7", R.ROLE_DELEGATE, 120, SOBOTA_STARA, BOOK_OLD, prov=PROV_SLASKIE_PROGI) == 314
    assert _gross("S/JMM/7", R.ROLE_DELEGATE, 20, sroda, BOOK_OLD, prov=PROV_SLASKIE_PROGI) == 356
    assert _gross("S/JMM/7", R.ROLE_DELEGATE, 120, sroda, BOOK_OLD, prov=PROV_SLASKIE_PROGI) == 406


def test_okregowy_bez_tabeli_wojewodzkiej_schodzi_do_galezi_okregowej():
    value = _gross("S/JMM/7", R.ROLE_FIELD, 20, SOBOTA_NOWA, BOOK_NEW, prov=None)
    assert value == 152  # calcRates.okregowe.boiskowy, prog 15-30


def test_mecz_bez_stawki_w_tabeli_zwraca_zero():
    assert _gross("EHF/1", R.ROLE_FIELD, 10, SOBOTA_NOWA, BOOK_NEW) == 0


# -------------------------------------------------------------- kilometrowka

def _km(code, prov=PROV_SLASKIE):
    return R.kilometer_rate(
        code=code, province="ŚLĄSKIE", province_content=prov,
        central_book=BOOK_NEW, when=SOBOTA_NOWA,
    )


def test_kilometrowka_centralna_dla_wszystkiego_od_ii_ligi():
    # I stolik, i boiskowy - decyduje szczebel meczu, nie rola.
    assert _km("IIM4/12") == 0.8
    assert _km("OSM/3") == 0.8
    # Puchar wojewodzki liczy sie jak II liga, wiec tez centralna.
    assert _km("S/PPK/2") == 0.8


def test_kilometrowka_okregowa_bierze_sie_z_tabeli_wojewodztwa():
    assert _km("S/JMM/7") == 0.7
    podmieniona = {**PROV_SLASKIE, "kilometrowka": {"ŚLĄSKIE": 0.5}}
    assert _km("S/JMM/7", prov=podmieniona) == 0.5


def test_dojazd_zawsze_w_obie_strony():
    assert R.travel_pln(93, 0.8) == 149  # 93 km -> 186 km -> 148,80 -> 149
    assert R.travel_pln(0, 0.8) == 0


# -------------------------------------------------------------------- podatek

def test_podatek_za_jeden_mecz():
    # Wiersz z papierowego zestawienia: 350 -> 70 -> 280 -> 34 -> 316.
    assert R.net_parts(350) == {
        "gross": 350, "costs": 70, "taxable": 280, "tax": 34, "net": 316,
    }


def test_prog_kosztow_uzysku_dziala_na_pojedynczym_meczu():
    assert R.net_parts(150)["costs"] == 0
    assert R.net_parts(201)["costs"] == 40


def test_rozliczenie_okresu_liczy_od_SUMY_nie_mecz_po_meczu():
    """
    Decyzja z 09.09.2026: w zestawieniu zbiorczym prog 200 zl wypada RAZ,
    na sumie miesiaca - tak czyta sie papierowy dokument.
    """
    # Trzy mecze po 150 zl: mecz po meczu koszty nie przyslugiwalyby wcale,
    # a od sumy 450 zl juz tak.
    assert R.settle_period(450) == {
        "gross": 450, "costs": 90, "taxable": 360, "tax": 43, "net": 407,
    }
    assert sum(R.net_parts(150)["costs"] for _ in range(3)) == 0


def test_rozliczenie_okresu_ponizej_progu():
    assert R.settle_period(150)["costs"] == 0


# ------------------------------------------------------------- wybor wersji

VERSIONS = [
    {"id": 1, "valid_from": None, "valid_to": "2026-08-31", "enabled": True, "content": {"z": "stara"}},
    {"id": 2, "valid_from": "2026-09-01", "valid_to": None, "enabled": True, "content": {"z": "nowa"}},
]


def test_wersja_tabeli_idzie_za_data_meczu():
    assert R.pick_version(VERSIONS, date(2026, 3, 7))["id"] == 1
    assert R.pick_version(VERSIONS, date(2026, 8, 31))["id"] == 1
    assert R.pick_version(VERSIONS, date(2026, 9, 1))["id"] == 2


def test_wersja_dla_meczu_bez_daty_to_najstarsza():
    # Podniesienie stawki wpisowi bez terminu byloby zgadywaniem na korzysc.
    assert R.pick_version(VERSIONS, None)["id"] == 1


def test_kolejnosc_na_wejsciu_nie_ma_znaczenia():
    assert R.pick_version(list(reversed(VERSIONS)), date(2026, 3, 7))["id"] == 1


def test_wersje_wylaczone_sa_pomijane():
    versions = [VERSIONS[0], {**VERSIONS[1], "enabled": False}]
    assert R.pick_version(versions, date(2026, 9, 5))["id"] == 1


# ------------------------------------------------------------------- dzieci

def test_dzieci_to_jedyna_kategoria_z_dojazdem_zbiorczym():
    assert R.is_children_competition("S/DZM/3") is True
    assert R.is_children_competition("S/DZK/1") is True
    assert R.is_children_competition("S/JMM/7") is False
    assert R.is_children_competition("IIM4/12") is False

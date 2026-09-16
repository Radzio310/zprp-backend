"""Zakres listy obsadowego (`app/assignment_scope.py`) - decyzje z 16.09.2026.

Zgloszenie: na liscie „do obsadzenia" wisialy mecze z sezonow sprzed lat
(numery 113xxx), bo mecz bez terminu wpadal do okna bez wzgledu na sezon.
Sezon meczu ma rozstrzygac `ID_sezon` przeliczony na rok - ale NIE odejmowaniem,
bo numery sezonow zwiazku maja dziury.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from app import assignment_scope as S


CATALOG_ROWS = {
    "0": {"ID_sezon": "185", "Rok_rozpoczecia": "2017", "Nazwa": "2017/2018", "Stan": "0"},
    "1": {"ID_sezon": "188", "Rok_rozpoczecia": "2020", "Nazwa": "2020/2021", "Stan": "0"},
    "2": {"ID_sezon": "190", "Rok_rozpoczecia": "2021", "Nazwa": "2021/2022", "Stan": "0"},
    "3": {"ID_sezon": "194", "Rok_rozpoczecia": "2025", "Nazwa": "2025/2026", "Stan": "0"},
    "4": {"ID_sezon": "195", "Rok_rozpoczecia": "2026", "Nazwa": "2026/2027", "Stan": "1"},
}


def test_numer_sezonu_to_nie_rok_plus_stala():
    catalog = S.season_catalog(CATALOG_ROWS)
    # 185 -> 2017, ale 195 -> 2026, nie 2027: 189 nie istnieje.
    assert catalog["185"].start == 2017
    assert catalog["190"].start == 2021
    assert catalog["195"].start == 2026
    assert catalog["195"].label == "2026/2027"
    assert catalog["195"].short == "2026/27"


def test_katalog_ma_zapas_gdy_api_milczy():
    catalog = S.season_catalog(None)
    assert catalog["195"].start == 2026
    assert catalog["185"].start == 2017
    assert not any(season.flagged for season in catalog.values())


def test_katalog_przyjmuje_liste_i_rok_z_nazwy():
    catalog = S.season_catalog([{"ID_sezon": "196", "Nazwa": "2027/2028", "Stan": "1"}, None, "x"])
    assert catalog["196"].start == 2027
    assert catalog["196"].flagged


def test_wiersz_bez_roku_odpada():
    catalog = S.season_catalog([{"ID_sezon": "999", "Nazwa": "cos"}])
    assert "999" not in catalog


def test_biezacy_sezon_wedlug_znacznika_zwiazku():
    catalog = S.season_catalog(CATALOG_ROWS)
    assert S.current_start(catalog, date(2026, 9, 16)) == 2026


def test_zwiazek_otwiera_sezon_przed_sierpniem():
    rows = dict(CATALOG_ROWS)
    rows["4"] = {**rows["4"], "Stan": "0"}
    rows["5"] = {"ID_sezon": "196", "Rok_rozpoczecia": "2027", "Stan": "1"}
    catalog = S.season_catalog(rows)
    # Lipiec 2027 to z kalendarza jeszcze 2026/2027, ale zwiazek juz przestawil.
    assert S.current_start(catalog, date(2027, 7, 10)) == 2027


def test_zapomniany_znacznik_nie_cofa_sezonu():
    catalog = S.season_catalog(CATALOG_ROWS)  # Stan=1 wciaz na 2026
    assert S.current_start(catalog, date(2027, 9, 5)) == 2027


def test_bez_katalogu_decyduje_kalendarz():
    assert S.current_start({}, date(2026, 8, 2)) == 2026
    assert S.current_start({}, date(2026, 7, 30)) == 2025


def test_sezon_dla_roku_bez_wpisu():
    season = S.season_for_start({}, 2031)
    assert season.id == ""
    assert season.label == "2031/2032"


@pytest.mark.parametrize(
    "state,column,match_at,expected",
    [
        # 1. ID_sezon wygrywa ze wszystkim innym
        ({"ID_sezon": "185", "season": "2026/2027"}, "2026/2027", datetime(2026, 9, 20), 2017),
        # 2. etykieta z terminarza
        ({"season": "2025/2026"}, None, None, 2025),
        ({"season": "2025/26"}, None, None, 2025),
        # 3. kolumna migawki
        ({}, "2024/2025", None, 2024),
        # 4. data meczu - granica sierpniowa
        ({}, None, datetime(2026, 8, 29, tzinfo=timezone.utc), 2026),
        ({}, None, datetime(2026, 7, 31, tzinfo=timezone.utc), 2025),
        # nieznany numer sezonu nie zgaduje - idzie dalej
        ({"ID_sezon": "777", "season": "2026/2027"}, None, None, 2026),
        # nic nie wiadomo
        ({"ID_sezon": "777"}, "", None, None),
        ({"season": "sezon"}, None, None, None),
    ],
)
def test_sezon_meczu(state, column, match_at, expected):
    catalog = S.season_catalog(CATALOG_ROWS)
    assert S.match_season_start(state, catalog=catalog, column=column, match_at=match_at) == expected


@pytest.mark.parametrize(
    "code,expected",
    [
        ("IIM4/1", True),
        ("IIK4/12", True),
        ("SM/5", True),
        ("S/JmM/17", False),
        ("S/PPK/2", False),
        ("IIIM/3", False),
        ("", False),
    ],
)
def test_ii_liga(code, expected):
    assert S.is_league(code) is expected


def test_tryb_terminu():
    assert S.normalize_when("dated") == S.WHEN_DATED
    assert S.normalize_when("UNDATED") == S.WHEN_UNDATED
    assert S.normalize_when("cos") == S.WHEN_ALL
    # starszy panel wysylal samo `undated`
    assert S.normalize_when(None, False) == S.WHEN_DATED
    assert S.normalize_when(None, True) == S.WHEN_ALL
    assert S.normalize_when(None, None) == S.WHEN_ALL

    assert S.when_allows(S.WHEN_DATED, True) and not S.when_allows(S.WHEN_DATED, False)
    assert S.when_allows(S.WHEN_UNDATED, False) and not S.when_allows(S.WHEN_UNDATED, True)
    assert S.when_allows(S.WHEN_ALL, True) and S.when_allows(S.WHEN_ALL, False)


def test_kolejka_z_api_i_zakres_z_terminarza():
    info = S.round_info(
        {"Runda": "Runda I", "Kolejka": "Kolejka 3", "kolejka": "03 - 04.10.2026", "kolejka_no": 3}
    )
    assert info == {
        "key": "runda i|kolejka 3",
        "phase": "Runda I",
        "name": "Kolejka 3",
        "no": 3,
        "span": "03 - 04.10.2026",
    }


def test_ta_sama_kolejka_w_innej_rundzie_to_inna_grupa():
    first = S.round_info({"Runda": "Runda I", "Kolejka": "Kolejka 1"})
    second = S.round_info({"Runda": "Runda II", "Kolejka": "Kolejka 1"})
    assert first["key"] != second["key"]


def test_kolejka_tylko_z_terminarza():
    info = S.round_info({"kolejka": "21.09.2026", "kolejka_no": "4"})
    assert info["name"] == "Kolejka 4"
    assert info["no"] == 4
    assert info["span"] == "21.09.2026"


def test_etap_pucharu_bez_numeru():
    info = S.round_info({"Kolejka": "1/2 finału"})
    assert info["name"] == "1/2 finału"
    assert info["no"] is None
    assert info["key"] == "|1/2 finału"


def test_seria_ma_numer():
    assert S.round_info({"Kolejka": "Seria 1"})["no"] == 1


def test_bez_kolejki_pusty_klucz():
    info = S.round_info({})
    assert info["key"] == ""
    assert info["name"] == ""
    assert info["no"] is None

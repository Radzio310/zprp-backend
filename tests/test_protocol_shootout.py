"""Seria rzutów karnych w protokole - każdy rzut i właściwa kolejność.

Dane w pierwszym teście pochodzą z prawdziwego meczu TEST/2 (IdZawody 208136),
w którym sędzia zgłosił, że w wydruku brakuje ostatniego rzutu, a serie po
piątej są poprzestawiane.
"""
from __future__ import annotations

import pytest

from app.protocol_shootout import (
    first_team_of_series,
    recorded_shot_count,
    shootout_rows,
)


def _shots(host, guest):
    return {
        "host": [{"player": p, "result": r} for p, r in host],
        "guest": [{"player": p, "result": r} for p, r in guest],
    }


# Mecz TEST/2: osiem serii, decyduje ostatni rzut gości (6:7).
MATCH_208136 = _shots(
    host=[(3, 1), (23, 1), (2, 1), (1, 1), (17, 0), (3, 1), (2, 1), (23, 0)],
    guest=[(2, 1), (1, 1), (34, 1), (16, 0), (20, 1), (34, 1), (2, 1), (20, 1)],
)


# ───────────────────────── kolejność ─────────────────────────


@pytest.mark.parametrize("series_no", [1, 2, 3, 4, 5])
def test_pierwsze_piec_serii_zaczyna_druzyna_rozpoczynajaca(series_no):
    assert first_team_of_series(series_no, "guest") == "guest"
    assert first_team_of_series(series_no, "host") == "host"


@pytest.mark.parametrize("series_no", [6, 7, 8, 9, 10])
def test_serie_od_szostej_do_dziesiatej_zaczyna_druzyna_przeciwna(series_no):
    # Tu leżał błąd: przełącznik `flip = not flip` odpalał się w KAŻDEJ z tych
    # serii, więc siódma i dziewiąta wracały do pierwotnej kolejności.
    assert first_team_of_series(series_no, "guest") == "host"
    assert first_team_of_series(series_no, "host") == "guest"


@pytest.mark.parametrize("series_no", [11, 12, 15])
def test_kolejny_cykl_wraca_do_druzyny_rozpoczynajacej(series_no):
    assert first_team_of_series(series_no, "guest") == "guest"


# ───────────────────────── kompletność ─────────────────────────


def test_kazdy_oddany_rzut_ma_swoj_wiersz():
    rows = shootout_rows(MATCH_208136, "guest")
    filled = [r for r in rows if r["host"] != "--" or r["guest"] != "--"]
    assert len(filled) == recorded_shot_count(MATCH_208136) == 16


def test_ostatni_rzut_serii_konczy_wydruk_wlasciwym_wynikiem():
    rows = shootout_rows(MATCH_208136, "guest")
    last = rows[-1]
    assert last["series"] == "8"
    assert last["guest"] == "20"
    assert (last["score_host"], last["score_guest"]) == ("6", "7")


def test_wynik_narasta_tylko_po_trafieniu():
    rows = shootout_rows(MATCH_208136, "guest")
    # Seria 4: gość pudłuje (16), gospodarz trafia (1).
    seria4 = [r for r in rows if r["series"] == "4"]
    pudlo = next(r for r in seria4 if r["guest"] == "16")
    assert (pudlo["score_host"], pudlo["score_guest"]) == ("--", "--")
    trafienie = next(r for r in seria4 if r["host"] == "1")
    assert (trafienie["score_host"], trafienie["score_guest"]) == ("4", "3")


def test_szosta_seria_zaczyna_gospodarz_gdy_zaczynali_goscie():
    rows = shootout_rows(MATCH_208136, "guest")
    seria6 = [r for r in rows if r["series"] == "6"]
    assert seria6[0]["host"] == "3"
    assert seria6[1]["guest"] == "34"


def test_siodma_seria_tez_zaczyna_gospodarz():
    # W wydruku sprzed poprawki siódmą serię zaczynali goście.
    rows = shootout_rows(MATCH_208136, "guest")
    seria7 = [r for r in rows if r["series"] == "7"]
    assert seria7[0]["host"] == "2"
    assert seria7[1]["guest"] == "2"


def test_niedokonczona_seria_zostawia_pusta_rubryke_a_nie_znika():
    # Gospodarz spudłował jako drugi, gościom nie kazano już strzelać.
    shots = _shots(host=[(7, 0)], guest=[])
    rows = shootout_rows(shots, "host")
    assert len(rows) == 2
    assert rows[0]["host"] == "7"
    assert rows[1]["host"] == "--" and rows[1]["guest"] == "--"
    assert rows[1]["series"] == "1"


# ───────────────────────── śmieci na wejściu ─────────────────────────


def test_brak_serii_daje_pusty_wydruk():
    assert shootout_rows(None) == []
    assert shootout_rows({}) == []
    assert shootout_rows({"host": [], "guest": []}) == []


def test_uszkodzony_wpis_nie_wywraca_wydruku():
    shots = {"host": ["nie-obiekt", {"player": 5, "result": "1"}], "guest": []}
    rows = shootout_rows(shots, "host")
    assert len(rows) == 4
    assert rows[2]["host"] == "5"
    assert rows[2]["score_host"] == "1"


def test_licznik_oddanych_rzutow_pomija_puste_rundy():
    shots = _shots(host=[(3, 1), (None, None)], guest=[(4, 0)])
    assert recorded_shot_count(shots) == 2

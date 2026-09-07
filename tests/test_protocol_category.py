"""Kratka „ZAWODY" w nagłówku protokołu: rozgrywki, wiek i płeć z numeru meczu.

Trzy rzeczy do upilnowania: najdłuższy kod wygrywa (IIIM to nie IIM, SPK to
nie SK), płeć bez litery w kodzie idzie ze składów z progami 2/3 i 1/3, a
nadpisany napis dostaje rozmiar, przy którym mieści się w polu kratki.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.protocol_category import (
    COMPETITION_TOKENS,
    LEFT_OVERRIDES,
    classify_match_code,
    fit_label,
    gender_from_names,
    header_marks,
    looks_female,
)

# ───────────────────────── rozgrywki ─────────────────────────


@pytest.mark.parametrize(
    "code, competition, gender",
    [
        ("SM/12", "superliga", "M"),
        ("SK/5", "superliga", "K"),
        ("OSM/12", "superliga", "M"),
        ("OSK/12", "superliga", "K"),
        ("LSM/3", "superliga", "M"),
        ("LSK/3", "superliga", "K"),
        ("SPM/1", "superpuchar", "M"),
        ("SPK/1", "superpuchar", "K"),
        ("LCM/7", "liga_centralna", "M"),
        ("LCK/7", "liga_centralna", "K"),
        ("LC/7", "liga_centralna", ""),
        ("IM/20", "i_liga", "M"),
        ("IK/20", "i_liga", "K"),
        ("IMD/3", "i_liga", "M"),
        ("IIM4/1", "ii_liga", "M"),
        ("IIK4/33", "ii_liga", "K"),
        ("IIIM/5", "iii_liga", "M"),
        ("IIIK/5", "iii_liga", "K"),
        ("MPM/2", "mp", "M"),
        ("MPK/2", "mp", "K"),
        ("MP/846", "mp", ""),
        ("PPM/4", "pp", "M"),
        ("PPK/4", "pp", "K"),
        ("PP/846", "pp", ""),
        ("S/PPK/2", "pp", "K"),
        ("JM/9", "junior", "M"),
        ("JK/9", "junior", "K"),
        ("JmM/9", "junior_ml", "M"),
        ("JmK/9", "junior_ml", "K"),
        ("MłM/11", "mlodzik", "M"),
        ("MłK/11", "mlodzik", "K"),
        ("MłM1213/6", "mlodzik_ml", "M"),
        ("MłK1213/6", "mlodzik_ml", "K"),
        ("DzM/1", "dzieci", "M"),
        ("DzK/1", "dzieci", "K"),
    ],
)
def test_kod_rozgrywek_daje_rodzaj_i_plec(code, competition, gender):
    kind = classify_match_code(code)
    assert (kind.competition, kind.gender) == (competition, gender)


@pytest.mark.parametrize("code", ["", None, "   ", "OOM/1", "TEST/2", "ML/251", "S/1", "A&B<C>"])
def test_nierozpoznany_numer_zostawia_pusty_rodzaj(code):
    assert not classify_match_code(code).known


def test_najdluzszy_kod_wygrywa():
    assert classify_match_code("IIIM/5").token == "IIIM"
    assert classify_match_code("IIM4/1").token == "IIM"
    assert classify_match_code("IM/20").token == "IM"
    assert classify_match_code("SPK/1").token == "SPK"
    assert classify_match_code("MłM1213/6").token == "MłM1213"
    assert classify_match_code("MłM/6").token == "MłM"
    assert classify_match_code("PPK/4").token == "PPK"


def test_czlon_z_plcia_wygrywa_z_golym_przedrostkiem():
    # „MP" bywa i Mistrzostwami Polski, i przedrostkiem okręgu w numerze.
    assert classify_match_code("MP/JM/12").competition == "junior"
    assert classify_match_code("MP/846").competition == "mp"


def test_wielkosc_liter_rozroznia_juniora_od_juniora_mlodszego():
    assert classify_match_code("JmK/3").competition == "junior_ml"
    assert classify_match_code("JK/3").competition == "junior"


def test_kazdy_kod_z_katalogu_rozpoznaje_sie_sam():
    for token, (competition, gender) in COMPETITION_TOKENS.items():
        kind = classify_match_code(f"{token}/1")
        assert (kind.token, kind.competition, kind.gender) == (token, competition, gender)


# ───────────────────────── płeć ze składów ─────────────────────────


def test_zprp_pisze_nazwisko_wielkimi_a_imie_zwyklym():
    assert looks_female("KOWALSKA Anna") is True
    assert looks_female("NOWAK Jan") is False
    assert looks_female("Ivana GAKIDOVA") is True
    assert looks_female("BRYZIK Jacek") is False
    # Nazwisko na „a" pisane wielkimi nie jest imieniem.
    assert looks_female("SROKA Adam") is False
    assert looks_female("") is None
    assert looks_female(None) is None


def test_nazwisko_na_ska_rozstrzyga_samo():
    assert looks_female("KOWALSKA Zofia") is True
    assert looks_female("NOWICKA Ewa") is True
    assert looks_female("NOWICKI Adam") is False


def test_reczny_sklad_bez_wielkich_liter():
    assert looks_female("Kowalska Anna") is True
    assert looks_female("Nowak Jan") is False


def test_progi_dwie_trzecie_i_jedna_trzecia():
    women = ["KOWALSKA Anna", "MAJ Zofia", "GAKIDOVA Ivana", "LIS Ewa", "KOT Maria", "SOWA Ola"]
    men = ["NOWAK Jan", "BRYZIK Jacek", "DAJERLING Piotr", "LEWANDOWSKI Marek"]
    assert gender_from_names(women[:6] + men[:2]) == "K"  # 6/8
    assert gender_from_names(women[:2] + men[:4] + men[:2]) == "M"  # 2/8
    assert gender_from_names(women[:4] + men[:4]) == ""  # 4/8 - nic
    assert gender_from_names([]) == ""
    assert gender_from_names(["", None]) == ""


# ───────────────────────── nadpisany napis ─────────────────────────


def test_teksty_odniesienia_mieszcza_sie_w_swoich_polach():
    assert fit_label("PUCHAR POLSKI", "left").size_pt == 5.0
    assert fit_label("SUPERLIGA", "left").size_pt == 6.0
    assert fit_label("JUNIORZY MŁ.", "right").size_pt == 6.0
    assert fit_label("SENIORZY", "right").size_pt == 6.0


def test_liga_centralna_schodzi_do_czterech_i_pol_punktu():
    fitted = fit_label("LIGA CENTRALNA", "left")
    assert (fitted.text, fitted.size_pt, fitted.wrap) == ("LIGA CENTRALNA", 4.5, False)


def test_superpuchar_i_trzecia_liga():
    assert fit_label("SUPERPUCHAR", "left").size_pt == 5.0
    assert fit_label("III LIGA", "left").size_pt == 6.0


def test_mistrzostwa_polski_lamia_sie_na_dwa_wiersze():
    fitted = fit_label("MISTRZOSTWA POLSKI", "left")
    assert fitted.text == "MISTRZOSTWA\nPOLSKI"
    assert fitted.wrap is True
    assert fitted.size_pt == 5.0


def test_mlodzicy_mlodsi_w_prawej_kolumnie():
    fitted = fit_label("MŁODZICY MŁ.", "right")
    assert (fitted.size_pt, fitted.wrap) == (5.5, False)


def test_kazdy_nadpisany_napis_ma_czytelny_rozmiar():
    for text in LEFT_OVERRIDES.values():
        assert fit_label(text, "left").size_pt >= 4.5


# ───────────────────────── kratka ─────────────────────────


def _crosses(marks):
    return set(marks.crosses)


def _labels(marks):
    return [(l.cell, l.text, l.size_pt, l.wrap) for l in marks.labels]


def test_superliga_kobiet():
    marks = header_marks("SK/5")
    assert _crosses(marks) == {"U3", "AG3", "AA7"}
    assert _labels(marks) == []
    assert (marks.gender, marks.gender_source) == ("K", "code")


def test_liga_centralna_bez_litery_czyta_plec_ze_skladow():
    marks = header_marks("LC/7", ["KOWALSKA Anna", "NOWICKA Ewa", "MAJ Zofia"])
    assert _labels(marks) == [("V3", "LIGA CENTRALNA", 4.5, False)]
    assert _crosses(marks) == {"U3", "AG3", "AA7"}
    assert marks.gender_source == "names"


def test_mistrzostwa_polski_bez_wieku_i_bez_zgadywania():
    marks = header_marks("MP/846", ["NOWAK Jan", "KOWALSKA Anna"])
    assert _crosses(marks) == {"U3"}
    assert _labels(marks) == [("V3", "MISTRZOSTWA\nPOLSKI", 5.0, True)]
    assert (marks.age, marks.gender) == ("", "")


def test_puchar_polski_ma_wlasne_pole_i_seniorow():
    marks = header_marks("PP/846", ["NOWAK Jan", "BRYZIK Jacek", "DAJERLING Piotr"])
    assert _crosses(marks) == {"U6", "AG3", "AD7"}
    assert _labels(marks) == []


def test_superpuchar_nadpisuje_superlige():
    marks = header_marks("SPM/1")
    assert _labels(marks) == [("V3", "SUPERPUCHAR", 5.0, False)]
    assert _crosses(marks) == {"U3", "AG3", "AD7"}


def test_trzecia_liga_nadpisuje_superlige():
    marks = header_marks("IIIM/5")
    assert _labels(marks) == [("V3", "III LIGA", 6.0, False)]
    assert _crosses(marks) == {"U3", "AG3", "AD7"}


def test_pierwsza_i_druga_liga_z_grupa():
    assert _crosses(header_marks("IMD/3")) == {"U4", "AG3", "AD7"}
    assert _crosses(header_marks("IIK4/33")) == {"U5", "AG3", "AA7"}


def test_mlodziez_dostaje_tylko_prawa_kolumne():
    assert _crosses(header_marks("JM/9")) == {"AG4", "AD7"}
    assert _crosses(header_marks("JmK/9")) == {"AG5", "AA7"}
    assert _crosses(header_marks("MłK/2")) == {"AG6", "AA7"}
    assert _crosses(header_marks("DzM/1")) == {"AG7", "AD7"}
    for code in ("JM/9", "JmK/9", "MłK/2", "DzM/1"):
        assert _labels(header_marks(code)) == []


def test_mlodzik_mlodszy_nadpisuje_mlodzikow():
    marks = header_marks("MłK1213/6")
    assert _labels(marks) == [("AH6", "MŁODZICY MŁ.", 5.5, False)]
    assert _crosses(marks) == {"AG6", "AA7"}


def test_nieznany_numer_nie_rusza_kratki():
    assert header_marks("OOM/1", ["KOWALSKA Anna"]).empty
    assert header_marks("", ["KOWALSKA Anna"]).empty
    assert header_marks(None).empty


def test_modul_bez_dlugich_myslnikow():
    src = (Path(__file__).resolve().parents[1] / "app" / "protocol_category.py").read_text(
        encoding="utf-8"
    )
    assert chr(0x2013) not in src and chr(0x2014) not in src

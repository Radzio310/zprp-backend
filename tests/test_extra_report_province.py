"""Adresat dodatkowego raportu per OKRĘG.

CZEGO BRAKOWAŁO. Adresaci byli przypisani wyłącznie do kategorii rozgrywek.
Dla Superligi to wystarcza - jest jedna w kraju. Dla rozgrywek od II ligi w
dół nie wystarcza wcale: prowadzą je związki wojewódzkie, więc „II liga
mężczyzn" to osiem różnych skrzynek, a liga juniorów szesnaście. Raport z
meczu młodzieżowego w Katowicach jechał tam, gdzie ktoś wpisał pierwszy adres.

Bez sieci i bez bazy: reguła zakresu i odczyt okręgu z odpowiedzi API to czysta
decyzja, a właśnie ona rozstrzyga, do kogo pójdzie raport.
"""
from __future__ import annotations

import pytest

from app.extra_report_scope import (
    PROVINCE_SCOPED_CATEGORIES,
    fetch_match_province,
    is_province_scoped,
    province_from_match,
)


# ───────────────────────── zakres kategorii ─────────────────────────

def test_druga_i_trzecia_liga_pytaja_okreg():
    for cat in ("IIM", "IIK", "IIIM", "IIIK"):
        assert is_province_scoped(cat), cat


def test_mlodziez_pyta_okreg():
    for cat in ("JM", "JK", "JmM", "JmK", "MłM", "MłK", "MłM1213", "MłK1213"):
        assert is_province_scoped(cat), cat


def test_rozgrywki_centralne_nie_pytaja_okregu():
    """I liga i wyżej prowadzi ZPRP - jedna skrzynka na kategorię jest tam prawdą."""
    for cat in ("IM", "IK", "LCM", "LCK", "OSM", "OSK", "SM", "SK", "SPM", "SPK"):
        assert not is_province_scoped(cat), cat


def test_puchar_i_mistrzostwa_zostaja_centralne():
    for cat in ("MP", "PP"):
        assert not is_province_scoped(cat)


def test_porownanie_jest_dokladne_a_nie_po_prefiksie():
    """„IIM" i „IIIM" różnią się jedną literą - dopasowanie po prefiksie myliło je."""
    assert not is_province_scoped("II")
    assert not is_province_scoped("IIM4")
    assert not is_province_scoped("IIM/22")


def test_smieci_nie_wchodza_w_zakres():
    for value in ("", None, "  ", "Pozostałe"):
        assert not is_province_scoped(value)


def test_zakres_jest_domkniety():
    """Gdyby ktoś dołożył kategorię, ten test przypomni o stronie klienta."""
    assert len(PROVINCE_SCOPED_CATEGORIES) == 12


# ───────────────────── okręg z odpowiedzi API ─────────────────────

def test_okreg_czytamy_z_nazwy_wzpr():
    """Sprawdzone na żywym API: mecz IIM4/1 wraca z NazwaWZPR = ŚLĄSKIE."""
    match = {
        "Id": "191335",
        "RozgrywkiCode": "IIM4/1",
        "Nazwa": "II Liga Mężczyzn gr. 4",
        "NrWZPR": "12",
        "NazwaWZPR": "ŚLĄSKIE",
    }
    assert province_from_match(match) == "SLASKIE"


def test_ogonki_i_myslniki_schodza_do_sluga():
    assert province_from_match({"NazwaWZPR": "KUJAWSKO-POMORSKIE"}) == "KUJAWSKO_POMORSKIE"
    assert province_from_match({"NazwaWZPR": "WARMIŃSKO-MAZURSKIE"}) == "WARMINSKO_MAZURSKIE"
    assert province_from_match({"NazwaWZPR": "ŁÓDZKIE"}) == "LODZKIE"


def test_wojewodztwo_klubu_nie_jest_okregiem_prowadzacym():
    """Klub z Opola gra w grupie prowadzonej przez inny związek.

    Pole `ID_zespoly_gosp_ZespolNrWoj` odpowiada na inne pytanie i nie ma prawa
    tu wejść - dlatego czytamy WYŁĄCZNIE `NazwaWZPR`.
    """
    match = {"NazwaWZPR": "WIELKOPOLSKIE", "ID_zespoly_gosp_ZespolNrWoj": "8"}
    assert province_from_match(match) == "WIELKOPOLSKIE"


def test_brak_wiedzy_to_pusty_napis():
    for value in (None, {}, {"NazwaWZPR": ""}, {"NazwaWZPR": "NIE MA TAKIEGO"}, "nie dict"):
        assert province_from_match(value) == ""  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_nie_pytamy_api_o_identyfikator_ktory_nie_jest_liczba():
    """`IdZawody` jest liczbą. Wszystko inne to numer meczu albo śmieć."""
    for value in ("", None, "IIM4/22", "abc"):
        assert await fetch_match_province(value) == ""


@pytest.mark.asyncio
async def test_awaria_zprp_nie_wywraca_odczytu(monkeypatch):
    """Adresaci to wygoda przy wysyłce, nie warunek jej istnienia.

    Sędzia, któremu ZPRP akurat nie odpowiada, ma dostać listę z samych
    kategorii i móc wysłać raport - zamiast oglądać błąd.
    """

    class _Boom:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

        async def get(self, *_a, **_k):
            raise RuntimeError("ZPRP nie odpowiada")

    monkeypatch.setattr("app.extra_report_scope.AsyncClient", lambda **_k: _Boom())
    assert await fetch_match_province("191335") == ""


def test_l_z_kreska_nie_jest_znakiem_diakrytycznym():
    """ŁÓDZKIE i MAŁOPOLSKIE - dwa okręgi, które przepadały po cichu.

    `Ł` to osobny znak Unicode, a nie `L` z ogonkiem: NFD go nie rozkłada, więc
    filtr znaków diakrytycznych zostawiał je nietknięte, a następny krok zamieniał
    na podkreślenie. `normalize_province` zwracała pusty napis, czyli „to nie jest
    województwo" - i adresaci obu okręgów nigdy by się nie znaleźli.

    Publiczne API rozgrywek podaje właśnie te nazwy (sprawdzone na sezonie
    2025/2026), więc to nie jest przypadek teoretyczny.
    """
    assert province_from_match({"NazwaWZPR": "ŁÓDZKIE"}) == "LODZKIE"
    assert province_from_match({"NazwaWZPR": "MAŁOPOLSKIE"}) == "MALOPOLSKIE"


def test_departament_zprp_nie_jest_okregiem():
    """Rozgrywki centralne wracają z „DEPARTAMENT ROZGRYWEK KRAJOWYCH".

    To nie jest województwo i ma stąd wyjść pusto - inaczej raport z Superligi
    szukałby adresata okręgowego.
    """
    assert province_from_match({"NazwaWZPR": "DEPARTAMENT ROZGRYWEK KRAJOWYCH"}) == ""

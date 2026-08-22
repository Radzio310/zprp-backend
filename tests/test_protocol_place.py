"""Miejscowość w nagłówku strony uwag sędziów.

W protokole meczu 208136 stało „20.08.2026, MOSiR Pszelnik" - czyli nazwa hali
zamiast miasta. Adres brzmiał „Hala MOSiR Pszelnik, Siemianowice Śląskie",
a stara reguła znała tylko układ odwrotny, z miastem w nazwie hali.
"""
from __future__ import annotations

from app.results import (
    _extract_city_from_venue_address,
    _get_match_core,
    _looks_like_street,
    _notes_place,
)


def test_miasto_przechodzi_z_paczki_aplikacji_do_naglowka():
    """Cała droga: `matchConfig.venueCity` -> rdzeń meczu -> nagłówek strony.

    Seam wart testu, bo literówka w nazwie klucza nie da żadnego objawu poza
    cichym powrotem do zgadywania z adresu.
    """
    data = {
        "matchConfig": {
            "matchNumber": "OSK/12",
            "venueAddress": "Hala MOSiR Pszelnik, Siemianowice Śląskie",
            "venueCity": "Siemianowice Śląskie",
        }
    }
    assert _notes_place(_get_match_core(data)) == "Siemianowice Śląskie"


def test_zapis_sprzed_zmiany_tez_drukuje_miasto():
    # Protokoły zapisane starszą wersją aplikacji nie mają `venueCity` - i mają
    # się drukować poprawnie bez ponownego wczytywania meczu.
    data = {
        "matchConfig": {
            "matchNumber": "OSK/12",
            "venueAddress": "Hala MOSiR Pszelnik, Siemianowice Śląskie",
        }
    }
    assert _notes_place(_get_match_core(data)) == "Siemianowice Śląskie"


# ───────────────────────── wprost z ZPRP ─────────────────────────


def test_hala_miasto_wygrywa_z_adresem():
    core = {
        "venueCity": "Siemianowice Śląskie",
        "venueAddress": "Hala MOSiR Pszelnik, Siemianowice Śląskie",
    }
    assert _notes_place(core) == "Siemianowice Śląskie"


def test_hala_miasto_wygrywa_takze_z_myslacym_adresem():
    # Adres wpisany ręcznie bywa czymkolwiek; pole z bazy związku nie.
    core = {"venueCity": "Mysłowice", "venueAddress": "przy szkole, wjazd od tyłu"}
    assert _notes_place(core) == "Mysłowice"


def test_puste_hala_miasto_spada_na_adres():
    core = {"venueCity": "  ", "venueAddress": "Hala Miejska, Gliwice"}
    assert _notes_place(core) == "Gliwice"


def test_brak_obu_zrodel_daje_pustke():
    assert _notes_place({}) == ""


# ───────────────────────── odczyt z adresu ─────────────────────────


def test_miasto_na_koncu_adresu_skladanego_przez_aplikacje():
    # Tak sklejamy adres z pól Hala_*: nazwa, ulica z numerem, miasto.
    assert (
        _extract_city_from_venue_address("Hala MOSiR Pszelnik, Siemianowice Śląskie")
        == "Siemianowice Śląskie"
    )
    assert (
        _extract_city_from_venue_address("Hala Sportowa, Kwiatowa 5, Wrocław")
        == "Wrocław"
    )


def test_miasto_w_nazwie_hali_gdy_na_koncu_stoi_ulica():
    # Adres z tytułu linku do mapy - miasto siedzi w nazwie hali.
    assert (
        _extract_city_from_venue_address(
            "Hala Relax Piotrków Trybunalski, Stefana Batorego 8"
        )
        == "Piotrków Trybunalski"
    )


def test_ulica_z_przedrostkiem_bez_numeru_tez_nie_jest_miastem():
    assert (
        _extract_city_from_venue_address("Hala Miejska Zabrze, ul. Sportowa")
        == "Miejska Zabrze"
    )


def test_pusty_adres_nie_wywraca_odczytu():
    assert _extract_city_from_venue_address("") == ""
    assert _extract_city_from_venue_address(None) == ""
    assert _extract_city_from_venue_address(" , , ") == ""


def test_rozpoznanie_ulicy():
    assert _looks_like_street("Stefana Batorego 8")
    assert _looks_like_street("ul. Sportowa")
    assert _looks_like_street("al. Jana Pawła II")
    assert not _looks_like_street("Siemianowice Śląskie")
    assert not _looks_like_street("Wrocław")

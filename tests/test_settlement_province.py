from app.settlement_province import DISPLAY, canonical, display, spellings


def test_klucz_naszych_tabel_to_klucz_kont_railway():
    # Z tym kluczem laczy sie petla dobowa (`configured_provinces`) i
    # `province_matches`, wiec nasze tabele musza mowic tym samym jezykiem.
    assert canonical("ŚLĄSKIE") == "SLASKIE"
    assert canonical("slaskie") == "SLASKIE"
    assert canonical("Kujawsko-Pomorskie") == "KUJAWSKO_POMORSKIE"
    # „L" nie rozklada sie przez NFD - bez osobnej podmiany Lodzkie ginelo.
    assert canonical("ŁÓDZKIE") == "LODZKIE"
    assert canonical("MAŁOPOLSKIE") == "MALOPOLSKIE"


def test_nieznane_wojewodztwo_to_pusty_klucz():
    assert canonical("MARS") == ""
    assert canonical("") == ""


def test_nazwa_dla_czlowieka():
    assert display("SLASKIE") == "ŚLĄSKIE"
    assert display("kujawsko_pomorskie") == "KUJAWSKO-POMORSKIE"
    assert display("ŁÓDZKIE") == "ŁÓDZKIE"


def test_pisownie_obejmuja_wszystkie_formy_z_bazy():
    forms = spellings("SLASKIE")
    # aplikacja / okreg_rates / province_judges
    assert "ŚLĄSKIE" in forms
    # province_matches / konta Railway
    assert "SLASKIE" in forms

    forms = spellings("ŚLĄSKIE")
    assert "SLASKIE" in forms and "ŚLĄSKIE" in forms

    forms = spellings("KUJAWSKO-POMORSKIE")
    assert {"KUJAWSKO-POMORSKIE", "KUJAWSKO_POMORSKIE", "KUJAWSKOPOMORSKIE"} <= set(forms)


def test_kazde_wojewodztwo_wraca_do_siebie():
    for key, name in DISPLAY.items():
        assert canonical(name) == key
        assert display(key) == name
        assert name in spellings(key)
        assert key in spellings(name)


def test_nieznana_nazwa_jest_pytana_wprost():
    assert spellings("marsjanskie") == ["MARSJANSKIE"]
    assert spellings("") == []

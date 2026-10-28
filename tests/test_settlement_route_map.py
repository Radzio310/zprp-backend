from app import national_place_rules as P
from app import settlement_route_map_rules as RM


def gaz():
    return P.Gazetteer([
        (P.Place("1", "Lipnik", 50.774, 19.432, "slaskie", 100), []),
        (P.Place("2", "Lipnik", 50.730, 21.494, "swietokrzyskie", 400), []),
        (P.Place("3", "Gliwice", 50.294, 18.666, "slaskie", 180000), []),
    ])


def test_dom_wybierany_po_wojewodztwie_okregu():
    point = RM.place_point(gaz(), "Lipnik", "slaskie")
    assert point["province"] == "slaskie"
    assert point["ambiguous"] is True


def test_mapa_trasy_i_brak_wspolrzednych():
    rows = [
        {"home_city": "Lipnik", "city": "Gliwice"},
        {"home_city": "Lipnik", "city": "Nieznanowo"},
    ]
    out = RM.build_route_map(rows, gaz(), "slaskie")
    assert out["home_city"] == "Lipnik"
    assert out["home"]["province"] == "slaskie"
    assert out["points"]["Gliwice"]["lat"] > 50
    assert out["points"]["Nieznanowo"] is None


def test_locator_daje_srodki_miejscowosci_z_imiennikiem_po_wojewodztwie():
    home, dest = RM.locator(gaz(), "slaskie")("Lipnik", "Gliwice")
    assert abs(home[0] - 50.774) < 0.01 and abs(home[1] - 19.432) < 0.01
    assert abs(dest[0] - 50.294) < 0.01


def test_wieloznaczna_hala_bez_punktu_i_dokladna_nazwa_bije_zblizona():
    g = P.Gazetteer([
        (P.Place("1", "Grodków", 50.698, 17.384, "opolskie", 8654), []),
        (P.Place("2", "Gródków", 50.36, 19.11, "slaskie", 0), []),
        (P.Place("3", "Dąbrowa", 52.75, 17.94, "kujawsko-pomorskie", 0), []),
        (P.Place("4", "Dąbrowa", 50.68, 17.75, "opolskie", 0), []),
    ])
    assert RM.unique_point(g, "Grodków") == (50.698, 17.384)
    assert RM.unique_point(g, "Dąbrowa") is None


def _naklo_gaz():
    return P.Gazetteer([
        (P.Place("1", "Nakło", 50.4369, 18.9106, "slaskie", 3824), []),
        (P.Place("2", "Nakło", 50.656, 19.726, "slaskie", 614), []),
        (P.Place("3", "Piekary Śląskie", 50.38, 18.95, "slaskie", 55000), []),
    ])


def test_nakło_śląskie_dostaje_punkt_a_nie_imiennika():
    # Pełnej nazwy nie ma w skorowidzu; goły tekst do Google trafiał w Nakło spod Lelowa.
    point = RM.unique_point(_naklo_gaz(), "Nakło Śląskie", "śląskie")
    assert point == (50.4369, 18.9106)
    origin, dest = RM.locator(_naklo_gaz(), "śląskie")("Nakło Śląskie", "Piekary Śląskie")
    assert origin == (50.4369, 18.9106)
    assert dest is not None


def test_przymiotnik_bez_przewagi_ludnosci_nie_zgaduje():
    g = P.Gazetteer([
        (P.Place("1", "Nakło", 50.4, 18.9, "slaskie", 1000), []),
        (P.Place("2", "Nakło", 50.6, 19.7, "slaskie", 900), []),
    ])
    assert RM.unique_point(g, "Nakło Śląskie", "śląskie") is None

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

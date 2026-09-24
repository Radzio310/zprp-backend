"""
Pary z listy „Sędziowie i Delegaci" baza.zprp.pl zamienione na numery sędziów
okręgu (`app/assignment_pairs.py`).
"""

from app.assignment_pairs import pair_rows_diff, zprp_pairs

JUDGES = [
    ("101", "KASZNIA Wojciech"),
    ("102", "Jędrycha Artur"),
    ("103", "Łuszczykiewicz Maksymilian"),
    ("104", "Nowak Jan"),
    ("105", "NOWAK Jan"),
    ("106", "Zubek Marcin"),
    ("107", "Zubek Artur"),
]


def test_partner_po_nazwisku_w_dowolnej_kolejnosci_i_bez_ogonkow():
    officials = {
        "101": {"name": "KASZNIA Wojciech", "partner": "JEDRYCHA Artur"},
        "102": {"name": "JĘDRYCHA Artur", "partner": "KASZNIA Wojciech"},
    }
    assert zprp_pairs(officials, JUDGES) == {"101": "102", "102": "101"}


def test_jednostronny_wpis_wystarcza():
    officials = {"106": {"name": "ZUBEK Marcin", "partner": "Artur Zubek"}}
    assert zprp_pairs(officials, JUDGES) == {"106": "107", "107": "106"}


def test_l_z_kreska_pasuje():
    officials = {"103": {"name": "ŁUSZCZYKIEWICZ Maksymilian", "partner": "KASZNIA Wojciech"}}
    assert zprp_pairs(officials, JUDGES) == {"103": "101", "101": "103"}


def test_niejednoznaczne_nazwisko_nie_zgadujemy():
    # Dwóch „Nowak Jan" w okręgu - para przepada zamiast trafić w złego.
    officials = {"101": {"name": "KASZNIA Wojciech", "partner": "NOWAK Jan"}}
    assert zprp_pairs(officials, JUDGES) == {}


def test_niespojne_pary_przepadaja():
    officials = {
        "101": {"name": "KASZNIA Wojciech", "partner": "JĘDRYCHA Artur"},
        "102": {"name": "JĘDRYCHA Artur", "partner": "ZUBEK Marcin"},
        "106": {"name": "ZUBEK Marcin", "partner": "ZUBEK Artur"},
    }
    # 102 jest w dwóch parach, 106 też - zostaje tylko nic.
    assert zprp_pairs(officials, JUDGES) == {}


def test_obcy_numer_rozpoznany_po_nazwisku():
    officials = {"9999": {"name": "Kasznia Wojciech", "partner": "JĘDRYCHA Artur"}}
    assert zprp_pairs(officials, JUDGES) == {"101": "102", "102": "101"}


def test_partner_spoza_okregu_nie_wchodzi():
    officials = {"101": {"name": "KASZNIA Wojciech", "partner": "OBCY Ktoś"}}
    assert zprp_pairs(officials, JUDGES) == {}


def test_brak_partnera_to_brak_pary():
    officials = {"101": {"name": "KASZNIA Wojciech", "partner": ""}, "102": {}}
    assert zprp_pairs(officials, JUDGES) == {}


def test_roznica_wierszy():
    existing = [("101", "102"), ("102", "101"), ("106", "107"), ("107", "106")]
    wanted = {"101": "102", "102": "101", "103": "104", "104": "103"}
    add, drop = pair_rows_diff(existing, wanted)
    assert add == [("103", "104"), ("104", "103")]
    assert drop == [("106", "107"), ("107", "106")]


def test_bez_zmian_nic_do_zrobienia():
    wanted = {"101": "102", "102": "101"}
    assert pair_rows_diff(list(wanted.items()), wanted) == ([], [])

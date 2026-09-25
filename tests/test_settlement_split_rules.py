"""
Podział puli sędziego na listy sędziowskie - reguła bez bazy.

Pieniądze, więc każdy przypadek liczony ręcznie obok: koszty 20% tylko na
liście powyżej 200 zł, podatek 12%, zaokrąglenia do złotówki jak
`settlement_rates._tax_parts`.
"""

from app import settlement_split_rules as S


def _m(key, gross, travel=0.0, code="S/JMM/1", day="2026-09-05"):
    return {"match_key": key, "gross": gross, "travel": travel, "code": code, "day": day}


POOL = [_m("m1", 400.0, 30.0), _m("m2", 350.0, 20.0), _m("m3", 250.0)]


def _lists(*groups, shifts=None):
    shifts = shifts or [0] * len(groups)
    return S.normalize_lists(
        [{"match_keys": list(g), "manual_shift": s} for g, s in zip(groups, shifts)]
    )


def test_trzy_listy_powyzej_progu_daja_to_samo_netto():
    calc = S.compute(_lists(["m1"], ["m2"], ["m3"]), POOL)
    a, b, c = calc["lists"]
    assert (a["gross"], a["costs"], a["taxable"], a["tax"], a["net"]) == (400.0, 80, 320, 38, 362.0)
    assert (b["gross"], b["costs"], b["taxable"], b["tax"], b["net"]) == (350.0, 70, 280, 34, 316.0)
    assert (c["gross"], c["costs"], c["taxable"], c["tax"], c["net"]) == (250.0, 50, 200, 24, 226.0)
    assert calc["unsplit"]["net"] == 904.0 and calc["unsplit"]["tax"] == 96
    assert calc["split"]["net"] == 904.0
    assert calc["difference"]["net"] == 0.0
    assert calc["remainder"] == 0.0
    # Dojazd zostaje przy meczu i nie wchodzi do podatku.
    assert (a["travel"], b["travel"], c["travel"]) == (30.0, 20.0, 0.0)
    assert a["total"] == 392.0


def test_lista_do_200_zl_traci_koszty_uzyskania():
    # m1+m2 = 750, przesuwamy 600 na B: A=150, B=250+600=850
    lists = _lists(["m1", "m2"], ["m3"], shifts=[-600, 600])
    calc = S.compute(lists, POOL)
    a, b = calc["lists"]
    assert a["gross"] == 150.0 and a["costs"] == 0 and a["tax"] == 18 and a["net"] == 132.0
    assert b["gross"] == 850.0 and b["costs"] == 170 and b["taxable"] == 680 and b["tax"] == 82
    assert calc["split"]["net"] == 132.0 + 768.0
    assert calc["difference"]["net"] == -4.0
    assert S.problems(lists, POOL, for_issue=True) == []


def test_grosze_i_suma_co_do_grosza():
    pool = [_m("x", 252.5), _m("y", 100.25)]
    lists = _lists(["x"], ["y"], shifts=[-0.25, 0.25])
    calc = S.compute(lists, pool)
    assert calc["lists"][0]["gross"] == 252.25
    assert calc["lists"][1]["gross"] == 100.5
    assert calc["remainder"] == 0.0
    # 0,2 x 252,25 = 50,45 -> 50 zł; podstawa 202,25 -> 202; podatek 24,24 -> 24.
    assert calc["lists"][0]["costs"] == 50 and calc["lists"][0]["taxable"] == 202
    assert calc["lists"][0]["net"] == 228.25


def test_niezbilansowane_przesuniecie_to_problem():
    lists = _lists(["m1"], ["m2", "m3"], shifts=[-50, 40])
    out = S.problems(lists, POOL)
    assert any("Rozdzielono 990,00 zł z 1 000,00 zł" in p and "10,00 zł" in p for p in out)


def test_mecz_na_dwoch_listach_i_brakujacy():
    lists = _lists(["m1", "m2"], ["m2"])
    out = S.problems(lists, POOL)
    assert any("jest na liście A i B" in p for p in out)
    assert any("na żadnej liście" in p for p in out)


def test_obcy_mecz_i_ujemna_lista():
    lists = _lists(["m1", "obcy"], ["m2", "m3"], shifts=[-500, 500])
    out = S.problems(lists, POOL)
    assert any("obcy" in p and "nie należy" in p for p in out)
    assert any("Lista A wychodzi na minus" in p for p in out)


def test_wydanie_wymaga_dwoch_niepustych_list():
    assert any("co najmniej dwie" in p for p in S.problems(_lists(["m1", "m2", "m3"]), POOL, for_issue=True))
    empty = _lists(["m1", "m2", "m3"], [])
    assert any("Lista B jest pusta" in p for p in S.problems(empty, POOL, for_issue=True))
    # Szkic może mieć pustą listę - to dopiero praca w toku.
    assert S.problems(empty, POOL) == []


def test_litery_nadawane_po_kolei_i_limit():
    lists = S.normalize_lists([{"letter": "C", "match_keys": ["a", "a"]}, {"letter": "Z"}])
    assert [l["letter"] for l in lists] == ["A", "B"]
    assert lists[0]["match_keys"] == ["a"]
    many = S.normalize_lists([{"match_keys": []}] * 9)
    assert any("Najwięcej 8 list" in p for p in S.problems(many, POOL))


def test_reconcile_nowy_mecz_na_a_a_zniknietego_zdejmuje():
    stored = [{"match_keys": ["m1", "stary"]}, {"match_keys": ["m2"]}]
    lists, notes = S.reconcile(stored, ["m1", "m2", "m3"])
    assert lists[0]["match_keys"] == ["m1", "m3"]
    assert lists[1]["match_keys"] == ["m2"]
    assert any("stary" in n for n in notes) and any("nowy mecz" in n for n in notes)


def test_issued_state_aktualne_i_nieaktualne():
    lists = _lists(["m1"], ["m2", "m3"])
    snapshot = S.compute(lists, POOL)["lists"]
    assert S.issued_state(snapshot, lists, POOL)["current"] is True
    # Doszedł mecz spoza list.
    grown = POOL + [_m("m4", 120.0)]
    state = S.issued_state(snapshot, lists, grown)
    assert state["current"] is False and any("spoza list" in r for r in state["reasons"])
    # Zmieniła się stawka meczu - brutto listy inne niż w dniu wydania.
    cheaper = [_m("m1", 380.0, 30.0), POOL[1], POOL[2]]
    state = S.issued_state(snapshot, lists, cheaper)
    assert state["current"] is False and any("zmieniło się od wydania" in r for r in state["reasons"])


def test_applied_values_to_suma_list():
    calc = S.compute(_lists(["m1", "m2"], ["m3"], shifts=[-600, 600]), POOL)
    values = S.applied_values(calc)
    assert values == {
        "costs": 170,
        "taxable": 830,
        "tax": 100,
        "net": 900.0,
        "total": 950.0,
    }


def test_numbers_label():
    assert S.numbers_label(["SL/09/2026/4", "SL/09/2026/5", "SL/09/2026/6"]) == "SL/09/2026/4-6"
    assert S.numbers_label(["SL/09/2026/4"]) == "SL/09/2026/4"
    assert S.numbers_label(["SL/09/2026/4", "SL/09/2026/7"]) == "SL/09/2026/4, SL/09/2026/7"
    assert S.numbers_label([]) == ""


def test_default_lists():
    lists = S.default_lists(["a", "b"], 3)
    assert [l["letter"] for l in lists] == ["A", "B", "C"]
    assert lists[0]["match_keys"] == ["a", "b"] and lists[1]["match_keys"] == []

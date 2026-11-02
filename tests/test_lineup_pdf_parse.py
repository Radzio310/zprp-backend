"""Parser PDF-a protokołu ZPRP (02.11.2026) na SYNTETYCZNYM pliku ze zmyślonymi danymi (nigdy na prawdziwych nazwiskach)."""

import pytest

from app import lineup_pdf_parse as P
from app import lineup_read_rules as R
from tests import lineup_support as S


def parse(**kw):
    return P.parse_pdf(S.build_protocol(**kw))


def test_naglowek_i_idzawody():
    out = parse()
    h = out["header"]
    assert out["source"] == "pdf_text" and out["ok"] is True
    assert h["zprp_match_id"] == "123456"
    assert h["match_number"] == "JmK/7"  # wielkość liter jak wydrukowano
    assert (h["home_name"], h["away_name"]) == (S.HOME, S.AWAY)
    assert (h["date"], h["time"]) == ("2026-10-31", "18:00")
    assert h["hall"] == "Hala Łąkowa" and h["address"] == "Źródlana 5, 41-100 Łąkowo"


def test_idzawody_tylko_gdy_cyfry():
    assert parse(zprp_id=None)["header"]["zprp_match_id"] is None
    assert R.clean_zprp_id("IMD/54") is None and R.clean_zprp_id("207457") == "207457"


def test_zawodnicy_numery_i_polskie_znaki():
    out = parse()
    players = out["home"]["players"]
    assert [p["number"] for p in players] == [2, 3, 7, 9, 10, 12, 15, 91]
    names = [p["name"] for p in players]
    assert "ŻÓŁTEK Błażej" in names and "ŁOBODA Łukasz" in names and "ŚWIT Ćwik" in names
    assert "KOWALEWSKI-NOWAK Zdzisław" in names  # nazwisko z łącznikiem
    assert "VAN DER BERG Jan" in names  # nazwisko wieloczłonowe
    ziom = next(p for p in players if p["name"].startswith("VAN"))
    assert ziom["surname"] == "VAN DER BERG" and ziom["given"] == "Jan"
    assert all(p["confidence"] >= 0.9 and p["source"] == "pdf_text" for p in players)
    assert [p["number"] for p in out["away"]["players"]] == [1, 4, 5, 11, 25, 36]


def test_kolejnosc_a_b_wiazana_naglowkiem_a_nie_pozycja():
    out = parse(swap=True)  # tabela B stoi nad tabelą A
    assert out["home"]["name"] == S.HOME and out["away"]["name"] == S.AWAY
    assert [p["number"] for p in out["home"]["players"]] == [2, 3, 7, 9, 10, 12, 15, 91]
    assert [p["number"] for p in out["away"]["players"]] == [1, 4, 5, 11, 25, 36]
    assert [s["name"] for s in out["home"]["staff"]] == ["TESTOWSKI Tomasz", "PRÓBNY Piotr"]


def test_osoby_zlepione_litery_licencje_i_funkcje():
    out = parse()
    home = out["home"]["staff"]
    assert [s["slot"] for s in home] == ["A", "B"]
    assert home[0]["name"] == "TESTOWSKI Tomasz" and home[0]["surname"] == "TESTOWSKI"  # litera slotu nie jest częścią nazwiska
    assert home[0]["function"] == "TRENER B"
    assert (home[0]["license"], home[0]["license_category"], home[0]["license_number"]) == ("B 0544/2026", "B", "0544/2026")
    assert (home[1]["license"], home[1]["license_category"], home[1]["license_number"]) == ("0404/18", None, "0404/18")
    assert home[1]["function"] == "OSOBA TOWARZYSZĄCA"
    away = out["away"]["staff"]
    assert [s["slot"] for s in away] == list("ABCDE")
    assert [s["license"] for s in away] == ["A 0001/2025", "0123/19", "0456/2027", "0789/20", "0999/17"]
    # Ostatnia kolumna sąsiaduje z tabelą czasu (dwukropki) - nie może jej niczego dopisać.
    assert away[4]["function"] == "OSOBA TOWARZYSZĄCA" and ":" not in away[4]["name"]


def test_puste_miejsca_i_powtarzane_etykiety_nie_sa_osobami():
    out = parse(home_staff=[], away_staff=[("C", "WĄS Bartosz", "OSOBA TOWARZYSZĄCA", "0456/2027")])
    assert out["home"]["staff"] == []
    assert [s["slot"] for s in out["away"]["staff"]] == ["C"]
    flat = str(out)
    assert "numer licencji" not in flat and "Nazwisko, imię" not in flat


def test_puste_tabele_czasu_i_tabela_czasu_nie_wchodzi_do_skladu():
    for empty in (True, False):
        out = parse(empty_time_table=empty)
        assert len(out["home"]["players"]) == 8 and len(out["away"]["players"]) == 6
        assert all(":" not in (p["name"] or "") for p in out["home"]["players"])


def test_krotki_x_dla_rozgrywek_plci_i_kategorii():
    marks = parse()["header"]["competition"]
    assert marks == {"stage": ["I LIGA", "ELIMINACJE"], "sex": "M", "age": ["SENIORZY"]}


def test_ptaszki_obrazek_rysunek_i_brak_znacznikow():
    out = parse(tick_mode="image")
    assert out["checks_detectable"] is True
    assert all(p["checked"] is True for p in out["home"]["players"] + out["away"]["players"])
    out = parse(tick_mode="drawing")
    assert out["checks_detectable"] is True and all(p["checked"] is True for p in out["home"]["players"])
    # Szablon bez żadnych znaczników: NIE twierdzimy, że nikt nie ma ptaszka - null i jasna informacja.
    out = parse(tick_mode="none")
    assert out["checks_detectable"] is None
    assert all(p["checked"] is None for p in out["home"]["players"] + out["away"]["players"])


def test_ptaszki_zielony_czerwony_i_brak_w_wierszu():
    out = parse(tick_mode="mixed")
    checked = [p["checked"] for p in out["home"]["players"]]
    assert checked[0] is True and checked[1] is False and checked[2] is False  # wiersz bez znaku, gdy znaki są na stronie
    assert out["checks_detectable"] is True


def test_sedziowie_i_stolik_jako_podpowiedz():
    out = parse()
    roles = {o["role"]: o["name"] for o in out["officials"]}
    assert roles == {"sedzia1": "SĘDZIOWSKI Sebastian", "sedzia2": "ARBITER Ala", "czas": "CZASOWY Cezary", "sekretarz": "STOLIK Sylwia"}
    assert "delegat" not in roles  # kreski = brak
    assert "Omiejscowość" not in str(out)


def test_duplikat_numeru_ostrzega_zgodnie_z_modelem_clashed_number():
    out = parse(home_players=[(7, "ADAMSKI Adam"), (7, "BRZOZA Bartek"), (9, "CZAJA Czesław")])
    players = out["home"]["players"]
    assert players[0]["number"] == 7 and players[1]["number"] is None and players[1]["clashed_number"] == 7
    assert {"code": "DUPLICATE_NUMBER", "team": "home", "number": 7, "rows": [0, 1]} in out["warnings"]


def test_to_nie_protokol():
    with pytest.raises(R.LineupError) as exc:
        P.parse_pdf(S.build_plain_pdf())
    assert exc.value.code == "NOT_A_PROTOCOL" and exc.value.status == 422


def test_warstwa_tekstowa_rozpoznawana_a_skan_nie():
    assert P.has_text_layer(S.build_protocol()) is True
    assert P.has_text_layer(S.build_blank_pdf()) is False

"""
Miasto meczu: rozbior odpowiedzi publicznego API i odsiew nazw hal.

Tabela odleglosci jest miasto-miasto, wiec od tego, co wpiszemy w pole
„miasto", zalezy cala Lista kosztow przejazdow.
"""

from app.settlement_venues import looks_like_city, pretty_city, venue_from_payload


def test_miasto_bez_kodu_pocztowego_i_bez_ogona_po_przecinku():
    assert pretty_city("43-360 Bystra, ul. Szczyrkowska 1") == "Bystra"
    assert pretty_city("41-902 Bytom") == "Bytom"
    assert pretty_city("  Głogów  ") == "Głogów"
    assert pretty_city(None) == ""


def test_nazwa_hali_to_nie_miasto():
    assert looks_like_city("Głogów") is True
    assert looks_like_city("Siemianowice Śląskie") is True
    assert looks_like_city("Dąbrowa Górnicza") is True
    # Tego wlasnie scraper terminarza wpisywal do pola „miasto".
    assert looks_like_city("Hala Widowiskowo-Sportowa im. Ryszarda Matuszaka") is False
    assert looks_like_city("MOSiR") is False
    assert looks_like_city("Wita Stwosza 1") is False
    assert looks_like_city("") is False


def test_venue_z_odpowiedzi_api():
    payload = {
        "0": [
            {
                "Hala_nazwa": "Hala Widowiskowo-Sportowa im. Ryszarda Matuszaka",
                "Hala_miasto": "Głogów",
                "Hala_ulica": "Wita Stwosza",
                "Hala_numer": "1",
            }
        ]
    }
    venue = venue_from_payload(payload)
    assert venue["city"] == "Głogów"
    assert venue["hall"].startswith("Hala Widowiskowo")
    assert venue["street"] == "Wita Stwosza"
    assert venue["number"] == "1"


def test_druga_postac_odpowiedzi_gola_lista():
    """Swiezy mecz bez protokolu wraca `[[{...}]]` - ta sama pulapka co w monitorze."""
    payload = [[{"Hala_nazwa": "Hala MOSiR", "Hala_miasto": "Zabrze"}]]
    assert venue_from_payload(payload)["city"] == "Zabrze"


def test_kod_pocztowy_w_polu_miasta_z_api_tez_schodzi():
    payload = {"0": [{"Hala_miasto": "44-100 Gliwice", "Hala_nazwa": "Hala Sportowa"}]}
    assert venue_from_payload(payload)["city"] == "Gliwice"


def test_brak_hali_to_puste_pola_a_nie_wyjatek():
    assert venue_from_payload(None)["city"] == ""
    assert venue_from_payload({"0": []})["hall"] == ""
    assert venue_from_payload("cokolwiek")["city"] == ""

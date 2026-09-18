"""
Deklaracja „drugiego stolikowego stawia klub" - Obsada i data obowiązywania.

Ta sama deklaracja rządzi trzema miejscami: Automatem (kogo wysłać), stanem
obsady na liście (dziura / lekka różnica / komplet) i obciążeniem klubu.
Tu pilnujemy dwóch pierwszych i daty, od której działa na pieniądze.
"""

from datetime import date

from app import assignment_rules as A
from app.province_clubs_bulk import table_since

TODAY = date(2026, 9, 18)
SEZON = date(2026, 8, 1)


def junior(**slots):
    state = {}
    for slot, number in slots.items():
        state[f"NrSedzia_{slot}"] = number
        state[f"NrSedzia_{slot}_nazwisko"] = f"SĘDZIA {number}"
    return state


class TestPotrzebStolika:
    def test_bez_deklaracji_dwoch_stolikowych(self):
        assert A.club_crew_needs("S/JmM/7") == {"field": 2, "table": 2}

    def test_klub_daje_jednego_okreg_drugiego(self):
        assert A.club_crew_needs("S/JmM/7", 1) == {"field": 2, "table": 1}

    def test_okreg_zawsze_daje_co_najmniej_jednego(self):
        # Dzieci: stolik jednoosobowy, deklaracja nie ma czego odjąć.
        assert A.club_crew_needs("S/DZM/3", 1)["table"] == 1

    def test_boiskowych_deklaracja_nie_dotyczy(self):
        assert A.club_crew_needs("S/JmM/7", 1)["field"] == 2

    def test_smieci_w_deklaracji_to_brak_deklaracji(self):
        assert A.club_crew_needs("S/JmM/7", None)["table"] == 2
        assert A.club_crew_needs("S/JmM/7", -3)["table"] == 2


class TestStanuObsady:
    PELNE_BOISKO = {"pierwszy": "11", "drugi": "12"}

    def test_jeden_stolikowy_bez_deklaracji_to_lekka_roznica(self):
        status = A.crew_status(junior(**self.PELNE_BOISKO, sekretarz="21"), "S/JmM/7")
        assert status["state"] == A.SOFT

    def test_jeden_stolikowy_u_klubu_z_deklaracja_to_komplet(self):
        status = A.crew_status(junior(**self.PELNE_BOISKO, sekretarz="21"), "S/JmM/7", 1)
        assert status["state"] == A.COMPLETE
        assert status["table"]["need"] == 1

    def test_pusty_stolik_to_dziura_mimo_deklaracji(self):
        # Okręg zawsze daje co najmniej jednego - pusty stolik to nasz brak.
        status = A.crew_status(junior(**self.PELNE_BOISKO), "S/JmM/7", 1)
        assert status["state"] == A.GAP
        assert status["table"]["missing"] == 1

    def test_lista_i_automat_licza_tak_samo(self):
        for code in ("S/JmM/7", "S/DZM/3", "S/MLM1213/2"):
            for declared in (0, 1):
                assert A.crew_status({}, code, declared)["table"]["need"] == (
                    A.club_crew_needs(code, declared)["table"]
                )


class TestDatyDeklaracji:
    def test_bez_deklaracji_daty_nie_ma(self):
        assert table_since(0, SEZON, 1, SEZON, TODAY) is None

    def test_data_z_pisma_wygrywa(self):
        assert table_since(1, SEZON, 0, None, TODAY) == SEZON

    def test_nowa_deklaracja_bez_daty_od_dzis(self):
        # Historia zostaje nietknięta - mecze sprzed dziś liczą się po staremu.
        assert table_since(1, None, 0, None, TODAY) == TODAY

    def test_zapis_innego_pola_nie_przesuwa_daty(self):
        # Obsadowy zmienia „miejscowych" albo notatkę - deklaracja trwa od sezonu.
        assert table_since(1, None, 1, SEZON, TODAY) == SEZON

    def test_stara_deklaracja_bez_daty_zostaje_bez_daty(self):
        # Pusta data przy deklaracji znaczy „od zawsze" - nie wolno jej zawęzić.
        assert table_since(1, None, 1, None, TODAY) is None

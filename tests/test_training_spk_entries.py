# Kto wszedł na boisko w meczu wzorcowym.
#
# Bez tej listy prowadzenie za rękę umiało wskazać tylko zawodników, którzy
# COŚ ROBIĄ w prezentacji - i ćwiczący kończył mecz z sześcioma pustymi
# rubrykami wejścia na drużynę, choć nie zrobił nic źle.

import pytest

from app.training_spk_entries import entered_players


def blob(**over):
    base = {
        "hostPlayerStats": [
            {"number": 16, "entered": True, "goals": 9},
            {"number": 7, "entered": True},
            {"number": 99, "entered": False},
            {"number": 3},
        ],
        "guestPlayerStats": [
            {"number": 9, "entered": True},
            {"number": 1, "entered": True},
        ],
    }
    base.update(over)
    return base


class TestWejscia:
    def test_tylko_oznaczeni_wchodza(self):
        out = entered_players(blob())
        assert out["host"] == ["7", "16"]

    def test_rosnaco_po_liczbie_a_nie_po_znaku(self):
        # Sortowanie tekstem dawało „16" przed „7".
        out = entered_players(blob())
        assert out["guest"] == ["1", "9"]

    def test_brak_rubryki_znaczy_brak_wejscia(self):
        out = entered_players(blob())
        assert "3" not in out["host"]
        assert "99" not in out["host"]

    def test_osoba_towarzyszaca_nie_wchodzi_na_boisko(self):
        out = entered_players(
            blob(hostPlayerStats=[{"number": "A", "entered": True}])
        )
        assert out["host"] == []

    def test_numer_z_kropka_to_ten_sam_zawodnik(self):
        out = entered_players(
            blob(hostPlayerStats=[{"number": "16.0", "entered": True}])
        )
        assert out["host"] == ["16"]

    def test_powtorzony_numer_liczy_sie_raz(self):
        out = entered_players(
            blob(
                hostPlayerStats=[
                    {"number": 16, "entered": True},
                    {"number": 16, "entered": True},
                ]
            )
        )
        assert out["host"] == ["16"]

    def test_starszy_zapis_bez_rubryki_daje_pusto(self):
        # Wtedy telefon zostaje przy wejściach wyczytanych z akcji - to jest
        # świadome wycofanie, nie awaria.
        out = entered_players({"hostPlayerStats": [{"number": 16, "goals": 3}]})
        assert out == {"host": [], "guest": []}

    @pytest.mark.parametrize("junk", [None, "tekst", 7, [], {"hostPlayerStats": "x"}])
    def test_smieci_nie_wywracaja(self, junk):
        assert entered_players(junk) == {"host": [], "guest": []}

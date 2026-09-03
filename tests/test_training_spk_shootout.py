# Seria rzutów karnych wzorca.
#
# Ta seria jest w dokumencie meczu, ale NIE w osi czasu - i dokładnie dlatego
# prezentacja kończyła się remisem 26:26, jakby mecz na tym się skończył. Te
# testy pilnują dwóch rzeczy: że rzuty wychodzą w kolejności strzelania i że
# puste rundy nie zamieniają się w polecenia.

import pytest

from app.training_spk_shootout import shootout_shots
from app.training_spk_slides import shootout_slide, slides_from_timeline


def blob(**over):
    base = {
        "penaltyStarterTeam": "guest",
        "penaltyShots": {
            "host": [
                {"player": 16, "result": 1},
                {"player": 7, "result": 0},
                {"player": None, "result": None},
            ],
            "guest": [
                {"player": 9, "result": 1},
                {"player": 3, "result": 1},
                {"player": None, "result": None},
            ],
        },
    }
    base.update(over)
    return base


class TestKolejnoscStrzelania:
    def test_przeplot_zaczyna_druzyna_rozpoczynajaca(self):
        out = shootout_shots(blob())
        assert [(s["team"], s["player"]) for s in out] == [
            ("guest", "9"),
            ("host", "16"),
            ("guest", "3"),
            ("host", "7"),
        ]

    def test_numer_serii_rosnie_co_dwa_rzuty(self):
        out = shootout_shots(blob())
        assert [s["round"] for s in out] == [1, 1, 2, 2]

    def test_indeks_rzutu_liczy_sie_w_ramach_druzyny(self):
        # To jest klucz parowania na telefonie: sędzia sam wybiera, kto
        # rozpoczyna, więc „trzeci rzut gospodarzy" musi znaczyć to samo.
        out = shootout_shots(blob())
        host = [s["shotIndex"] for s in out if s["team"] == "host"]
        assert host == [0, 1]

    def test_bez_wskazania_rozpoczynajacego_zaczynaja_gospodarze(self):
        out = shootout_shots(blob(penaltyStarterTeam=None))
        assert out[0]["team"] == "host"

    def test_trafienie_i_pudlo_rozroznione(self):
        out = shootout_shots(blob())
        assert [s["scored"] for s in out] == [True, True, True, False]


class TestRzutyNieoddane:
    def test_runda_bez_wyniku_nie_jest_rzutem(self):
        # Aplikacja trzyma puste rundy z góry - slajd z takiej rundy kazałby
        # wpisać rzut, którego nie było.
        assert len(shootout_shots(blob())) == 4

    def test_seria_nierowna_nie_wywraca(self):
        out = shootout_shots(
            blob(
                penaltyShots={
                    "host": [{"player": 5, "result": 1}],
                    "guest": [],
                }
            )
        )
        assert [(s["team"], s["player"]) for s in out] == [("host", "5")]

    def test_brak_serii_to_pusta_lista(self):
        assert shootout_shots({}) == []
        assert shootout_shots({"penaltyShots": {}}) == []

    @pytest.mark.parametrize("junk", [None, "tekst", 7, [], {"penaltyShots": "x"}])
    def test_smieci_nie_wywracaja(self, junk):
        assert shootout_shots(junk) == []


class TestSlajdSerii:
    def test_mowi_trafienie_po_numerze(self):
        slide = shootout_slide(
            {"team": "host", "player": "16", "scored": True, "round": 3, "shotIndex": 2}
        )
        assert slide["text"] == "Seria karnych, rzut 3: gospodarze nr 16 - trafienie"
        assert slide["shootout"] is True

    def test_mowi_pudlo(self):
        slide = shootout_slide(
            {"team": "guest", "player": "9", "scored": False, "round": 1, "shotIndex": 0}
        )
        assert slide["text"] == "Seria karnych, rzut 1: goście nr 9 - pudło"

    def test_akcja_jako_dane_niesie_numer_rzutu(self):
        slide = shootout_slide(
            {"team": "host", "player": "16", "scored": True, "round": 2, "shotIndex": 1}
        )
        assert slide["events"] == [
            {
                "type": "penaltyKickScored",
                "team": "host",
                "player": "16",
                "shot": 1,
            }
        ]

    def test_w_miejscu_zegara_stoi_numer_serii(self):
        # Rzuty po meczu nie mają czasu gry, a pusty duży zegar zostawiał na
        # stronie PDF dziurę.
        slide = shootout_slide(
            {"team": "host", "player": "1", "scored": True, "round": 4, "shotIndex": 0}
        )
        assert slide["clock"] == "4"


class TestSeriaWMateriale:
    def _timeline(self):
        return [
            {"type": "goal", "team": "host", "time": 60_000, "half": 1, "player": 16},
            {"type": "goal", "team": "guest", "time": 2_000_000, "half": 2, "player": 9},
        ]

    def test_seria_dochodzi_na_koncu(self):
        slides = slides_from_timeline(
            self._timeline(), {}, shootout=shootout_shots(blob())
        )
        assert len(slides) == 6
        assert [s["shootout"] for s in slides] == [False, False, True, True, True, True]

    def test_numeracja_idzie_dalej_bez_dziur(self):
        slides = slides_from_timeline(
            self._timeline(), {}, shootout=shootout_shots(blob())
        )
        assert [s["n"] for s in slides] == [1, 2, 3, 4, 5, 6]

    def test_rzuty_serii_nie_scalaja_sie_w_jeden_slajd(self):
        # Wszystkie mają ten sam czas (zera), a scalanie zdarzeń równoczesnych
        # zrobiłoby z całej serii jedno polecenie.
        slides = slides_from_timeline([], {}, shootout=shootout_shots(blob()))
        assert len(slides) == 4

    def test_bez_serii_material_zostaje_jak_byl(self):
        assert len(slides_from_timeline(self._timeline(), {})) == 2

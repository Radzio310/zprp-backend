# Wzorzec odcięty na przerwie.
#
# To jest stan, który sędzia dostaje wczytany przy skróconym nagraniu, więc
# każdy błąd tutaj kończy się nieprawdziwym meczem: karą, której jeszcze nie
# było, siódemką doliczoną z drugiej połowy albo zegarem od zera.

import pytest

from app.training_spk_halftime import (
    first_half_events,
    half_length_ms,
    penalty_stats_from,
    state_after_first_half,
)

HALF = 30 * 60_000  # 1 800 000 ms


def blob(**over):
    base = {
        "matchConfig": {"matchNumber": "SPK/1", "halfTime": 30},
        "halfScore": {"host": 10, "guest": 14},
        "scoreHost": 26,
        "scoreGuest": 26,
        "protocol": [
            {"type": "goal", "team": "host", "time": 60_000, "half": 1, "player": 16},
            {"type": "penalty2", "team": "guest", "time": 300_000, "half": 1, "player": 7},
            {"type": "goal", "team": "guest", "time": 2_000_000, "half": 2, "player": 9},
            {"type": "penaltyKickScored", "team": "host", "time": 0, "shootout": True},
        ],
        "penaltyStats": {
            "host": {"total": 6, "goals": 5},
            "guest": {"total": 5, "goals": 4},
        },
        "teamTimeouts": {
            "host": {"first": 400_000, "second": 2_100_000, "third": None},
            "guest": {"first": None, "second": None, "third": None},
        },
        "penaltyTiles": [
            {"id": 1, "team": "guest", "playerNumber": 7, "assignedAt": 300_000},
            {"id": 2, "team": "host", "playerNumber": 3, "assignedAt": 2_200_000},
        ],
        "warningTiles": [
            {"id": 1, "team": "host", "player": 16, "minute": "12"},
            {"id": 2, "team": "guest", "player": 4, "minute": "41"},
        ],
        "goalHistory": [
            {"team": "host", "time": 60_000, "half": 1},
            {"team": "guest", "time": 2_000_000, "half": 2},
        ],
        "penaltyShootoutFinished": True,
        "penaltyShootoutScoreLabel": "5:4",
        "firstHalfStarterTeam": "host",
        "hostPlayerStats": [{"number": 16, "goals": 9}],
        "guestPlayerStats": [{"number": 9, "goals": 7}],
    }
    base.update(over)
    return base


class TestDlugoscPolowy:
    def test_z_konfiguracji_meczu(self):
        assert half_length_ms({"matchConfig": {"halfTime": 25}}) == 25 * 60_000

    def test_bez_konfiguracji_trzydziesci_minut(self):
        assert half_length_ms({}) == HALF

    def test_zero_w_konfiguracji_nie_zeruje_zegara(self):
        # Połowa zerowej długości odcinałaby CAŁY mecz.
        assert half_length_ms({"matchConfig": {"halfTime": 0}}) == HALF


class TestZdarzeniaPierwszejPolowy:
    def test_rozstrzyga_znacznik_polowy(self):
        out = first_half_events(blob()["protocol"], HALF)
        assert [e["type"] for e in out] == ["goal", "penalty2"]

    def test_rzuty_karne_nigdy_nie_naleza_do_pierwszej_polowy(self):
        events = [{"type": "penaltyKickScored", "team": "host", "shootout": True}]
        assert first_half_events(events, HALF) == []

    def test_bez_znacznika_polowy_decyduje_czas(self):
        events = [
            {"type": "goal", "team": "host", "time": 100_000},
            {"type": "goal", "team": "host", "time": 2_000_000},
        ]
        assert len(first_half_events(events, HALF)) == 1

    def test_zdarzenie_bez_czasu_i_polowy_zostaje(self):
        # Brak znacznika znaczy zwykle „coś, co nie ma czasu" - gubienie tego
        # po cichu byłoby gorsze niż zostawienie.
        assert len(first_half_events([{"type": "goal", "team": "host"}], HALF)) == 1

    def test_smieci_nie_wywracaja(self):
        assert first_half_events(None, HALF) == []
        assert first_half_events(["tekst", 7], HALF) == []


class TestSiodemki:
    def test_liczone_z_podanych_zdarzen(self):
        events = [
            {"type": "penaltyKickScored", "team": "host"},
            {"type": "penaltyKickMissed", "team": "host"},
            {"type": "penaltyKickScored", "team": "guest"},
            {"type": "goal", "team": "host"},
        ]
        out = penalty_stats_from(events)
        assert out["host"] == {"total": 2, "goals": 1}
        assert out["guest"] == {"total": 1, "goals": 1}

    def test_bez_siodemek_zera_a_nie_braki(self):
        out = penalty_stats_from([])
        assert out == {
            "host": {"total": 0, "goals": 0},
            "guest": {"total": 0, "goals": 0},
        }


class TestStanNaPrzerwie:
    def test_zegar_stoi_na_koncu_pierwszej_polowy(self):
        st = state_after_first_half(blob())
        assert st["mainTime"] == HALF
        assert st["isFirstHalf"] is False
        assert st["isGameRunning"] is False
        assert st["isHalfBreak"] is False

    def test_wynik_jest_wynikiem_do_przerwy(self):
        st = state_after_first_half(blob())
        assert (st["scoreHost"], st["scoreGuest"]) == (10, 14)
        assert st["halfScore"] == {"host": 10, "guest": 14}

    def test_protokol_bez_drugiej_polowy_i_bez_karnych(self):
        st = state_after_first_half(blob())
        assert len(st["protocol"]) == 2

    def test_siodemki_przeliczone_a_nie_przepisane(self):
        # W zapisie meczu było 6:5 z całego spotkania.
        st = state_after_first_half(blob())
        assert st["penaltyStats"]["host"] == {"total": 0, "goals": 0}

    def test_kara_z_drugiej_polowy_nie_wisi_na_boisku(self):
        st = state_after_first_half(blob())
        assert [t["id"] for t in st["penaltyTiles"]] == [1]

    def test_upomnienie_z_czterdziestej_pierwszej_minuty_znika(self):
        st = state_after_first_half(blob())
        assert [t["id"] for t in st["warningTiles"]] == [1]

    def test_czas_dla_druzyny_z_drugiej_polowy_wraca_do_puli(self):
        st = state_after_first_half(blob())
        assert st["teamTimeouts"]["host"]["first"] == 400_000
        assert st["teamTimeouts"]["host"]["second"] is None

    def test_seria_karnych_znika_w_calosci(self):
        st = state_after_first_half(blob())
        assert st["penaltyShootoutFinished"] is False
        assert st["penaltyShootoutScoreLabel"] == ""
        assert st["penaltyShots"] is None

    def test_stos_cofania_startuje_pusty(self):
        # Sędzia nie wpisywał pierwszej połowy, więc nie ma czego cofać.
        assert state_after_first_half(blob())["undoStack"] == []

    def test_kto_rozpoczynal_zostaje(self):
        assert state_after_first_half(blob())["firstHalfStarterTeam"] == "host"

    def test_sklady_ida_bez_zmian(self):
        st = state_after_first_half(blob())
        assert st["hostPlayerStats"] == [{"number": 16, "goals": 9}]

    def test_pusty_dokument_nie_wywraca(self):
        st = state_after_first_half({})
        assert st["protocol"] == []
        assert st["mainTime"] == HALF
        assert st["halfScore"] == {"host": 0, "guest": 0}

    @pytest.mark.parametrize("junk", [None, "tekst", 7, []])
    def test_dokument_innego_typu_nie_wywraca(self, junk):
        assert state_after_first_half(junk)["protocol"] == []

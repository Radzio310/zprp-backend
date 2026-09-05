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
    def test_kontenery_serii_karnych_sa_puste_a_nie_none(self):
        # Ekran meczu czyta ``penaltyShots.host`` w pierwszym renderze -
        # ``None`` wywracał moduł stolikowy przy wejściu w skrót nagrania.
        st = state_after_first_half(blob())
        assert st["penaltyShots"] == {"host": [], "guest": []}
        assert st["penaltyScores"] == {"host": 0, "guest": 0}
        assert st["penaltyResults"] == {"host": [None] * 5, "guest": [None] * 5}
        assert st["activeTeamTimeout"] == {"host": False, "guest": False}
        assert st["penaltyShootoutScoreLabel"] is None

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
        assert st["penaltyShootoutScoreLabel"] is None
        assert st["penaltyShots"] == {"host": [], "guest": []}

    def test_stos_cofania_startuje_pusty(self):
        # Sędzia nie wpisywał pierwszej połowy, więc nie ma czego cofać.
        assert state_after_first_half(blob())["undoStack"] == []

    def test_kto_rozpoczynal_zostaje(self):
        assert state_after_first_half(blob())["firstHalfStarterTeam"] == "host"

    def test_sklady_ida_bez_zmian(self):
        st = state_after_first_half(blob())
        assert st["hostPlayerStats"] == [{"number": 16, "goals": 9}]

    def test_rubryki_kar_z_drugiej_polowy_znikaja_ze_skladow(self):
        # Z terenu (SPK/1): zawodniczka 17 miała I 25:56 i II 37:27, a 7 - I
        # 49:04. Na przerwie aplikacja odbudowała z tych rubryk AKTYWNE kary
        # z 49. minuty i pokazała je jako trwające.
        st = state_after_first_half(
            blob(
                hostPlayerStats=[
                    {"number": 17, "goals": 1, "warning": "9'", "penalty1": "25:56", "penalty2": "37:27"},
                    {"number": 7, "goals": 0, "penalty1": "49:04"},
                    {"number": 3, "goals": 5, "warning": "41'", "disqualification": "55:10", "hasRedCard": True},
                ]
            )
        )
        by = {p["number"]: p for p in st["hostPlayerStats"]}
        assert by[17]["penalty1"] == "25:56" and by[17]["penalty2"] == ""
        assert by[17]["warning"] == "9'"
        assert by[7]["penalty1"] == ""
        assert by[3]["warning"] == "" and by[3]["disqualification"] == ""
        assert by[3]["hasRedCard"] is False

    def test_wykluczenia_dosuwaja_sie_do_poczatku(self):
        # Pierwsze z II połowy, drugie z I (zapis po korekcie kolejności):
        # zostaje jedno i ma być „pierwszym", inaczej aplikacja czyta
        # dyskwalifikację z numeru rubryki.
        st = state_after_first_half(
            blob(guestPlayerStats=[{"number": 9, "goals": 0, "penalty1": "44:00", "penalty2": "12:00", "penalty3": "58:00"}])
        )
        p = st["guestPlayerStats"][0]
        assert (p["penalty1"], p["penalty2"], p["penalty3"]) == ("12:00", "", "")

    def test_rubryka_bez_czasu_zostaje(self):
        st = state_after_first_half(blob(hostPlayerStats=[{"number": 5, "goals": 0, "warning": "tak"}]))
        assert st["hostPlayerStats"][0]["warning"] == "tak"

    def test_sankcje_osob_towarzyszacych_z_drugiej_polowy_znikaja(self):
        st = state_after_first_half(
            blob(
                matchConfig={
                    "matchNumber": "SPK/1",
                    "halfTime": 30,
                    "hostCompanions": [
                        {"id": "A", "warned": True, "warningTime": "51:51"},
                        {"id": "B", "warned": True, "warningTime": "12:00", "twoMinutes": True, "penaltyTimes": ["52:12"]},
                    ],
                }
            )
        )
        comps = {c["id"]: c for c in st["matchConfig"]["hostCompanions"]}
        assert comps["A"]["warned"] is False and comps["A"]["warningTime"] == ""
        assert comps["B"]["warned"] is True
        assert comps["B"]["twoMinutes"] is False and comps["B"]["penaltyTimes"] == []

    def test_pusty_dokument_nie_wywraca(self):
        st = state_after_first_half({})
        assert st["protocol"] == []
        assert st["mainTime"] == HALF
        assert st["halfScore"] == {"host": 0, "guest": 0}

    @pytest.mark.parametrize("junk", [None, "tekst", 7, []])
    def test_dokument_innego_typu_nie_wywraca(self, junk):
        assert state_after_first_half(junk)["protocol"] == []


class TestPodpisy:
    """Podpis jest potwierdzeniem człowieka, nie daną meczu."""

    def _cfg(self):
        return {
            "matchConfig": {
                "hostTeamName": "Lubin",
                "extras": {
                    "hostTeamSignature": "bazgroł gospodarzy",
                    "guestTeamSignature": "bazgroł gości",
                    "medic": {
                        "fullName": "KOWALSKA Anna",
                        "role": "ratownik medyczny",
                        "number": "PWZ 12345",
                        "signature": "bazgroł medyka",
                    },
                    "officials": {
                        "referee1": {"fullName": "NOWAK Jan", "signature": "bazgroł"},
                    },
                },
            }
        }

    def test_podpisy_druzyn_znikaja(self):
        cfg = state_after_first_half(self._cfg())["matchConfig"]
        assert "hostTeamSignature" not in cfg["extras"]
        assert "guestTeamSignature" not in cfg["extras"]

    def test_medyk_zostaje_bez_podpisu(self):
        medic = state_after_first_half(self._cfg())["matchConfig"]["extras"]["medic"]
        assert medic["fullName"] == "KOWALSKA Anna"
        assert medic["role"] == "ratownik medyczny"
        assert medic["number"] == "PWZ 12345"
        assert "signature" not in medic

    def test_obsada_zostaje_bez_podpisow(self):
        officials = state_after_first_half(self._cfg())["matchConfig"]["extras"][
            "officials"
        ]
        assert officials["referee1"]["fullName"] == "NOWAK Jan"
        assert "signature" not in officials["referee1"]

    def test_reszta_konfiguracji_nietknieta(self):
        cfg = state_after_first_half(self._cfg())["matchConfig"]
        assert cfg["hostTeamName"] == "Lubin"

    def test_konfiguracja_bez_extras_nie_wywraca(self):
        cfg = state_after_first_half({"matchConfig": {"hostTeamName": "X"}})[
            "matchConfig"
        ]
        assert cfg == {"hostTeamName": "X"}

    def test_zrodlowy_dokument_nie_jest_modyfikowany(self):
        # Wzorzec leży w bazie i ma zostać nietknięty - kopiujemy, nie tniemy
        # w miejscu.
        blob = self._cfg()
        state_after_first_half(blob)
        assert blob["matchConfig"]["extras"]["medic"]["signature"] == "bazgroł medyka"

# Ocena przy skróconym nagraniu: druga połowa i karne, czas tylko przy karach.
#
# Trzy rzeczy odróżniają ten tryb od pozostałych i każda może po cichu wypaczyć
# wynik:
#   1. pierwsza połowa NIE wchodzi do oceny po żadnej ze stron - sędzia dostaje
#      ją wczytaną, więc liczyłaby się jako trafiona bez jednego naciśnięcia,
#   2. czas bramek nie jest oceniany, bo materiał jest cięty,
#   3. czas kar i czasów dla drużyny jest oceniany, ale luźno.

from app.training_spk_score import (
    CONDENSED_TOLERANCE_MS,
    WEIGHTS_CONDENSED,
    score_run,
)

H1 = 600_000  # 10. minuta - pierwsza połowa
H2 = 2_100_000  # 35. minuta - druga połowa


def goal(time, half, player="7", team="host"):
    return {"type": "goal", "team": team, "time": time, "half": half, "player": player}


def penalty(time, half, player="3", team="guest"):
    return {
        "type": "penalty2",
        "team": team,
        "time": time,
        "half": half,
        "player": player,
    }


class TestZakresOceny:
    def test_pierwsza_polowa_nie_liczy_sie_po_zadnej_stronie(self):
        ref = [goal(H1, 1), goal(H2, 2)]
        mine = [goal(H1, 1), goal(H2, 2)]
        out = score_run(ref, mine, mode="condensed")
        assert out["counts"]["reference"] == 1
        assert out["counts"]["mine"] == 1

    def test_pominiecie_w_pierwszej_polowie_nie_szkodzi(self):
        # Sędzia dostaje ją wczytaną - nie ma tam czego pomijać.
        ref = [goal(H1, 1), goal(H2, 2)]
        mine = [goal(H2, 2)]
        assert score_run(ref, mine, mode="condensed")["score"] == 100.0

    def test_dopisek_w_pierwszej_polowie_tez_nie_szkodzi(self):
        ref = [goal(H2, 2)]
        mine = [goal(H1, 1), goal(H1 + 1000, 1), goal(H2, 2)]
        out = score_run(ref, mine, mode="condensed")
        assert out["counts"]["extra"] == 0
        assert out["score"] == 100.0

    def test_rzuty_karne_zostaja_w_ocenie(self):
        # Seria jest tym, co skrót pokazuje na końcu.
        shot = {
            "type": "penaltyKickScored",
            "team": "host",
            "time": 0,
            "half": 2,
            "player": "9",
            "shootout": True,
        }
        out = score_run([shot], [shot], mode="condensed")
        assert out["counts"]["reference"] == 1
        assert out["score"] == 100.0

    def test_pominiecie_w_drugiej_polowie_boli(self):
        ref = [goal(H2, 2), goal(H2 + 60_000, 2, player="9")]
        out = score_run(ref, [goal(H2, 2)], mode="condensed")
        assert out["counts"]["missed"] == 1
        assert out["score"] < 100.0


class TestCzas:
    def test_bramka_pol_minuty_obok_nie_jest_bledem(self):
        ref = [goal(H2, 2)]
        mine = [goal(H2 + 30_000, 2)]
        out = score_run(ref, mine, mode="condensed")
        assert out["parts"]["timing"] == 100.0
        assert out["counts"]["lateOrEarly"] == 0

    def test_kara_dziesiec_sekund_obok_jeszcze_przechodzi(self):
        ref = [penalty(H2, 2)]
        mine = [penalty(H2 + CONDENSED_TOLERANCE_MS, 2)]
        assert score_run(ref, mine, mode="condensed")["parts"]["timing"] == 100.0

    def test_kara_minute_obok_juz_nie(self):
        ref = [penalty(H2, 2)]
        mine = [penalty(H2 + 60_000, 2)]
        out = score_run(ref, mine, mode="condensed")
        assert out["parts"]["timing"] == 0.0
        assert out["counts"]["lateOrEarly"] == 1

    def test_czas_wazy_najmniej_ze_wszystkiego(self):
        # „Luźne kryterium, nie najważniejsze" - i tak ma zostać.
        assert WEIGHTS_CONDENSED["timing"] == 10
        assert WEIGHTS_CONDENSED["timing"] < WEIGHTS_CONDENSED["players"]
        assert sum(WEIGHTS_CONDENSED.values()) == 100

    def test_sam_zly_czas_kary_nie_wywraca_wyniku(self):
        ref = [goal(H2, 2), penalty(H2 + 10_000, 2)]
        mine = [goal(H2, 2), penalty(H2 + 300_000, 2)]
        out = score_run(ref, mine, mode="condensed")
        # Zdarzenia i numery bez zarzutu, więc traci się tylko wagę czasu.
        assert out["score"] == 90.0


class TestOdroznienieOdPozostalychTrybow:
    def test_pelne_nagranie_nadal_liczy_pierwsza_polowe(self):
        ref = [goal(H1, 1), goal(H2, 2)]
        assert score_run(ref, ref, mode="video")["counts"]["reference"] == 2

    def test_prezentacja_nadal_nie_ma_oceny_czasu(self):
        out = score_run([goal(H2, 2)], [goal(H2, 2)], mode="slides")
        assert "timing" not in out["parts"]

    def test_skrot_ma_ocene_czasu(self):
        out = score_run([penalty(H2, 2)], [penalty(H2, 2)], mode="condensed")
        assert "timing" in out["parts"]

    def test_tryb_wraca_w_odpowiedzi(self):
        assert score_run([], [], mode="condensed")["mode"] == "condensed"

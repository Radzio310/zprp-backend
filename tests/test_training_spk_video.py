"""Kotwice czasu wideo dla skrótu SPK/1.

Zegar meczu przy skrócie idzie za czasem wideo i przeskakuje między
akcjami. Kotwice muszą być rosnące w obu osiach, bez treści zdarzeń, a
bramki - dociągnięte do sekundy ze wzorca, gdy wzorzec je zna.
"""
from __future__ import annotations

from app.training_spk_video import (
    BENCH_WARNINGS,
    GOALS,
    HALF_START_MS,
    PENALTIES,
    TIMEOUTS,
    clock_anchors,
    goal_anchor_times,
    video_clock,
)


def _ms(mm, ss=0):
    return (mm * 60 + ss) * 1000


class TestArkusz:
    def test_liczby_z_arkusza(self):
        assert len(GOALS) == 28
        assert len(PENALTIES) == 5
        assert len(BENCH_WARNINGS) == 2
        assert len(TIMEOUTS) == 3

    def test_wynik_koncowy_zgadza_sie_z_bramkami(self):
        # Arkusz kończy na 26:26; pierwsza połowa to 10:14.
        host = sum(1 for _v, _m, team, _p, _pen in GOALS if team == "host")
        guest = sum(1 for _v, _m, team, _p, _pen in GOALS if team == "guest")
        assert (10 + host, 14 + guest) == (26, 26)

    def test_upomnienia_lawek_to_osoba_B(self):
        assert [(t, letter) for _v, _m, t, letter in BENCH_WARNINGS] == [
            ("host", "B"),
            ("guest", "B"),
        ]


class TestKotwice:
    def test_bez_wzorca_rosna_w_obu_osiach(self):
        anchors = clock_anchors(None)
        assert anchors, "brak kotwic"
        videos = [a[0] for a in anchors]
        matches = [a[1] for a in anchors]
        assert videos == sorted(videos) and len(set(videos)) == len(videos)
        assert matches == sorted(matches)
        assert matches[0] >= HALF_START_MS

    def test_kary_i_czasy_maja_czas_co_do_sekundy(self):
        anchors = {a[0]: a[1] for a in clock_anchors(None)}
        assert anchors[_ms(1, 38)] == _ms(34, 51)
        assert anchors[_ms(5, 8)] == _ms(46, 38)
        assert anchors[_ms(6, 29)] == _ms(51, 51)

    def test_bramka_bez_wzorca_stoi_w_srodku_minuty(self):
        times = dict(goal_anchor_times(None))
        assert times[_ms(0, 47)] == _ms(30, 30)

    def test_bramka_ze_wzorca_dostaje_dokladny_czas(self):
        timeline = [
            {"type": "goal", "team": "host", "player": 3, "time": _ms(30, 41), "half": 2},
            {"type": "goal", "team": "guest", "player": 28, "time": _ms(31, 12), "half": 2},
        ]
        times = dict(goal_anchor_times(timeline))
        assert times[_ms(0, 47)] == _ms(30, 41)
        assert times[_ms(1, 0)] == _ms(31, 12)

    def test_bramka_z_pierwszej_polowy_nie_jest_brana(self):
        timeline = [
            {"type": "goal", "team": "host", "player": 3, "time": _ms(12, 0), "half": 1},
        ]
        times = dict(goal_anchor_times(timeline))
        assert times[_ms(0, 47)] == _ms(30, 30)

    def test_dwie_bramki_tego_samego_zawodnika_ida_po_kolei(self):
        # Zawodnik 28 gości: 32. i 34. minuta. Każda ma dostać swoją.
        timeline = [
            {"type": "goal", "team": "guest", "player": 28, "time": _ms(31, 20), "half": 2},
            {"type": "goal", "team": "guest", "player": 28, "time": _ms(33, 5), "half": 2},
        ]
        times = dict(goal_anchor_times(timeline))
        assert times[_ms(1, 0)] == _ms(31, 20)
        assert times[_ms(1, 11)] == _ms(33, 5)

    def test_karny_ze_wzorca_liczy_sie_jak_bramka(self):
        # Zawodnik 34 gospodarzy: bramka w 34. minucie (1:18 wideo) i karny
        # w 35. (2:03). Dopasowanie po kolei daje każdej jej własny czas.
        timeline = [
            {"type": "goal", "team": "host", "player": 34, "time": _ms(33, 40), "half": 2},
            {"type": "penaltyKickScored", "team": "host", "player": 34, "time": _ms(34, 20), "half": 2},
        ]
        times = dict(goal_anchor_times(timeline))
        assert times[_ms(1, 18)] == _ms(33, 40)
        assert times[_ms(2, 3)] == _ms(34, 20)

    def test_telefon_dostaje_same_pary(self):
        clock = video_clock(None)
        assert clock["halfStartMs"] == HALF_START_MS
        assert all(len(a) == 2 for a in clock["anchors"])
        assert "goals" not in clock

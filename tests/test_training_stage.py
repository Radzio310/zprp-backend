"""Drabina etapów ćwiczenia i reguła zapisu punktów na osi czasu.

Obie rzeczy decydują o tym, co administrator zobaczy w analizie szkolenia:
pierwsza odpowiada na pytanie „dokąd sędzia doprowadził mecz", druga na
„co się z nim działo po drodze". Pomyłka w pierwszej cofa komuś wynik pracy,
pomyłka w drugiej zamienia wykres w linię prostą albo w las identycznych
punktów.
"""

from app.training_stage import (
    COMPLETED_FROM,
    MIN_TICK_GAP_S,
    STAGE_ORDER,
    furthest_stage,
    is_completed,
    normalize_stage,
    tick_is_new,
)


class TestStageLadder:
    def test_drabina_idzie_od_pierwszej_polowy_do_zatwierdzenia(self):
        assert STAGE_ORDER[0] == "first_half"
        assert STAGE_ORDER[-1] == "finalized"
        assert COMPLETED_FROM in STAGE_ORDER

    def test_nieznany_etap_nie_wywraca_zapisu(self):
        assert normalize_stage("kosmos") == "first_half"
        assert normalize_stage(None) == "first_half"
        assert normalize_stage("") == "first_half"

    def test_trzymamy_etap_najdalszy_a_nie_ostatni(self):
        # Sędzia schodzi z podsumowania z powrotem na tor meczowy, żeby
        # poprawić karę. To NIE jest cofnięcie postępu.
        assert furthest_stage("second_half", "summary") == "summary"
        assert furthest_stage("summary", "second_half") == "summary"

    def test_kolejne_etapy_podnosza_poprzeczke(self):
        assert furthest_stage("first_half", "half_break") == "half_break"
        assert furthest_stage("ended", "finalized") == "finalized"

    def test_doprowadzony_do_konca_liczy_sie_od_zakonczenia_meczu(self):
        assert not is_completed("second_half")
        assert not is_completed("penalties")
        assert is_completed("ended")
        assert is_completed("summary")
        assert is_completed("finalized")


class TestTickRule:
    BASE = {
        "stage": "first_half",
        "score_host": 5,
        "score_guest": 3,
        "events_count": 12,
    }

    def test_pierwszy_punkt_wchodzi_zawsze(self):
        assert tick_is_new(None, self.BASE, None) is True

    def test_bramka_wchodzi_natychmiast(self):
        cur = {**self.BASE, "score_host": 6}
        assert tick_is_new(self.BASE, cur, 1.0) is True

    def test_zdarzenie_bez_bramki_tez_wchodzi(self):
        # Kara albo upomnienie nie rusza wyniku, ale rusza przebieg - i to
        # jest dokładnie ta informacja, po którą oś czasu istnieje.
        cur = {**self.BASE, "events_count": 13}
        assert tick_is_new(self.BASE, cur, 1.0) is True

    def test_zmiana_etapu_wchodzi_natychmiast(self):
        cur = {**self.BASE, "stage": "half_break"}
        assert tick_is_new(self.BASE, cur, 0.5) is True

    def test_seria_identycznych_taktow_nie_zasmieca_osi(self):
        assert tick_is_new(self.BASE, dict(self.BASE), 2.0) is False
        assert tick_is_new(self.BASE, dict(self.BASE), MIN_TICK_GAP_S - 0.1) is False

    def test_cisza_sama_w_sobie_cos_znaczy(self):
        # Sędzia stojący w miejscu ma zostawić płaski odcinek, nie dziurę.
        assert tick_is_new(self.BASE, dict(self.BASE), MIN_TICK_GAP_S) is True
        assert tick_is_new(self.BASE, dict(self.BASE), 600.0) is True

    def test_nieznany_odstep_traktujemy_jak_nowy_punkt(self):
        assert tick_is_new(self.BASE, dict(self.BASE), None) is True

    def test_smieci_w_liczbach_nie_wywracaja_reguly(self):
        prev = {**self.BASE, "score_host": None, "events_count": "x"}
        cur = {**self.BASE, "score_host": 0, "events_count": 0}
        assert tick_is_new(prev, cur, 1.0) is False

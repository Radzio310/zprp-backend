"""
Za mały odstęp między meczami sędziego (decyzje 18.10.2026).

  - RĘCZNA obsada dostaje stopień ostrzeżenia (żółty / pomarańczowy / czerwony),
  - Automat, optymalizacja i zamiany dalej NIGDY nie biorą takiego sędziego.
"""

from datetime import datetime

from app import collision_rules as CR
from app.assignment_auto import (
    GAP,
    BusyMatch,
    Context,
    MatchNeed,
    build_plan,
    describe_candidates,
    gap_with,
)
from app.assignment_people import make_judge

HALL_A = "Hala A"
HALL_B = "Hala B"
SENIOR_CODE = "SM/5"  # Senior, 105 min


def at(hour, minute=0):
    return datetime(2026, 10, 3, hour, minute)


def grade(first, second, km=20.0, same_venue=False):
    return CR.gap_grade(
        first, second, km, first_code=SENIOR_CODE, second_code=SENIOR_CODE, same_venue=same_venue
    )


class TestStopnie:
    # Inna hala, 20 km: 105 + 20 + 30 = 155 min potrzeba, zapas okręgu 30.
    def test_wystarcza_bez_ostrzezenia(self):
        assert grade(at(10), at(12, 35)) is None

    def test_zolty_zjada_zapas(self):
        g = grade(at(10), at(12, 20))  # odstęp 140, brakuje 15 <= 30
        assert g.level == CR.GAP_YELLOW and g.shortfall == 15 and not g.overlap

    def test_pomaranczowy_do_30_ponad_zapas(self):
        g = grade(at(10), at(11, 50))  # odstęp 110, brakuje 45 (30 < 45 <= 60)
        assert g.level == CR.GAP_ORANGE and g.shortfall == 45 and not g.overlap

    def test_czerwony_gdy_mecze_nachodza(self):
        g = grade(at(10), at(11, 30))  # odstęp 90 < 105: nachodzą
        assert g.level == CR.GAP_RED and g.overlap

    def test_czerwony_gdy_brakuje_ponad_60(self):
        # Szybki mecz dzieci (60 min), ale daleki dojazd: 60 + 120 + 30 = 210; odstęp 70 > 60
        g = CR.gap_grade(
            at(10), at(11, 10), 120.0, first_code="DZM/1", second_code="DZM/1"
        )
        assert g.level == CR.GAP_RED and not g.overlap and g.shortfall == 140

    def test_ta_sama_hala_nachodzenie_to_czerwony(self):
        g = grade(at(10), at(11, 0), km=0.0, same_venue=True)
        assert g.level == CR.GAP_RED and g.overlap
        assert grade(at(10), at(11, 45), km=0.0, same_venue=True) is None

    def test_bez_terminu_nie_ostrzega(self):
        assert CR.gap_grade(None, at(10), 5.0) is None


def need_for(when=at(12, 20), city="Zabrze", hall=HALL_B):
    return MatchNeed(
        match_id="500",
        code=SENIOR_CODE,
        moment=when,
        day=when.date(),
        host_city=city,
        hall=hall,
        field_needed=["pierwszy"],
        table_needed=[],
    )


def world(judge, busy):
    return Context(
        judges={judge.judge_id: judge},
        available=lambda judge_id, moment: True,
        paused=lambda judge_id, day: False,
        city_of=lambda judge_id, day: judge.city,
        km=lambda a, b: 20.0,
        busy={judge.judge_id: busy},
    )


def busy_match():
    return BusyMatch(moment=at(10), city="Gliwice", match_id="9", code=SENIOR_CODE, hall=HALL_A)


class TestKafelekIAutomat:
    def test_kafelek_ma_status_gap_ze_stopniem_i_opisem(self):
        judge = make_judge("1", "KOLIZJA Ewa", city="Zabrze")
        ctx = world(judge, [busy_match()])
        (view,) = describe_candidates(ctx, need_for())
        assert view.status == GAP and view.gap_level == "yellow"
        assert "15 min" in view.reason and "10:00" in view.reason and HALL_A in view.reason
        assert "10:00" in view.gap_note
        # Można go wskazać ręcznie: pasuje do boiska, więc nie jest wygaszony.
        assert "field" in view.fits

    def test_czerwony_opis_z_minutami(self):
        judge = make_judge("1", "KOLIZJA Ewa", city="Zabrze")
        ctx = world(judge, [busy_match()])
        (view,) = describe_candidates(ctx, need_for(at(11, 0)))
        assert view.gap_level == "red" and "nachodzą" in view.reason

    def test_automat_nadal_odrzuca(self):
        judge = make_judge("1", "KOLIZJA Ewa", city="Zabrze")
        ctx = world(judge, [busy_match()])
        # Żółty w ręcznej obsadzie, ale Automat go NIE bierze.
        assert gap_with(ctx, "1", need_for()) is not None
        plan = build_plan([need_for()], ctx)
        assert not plan.proposals
        assert plan.gaps and "nie zdąży" in plan.gaps[0].reason

    def test_inne_odmowy_zostaja_blokada(self):
        judge = make_judge("1", "ZAJĘTY Ewa", city="Zabrze")
        ctx = world(judge, [busy_match()])
        ctx.available = lambda judge_id, moment: False
        (view,) = describe_candidates(ctx, need_for())
        assert view.status == "off" and not view.gap_level

"""Czas realny i czas poza egzaminem: reguły liczone z zapisanych śladów."""

from datetime import datetime, timedelta, timezone

from app.exam_report_rules import durations_s
from app.exam_record_rules import duration_s as record_duration
from app.exam_stats_rules import duration_s as stats_duration
from app.exam_time_rules import BETWEEN_CAP_S, IDLE_CAP_S, active_ms, attempt_time

T0 = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def row(shown: float, answered: float, timed_out: bool = False):
    return {"shown_at": at(shown), "answered_at": at(answered), "timed_out": timed_out}


def test_bez_przerw_realny_rowny_calosci():
    t = attempt_time(T0, at(120), [row(0, 40), row(40, 90), row(90, 120)], [], 100)
    assert t["known"] and t["real_s"] == 120 and t["away_s"] == 0 and t["gaps"] == []


def test_zrzut_wlasciciela_69_godzin_przerwy_nie_sa_pisaniem():
    # Pięć pytań po 40 s, potem laptop zamknięty na prawie 70 h, powrót i oddanie po naruszeniach.
    away = 69 * 3600 + 35 * 60
    rows = [row(i * 40, (i + 1) * 40) for i in range(5)]
    rows.append(row(200, 300, timed_out=True))  # pytanie, któremu minął limit w trakcie nieobecności
    rows.append(row(200 + away, 200 + away + 12))
    t = attempt_time(T0, at(200 + away + 12), rows, [], 100)
    assert t["known"]
    assert 300 <= t["real_s"] <= 300 + BETWEEN_CAP_S + 12
    assert t["away_s"] > 69 * 3600
    assert t["inferred_s"] == t["away_s"] and t["measured_s"] == 0
    assert len(t["gaps"]) == 1 and t["gaps"][0]["source"] == "inferred"


def test_zmierzone_wyjscie_odejmuje_sie_co_do_sekundy():
    events = [{"kind": "app_background", "detail": {"seconds": 60}, "at": at(100).isoformat()}]
    t = attempt_time(T0, at(180), [row(0, 180)], events, None)
    assert t["real_s"] == 120 and t["measured_s"] == 60 and t["inferred_s"] == 0
    assert t["gaps"] == [{"from_ms": 40000, "to_ms": 100000, "seconds": 60.0, "source": "measured"}]


def test_nakladajace_sie_zgloszenia_licza_sie_raz():
    events = [{"kind": "app_background", "detail": {"seconds": 60}, "at": at(100).isoformat()},
              {"kind": "resume", "detail": {"seconds": 50}, "at": at(100).isoformat()}]
    t = attempt_time(T0, at(180), [row(0, 180)], events, None)
    assert t["measured_s"] == 60 and t["real_s"] == 120


def test_bez_limitu_dlugie_czytanie_tylko_ponad_granice_jest_przerwa():
    t = attempt_time(T0, at(IDLE_CAP_S + 600), [row(0, IDLE_CAP_S + 600)], [], None)
    assert t["real_s"] == IDLE_CAP_S and t["inferred_s"] == 600


def test_brak_sladow_nie_zgadujemy():
    t = attempt_time(T0, at(40000), [], [], None)
    assert t["known"] is False and t["real_s"] is None and t["away_s"] is None and t["total_s"] == 40000


def test_krotkie_podejscie_bez_sladow_jest_znane():
    t = attempt_time(T0, at(30), [], [], 100)
    assert t["known"] and t["real_s"] == 30


def test_trwajace_podejscie_nie_ma_czasu():
    assert attempt_time(T0, None, [], [], None) is None


def test_czas_na_pytaniu_bez_przerwy():
    gaps = [{"from_ms": 10000, "to_ms": 70000, "source": "measured"}]
    assert active_ms(at(0), at(100), 100000, gaps, T0) == 40000
    assert active_ms(at(0), at(100), None, gaps, T0) is None
    assert active_ms(at(80), at(100), 20000, gaps, T0) == 20000


def test_agregaty_biora_realny_gdy_policzony_a_stare_wiersze_sciana_zegara():
    done = {"status": "submitted", "started_at": T0, "finished_at": at(1000)}
    assert durations_s([done]) == [1000]
    assert durations_s([{**done, "real_s": 90.0}]) == [90.0]
    assert durations_s([{**done, "real_s": None}]) == []
    assert record_duration({**done, "real_s": 90.0}) == 90.0
    assert record_duration({**done, "real_s": None}) is None
    assert stats_duration({**done, "real_s": 90.0}) == 90.0
    assert stats_duration(done) == 1000

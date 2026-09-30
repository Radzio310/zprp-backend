"""Okresy szkoleniowe: walidacja, widoczność, kolejność i odtwarzanie z przebiegów.

Pomyłka tutaj kosztuje wyniki: zmieniony albo powtórzony identyfikator okresu
miesza przebiegi dwóch szkoleń, a zgubiony okres sprzed zmiany znika z
analizy, choć jego przebiegi dalej leżą w bazie.
"""

from datetime import date, datetime, timezone

import pytest

from app.training_events_rules import (
    PeriodError,
    STATUS_ACTIVE,
    STATUS_ARCHIVED,
    STATUS_DISABLED,
    STATUS_ENDED,
    STATUS_RECOVERED,
    STATUS_SCHEDULED,
    first_visible,
    is_visible,
    normalize_period,
    period_status,
    recover_periods,
    sort_periods,
    valid_key,
)

D = date(2026, 9, 29)


def _p(**kw):
    base = {
        "id": "kk-2026",
        "title": "Kursokonferencja",
        "visibleFrom": "",
        "visibleTo": "",
        "matches": [{"zprpMatchId": "208132", "matchNumber": "SPM/1"}],
    }
    base.update(kw)
    return base


class TestNormalize:
    def test_poprawny_okres(self):
        out = normalize_period(_p(subtitle="  ", visibleFrom="2026-09-01"))
        assert out["id"] == "kk-2026"
        assert out["enabled"] is True
        assert out["subtitle"] is None
        assert out["visibleFrom"] == "2026-09-01"
        assert out["matches"] == [
            {"zprpMatchId": "208132", "matchNumber": "SPM/1", "label": None}
        ]

    def test_brak_tytulu(self):
        with pytest.raises(PeriodError):
            normalize_period(_p(title=" "))

    def test_zly_identyfikator(self):
        with pytest.raises(PeriodError):
            normalize_period(_p(id="ze spacją"))
        assert valid_key("kk-lodz-2026")
        assert not valid_key("-zly")

    def test_zla_data(self):
        with pytest.raises(PeriodError):
            normalize_period(_p(visibleFrom="29.09.2026"))
        with pytest.raises(PeriodError):
            normalize_period(_p(visibleTo="2026-02-30"))

    def test_odwrocone_okno(self):
        with pytest.raises(PeriodError):
            normalize_period(_p(visibleFrom="2026-10-02", visibleTo="2026-10-01"))

    def test_idzawody_liczba(self):
        with pytest.raises(PeriodError):
            normalize_period(_p(matches=[{"zprpMatchId": "abc", "matchNumber": "X/1"}]))

    def test_puste_mecze_pomijane_a_powtorzony_numer_odrzucony(self):
        out = normalize_period(_p(matches=[{"zprpMatchId": "", "matchNumber": "A"}]))
        assert out["matches"] == []
        with pytest.raises(PeriodError):
            normalize_period(
                _p(
                    matches=[
                        {"zprpMatchId": "1", "matchNumber": "A/1"},
                        {"zprpMatchId": "2", "matchNumber": "A/1"},
                    ]
                )
            )


class TestVisibilityAndStatus:
    def test_okno_wlacznie(self):
        p = _p(visibleFrom="2026-09-29", visibleTo="2026-09-29")
        assert is_visible(p, today=D)
        assert not is_visible(p, today=date(2026, 9, 30))
        assert not is_visible(p, today=date(2026, 9, 28))

    def test_wylaczony_zarchiwizowany_bez_meczow(self):
        assert not is_visible(_p(enabled=False), today=D)
        assert not is_visible(_p(), archived=True, today=D)
        assert not is_visible(_p(matches=[]), today=D)

    def test_statusy(self):
        assert period_status(_p(), today=D) == STATUS_ACTIVE
        assert period_status(_p(visibleFrom="2026-10-01"), today=D) == STATUS_SCHEDULED
        assert period_status(_p(visibleTo="2026-09-01"), today=D) == STATUS_ENDED
        assert period_status(_p(enabled=False), today=D) == STATUS_DISABLED
        assert period_status(_p(), archived=True, today=D) == STATUS_ARCHIVED
        assert period_status(_p(), recovered=True, today=D) == STATUS_RECOVERED

    def test_first_visible_dla_starej_aplikacji(self):
        rows = [
            {"payload": _p(id="nowy", visibleFrom="2026-12-01"), "archived": False},
            {"payload": _p(id="teraz"), "archived": False},
        ]
        assert first_visible(rows, today=D)["id"] == "teraz"
        rows2 = [
            {"payload": _p(id="arch"), "archived": True},
            {"payload": _p(id="przyszly", visibleFrom="2026-12-01"), "archived": False},
        ]
        assert first_visible(rows2, today=D)["id"] == "przyszly"
        assert first_visible([], today=D) is None


class TestSort:
    def test_kolejnosc(self):
        ps = [
            {"id": "odtw", "status": STATUS_RECOVERED, "visibleTo": "2026-08-30"},
            {"id": "stary", "status": STATUS_ENDED, "visibleTo": "2026-05-01"},
            {"id": "nowszy", "status": STATUS_ENDED, "visibleTo": "2026-08-31"},
            {"id": "pozny", "status": STATUS_SCHEDULED, "visibleFrom": "2026-12-01"},
            {"id": "blisko", "status": STATUS_SCHEDULED, "visibleFrom": "2026-10-01"},
            {"id": "trwa", "status": STATUS_ACTIVE},
            {"id": "arch", "status": STATUS_ARCHIVED, "visibleTo": "2026-09-01"},
        ]
        assert [p["id"] for p in sort_periods(ps)] == [
            "trwa",
            "blisko",
            "pozny",
            "nowszy",
            "stary",
            "arch",
            "odtw",
        ]


class TestRecover:
    def test_odtwarza_okres_z_przebiegow(self):
        rows = [
            {
                "event_id": "kk-lodz-2026",
                "match_number": "SPM/1",
                "zprp_match_id": "208132",
                "first_at": datetime(2026, 8, 29, 18, tzinfo=timezone.utc),
                "last_at": datetime(2026, 8, 30, 9, tzinfo=timezone.utc),
                "runs": 5,
                "title": "Kursokonferencja sędziów Łódź 2026",
            },
            {
                "event_id": "kk-lodz-2026",
                "match_number": "SPK/1",
                "zprp_match_id": None,
                "first_at": datetime(2026, 8, 28, 12, tzinfo=timezone.utc),
                "last_at": datetime(2026, 8, 29, 12, tzinfo=timezone.utc),
                "runs": 3,
                "title": None,
            },
            {
                "event_id": "znany",
                "match_number": "A/1",
                "first_at": "2026-09-01T10:00:00",
                "last_at": "2026-09-01T10:00:00",
                "runs": 1,
            },
        ]
        out = recover_periods(rows, known_keys=["znany"])
        assert len(out) == 1
        p = out[0]
        assert p["id"] == "kk-lodz-2026"
        assert p["title"] == "Kursokonferencja sędziów Łódź 2026"
        assert p["visibleFrom"] == "2026-08-28"
        assert p["visibleTo"] == "2026-08-30"
        assert p["runsCount"] == 8
        assert p["recovered"] is True and p["status"] == STATUS_RECOVERED
        # Mecze w kolejności pierwszego przebiegu.
        assert [m["matchNumber"] for m in p["matches"]] == ["SPK/1", "SPM/1"]
        assert p["matches"][1]["zprpMatchId"] == "208132"
        assert "_first" not in p["matches"][0]

    def test_bez_tytulu_dostaje_zastepczy(self):
        out = recover_periods(
            [{"event_id": "x1", "match_number": "B/2", "first_at": None, "last_at": None, "runs": 1}]
        )
        assert out[0]["title"] == "Okres x1"
        assert out[0]["visibleFrom"] == ""

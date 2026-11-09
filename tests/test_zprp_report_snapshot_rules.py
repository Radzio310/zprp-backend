"""Zapisane stany zakładek Raportów ZPRP (`app/zprp_report_snapshot_rules.py`)."""
from __future__ import annotations

import datetime as dt

from app import zprp_report_snapshot_rules as R

UTC = dt.timezone.utc


def test_klucze_i_rodzaje():
    assert R.valid_kind("officials") and R.valid_kind("schedule_full")
    assert not R.valid_kind("cokolwiek")
    assert R.clean_key("") == ""
    assert R.clean_key("::") == ""  # domyślny wybór statystyk = pusty klucz
    assert R.clean_key("195::11625") == "195::11625"
    assert R.clean_key("195::1|M::11625") == "195::1|M::11625"
    assert R.clean_key("../etc") is None
    assert R.clean_key("x" * 200) is None
    assert R.stats_key("", "") == ""
    assert R.stats_key("195", "") == "195::"


def test_najnowszy_sezon_jak_w_zakladce():
    meta = {"filters": {"Filtr_sezon": [{"value": "---"}, {"value": "193"}, {"value": "195"}, {"value": "194"}]}}
    assert R.newest_season(meta) == "195"
    assert R.newest_season({"Filtr_sezon_selected": "190"}) == "190"


def test_noc_raz_na_dobe():
    night = dt.datetime(2026, 11, 10, 3, 30, tzinfo=UTC)  # 4:30 w Polsce
    day = dt.datetime(2026, 11, 10, 11, 0, tzinfo=UTC)
    assert R.nightly_due(None, day)  # nigdy nie było - od razu
    assert not R.nightly_due(day - dt.timedelta(hours=5), day)
    assert R.nightly_due(night - dt.timedelta(hours=24), night)
    assert not R.nightly_due(day - dt.timedelta(hours=24), day)  # dzień - czekamy na noc
    assert R.nightly_due(day - dt.timedelta(hours=31), day)  # noc przepadła - nie czekamy kolejnej


def test_nieaktualny_stan():
    now = dt.datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
    assert R.is_stale("officials", now - dt.timedelta(hours=7), now)
    assert not R.is_stale("officials", now - dt.timedelta(hours=3), now)
    assert not R.is_stale("schedule_full", now - dt.timedelta(hours=30), now)
    assert R.is_stale("schedule_full", None, now)


def test_lista_sedziow_w_ksztalcie_trasy():
    payload = R.officials_payload(
        {"5124": {"name": "Jan Kowalski"}},
        base_url="https://baza.zprp.pl",
        entry_href="/index.php?a=sedzia",
        summary={"sedzia": 1},
        fetched_at="2026-11-10T03:00:00Z",
    )
    assert payload["officials"]["5124"]["name"] == "Jan Kowalski"
    assert payload["summary"] == {"officials_total": 1, "sedzia": 1}

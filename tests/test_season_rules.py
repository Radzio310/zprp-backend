"""Sezon rozgrywkowy - JEDNA regula na caly backend (`app/season_rules.py`).

Zgloszenie 14.09.2026: mecz z 29.08.2026 nalezy do sezonu 2026/2027, a wpadal
do 2025/2026. Regula zyla w dwoch kopiach - w bombach i w rozliczeniach - i
obie lamaly sezon we wrzesniu. Te testy pilnuja, ze jest jedna i sierpniowa.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from app.season_rules import (
    SEASON_START_MONTH,
    season_label_full,
    season_label_short,
    season_start_year,
)


def test_granica_jest_sierpniowa():
    assert SEASON_START_MONTH == 8


@pytest.mark.parametrize(
    "when,expected",
    [
        (date(2026, 8, 1), 2026),   # pierwszy dzien nowego sezonu
        (date(2026, 8, 29), 2026),  # dokladnie ten mecz ze zgloszenia
        (date(2026, 9, 1), 2026),
        (date(2027, 5, 4), 2026),   # wiosna nalezy do sezonu z jesieni
        (date(2026, 7, 31), 2025),  # ostatni dzien poprzedniego
        (datetime(2026, 8, 29, 18, 0, tzinfo=timezone.utc), 2026),
    ],
)
def test_rok_startu_sezonu(when, expected):
    assert season_start_year(when) == expected


def test_brak_daty_to_brak_sezonu():
    """Zgadywanie przestawiloby wpis w cudzym zestawieniu."""
    assert season_start_year(None) is None
    assert season_start_year("2026-08-29") is None
    assert season_start_year(12345) is None


def test_dwie_etykiety_tego_samego_sezonu():
    # Pelna - w takiej postaci sezon przyjezdza z ZPRP.
    assert season_label_full(2026) == "2026/2027"
    # Skrocona - na przelacznik, jak w aplikacji.
    assert season_label_short(2026) == "2026/27"


def test_etykieta_na_przelomie_wieku_nie_gubi_zera():
    assert season_label_short(1999) == "1999/00"
    assert season_label_full(1999) == "1999/2000"


def test_smiec_w_roku_to_pusty_napis_a_nie_wyjatek():
    for junk in (None, "", "abc", {}):
        assert season_label_full(junk) == ""
        assert season_label_short(junk) == ""

"""Ktore sezony pobiera odswiezenie danych okregu - `app/settlement_seasons.py`."""

from datetime import date, datetime, timezone

from app.settlement_seasons import (
    in_scope,
    normalize_season_label,
    plan_seasons,
    season_of,
)

CURRENT = "2026/2027"
AVAILABLE = ["2026/2027", "2025/2026", "2024/2025", "2023/2024"]


def test_sezon_od_wrzesnia():
    assert season_of(date(2026, 9, 1)) == "2026/2027"
    assert season_of(date(2026, 8, 31)) == "2025/2026"
    assert season_of(datetime(2027, 3, 5, tzinfo=timezone.utc)) == "2026/2027"
    assert season_of(None) == ""


def test_etykiety_z_zprp():
    assert normalize_season_label("2026/2027") == "2026/2027"
    assert normalize_season_label("2026/27") == "2026/2027"
    assert normalize_season_label("Sezon 2025-2026") == "2025/2026"
    assert normalize_season_label("1999/00") == "1999/2000"
    # Nie para kolejnych lat - pomijamy, zamiast pobrac zle.
    assert normalize_season_label("2026/2028") == ""
    assert normalize_season_label("wszystkie") == ""


def test_pierwsze_odswiezenie_bierze_wszystko_od_poczatku():
    assert plan_seasons(available=AVAILABLE, completed=[], current=CURRENT, full_check=False) == AVAILABLE


def test_potem_tylko_biezacy_takze_dobowo():
    done = AVAILABLE
    assert plan_seasons(available=AVAILABLE, completed=done, current=CURRENT, full_check=False) == [CURRENT]
    # Nawet gdy jakiegos sezonu brakuje - zwykle odswiezenie go nie nadrabia.
    partial = ["2026/2027", "2025/2026"]
    assert plan_seasons(available=AVAILABLE, completed=partial, current=CURRENT, full_check=False) == [CURRENT]


def test_reczne_nadrabia_sezony_nigdy_niepobrane():
    partial = ["2026/2027", "2025/2026"]
    assert plan_seasons(available=AVAILABLE, completed=partial, current=CURRENT, full_check=True) == [
        "2026/2027",
        "2024/2025",
        "2023/2024",
    ]


def test_reczne_przy_komplecie_to_sam_biezacy():
    assert plan_seasons(available=AVAILABLE, completed=AVAILABLE, current=CURRENT, full_check=True) == [CURRENT]


def test_sezon_z_przyszlosci_nie_jest_pobierany():
    out = plan_seasons(
        available=["2027/2028", *AVAILABLE], completed=[], current=CURRENT, full_check=False
    )
    assert "2027/2028" not in out
    assert out[0] == CURRENT


def test_biezacy_nawet_gdy_zprp_go_nie_podaje():
    assert plan_seasons(available=["2025/2026"], completed=["2025/2026"], current=CURRENT, full_check=True) == [CURRENT]


def test_zakres_przebiegu():
    scope = {"2026/2027"}
    assert in_scope(date(2026, 10, 1), scope, current=CURRENT)
    assert not in_scope(date(2026, 5, 1), scope, current=CURRENT)
    # Mecz bez daty to biezacy sezon.
    assert in_scope(None, scope, current=CURRENT)
    assert in_scope(date(2010, 1, 1), None, current=CURRENT)

from datetime import datetime, timedelta, timezone

from app.settlement_runs import (
    MANUAL_COOLDOWN,
    RUN_STALE_AFTER,
    cooldown_left,
    run_is_active,
)

NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


def test_przebieg_w_toku_blokuje_drugi():
    assert run_is_active(NOW - timedelta(minutes=3), None, NOW) is True


def test_zakonczony_przebieg_nie_blokuje():
    assert run_is_active(NOW - timedelta(minutes=3), NOW - timedelta(minutes=1), NOW) is False


def test_trup_po_restarcie_nie_blokuje_okregu_na_zawsze():
    # Wiersz bez `finished_at`, ktorego nikt juz nie domknie.
    started = NOW - RUN_STALE_AFTER - timedelta(seconds=1)
    assert run_is_active(started, None, NOW) is False


def test_czas_bez_strefy_traktujemy_jak_utc():
    naive = (NOW - timedelta(minutes=2)).replace(tzinfo=None)
    assert run_is_active(naive, None, NOW) is True


def test_przerwa_po_udanym_przebiegu():
    left = cooldown_left(NOW - timedelta(minutes=4), True, NOW)
    assert left == MANUAL_COOLDOWN - timedelta(minutes=4)


def test_po_nieudanym_przebiegu_wolno_od_razu():
    # Czekanie dziesiec minut, zeby sprobowac jeszcze raz, niczego nie chroni.
    assert cooldown_left(NOW - timedelta(minutes=1), False, NOW) is None


def test_po_przerwie_wolno_znowu():
    assert cooldown_left(NOW - MANUAL_COOLDOWN - timedelta(seconds=1), True, NOW) is None


def test_bez_zadnego_przebiegu_nie_ma_przerwy():
    assert cooldown_left(None, None, NOW) is None

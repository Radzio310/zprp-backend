"""Faktury oczekujące na płatność: tryby, sumy rejestru, brak wpływu na saldo."""
from app import club_charges as C
from app import invoice_payment_rules as I
from app.invoice_payment_rules import pending_sum


def test_pay_mode_defaults_and_overrides():
    assert I.pay_mode(None) == "paid"
    assert I.pay_mode("PENDING") == "pending"
    assert I.pay_mode("zzz") == "paid"
    assert I.pay_mode("zzz", default="pending") == "pending"


def test_null_payment_status_is_paid():
    assert not I.is_pending(None)
    assert not I.is_pending("paid")
    assert I.is_pending("pending")


def test_register_totals_split_without_float_drift():
    items = [
        {"amount": 0.1, "payment_status": "pending"},
        {"amount": 0.2, "payment_status": "pending"},
        {"amount": 100.5, "payment_status": "paid"},
    ]
    totals = I.register_totals(items)
    assert totals == {"pending": 0.3, "paid": 100.5, "total": 100.8, "pending_count": 2, "paid_count": 1}


def test_pending_does_not_change_balance():
    # pending nie ma wpisu w saldzie: saldo liczy tylko wpłaty/wypłaty/obciążenia
    base = C.balance(paid_in=0.0, paid_out=0.0, charged=250.0)
    pending = {"c1": [{"id": 1, "amount": 100.0}], "c2": [{"id": 2, "amount": 50.0}]}
    assert pending_sum(pending, ["c1"]) == 100.0
    assert pending_sum(pending, ["c1", "c2"]) == 150.0
    assert pending_sum(pending, ["x"]) == 0.0
    assert base == C.balance(paid_in=0.0, paid_out=0.0, charged=250.0) == -250.0
    # po potwierdzeniu wpłata wchodzi do salda
    assert C.balance(paid_in=100.0, paid_out=0.0, charged=250.0) == -150.0


def test_trash_days_left_counts_down_and_clamps():
    from datetime import datetime, timedelta, timezone

    now = datetime(2026, 10, 20, tzinfo=timezone.utc)
    assert I.trash_days_left(None, now) == I.TRASH_DAYS
    assert I.trash_days_left(now, now) == 30
    assert I.trash_days_left(now - timedelta(days=10), now) == 20
    assert I.trash_days_left(now - timedelta(days=45), now) == 0

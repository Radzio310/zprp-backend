from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from app.release_tablets import (
    CLEAR, auto_promotion_due, effective_required_tablets, since_transition,
    tablet_fields, tablets_due_at,
)

W = ZoneInfo("Europe/Warsaw")


def w(*a):
    return datetime(*a, tzinfo=W)


def row(since, **kw):
    base = {"required": True, "available_ios": True, "available_android": True,
            "required_tablets": False, "required_tablets_auto": True,
            "required_tablets_source": None, "required_since": since}
    base.update(kw)
    return base


def test_deploy_monday_noon_exact_is_due_next_monday():
    # 2026-11-23 to poniedziałek; dokładnie 7 dób później = 30.11 12:00
    assert tablets_due_at(w(2026, 11, 23, 12, 0)) == w(2026, 11, 30, 12, 0)


def test_week_ends_monday_1159_and_1201():
    assert tablets_due_at(w(2026, 11, 23, 11, 59)) == w(2026, 11, 30, 12, 0)
    assert tablets_due_at(w(2026, 11, 23, 12, 1)) == w(2026, 12, 7, 12, 0)


def test_midweek_deploy_goes_to_following_monday():
    # środa 25.11 -> próg 2.12 (środa) -> poniedziałek 7.12
    assert tablets_due_at(w(2026, 11, 25, 10, 0)) == w(2026, 12, 7, 12, 0)


def test_dst_change_keeps_noon_warsaw():
    # zmiana na czas zimowy 25.10.2026; próg 26.10 (pon.) 11:00 -> 12:00 CET
    due = tablets_due_at(w(2026, 10, 19, 11, 0))
    assert due == w(2026, 10, 26, 12, 0)
    assert due.utcoffset().total_seconds() == 3600
    # lato: 12:00 CEST = 10:00 UTC
    assert tablets_due_at(w(2026, 6, 1, 8, 0)).astimezone(timezone.utc).hour == 10


def test_effective_before_and_after_due():
    r = row(w(2026, 11, 23, 12, 1))
    assert not effective_required_tablets(r, w(2026, 11, 30, 12, 0))
    assert effective_required_tablets(r, w(2026, 12, 7, 12, 0))
    assert auto_promotion_due(r, w(2026, 12, 7, 12, 0))


def test_naive_since_treated_as_utc():
    r = row(datetime(2026, 11, 23, 11, 0))
    assert effective_required_tablets(r, datetime(2026, 12, 1, tzinfo=timezone.utc))


def test_missing_platform_never_auto():
    r = row(w(2026, 11, 1, 12, 0), available_ios=False)
    assert not effective_required_tablets(r, w(2027, 1, 1, 12, 0))
    assert tablet_fields(r, w(2027, 1, 1, 12, 0))["tablets_due_at"] is None


def test_paused_auto_never_applies():
    r = row(w(2026, 11, 1, 12, 0), required_tablets_auto=False)
    assert not effective_required_tablets(r, w(2027, 1, 1, 12, 0))
    assert not auto_promotion_due(r, w(2027, 1, 1, 12, 0))
    assert tablet_fields(r, w(2027, 1, 1, 12, 0))["tablets_due_at"] is None


def test_admin_flag_wins_and_not_required_is_false():
    assert effective_required_tablets(row(None, required_tablets=True), w(2026, 11, 1, 0, 0))
    assert not effective_required_tablets(row(w(2026, 1, 1, 0, 0), required=False), w(2027, 1, 1, 0, 0))


def test_fields_shape_pending():
    f = tablet_fields(row(w(2026, 11, 23, 12, 1)), w(2026, 11, 24, 0, 0))
    assert f["required_tablets"] is False and f["required_tablets_auto"] is True
    assert f["tablets_due_at"].startswith("2026-12-07T12:00:00+01:00")


def test_since_transition():
    now = w(2026, 11, 25, 9, 0)
    off = row(None, available_android=False)
    on = row(None)
    assert since_transition(off, on, now) == now
    assert since_transition(row(w(2026, 11, 1, 0, 0)), on, now) is None
    assert since_transition(row(w(2026, 11, 1, 0, 0)), off, now) is CLEAR
    assert since_transition(off, off, now) is None


def test_backfill_cases():
    from app.release_tablets import backfill_values
    now = w(2026, 11, 25, 12, 0)
    old = row(None, updated_at=w(2026, 10, 1, 10, 0))
    got = backfill_values(old, now)
    assert got["required_tablets"] is True and got["required_tablets_source"] == "auto"
    fresh = row(None, updated_at=w(2026, 11, 24, 10, 0))
    assert list(backfill_values(fresh, now)) == ["required_since"]
    paused = row(None, updated_at=w(2026, 10, 1, 10, 0), required_tablets_auto=False)
    assert list(backfill_values(paused, now)) == ["required_since"]
    assert backfill_values(row(w(2026, 10, 1, 10, 0), updated_at=w(2026, 10, 1, 10, 0)), now) is None
    assert backfill_values(row(None, updated_at=w(2026, 10, 1), available_ios=False), now) is None

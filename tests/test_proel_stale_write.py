"""Starszy zapis tego samego urzadzenia nie cofa pola (liczba widzow)."""
from __future__ import annotations

from app.proel_fields import is_stale_own_write


def entry(cts=None, install="tel-A"):
    e = {"v": 150, "rev": 3, "by": {"install": install}}
    if cts is not None:
        e["cts"] = cts
    return e


def test_older_write_from_same_device_is_stale():
    assert is_stale_own_write(entry(cts=2000), 1000, "tel-A") is True


def test_newer_or_equal_write_passes():
    assert is_stale_own_write(entry(cts=2000), 2000, "tel-A") is False
    assert is_stale_own_write(entry(cts=2000), 3000, "tel-A") is False


def test_other_device_is_never_compared_by_clock():
    assert is_stale_own_write(entry(cts=2000, install="tel-B"), 1000, "tel-A") is False


def test_missing_marks_keep_old_behaviour():
    assert is_stale_own_write(None, 1000, "tel-A") is False
    assert is_stale_own_write(entry(cts=None), 1000, "tel-A") is False
    assert is_stale_own_write(entry(cts=2000), None, "tel-A") is False
    assert is_stale_own_write(entry(cts=2000), 1000, "") is False
    assert is_stale_own_write(entry(cts="zle"), 1000, "tel-A") is False

"""Minuta meczu nigdy poza czasem gry (18.11.2026): 60:00 = 60', nie 61'; mecz 2 x 25: 50:00 = 50'."""

from app.match_minute import match_minute

M = 60_000


def test_mecz_2x30():
    assert match_minute(60 * M, 30 * M) == 60
    assert match_minute(60 * M + 400, 30 * M) == 60
    assert match_minute(59 * M + 59_000, 30 * M) == 60
    assert match_minute(30 * M, 30 * M) == 30
    assert match_minute(30 * M, 30 * M, 2) == 31
    assert match_minute(40 * M + 12_000, 30 * M) == 41
    assert match_minute(0, 30 * M) == 1


def test_mecz_2x25_i_dogrywka():
    assert match_minute(50 * M, 25 * M) == 50
    assert match_minute(25 * M, 25 * M) == 25
    assert match_minute(62 * M + 30_000, 30 * M) == 63
    assert match_minute(65 * M, 30 * M) == 65


def test_bez_dlugosci_polowy():
    assert match_minute(60 * M) == 60
    assert match_minute(50 * M) == 50
    assert match_minute(59 * M + 1) == 60
    assert match_minute(None) == 1

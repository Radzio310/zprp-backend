"""Okresy wypłat sędziego (`settlement_payout_ranges`) - 08.10.2026."""

from datetime import date

from app import settlement_payout_ranges as P

SL = [
    {"id": "sl-2026-10-05", "date_from": "2026-09-07", "date_to": "2026-10-04", "payout_date": "2026-10-05"},
    {"id": "sl-2026-11-02", "date_from": "2026-10-05", "date_to": "2026-11-01", "payout_date": "2026-11-02"},
    {"id": "off", "date_from": "2026-11-02", "date_to": "2026-12-06", "payout_date": "2026-12-07", "enabled": False},
]


def test_sezon_od_sierpnia_do_lipca():
    assert P.season_span(2026) == (date(2026, 8, 1), date(2027, 7, 31))


def test_okresy_okregu_i_luki_w_miesiacach():
    out = P.payout_ranges(SL, date(2026, 8, 1), date(2026, 12, 31))
    ids = [(r["id"], r["kind"], r["from"].isoformat(), r["to"].isoformat()) for r in out]
    assert ids == [
        ("m:2026-08", "month", "2026-08-01", "2026-08-31"),
        ("g:2026-09-01", "gap", "2026-09-01", "2026-09-06"),
        ("sl-2026-10-05", "period", "2026-09-07", "2026-10-04"),
        ("sl-2026-11-02", "period", "2026-10-05", "2026-11-01"),
        # Wyłączony okres nie liczy się - jego dni wracają do miesięcy.
        ("g:2026-11-02", "gap", "2026-11-02", "2026-11-30"),
        ("m:2026-12", "month", "2026-12-01", "2026-12-31"),
    ]
    # Okres należy do miesiąca wypłaty - tak klucz ma panel.
    assert (out[2]["year"], out[2]["month"]) == (2026, 10)


def test_okreg_bez_okresow_to_miesiace():
    out = P.payout_ranges([], date(2026, 8, 1), date(2027, 7, 31))
    assert len(out) == 12 and all(r["kind"] == "month" for r in out)
    assert P.range_of(out, date(2027, 2, 14))["id"] == "m:2027-02"
    assert P.range_of(out, None) is None


def test_okres_wystajacy_poza_sezon_wchodzi_caly():
    out = P.payout_ranges(
        [{"id": "x", "date_from": "2026-07-20", "date_to": "2026-08-10", "payout_date": "2026-08-11"}],
        date(2026, 8, 1),
        date(2026, 8, 31),
    )
    assert [(r["id"], r["from"].isoformat()) for r in out] == [("x", "2026-07-20"), ("g:2026-08-11", "2026-08-11")]


def test_podatek_okresu_rozdzielony_na_mecze_co_do_grosza():
    parts = P.share_by_gross([117.0, 117.0, 60.0], 58.80, 28)
    assert round(sum(c for c, _ in parts), 2) == 58.80
    assert sum(t for _, t in parts) == 28
    assert parts[0][0] >= parts[2][0]
    assert P.share_by_gross([], 10, 1) == []
    assert P.share_by_gross([0, 0], 0, 0) == [(0.0, 0), (0.0, 0)]

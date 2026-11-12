"""Odchudzanie /offtimes/all: okno dat i tryb lite (liść, bez bazy)."""
from __future__ import annotations

import json

from app.offtime_slim import parse_window, slim_entries


def match_server(n, day):
    return {"id": f"zprp-match:{n}", "source": "ZPRP_MATCH_SYNC", "source_match_id": str(n),
            "from": f"{day}T10:00:00+00:00", "to": f"{day}T12:00:00+00:00", "info": "A - B",
            "location": "Hala", "is_manual": False, "isMatch": True, "source_synced_at": "x"}


def match_phone(n, day):
    return {"id": str(n), "isMatch": True, "from": f"{day}T10:00:00+00:00",
            "to": f"{day}T12:00:00+00:00", "info": "A - B", "series": {"x": 1}, "updated_at": "z"}


def test_bez_parametrow_nic_sie_nie_zmienia():
    assert parse_window(None, None) is None
    items = [match_server(1, "2026-11-20"), {"x": 1}]
    assert slim_entries(items, None) == items


def test_okno_odrzuca_poza_zakresem_i_zostawia_zahaczajace():
    w = parse_window("2026-11-10", "2026-11-20")
    inside = {"id": "a", "from": "2026-11-15", "to": "2026-11-16"}
    spans = {"id": "b", "from": "2026-11-01", "to": "2026-12-01"}
    before = {"id": "c", "from": "2025-01-01", "to": "2025-01-02"}
    after = {"id": "d", "from": "2027-05-01"}
    nodate = {"id": "e"}
    got = [i["id"] for i in slim_entries([inside, spans, before, after, nodate], w)]
    assert got == ["a", "b", "e"]


def test_zle_daty_okna_to_brak_okna():
    assert parse_window("śmieć", "") is None
    assert parse_window("2026-11-10", None)[1] is None


def test_lite_dedup_meczu_z_telefonu_i_monitora():
    items = [match_phone(123, "2026-11-20"), match_server(123, "2026-11-20"), match_server(124, "2026-11-21")]
    got = slim_entries(items, None, lite=True)
    assert [g["source_match_id"] for g in got] == ["123", "124"]
    assert set(got[0]) == {"id", "source_match_id", "from", "isMatch"}


def test_lite_zero_wiodace_to_ten_sam_mecz():
    got = slim_entries([match_phone("0123", "2026-11-20"), match_server(123, "2026-11-20")], None, lite=True)
    assert len(got) == 1


def test_lite_zwykly_wpis_bez_pol_niepotrzebnych():
    item = {"id": "u1", "from": "2026-11-20", "to": "2026-11-21", "info": "i", "is_manual": True,
            "updated_at": "z", "series": {}, "category_name": "URLOP", "location": ""}
    got = slim_entries([item], None, lite=True)[0]
    assert got == {"from": "2026-11-20", "to": "2026-11-21", "id": "u1", "info": "i", "category_name": "URLOP"}


def test_lite_wpis_obsadowego_zostaje_w_calosci_ale_w_oknie():
    a = {"id": "x", "locked": True, "source": "OBSADOWY_ASSIGNED", "from": "2026-11-15", "assigned_by": {"a": 1}}
    old = dict(a, id="y", **{"from": "2020-01-01"})
    got = slim_entries([a, old], parse_window("2026-11-10", "2026-11-20"), lite=True)
    assert got == [a]


def test_lite_jest_mniejszy():
    items = [match_phone(i, "2026-11-20") for i in range(50)] + [match_server(i, "2026-11-20") for i in range(50)]
    full = len(json.dumps(items))
    lite = len(json.dumps(slim_entries(items, None, lite=True)))
    assert lite < full / 3

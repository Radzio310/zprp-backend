from __future__ import annotations

import importlib
import pathlib
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock


def _load_sync_module():
    # app.db tworzy przy imporcie cały produkcyjny schemat, który korzysta z
    # typów postgresowych. Te testy są czyste i bazy nie potrzebują.
    saved_db = sys.modules.get("app.db")
    saved_module = sys.modules.get("app.province_offtime_sync")
    sys.modules["app.db"] = MagicMock()
    try:
        sys.modules.pop("app.province_offtime_sync", None)
        return importlib.import_module("app.province_offtime_sync")
    finally:
        if saved_db is None:
            sys.modules.pop("app.db", None)
        else:
            sys.modules["app.db"] = saved_db
        if saved_module is None:
            sys.modules.pop("app.province_offtime_sync", None)
        else:
            sys.modules["app.province_offtime_sync"] = saved_module


sync = _load_sync_module()


def _load_silesia_module():
    saved_db = sys.modules.get("app.db")
    saved_module = sys.modules.get("app.silesia")
    transient_names = ("app.notify_utils", "app.release_stories")
    saved_transients = {name: sys.modules.get(name) for name in transient_names}
    sys.modules["app.db"] = MagicMock()
    try:
        sys.modules.pop("app.silesia", None)
        for name in transient_names:
            sys.modules.pop(name, None)
        return importlib.import_module("app.silesia")
    finally:
        if saved_db is None:
            sys.modules.pop("app.db", None)
        else:
            sys.modules["app.db"] = saved_db
        if saved_module is None:
            sys.modules.pop("app.silesia", None)
        else:
            sys.modules["app.silesia"] = saved_module
        for name, module in saved_transients.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


silesia = _load_silesia_module()


def test_only_active_valid_offtimes_enter_the_snapshot():
    parsed = {
        "offtimes": [
            {
                "lp": 1,
                "id": "871",
                "date_from": "2026-09-03",
                "date_to": "2026-09-05",
                "info": "Wyjazd",
                "created_by": "[komisja] 2026-09-01 10:00:00",
                "history": None,
                "is_deleted": False,
            },
            {
                "lp": 2,
                "id": "872",
                "date_from": "2026-09-10",
                "date_to": "2026-09-10",
                "info": "Usunięta",
                "is_deleted": True,
            },
            {
                "lp": 3,
                "id": "873",
                "date_from": "0000-00-00",
                "date_to": "0000-00-00",
                "info": "Niepoprawna",
                "is_deleted": False,
            },
        ]
    }
    entries = sync.central_entries_from_parsed(
        "5124",
        parsed,
        synced_at=datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc),
    )

    assert len(entries) == 1
    assert entries[0]["id"] == "zprp-central:5124:871"
    assert entries[0]["source"] == "ZPRP_CENTRAL_SYNC"
    assert entries[0]["source_id"] == "871"
    assert entries[0]["category_name"] == "BAZOWA"
    assert entries[0]["is_global"] is True
    # Początek i koniec dnia są liczone w Europe/Warsaw, nie jako naiwne UTC.
    assert entries[0]["from"] == "2026-09-02T22:00:00+00:00"
    assert entries[0]["to"] == "2026-09-05T21:59:59.999999+00:00"


def test_missing_source_id_gets_a_stable_fingerprint():
    parsed = {
        "offtimes": [
            {
                "lp": 1,
                "id": "",
                "date_from": "03.09.2026",
                "date_to": "03.09.2026",
                "info": "Szkolenie",
                "created_by": "[komisja] 2026-09-01 10:00:00",
                "is_deleted": False,
            }
        ]
    }
    first = sync.central_entries_from_parsed("7", parsed)[0]["id"]
    second = sync.central_entries_from_parsed("7", parsed)[0]["id"]
    assert first == second
    assert first.startswith("zprp-central:7:fp-")


def test_default_interval_is_two_hours_and_uses_railway_accounts():
    source = (
        pathlib.Path(__file__).resolve().parents[1]
        / "app"
        / "province_offtime_sync.py"
    ).read_text(encoding="utf-8")
    assert 'ZPRP_OFFTIME_SYNC_SECONDS", "7200"' in source
    assert "configured_provinces()" in source
    assert "province_match_sync_leases" in source


def test_offtime_parser_exposes_real_source_id():
    from app.zprp.officials import _parse_offtime_rows

    html = """
    <table id="tabelka">
      <tr><td colspan="5">Jan Kowalski</td></tr>
      <tr>
        <td title="[komisja] 2026-09-01 10:00:00">1.</td>
        <td>2026-09-03</td><td>2026-09-05</td><td>Wyjazd</td>
        <td><input type="hidden" name="IdOffT" value="991" /></td>
      </tr>
    </table>
    """
    parsed = _parse_offtime_rows(html)
    assert parsed["summary"] == {"total": 1, "deleted": 0, "active": 1}
    assert parsed["offtimes"][0]["id"] == "991"


def test_phone_payload_cannot_overwrite_central_snapshot():
    district = {
        "id": "district-1",
        "category_name": "SZKOLENIE",
        "is_global": False,
    }
    stale_central = {
        "id": "old-central",
        "category_name": "BAZOWA",
        "is_global": True,
        "isMatch": False,
    }
    match = {
        "id": "match-1",
        "category_name": "MECZ",
        "is_global": True,
        "isMatch": True,
    }

    cleaned = silesia._without_client_central(
        [district, stale_central, match]
    )
    assert cleaned == [district, match]


def test_new_source_marker_is_always_server_owned():
    assert silesia._without_client_central(
        [{"id": "x", "source": "ZPRP_CENTRAL_SYNC"}]
    ) == []

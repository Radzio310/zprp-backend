from datetime import date, datetime, timezone
from app.okreg_rates_manifest import build_rates_manifest


def row(**overrides):
    return dict(id=1, province="ŚLĄSKIE", enabled=True, valid_from=None, valid_to=None,
                updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc), **overrides)


def test_stable_between_days_without_changes():
    assert build_rates_manifest([row()], date(2026, 1, 1)) == build_rates_manifest([row()], date(2026, 1, 2))


def test_revision_tracks_edit_disable_delete_and_new_versions():
    original = row()
    initial = build_rates_manifest([original], date(2026, 1, 1))["revision"]
    for changed in [[], [{**original, "enabled": False}], [{**original, "updated_at": datetime(2026, 1, 2, tzinfo=timezone.utc)}], [original, {**original, "id": 2}]]:
        assert build_rates_manifest(changed, date(2026, 1, 1))["revision"] != initial


def test_activation_and_expiry_without_an_edit():
    item = {**row(), "valid_from": date(2026, 2, 1), "valid_to": date(2026, 2, 28)}
    before = build_rates_manifest([item], date(2026, 1, 31))
    active = build_rates_manifest([item], date(2026, 2, 1))
    after = build_rates_manifest([item], date(2026, 3, 1))
    assert active["provinces"]["ŚLĄSKIE"]["active_id"] == 1
    assert before["revision"] != active["revision"] != after["revision"]
    assert after["provinces"]["ŚLĄSKIE"]["active_id"] is None


def test_order_independent_and_changes_local_to_province():
    first = row()
    second = {**row(), "id": 2, "province": "ŁÓDZKIE"}
    manifest = build_rates_manifest([first, second], date(2026, 1, 1))
    assert manifest == build_rates_manifest([second, first], date(2026, 1, 1))
    edited = build_rates_manifest([first, {**second, "enabled": False}], date(2026, 1, 1))
    assert manifest["provinces"]["ŚLĄSKIE"] == edited["provinces"]["ŚLĄSKIE"]

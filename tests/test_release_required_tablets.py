import pytest

try:
    from app.release_stories import filter_rows_for_device
except Exception as exc:  # noqa: BLE001 - import łączy się z bazą
    pytest.skip(f"Wymaga Postgresa: {type(exc).__name__}", allow_module_level=True)

ROWS = [
    {"version": "1.0.0", "required": False, "required_tablets": False},
    {"version": "1.1.0", "required": True, "required_tablets": False},
    {"version": "1.2.0", "required": True, "required_tablets": True},
]


def test_phone_sees_everything():
    assert filter_rows_for_device(ROWS, "phone") == ROWS


def test_tablet_skips_required_without_flag():
    got = [r["version"] for r in filter_rows_for_device(ROWS, "tablet")]
    assert got == ["1.0.0", "1.2.0"]

from app.push.device_policy import device_allowed, is_dev_device


def test_dev_build_is_recognized_by_application_id():
    row = {"app_id": "com.radzio.RefHandballApp.dev"}
    assert is_dev_device(row) is True
    assert device_allowed(row, allow_dev=False) is False
    assert device_allowed(row, allow_dev=True) is True


def test_store_build_is_always_allowed():
    row = {"app_id": "com.radzio.RefHandballApp"}
    assert is_dev_device(row) is False
    assert device_allowed(row, allow_dev=False) is True


def test_legacy_device_without_application_id_is_treated_as_store():
    # Starsze wydania produkcyjne nie znały pola app_id. Nie wolno ich odciąć.
    assert device_allowed({"app_id": None}, allow_dev=False) is True
    assert device_allowed({}, allow_dev=False) is True

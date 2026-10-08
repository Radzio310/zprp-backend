"""SMS z wynikiem meczu - reguła konfiguracji (08.10.2026)."""

import pytest

from app import sms_config_rules as S


def test_numer_do_zapisu():
    assert S.normalize_phone("+48 604 583 150") == "604583150"
    assert S.normalize_phone("604-583-150") == "604583150"
    assert S.normalize_phone("0048604583150") == "604583150"
    assert S.normalize_phone("+44 7700 900123") == "+447700900123"
    assert S.phone_problem("60458") is not None
    assert S.phone_problem("604583150") is None


def test_domyslne_centralne_i_dolny_slask():
    central = S.default_scope(S.CENTRAL)
    assert central["enabled"] and central["groups"][0]["phone"] == "604583150"
    assert S.group_for(central, "LCM")["phone"] == "604583150"
    assert S.group_for(central, "JM") is None
    ds = S.default_scope("DOLNOSLASKIE")
    assert ds["template"] == S.TEMPLATE_PAIR
    assert S.group_for(ds, "IIIK")["phone"] == "602120659"
    # Okręg bez zapisu - wyłączony.
    assert S.group_for(S.default_scope("SLASKIE"), "IIIM") is None


def test_walidacja_wlaczonego_zakresu():
    with pytest.raises(ValueError):
        S.clean_scope({"enabled": True, "groups": []}, label="ŚLĄSKIE")
    with pytest.raises(ValueError):
        S.clean_scope({"enabled": True, "groups": [{"name": "III liga", "categories": ["IIIM"], "phone": ""}]}, label="X")
    with pytest.raises(ValueError):
        S.clean_scope({"enabled": True, "template": "inny", "groups": []}, label="X")
    # Wyłączony może być w trakcie ustawiania.
    draft = S.clean_scope({"enabled": False, "groups": [{"name": "", "categories": ["XX", "IIIM"], "phone": ""}]}, label="X")
    assert draft["groups"] == [{"name": "Grupa 1", "categories": ["IIIM"], "phone": ""}]


def test_pierwsza_grupa_z_kategoria_wygrywa():
    scope = S.clean_scope(
        {
            "enabled": True,
            "template": "pair",
            "groups": [
                {"name": "III liga", "categories": ["IIIM", "IIIK"], "phone": "600 000 001"},
                {"name": "Wszystko", "categories": ["IIIM", "JM"], "phone": "600000002"},
            ],
        },
        label="X",
    )
    assert S.group_for(scope, "IIIM")["phone"] == "600000001"
    assert S.group_for(scope, "JM")["phone"] == "600000002"

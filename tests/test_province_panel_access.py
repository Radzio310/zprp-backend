from pathlib import Path

from app.province_panel_access import (
    PANEL_PROVINCE_JUDGES,
    VipRecord,
    choose_vip_row,
    panel_write_refusal,
    vip_covers_province,
)

APP = Path(__file__).resolve().parents[1] / "app"


def test_existing_permission_record_wins_over_case_duplicate_without_permissions():
    rows = [
        {"username": "WOJ", "permissions_json": {}},
        {"username": "woj", "permissions_json": {"settlements": True}},
    ]
    assert choose_vip_row(rows, "WOJ")["username"] == "woj"


def test_extra_province_is_in_scope():
    assert vip_covers_province(
        "SLASKIE", {"provinces": ["OPOLSKIE"]}, "Opolskie"
    )


def test_province_judges_permission_allows_write_in_scope():
    vip = VipRecord(
        username="district",
        province="SLASKIE",
        permissions={"province_judges": True},
    )
    assert panel_write_refusal(
        panel=PANEL_PROVINCE_JUDGES,
        province="SLASKIE",
        account_type="org",
        judge_id="",
        login="district",
        is_admin=False,
        vip=vip,
    ) == ""


def test_private_settlement_reads_have_server_gate():
    source = (APP / "province_settlements.py").read_text(encoding="utf-8")
    assert source.count("Depends(panel_read_gate(PANEL_SETTLEMENTS") >= 4


def test_province_judges_writes_require_jwt():
    source = (APP / "province_judges.py").read_text(encoding="utf-8")
    assert source.count("payload: dict = Depends(get_jwt_payload)") == 4


def test_vip_admin_crud_requires_application_admin():
    source = (APP / "baza_vips.py").read_text(encoding="utf-8")
    assert source.count("Depends(require_app_admin)") == 5

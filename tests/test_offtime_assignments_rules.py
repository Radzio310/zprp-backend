"""Reguły niedyspozycji wpisywanych sędziom (liść bez bazy)."""
import pytest

from app.offtime_assignments_rules import (
    ASSIGNED_SOURCE,
    assigner_role,
    build_item,
    date_range_label,
    normalize_fields,
    push_data,
    push_text,
    short_name,
    strip_assigned,
)

OBSADOWY = {"Obsadowy": True}


def role(judge="5", province="ŚLĄSKIE", **kw):
    base = dict(
        judge_id=judge, province=province, admin_ids=["999"],
        calendar_master_ids=["7"], judge_province="SLASKIE", badges_raw=OBSADOWY,
    )
    base.update(kw)
    return assigner_role(**base)


def test_obsadowy_wlasnego_okregu_przechodzi_mimo_ogonkow():
    assert role() == "obsadowy"


def test_obsadowy_cudzego_okregu_nie_przechodzi():
    assert role(province="DOLNOŚLĄSKIE") is None


def test_obsadowy_z_napisowa_odznaka_przechodzi():
    assert role(badges_raw='["Obsadowy"]') == "obsadowy"


def test_wylaczona_albo_inna_odznaka_nie_daje_prawa():
    assert role(badges_raw={"Obsadowy": False}) is None
    assert role(badges_raw=["Delegat"]) is None


def test_zwykly_sedzia_nie_wpisuje():
    assert role(badges_raw={}) is None


def test_calendar_master_tylko_z_listy_okregu():
    assert role(judge="7", badges_raw={}, judge_province="OPOLSKIE") == "calendar_master"
    assert role(judge="8", badges_raw={}) is None


def test_admin_wszedzie():
    assert role(judge="999", province="POMORSKIE", judge_province=None, badges_raw=None) == "admin"


def test_pusty_numer_nic_nie_znaczy():
    assert role(judge="") is None


def test_strip_wycina_locked_znacznik_i_id_usunietych():
    blob = [
        {"id": "a", "locked": True},
        {"id": "b", "source": ASSIGNED_SOURCE},
        {"id": "gone"},
        {"id": "mine", "from": "2026-11-01T10:00:00Z"},
        "dziwny",
    ]
    out = strip_assigned(blob, ["gone"])
    assert [e["id"] if isinstance(e, dict) else e for e in out] == ["mine", "dziwny"]


def test_strip_nie_listy_daje_pusta():
    assert strip_assigned(None, []) == []


def test_item_ma_ksztalt_kontraktu():
    item = build_item({
        "id": "x", "judge_id": "5", "from": "2026-11-14T23:00:00.000Z",
        "to": "2026-11-15T22:59:59.000Z", "info": None, "category_id": "c",
        "category_name": "Praca", "category_color": "#f00", "created_by": "7",
        "created_by_name": "Jan Kowalski", "created_by_role": "obsadowy",
        "created_at": None, "updated_at": None,
    })
    assert item["locked"] is True and item["id"] == "x" and item["judge_id"] == "5"
    assert item["assigned_by"] == {"judge_id": "7", "name": "Jan Kowalski", "role": "obsadowy"}
    assert item["entry_type"] == "UNAVAIL" and item["color"] == "#f00"


def test_nazwisko_skrocone_w_obu_kolejnosciach():
    assert short_name("Jan Kowalski") == "J. Kowalski"
    assert short_name("KOWALSKI Jan") == "J. Kowalski"
    assert short_name("") == ""


@pytest.mark.parametrize("a,b,txt", [
    ("2026-11-14T23:00:00Z", "2026-11-15T22:59:59Z", "15.11"),
    ("2026-11-14T23:00:00Z", "2026-11-16T22:59:59Z", "15-16.11"),
    ("2026-11-29T23:00:00Z", "2026-12-02T22:59:59Z", "30.11-2.12"),
    ("2026-11-15T10:00:00Z", None, "15.11"),
])
def test_zakres_dat(a, b, txt):
    assert date_range_label(a, b) == txt


def test_push_brzmi_jak_w_zleceniu():
    title, body = push_text(
        "created", role="obsadowy", start="2026-11-14T23:00:00Z",
        end="2026-11-16T22:59:59Z", category="Praca", author_name="Jan Kowalski",
    )
    assert body == "Obsadowy wpisał Ci niedyspozycję 15-16.11 · Praca · J. Kowalski"
    assert "usunął" in push_text("deleted", role="admin", start="2026-11-15T10:00:00Z",
                                 end=None, category="", author_name="")[1]


def test_push_data_niesie_dzien_i_rodzaj():
    data = push_data(item_id="x", province="ŚLĄSKIE", start="2026-11-14T23:00:00Z", action="created")
    assert data["kind"] == "offtime_assigned" and data["day"] == "2026-11-15"
    assert all(isinstance(v, str) for v in data.values())


def test_zly_zakres_odrzucony():
    with pytest.raises(ValueError):
        normalize_fields({"from": "2026-11-16T10:00:00Z", "to": "2026-11-15T10:00:00Z"})
    with pytest.raises(ValueError):
        normalize_fields({"from": ""})
    assert normalize_fields({"from": "2026-11-15T10:00:00Z", "info": "  "})["info"] is None

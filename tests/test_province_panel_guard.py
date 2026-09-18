"""
Bramka zapisów w panelu klubów i Obsadzie (BAZA_web).

Trzy warstwy, bo każda psuje się inaczej:
  - reguła w liściu (kto może) - bez bazy,
  - `ensure_panel_write` - okres przejściowy i odmowa z powodem,
  - zależność routera przez prawdziwe żądania HTTP - że odczyty są wolne, że
    okręg przychodzi z adresu albo z treści JSON i że trasa po bramce dalej
    dostaje swoją treść.
Na końcu wiązania: oba routery MAJĄ bramkę, czytane ze źródła.
"""

from __future__ import annotations

import ast
import logging
import pathlib

import pytest
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app import province_panel_guard as G
from app.deps import get_optional_jwt_payload
from app.province_guard import STRICT_ENV
from app.province_panel_access import (
    NO_ACCOUNT,
    NO_PROVINCE,
    PANEL_ASSIGNMENTS,
    PANEL_SETTLEMENTS,
    VipRecord,
    panel_write_refusal,
    vip_covers_province,
    vip_has_panel,
)

SLASK = VipRecord("ksdzpr", "ŚLĄSKIE", {"settlements": True})


def refusal(**kw):
    base = dict(
        panel=PANEL_SETTLEMENTS,
        province="ŚLĄSKIE",
        account_type="org",
        judge_id="",
        login="ksdzpr",
        is_admin=False,
        vip=SLASK,
    )
    base.update(kw)
    return panel_write_refusal(**base)


class TestReguly:
    def test_vip_z_uprawnieniem_we_wlasnym_okregu(self):
        assert refusal() == ""

    def test_wojewodztwo_bez_ogonkow_to_ten_sam_okreg(self):
        assert refusal(province="SLASKIE") == ""

    def test_samo_wojewodztwo_nie_wystarcza(self):
        vip = VipRecord("ksdzpr", "ŚLĄSKIE", {"district_unavailability": True})
        reason = refusal(vip=vip)
        assert "Rozliczenia" in reason and "administrator" in reason

    def test_uprawnienie_obsady_nie_otwiera_rozliczen(self):
        # Kto układa obsadę, nie musi widzieć pieniędzy klubów - osobne flagi.
        vip = VipRecord("ksdzpr", "ŚLĄSKIE", {"assignments": True})
        assert refusal(vip=vip) != ""
        assert refusal(vip=vip, panel=PANEL_ASSIGNMENTS) == ""

    def test_admin_vip_ma_kazdy_panel_ale_tylko_w_swoim_okregu(self):
        vip = VipRecord("boss", "ŚLĄSKIE", {"admin": True})
        assert refusal(vip=vip) == ""
        assert refusal(vip=vip, panel=PANEL_ASSIGNMENTS) == ""
        assert refusal(vip=vip, province="MAZOWIECKIE") != ""

    def test_cudzy_okreg_z_powodem(self):
        reason = refusal(province="MAZOWIECKIE")
        assert "SLASKIE" in reason and "MAZOWIECKIE" in reason

    def test_dodatkowe_okregi_z_listy_uprawnien(self):
        vip = VipRecord("ksdzpr", "ŚLĄSKIE", {"settlements": True, "provinces": ["Opolskie"]})
        assert refusal(vip=vip, province="OPOLSKIE") == ""

    def test_konto_bez_rekordu_vip(self):
        reason = refusal(vip=None)
        assert "ksdzpr" in reason and "rekordu VIP" in reason

    def test_sedzia_admin_przechodzi(self):
        assert refusal(account_type="judge", judge_id="999", login="999", is_admin=True, vip=None) == ""

    def test_sedzia_bez_admina_odmowa(self):
        reason = refusal(account_type="judge", judge_id="7", login="7", vip=None)
        assert "administrator" in reason

    def test_nierozpoznane_konto(self):
        assert refusal(account_type="unknown", login="x", vip=None) == NO_ACCOUNT

    def test_bez_okregu_nie_ma_czego_sprawdzic(self):
        assert refusal(province="") == NO_PROVINCE

    def test_pomocnicze(self):
        assert vip_has_panel('{"settlements": true}', PANEL_SETTLEMENTS)
        assert not vip_has_panel("zepsuty json", PANEL_SETTLEMENTS)
        assert not vip_covers_province("ŚLĄSKIE", {}, "")


@pytest.fixture
def lookup(monkeypatch):
    """Konta: ksdzpr (VIP Śląska z Rozliczeniami), 999 (sędzia-admin)."""
    monkeypatch.delenv(STRICT_ENV, raising=False)

    async def fake(payload):
        if payload.get("judge_id"):
            return payload["judge_id"] == "999", None
        if payload.get("sub") == "ksdzpr":
            return False, SLASK
        return False, None

    monkeypatch.setattr(G, "_lookup", fake)


def org(login="ksdzpr"):
    return {"sub": login, "judge_id": "", "account_type": "org"}


class TestBramki:
    async def test_bez_tokenu_przechodzi_z_sladem_w_logu(self, lookup, caplog):
        with caplog.at_level(logging.WARNING):
            await G.ensure_panel_write(None, province="ŚLĄSKIE", panel=PANEL_SETTLEMENTS, action="Zapis")
        assert "zapis bez tokenu" in caplog.text

    async def test_tryb_scisly_zamyka_furtke(self, lookup, monkeypatch):
        monkeypatch.setenv(STRICT_ENV, "1")
        with pytest.raises(HTTPException) as err:
            await G.ensure_panel_write(None, province="ŚLĄSKIE", panel=PANEL_SETTLEMENTS, action="Zapis")
        assert err.value.status_code == 401
        assert "zalogowania" in err.value.detail

    async def test_token_z_uprawnieniem(self, lookup):
        await G.ensure_panel_write(org(), province="ŚLĄSKIE", panel=PANEL_SETTLEMENTS, action="Zapis")

    async def test_token_bez_uprawnienia_403_z_powodem(self, lookup):
        with pytest.raises(HTTPException) as err:
            await G.ensure_panel_write(
                org(), province="ŚLĄSKIE", panel=PANEL_ASSIGNMENTS, action="Zapis w Obsadzie"
            )
        assert err.value.status_code == 403
        assert err.value.detail.startswith("Zapis w Obsadzie:")
        assert "Obsada" in err.value.detail

    async def test_token_zawsze_sprawdzany_nawet_bez_trybu_scislego(self, lookup):
        # Okres przejściowy dotyczy WYŁĄCZNIE żądań bez tokenu.
        with pytest.raises(HTTPException):
            await G.ensure_panel_write(org("obcy"), province="ŚLĄSKIE", panel=PANEL_SETTLEMENTS, action="Zapis")


class Body(BaseModel):
    province: str
    amount: float = 0


def client(token):
    router = APIRouter(
        prefix="/panel",
        dependencies=[Depends(G.panel_write_gate(PANEL_SETTLEMENTS, "Zapis w panelu klubów"))],
    )

    @router.get("")
    async def read(province: str = Query(...)):
        return {"ok": True}

    @router.post("/entries")
    async def write(payload: Body):
        # Trasa po bramce dalej ma swoją treść - bramka jej nie „zjadła".
        return {"province": payload.province, "amount": payload.amount}

    @router.delete("/entries/{entry_id}")
    async def remove(entry_id: int, province: str = Query(...)):
        return {"removed": entry_id}

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_optional_jwt_payload] = lambda: token
    return TestClient(app)


class TestRoutera:
    def test_odczyt_wolny_nawet_dla_obcego(self, lookup):
        assert client(org("obcy")).get("/panel", params={"province": "ŚLĄSKIE"}).status_code == 200

    def test_zapis_z_okregiem_w_tresci(self, lookup):
        response = client(org()).post("/panel/entries", json={"province": "ŚLĄSKIE", "amount": 150})
        assert response.status_code == 200
        assert response.json() == {"province": "ŚLĄSKIE", "amount": 150}

    def test_zapis_w_cudzym_okregu_odrzucony(self, lookup):
        response = client(org()).post("/panel/entries", json={"province": "MAZOWIECKIE", "amount": 1})
        assert response.status_code == 403

    def test_usuwanie_z_okregiem_w_adresie(self, lookup):
        ok = client(org()).delete("/panel/entries/5", params={"province": "ŚLĄSKIE"})
        assert ok.status_code == 200
        bad = client(org("obcy")).delete("/panel/entries/5", params={"province": "ŚLĄSKIE"})
        assert bad.status_code == 403

    def test_bez_tokenu_przechodzi_w_okresie_przejsciowym(self, lookup):
        response = client(None).post("/panel/entries", json={"province": "ŚLĄSKIE"})
        assert response.status_code == 200


APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"


@pytest.mark.parametrize(
    "module, panel",
    [("province_clubs.py", "PANEL_SETTLEMENTS"), ("province_assignment_auto.py", "PANEL_ASSIGNMENTS")],
)
def test_router_ma_bramke(module, panel):
    """Czytane ze źródła: import tych modułów ciągnie `app.db` i żywą bazę."""
    tree = ast.parse((APP_DIR / module).read_text(encoding="utf-8"))
    routers = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "router" for t in node.targets)
    ]
    assert len(routers) == 1
    source = ast.unparse(routers[0])
    assert "dependencies=" in source
    assert f"panel_write_gate({panel}" in source

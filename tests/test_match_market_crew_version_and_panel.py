"""Oferty obsadowego: filtr wersji aplikacji i autoryzacja panelu Obsady (BAZA_web)."""

import pathlib

import pytest
from fastapi import HTTPException

from app import province_panel_guard as G
from app.client_version import (
    MIN_CREW_MARKET_VERSION,
    parse_version,
    supports_crew_market,
    version_at_least,
)
from app.province_panel_access import PANEL_ASSIGNMENTS, VipRecord

ROOT = pathlib.Path(__file__).resolve().parents[1]


def source(*parts):
    return ROOT.joinpath(*parts).read_text(encoding="utf-8")


class TestWersja:
    def test_parsowanie(self):
        assert parse_version("2.1.3") == (2, 1, 3)
        assert parse_version(" 2.1.3-dev ") == (2, 1, 3)
        assert parse_version("2.10") == (2, 10)

    @pytest.mark.parametrize("bad", [None, "", "  ", "abc", "2.x.1", "..", "undefined"])
    def test_brak_lub_smieci_to_nieznana(self, bad):
        assert parse_version(bad) == ()

    @pytest.mark.parametrize("bad", [None, "", "abc", "0.0.0"])
    def test_brak_wersji_to_stara(self, bad):
        assert supports_crew_market(bad) is False

    def test_porownanie_liczbowe_nie_tekstowe(self):
        assert version_at_least("2.10.0", "2.9.9")
        assert not version_at_least("2.9.9", "2.10.0")

    def test_rowna_i_nowsza_przechodza_starsza_nie(self):
        assert supports_crew_market(MIN_CREW_MARKET_VERSION)
        assert supports_crew_market("2.1.4") and supports_crew_market("3.0")
        assert not supports_crew_market("2.1.2") and not supports_crew_market("1.9.9")

    def test_rozna_dlugosc_numeru(self):
        assert version_at_least("2.1", "2.1.0")
        assert not version_at_least("2.1", "2.1.1")


class TestWiazania:
    def test_push_obsadowego_idzie_z_wersja_minimalna(self):
        src = source("app", "match_market_crew.py")
        assert "min_app_version=MIN_CREW_MARKET_VERSION" in src

    def test_wysylka_pomija_tokeny_bez_wersji(self):
        src = source("app", "push", "push.py")
        assert "min_app_version and not version_at_least(row[\"app_version\"], min_app_version)" in src
        assert "push_tokens.c.app_version" in src

    def test_rejestracja_zapisuje_wersje_i_kolumna_ma_migracje(self):
        assert "app_version=(req.app_version or \"\").strip() or None" in source("app", "push", "push.py")
        db = source("app", "db.py")
        assert "ALTER TABLE push_tokens ADD COLUMN IF NOT EXISTS app_version" in db

    def test_trasy_obsadowego_na_manager_actor_a_zgloszenia_na_sedziowskim(self):
        src = source("app", "match_market_crew.py")
        for name in ["suggest", "create_offer", "list_offers", "get_offer", "assign", "unassign", "withdraw_offer"]:
            head = src[src.index(f"async def {name}("):]
            head = head[: head.index(") ->")]
            assert "manager_actor" in head, name
        for name in ["create_claim", "withdraw_claim"]:
            head = src[src.index(f"async def {name}("):]
            head = head[: head.index(") ->")]
            assert "market_actor_v" in head, name
        assert "_require_approver(actor" not in src.replace("await _require_approver(actor, province)", "")


class TestPanelObsady:
    """Token organizacji (bez judge_id) z uprawnieniem Obsady przechodzi bramkę."""

    @staticmethod
    def payload():
        return {"sub": "ksdzpr", "account_type": "org"}

    async def run(self, monkeypatch, vip, province="SLASKIE", payload=None):
        async def fake_lookup(_payload):
            return False, vip

        monkeypatch.setattr(G, "_lookup", fake_lookup)
        await G.ensure_panel_write(
            payload or self.payload(), province=province, panel=PANEL_ASSIGNMENTS, action="Giełda ofert obsadowego"
        )

    async def test_vip_z_uprawnieniem_obsady_przechodzi(self, monkeypatch):
        await self.run(monkeypatch, VipRecord("ksdzpr", "ŚLĄSKIE", {"assignments": True}))

    async def test_vip_bez_uprawnienia_dostaje_403_z_wyjasnieniem(self, monkeypatch):
        with pytest.raises(HTTPException) as err:
            await self.run(monkeypatch, VipRecord("ksdzpr", "ŚLĄSKIE", {"settlements": True}))
        assert err.value.status_code == 403
        assert "uprawnienia" in err.value.detail and "Giełda ofert obsadowego" in err.value.detail

    async def test_inny_okreg_to_403(self, monkeypatch):
        with pytest.raises(HTTPException) as err:
            await self.run(monkeypatch, VipRecord("ksdzpr", "MAZOWIECKIE", {"assignments": True}))
        assert err.value.status_code == 403

    async def test_konto_bez_rekordu_vip_to_403(self, monkeypatch):
        with pytest.raises(HTTPException) as err:
            await self.run(monkeypatch, None)
        assert err.value.status_code == 403

"""Cofnięcie przydziału z panelu Obsady (konto VIP bez judge_id) - bez żywej bazy."""

import importlib
import sys
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException


def load_module():
    """Moduł tras z atrapą app.db (bez Postgresa); po imporcie sprząta cache."""
    before = set(sys.modules)
    sys.modules["app.db"] = MagicMock()
    try:
        return importlib.import_module("app.match_market_crew")
    finally:
        for name in set(sys.modules) - before:
            if name.startswith("app."):
                sys.modules.pop(name, None)
        sys.modules.pop("app.db", None) if isinstance(sys.modules.get("app.db"), MagicMock) else None


M = load_module()
R = M.R
pytestmark = pytest.mark.asyncio


class FakeDb:
    def __init__(self):
        self.updates = []

    async def execute(self, query):
        self.updates.append(query)


def setup(monkeypatch, *, changes, state, offer_status="filled", claim_status="assigned"):
    offer = {
        "id": 7, "province": "SLASKIE", "match_id": "123", "match_code": "S/JmM/1",
        "status": offer_status, "match_at": None, "slots": ["sekretarz"],
    }
    claim = {"id": 4, "judge_id": "5512", "status": claim_status, "slot": "sekretarz"}
    saved = {}
    db = FakeDb()
    pushed = []

    async def load(_id):
        return offer

    async def claims(_id):
        return [claim]

    async def ctx(_key, _mid):
        return {"state": state}

    async def manager(_actor, _prov):
        return None

    async def draft(_key, edit, _who):
        saved["changes"] = edit(list(changes))

    async def detail(_id, _actor):
        return {"id": 7}

    async def push(ids, text, _offer, **_kw):
        pushed.append((ids, text))

    monkeypatch.setattr(M, "_load_offer", load)
    monkeypatch.setattr(M, "_claims_of", claims)
    monkeypatch.setattr(M, "_match_context", ctx)
    monkeypatch.setattr(M, "_require_manager", manager)
    monkeypatch.setattr(M, "_draft_edit", draft)
    monkeypatch.setattr(M, "_detail", detail)
    monkeypatch.setattr(M, "_push", push)
    monkeypatch.setattr(M, "database", db)
    monkeypatch.setattr(M, "update", lambda *_a, **_k: MagicMock())
    return saved, db, pushed


def panel():
    return M.PanelActor({"sub": "ksdzpr", "account_type": "org"})


async def test_wpis_w_kolejce_znika_przez_panel(monkeypatch):
    changes = [{"id": "market-4", "match_id": "123", "kind": "slot", "slot": "sekretarz"}]
    saved, db, pushed = setup(monkeypatch, changes=changes, state={})
    out = await M.unassign(7, 4, panel())
    assert saved["changes"] == []
    assert out["unassign"]["removedFromQueue"] is True
    assert pushed and pushed[0][0] == ["5512"]


async def test_wpis_zapisany_w_zprp_dopisuje_zdjecie_z_gniazda(monkeypatch):
    state = {"NrSedzia_sekretarz": "5512", "NrSedzia_sekretarz_nazwisko": "Jan Kowalski"}
    saved, _, _ = setup(monkeypatch, changes=[], state=state)
    out = await M.unassign(7, 4, panel())
    assert out["unassign"]["queuedRemovalFromCrew"] is True
    assert saved["changes"][0]["judge_id"] == "" and saved["changes"][0]["before_id"] == "5512"


async def test_mecz_zniknal_z_terminarza_nie_blokuje_cofniecia(monkeypatch):
    saved, _, _ = setup(monkeypatch, changes=[], state={})

    async def gone(_key, _mid):
        raise HTTPException(404, "Nie ma takiego meczu w terminarzu okręgu.")

    monkeypatch.setattr(M, "_match_context", gone)
    out = await M.unassign(7, 4, panel())
    assert out["unassign"]["removedFromQueue"] is False


async def test_nieprzydzielone_to_409_z_wyjasnieniem(monkeypatch):
    setup(monkeypatch, changes=[], state={}, claim_status=R.PENDING)
    with pytest.raises(HTTPException) as err:
        await M.unassign(7, 4, panel())
    assert err.value.status_code == 409 and "nie jest przydzielone" in err.value.detail


def test_nieprzewidziany_blad_wraca_jako_500_z_koperta_i_cors():
    from fastapi import APIRouter, FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.testclient import TestClient

    router = APIRouter(route_class=M._ExplainedErrors)

    @router.post("/boom")
    async def boom():
        raise KeyError("slot")

    app = FastAPI()
    app.include_router(router)
    app.add_middleware(CORSMiddleware, allow_origins=["https://x.test"], allow_methods=["*"], allow_headers=["*"])
    res = TestClient(app, raise_server_exceptions=False).post("/boom", headers={"Origin": "https://x.test"})
    assert res.status_code == 500
    assert res.headers.get("access-control-allow-origin") == "https://x.test"
    assert "połączenie jest w porządku" in res.json()["detail"]

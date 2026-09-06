"""Regresja BAZA A -> ProEl B: dziennik, badania w blobie i autor PDF.

Bez połączenia z bazą i bez generowania pliku: resolver konta ma atrapę,
a trasy wymagające Postgresa sprawdzamy przez ich rzeczywiste AST.
"""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import Header, HTTPException

from app import proel_auth
from app.proel_journal import soft_actor
from app.proel_elevation import create_elevation_token
from app.proel_users.tokens import create_access_token

APP = Path(__file__).resolve().parents[1] / "app"
pytestmark = pytest.mark.asyncio


@pytest.fixture
def account(monkeypatch):
    async def load(_uid):
        return {"id": 7, "full_name": "AKTUALNA Anna", "is_active": True}
    monkeypatch.setattr(proel_auth, "_load_proel_account", load)
    return f"Bearer {create_access_token(7)}"


async def test_soft_actor_uses_account_instead_of_old_baza_headers(account):
    actor = await soft_actor("101", "phone", "POPRZEDNI Jan", account)
    assert actor.as_by() == {"judge_id": "proel:7", "name": "AKTUALNA Anna", "install": "phone", "verified": True}


async def test_soft_actor_respects_elevated_official(account):
    actor = await soft_actor("202", "phone", "SĘDZIA Piotr", account, create_elevation_token("202"))
    assert actor.judge_id == "202"
    assert actor.name == "SĘDZIA Piotr"
    assert actor.elevated is True


async def test_soft_actor_invalid_account_does_not_sign_as_previous_judge():
    actor = await soft_actor("101", "phone", "POPRZEDNI Jan", "Bearer invalid-token")
    assert actor.judge_id == "inst:phone"
    assert actor.name == ""
    assert actor.verified is False


async def test_soft_actor_blocked_account_does_not_sign_as_previous_judge(monkeypatch, account):
    async def load(_uid):
        return {"id": 7, "is_active": False}
    monkeypatch.setattr(proel_auth, "_load_proel_account", load)
    actor = await soft_actor("101", "phone", "POPRZEDNI Jan", account)
    assert actor.name == ""
    assert actor.judge_id != "101"


@pytest.mark.parametrize("filename,route", [
    ("proel.py", "create_proel_match"),
    ("proel.py", "update_proel_match"),
    ("results.py", "generate_protocol_pdf"),
])
async def test_routes_forward_both_credentials_to_shared_actor(filename, route):
    tree = ast.parse((APP / filename).read_text(encoding="utf-8"))
    fn = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == route)
    args = {arg.arg for arg in fn.args.args}
    assert {"authorization", "x_elevation"} <= args
    calls = [node for node in ast.walk(fn) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "soft_actor"]
    assert len(calls) == 1  # jeden autor na całą czynność
    assert {kw.arg: kw.value.id for kw in calls[0].keywords} == {
        "authorization": "authorization", "x_elevation": "x_elevation",
    }


async def test_pdf_footer_uses_account_identity(account):
    tree = ast.parse((APP / "results.py").read_text(encoding="utf-8"))
    fn = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "generate_protocol_pdf")
    # Uruchamiamy prawdziwy początek trasy: rozpoznanie autora i treść stopki.
    # Reszta wymaga szablonu, LibreOffice i bazy, których ten test nie dotyka.
    end = next(i for i, node in enumerate(fn.body) if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "generated_dt" for t in node.targets))
    fn.body = fn.body[:end] + ast.parse("return generated_by, actor_judge_id, actor_verified").body
    fn.decorator_list = []
    module = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), fn], type_ignores=[])
    namespace = {"Header": Header, "HTTPException": HTTPException, "soft_actor": soft_actor}
    exec(compile(ast.fix_missing_locations(module), "<pdf-author>", "exec"), namespace)
    author = await namespace[fn.name](SimpleNamespace(data_json={}), None, "101", "phone", "POPRZEDNI Jan", None, account, None)
    assert author == ("AKTUALNA Anna", "proel:7", True)

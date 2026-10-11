"""Wiązania tras `/partner-offtimes` - czytane z drzewa składni, nie z importu.

`app.partner_offtimes` ciągnie `app.db`, a ten żąda żywego Postgresa, więc
ten plik NIE importuje modułu (tak samo jak `test_province_guard_wiring`).

Pilnuje, żeby każda trasa zapisu brała tożsamość z tokenu i pytała
`write_allowed` - zapis wysyła partnerowi push, więc trasa bez bramki
pozwala obcemu pisać i powiadamiać w cudzym imieniu.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

SOURCE = (
    pathlib.Path(__file__).resolve().parents[1] / "app" / "partner_offtimes.py"
).read_text(encoding="utf-8")
FUNCTIONS = {
    node.name: node
    for node in ast.walk(ast.parse(SOURCE))
    if isinstance(node, ast.AsyncFunctionDef)
}
WRITES = ("create_partner_offtime", "update_partner_offtime", "delete_partner_offtime")


def _calls(fn: ast.AsyncFunctionDef) -> set[str]:
    return {
        node.func.id
        for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }


@pytest.mark.parametrize("name", WRITES)
def test_write_route_takes_token(name):
    fn = FUNCTIONS[name]
    defaults = [ast.unparse(d) for d in fn.args.defaults]
    assert "Depends(get_jwt_payload)" in defaults


@pytest.mark.parametrize("name", WRITES)
def test_write_route_checks_owner(name):
    calls = _calls(FUNCTIONS[name])
    assert {"write_allowed", "caller_judge_id"} <= calls


def test_update_checks_owner_before_writing():
    fn = FUNCTIONS["update_partner_offtime"]
    source = ast.unparse(fn)
    assert source.index("write_allowed(") < source.index("update(partner_offtimes)")


def test_only_update_notifies_partner():
    for name, fn in FUNCTIONS.items():
        mentions = "notify_partner_about_new_offtimes" in ast.unparse(fn)
        assert mentions == (name == "update_partner_offtime"), name

"""Wiązania szybkiego zapisu wydarzeń, bez importowania żywej bazy."""

from __future__ import annotations

import ast
import pathlib

SOURCE = (
    pathlib.Path(__file__).resolve().parents[1] / "app" / "province_events.py"
).read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)
FUNCTIONS = {
    node.name: node
    for node in ast.walk(TREE)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}


def source_of(name: str) -> str:
    return ast.get_source_segment(SOURCE, FUNCTIONS[name]) or ""


def test_patch_odpowiada_przed_wysylka_push():
    src = source_of("patch_v2")
    assert "background_tasks" in {arg.arg for arg in FUNCTIONS["patch_v2"].args.args}
    assert "background_tasks.add_task" in src
    assert "_notify_changed_after_update" in src
    assert "await _notify_changed" not in src
    assert "await _judges" not in src


def test_zadanie_w_tle_samo_pobiera_swieze_wydarzenie_i_adresatow():
    src = source_of("_notify_changed_after_update")
    assert "await _event" in src
    assert "await _judges" in src
    assert "await _notify_changed" in src


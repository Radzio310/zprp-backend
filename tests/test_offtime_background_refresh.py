"""Zapis niedyspozycji odpowiada zaraz po potwierdzeniu ZPRP.

Czytamy źródło (bez importu - `app.offtime` ciągnie bazę danych), jak w
`test_match_market_wiring.py`.
"""

import ast
import pathlib

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / "app" / "offtime.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)
FUNCS = {n.name: n for n in ast.walk(TREE) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _awaited_calls(name: str) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(FUNCS[name]):
        if isinstance(node, ast.Await) and isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Name):
                out.add(func.id)
    return out


def _calls(name: str) -> set[str]:
    return {
        n.func.id
        for n in ast.walk(FUNCS[name])
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }


def test_endpoints_do_not_wait_for_snapshot_refresh():
    for name in ("create_offtime", "update_offtime", "delete_offtime"):
        assert "_refresh_server_snapshot" not in _awaited_calls(name), name
        assert "_refresh_in_background" in _calls(name), name
        assert "_submit_offtime" in _awaited_calls(name), name


def test_background_task_closes_session_and_is_kept_alive():
    segment = ast.get_source_segment(SOURCE, FUNCS["_refresh_in_background"]) or ""
    assert "client.aclose()" in segment
    assert "_background_refreshes.add(task)" in segment

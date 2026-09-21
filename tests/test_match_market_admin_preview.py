"""Kontrakt podglądu cudzej giełdy bez importowania modułu z żywą bazą."""

import ast
from pathlib import Path


SOURCE = (Path(__file__).resolve().parents[1] / "app" / "match_market.py").read_text(
    encoding="utf-8"
)
TREE = ast.parse(SOURCE)
PREVIEW = next(
    node for node in TREE.body
    if isinstance(node, ast.AsyncFunctionDef) and node.name == "admin_province_offers"
)
CODE = ast.unparse(PREVIEW)


def test_preview_is_a_get_route_for_administrators_only():
    assert "@router.get('/admin/provinces/{province}/offers'" in CODE
    assert "may_manage_config(is_admin=actor.is_admin)" in CODE
    assert "raise HTTPException(403" in CODE


def test_preview_reads_only_requested_enabled_province():
    assert "normalize_province(province)" in CODE
    assert "cfg['market_enabled']" in CODE
    assert "match_market_offers.c.province == key" in CODE
    assert "match_market_offers.c.status == 'open'" in CODE
    assert "match_market_offers.c.deadline_at > _now()" in CODE
    assert "viewer_id=''" in CODE

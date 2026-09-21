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
    assert "viewer_id=actor.judge_id" in CODE
    assert "my_crew_label=my_roles.get" in CODE


def test_admin_actions_keep_actor_identity_and_target_province():
    functions = {
        node.name: ast.unparse(node)
        for node in TREE.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "not actor.is_admin" in functions["_market_province"]
    assert "_market_province(actor, req.province)" in functions["create_offer"]
    assert "_market_province(actor, province_override)" in functions["my_matches"]
    assert "not actor.is_admin" in functions["create_claim"]
    assert "_require_approver(actor, province)" in functions["approve_offer"]


def test_journal_enriches_events_with_match_snapshot_and_counts_matches():
    functions = {
        node.name: ast.unparse(node)
        for node in TREE.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    journal = functions["admin_journal"]
    provinces = functions["admin_provinces"]
    assert "match_market_offers.c.match_snapshot" in journal
    assert "province_matches.c.state_json" in journal
    assert "'match':" in journal
    assert "func.distinct(match_market_offers.c.match_id)" in provinces

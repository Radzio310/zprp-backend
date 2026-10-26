"""Ławka rezerwowych zwykłej giełdy - część czysta i wiązania (26.10.2026)."""

from __future__ import annotations

import ast
import pathlib

from app.match_market_bench import bench_fields, km_value, nearest_km

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / "app" / "match_market.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)
FUNCS = {n.name: n for n in ast.walk(TREE) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _code(name: str) -> str:
    return ast.unparse(FUNCS[name])


def test_km_value_none_is_not_zero():
    assert km_value(None) is None
    assert km_value({"km": None}) is None
    assert km_value({"km": "x"}) is None
    assert km_value({"km": -3}) is None
    assert km_value({"km": 0}) == 0.0
    assert km_value({"km": 12.4}) == 12.4


def test_nearest_km_skips_unknown_and_strangers():
    bench = {"1": {"km": 40}, "2": {"km": None}, "3": {"km": 12.5}, "9": {"km": 1}}
    assert nearest_km(bench, ["1", "2", "3"]) == 12.5
    assert nearest_km(bench, ["2"]) is None
    assert nearest_km({}, ["1"]) is None


def test_bench_fields_shape():
    row = bench_fields({"km": 7, "source": "district_table", "from": "Gliwice", "season": {"field": 5, "table": 3}})
    assert row == {
        "km": 7.0,
        "kmSource": "district_table",
        "fromCity": "Gliwice",
        "season": {"field": 5, "table": 3, "total": 8},
    }
    empty = bench_fields(None)
    assert empty["km"] is None and empty["kmSource"] == "unknown" and empty["season"] is None


def test_payload_carries_bench_numbers():
    code = _code("_offer_payload")
    assert "nearestKm" in code and "myKm" in code
    assert "bench_fields" in code


def test_list_offers_knows_decision_right_and_skips_network():
    code = _code("list_offers")
    assert "bench_metrics" in code
    assert "canApprove" in code
    # Lista nie pyta Google - tylko szczegóły mają budżet na dopytanie.
    assert "ask_google=True" not in code


def test_get_offer_asks_for_missing_km_and_season_only_for_deciders():
    code = _code("get_offer")
    assert "ask_google=True" in code
    assert "with_season=approver or mine" in code

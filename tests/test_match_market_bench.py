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
    # Szczegóły dopytują Google, chyba że aplikacja prosi o szybki odczyt (fast=1).
    assert "ask_google=not quick" in code
    assert "metricsPending" in code
    assert "with_season=approver or mine" in code


def test_lawka_dostaje_metryki_obsadowego_bez_nadpisywania():
    from app.match_market_bench import bench_fields, merge_metrics

    base = bench_fields({"km": None, "source": "unknown", "from": "Gliwice", "season": None})
    metric = {
        "km": {"km": 42, "source": "district_table", "from": "Gliwice", "to": "Zabrze"},
        "season": {"field": 2, "table": 4, "total": 6},
        "week_matches": 1,
        "nearest": None,
        "gap": {"level": "yellow", "shortfall_minutes": 0, "overlap": False},
        "collisions": [{"code": "S/JmM/3", "level": "yellow"}],
        "unavailable": None,
    }
    out = merge_metrics(base, metric)
    # Luki z ławki wypełniają metryki, nowe pola są obecne.
    assert out["km"] == 42.0 and out["kmSource"] == "district_table"
    assert out["season"] == {"field": 2, "table": 4, "total": 6}
    assert out["weekMatches"] == 1 and out["gap"]["level"] == "yellow" and len(out["collisions"]) == 1
    # Znane kilometry i sezon z ławki NIE są nadpisywane.
    known = bench_fields({"km": 10, "source": "same_city", "from": "Zabrze", "season": {"field": 1, "table": 0}})
    out2 = merge_metrics(known, metric)
    assert out2["km"] == 10.0 and out2["kmSource"] == "same_city"
    assert out2["season"]["total"] == 1
    # Bez metryk - wiersz bez zmian (zgodność wstecz).
    assert merge_metrics(known, None) == known


def test_szybki_odczyt_mowi_czy_dociagac_km():
    from app.match_market_bench import metrics_pending

    claims = [{"status": "pending", "km": None}, {"status": "pending", "km": 12.0}]
    assert metrics_pending(True, claims) is True
    # Pełny odczyt (z Google) nigdy nie każe pobierać drugi raz.
    assert metrics_pending(False, claims) is False
    assert metrics_pending(True, [{"status": "pending", "km": 3.0}, {"status": "withdrawn", "km": None}]) is False

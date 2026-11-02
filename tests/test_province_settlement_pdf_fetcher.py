"""Zgłoszenie 02.11.2026: PDF rozliczeń dawał 500, bo WeasyPrint nie ma już
`default_url_fetcher`, a zwykła funkcja nie jest dla niego poprawnym fetcherem."""
import ast
from pathlib import Path

SOURCE = (Path(__file__).resolve().parents[1] / "app" / "province_settlement_pdf.py").read_text(encoding="utf-8")


def test_nie_uzywa_usunietego_api_weasyprint():
    assert "default_url_fetcher" not in SOURCE


def test_fetcher_to_urlfetcher_tylko_dla_data_uri():
    assert 'URLFetcher(allowed_protocols=("data",))' in SOURCE


def test_html_dostaje_instancje_a_nie_funkcje():
    calls = [
        kw.value
        for node in ast.walk(ast.parse(SOURCE))
        if isinstance(node, ast.Call)
        for kw in node.keywords
        if kw.arg == "url_fetcher"
    ]
    assert calls and all(isinstance(value, ast.Call) for value in calls)

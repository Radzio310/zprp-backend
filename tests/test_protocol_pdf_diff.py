"""
Porównanie treści wydruku: co dokładnie ktoś podmienił w gotowym PDF-ie.

Kontekst, bez którego te testy nie mają sensu — w dzienniku są TRZY różne
porównania i łatwo je pomylić:
  • podpis           → czy znacznik wystawił nasz serwer,
  • state_sha256     → czy znacznik wskazuje ten wpis w dzienniku,
  • pdf_sha256       → czy bajty pliku są te, które wydaliśmy.
Edycja liczby widzów w gotowym PDF-ie rusza WYŁĄCZNIE to ostatnie. Dlatego
potrzebny jest osobny mechanizm, który powie, co się zmieniło.
"""
import pytest

from app.results import (
    PDF_DIFF_LIMIT,
    _diff_pdf_text,
    _normalize_pdf_lines,
)


# ─────────────────────── normalizacja ───────────────────────

def test_normalize_drops_blank_lines():
    assert _normalize_pdf_lines("a\n\n\nb\n") == ["a", "b"]


def test_normalize_collapses_whitespace():
    """PDF potrafi rozstrzelić spacje między znakami — bez tego diff pokazałby
    przesunięcia układu zamiast zmian treści."""
    assert _normalize_pdf_lines("Liczba   widzów:\t 852 ") == ["Liczba widzów: 852"]


def test_normalize_handles_empty():
    assert _normalize_pdf_lines("") == []
    assert _normalize_pdf_lines(None) == []


# ─────────────────────── różnice ───────────────────────

def test_identical_text_has_no_changes():
    text = "Protokół zawodów\nLiczba widzów: 852\nPojemność hali: 2318"
    out = _diff_pdf_text(text, text)
    assert out["changes"] == []
    assert out["truncated"] is False


def test_detects_replaced_value():
    """Dokładnie przypadek z testu na żywo: 852 → 853."""
    before = "Protokół zawodów\nLiczba widzów: 852\nPojemność hali: 2318"
    after = "Protokół zawodów\nLiczba widzów: 853\nPojemność hali: 2318"

    out = _diff_pdf_text(before, after)
    assert len(out["changes"]) == 1
    ch = out["changes"][0]
    assert ch["kind"] == "changed"
    assert "852" in ch["before"]
    assert "853" in ch["after"]


def test_detects_added_and_removed_lines():
    out = _diff_pdf_text("a\nb\nc", "a\nc\nd")
    kinds = {c["kind"] for c in out["changes"]}
    assert "removed" in kinds or "changed" in kinds
    assert any("d" == c["after"] for c in out["changes"])


def test_whitespace_only_change_is_not_reported():
    """Inny program mógł inaczej rozłożyć spacje — to nie jest zmiana treści."""
    out = _diff_pdf_text("Liczba widzów: 852", "Liczba    widzów:  852")
    assert out["changes"] == []


def test_limit_protects_against_rebuilt_files():
    """Plik przepuszczony przez inny program potrafi mieć przebudowany cały
    strumień tekstu — lista zmian byłaby wtedy bezużyteczna."""
    before = "\n".join("wiersz %d" % i for i in range(200))
    after = "\n".join("inny %d" % i for i in range(200))

    out = _diff_pdf_text(before, after)
    assert len(out["changes"]) <= PDF_DIFF_LIMIT
    assert out["truncated"] is True


def test_empty_original_does_not_explode():
    out = _diff_pdf_text("", "Liczba widzów: 853")
    assert out["changes"]
    assert all(c["kind"] == "added" for c in out["changes"])


def test_changes_keep_order_of_document():
    before = "linia 1\nwidzowie 852\nlinia 3\npojemnosc 2318"
    after = "linia 1\nwidzowie 853\nlinia 3\npojemnosc 9999"
    out = _diff_pdf_text(before, after)
    joined = [c["after"] for c in out["changes"]]
    assert joined.index("widzowie 853") < joined.index("pojemnosc 9999")

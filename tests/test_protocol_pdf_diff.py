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
    _label_for_value,
    _normalize_pdf_lines,
)

#: Stan meczu tak, jak leży w dzienniku — z niego bierze się nazwa pola.
STATE = {
    "matchConfig": {
        "matchNumber": "ML/251",
        "hostTeamName": "KS Vive Kielce",
        "guestTeamName": "Azoty Puławy",
        "extras": {
            "spectatorsCount": "852",
            "venueCapacity": "2318",
            "medic": {"fullName": "NOWAK Jan", "number": "12345"},
        },
    },
    "scoreHost": 5,
    "scoreGuest": 3,
}


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


# ─────────────────── nazwa zmienionego pola ───────────────────

def test_label_resolves_field_from_state():
    """W strumieniu PDF-a stoi gołe „2318" — nazwę pola odzyskujemy ze stanu."""
    assert _label_for_value(STATE, "2318") == "Pojemność obiektu"
    assert _label_for_value(STATE, "852") == "Liczba widzów"
    assert _label_for_value(STATE, "ML/251") == "Numer meczu"


def test_label_empty_when_value_unknown():
    assert _label_for_value(STATE, "99999") == ""
    assert _label_for_value(None, "2318") == ""
    assert _label_for_value(STATE, "") == ""


def test_label_empty_when_two_fields_share_value():
    """Dwa pola o tej samej wartości — wolimy nie nazwać niż nazwać źle."""
    state = {"scoreHost": 5, "scoreGuest": 5}
    assert _label_for_value(state, "5") == ""


def test_swap_split_by_difflib_is_reported_as_one_change():
    """
    Regresja z testu na żywo: edytor PDF przestawił układ strumienia, przez co
    `difflib` zwrócił osobno „usunięto 2318" i „dopisano 2319". Admin widział
    dwie pozycje zamiast jednej podmiany.
    """
    before = "Protokół\n2318\nstopka"
    after = "Protokół\nstopka\n2319"

    out = _diff_pdf_text(before, after, STATE)
    assert len(out["changes"]) == 1
    ch = out["changes"][0]
    assert ch["kind"] == "changed"
    assert ch["before"] == "2318"
    assert ch["after"] == "2319"
    assert ch["label"] == "Pojemność obiektu"


def test_two_swaps_each_get_their_own_label():
    """Dwie podmiany naraz — każda nazwana swoim polem, nie na krzyż."""
    before = "Protokół\n852\n2318\nstopka"
    after = "Protokół\n853\n2319\nstopka"

    out = _diff_pdf_text(before, after, STATE)
    by_label = {c.get("label"): c for c in out["changes"]}
    assert by_label["Liczba widzów"]["after"] == "853"
    assert by_label["Pojemność obiektu"]["after"] == "2319"


def test_pos_is_not_leaked_to_client():
    """`pos` jest wewnętrzną pomocą przy parowaniu — nie ma po co wychodzić."""
    out = _diff_pdf_text("2318", "2319", STATE)
    assert all("pos" not in c for c in out["changes"])


def test_diff_without_state_still_works():
    """Wpisy sprzed tej wersji nie mają czym nazwać pola — mają działać dalej."""
    out = _diff_pdf_text("2318", "2319")
    assert len(out["changes"]) == 1
    assert out["changes"][0]["label"] == ""


def test_changes_keep_order_of_document():
    before = "linia 1\nwidzowie 852\nlinia 3\npojemnosc 2318"
    after = "linia 1\nwidzowie 853\nlinia 3\npojemnosc 9999"
    out = _diff_pdf_text(before, after)
    joined = [c["after"] for c in out["changes"]]
    assert joined.index("widzowie 853") < joined.index("pojemnosc 9999")

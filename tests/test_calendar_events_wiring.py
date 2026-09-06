"""Kalendarz Google pod kategorie niedyspozycji - czytane z drzewa składni.

`app.calendar` importuje biblioteki Google, których lokalne środowisko testów
nie ma, więc ten plik nie importuje modułu. Pilnuje dwóch rzeczy z decyzji
2026-09-06 (kategorie = etykiety z konta + kategoria domyślna):

* listowanie wydarzeń prosi o `eventLabelId` (eventLabelVersion=1) i przy
  odmowie API wraca do zwykłego listowania zamiast wywrócić import,
* etykiety wracają razem z kolorem kalendarza głównego, ale jego brak nie
  psuje odpowiedzi.
"""

from __future__ import annotations

import ast
import pathlib

SRC = (pathlib.Path(__file__).resolve().parents[1] / "app" / "calendar.py").read_text(
    encoding="utf-8"
)
TREE = ast.parse(SRC)
FUN = {
    node.name: node
    for node in ast.walk(TREE)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}


def code_of(name: str) -> str:
    return ast.get_source_segment(SRC, FUN[name]) or ""


def test_events_list_asks_for_label_ids_and_falls_back_on_refusal():
    src = code_of("list_events")
    assert "_apply_event_label_version" in src
    # Dwa listowania: z parametrem i zapasowe bez niego.
    assert src.count(".list(**list_kwargs)") == 2
    assert "except HttpError" in src
    assert "!= 400" in src
    assert "from googleapiclient.errors import HttpError" in SRC


def test_fallback_is_only_for_a_rejected_parameter():
    """Inne błędy (401, 5xx) mają iść dalej, nie ginąć w zapasowym listowaniu."""
    src = code_of("list_events")
    assert "raise" in src.split("except HttpError")[1]


def test_labels_endpoint_adds_calendar_color_best_effort():
    node = FUN["list_event_labels"]
    src = code_of("list_event_labels")
    assert '"calendarColor": calendar_color' in src
    assert "calendarList().get(" in src
    # Pobranie koloru siedzi we własnym try/except - brak koloru nie zabija etykiet.
    guarded = [
        t
        for t in ast.walk(node)
        if isinstance(t, ast.Try)
        and "calendarList" in (ast.get_source_segment(SRC, t) or "")
    ]
    assert guarded, "kolor kalendarza bez osłony try/except"
    assert "_is_valid_hex(background)" in src


def test_empty_color_id_means_no_color_field():
    """Kategoria domyślna wysyła pusty colorId - Google ma dostać wydarzenie bez koloru."""
    src = code_of("_event_color_field")
    assert "if not color_id" in src
    assert "return {}" in src

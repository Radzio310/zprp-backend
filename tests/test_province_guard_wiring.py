"""Wiązania bramki okręgowej - czytane z drzewa składni, nie z importu.

`app.silesia` ciągnie `app.db`, a ten żąda żywego Postgresa, więc ten plik NIE
importuje modułu. Czyta jego źródło, tak samo jak `test_match_market_wiring`.

Łapie dokładnie te pomyłki, które inaczej wykonałyby się pierwszy raz na
produkcji: trasa zapisu bez bramki, bramka bez tokenu (czyli pytająca o
tożsamość samego nadawcę) i bramka doklejona tam, gdzie ma być otwarte.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"
SOURCE = (APP_DIR / "silesia.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)

FUNCTIONS = {
    node.name: node
    for node in ast.walk(TREE)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}

#: Trasa -> bramka, która musi w niej paść.
GUARDED = {
    "create_announcement": "ensure_announcement_write",
    "update_announcement": "ensure_announcement_write",
    "delete_announcement": "ensure_announcement_write",
    "pin_comment": "ensure_announcement_write",
    "delete_comment": "ensure_announcement_write",
    "set_offtimes": "ensure_offtimes_write",
    "delete_offtimes": "ensure_offtimes_write",
}

#: Trasy świadomie otwarte dla każdego zalogowanego - reakcja i komentarz to
#: głos zwykłego sędziego, nie moderacja.
OPEN = ("toggle_reaction", "add_comment")


def calls_in(name: str) -> set[str]:
    node = FUNCTIONS[name]
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Name):
                out.add(func.id)
            elif isinstance(func, ast.Attribute):
                out.add(func.attr)
    return out


def arg_names(name: str) -> set[str]:
    node = FUNCTIONS[name]
    args = node.args
    return {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}


@pytest.mark.parametrize("route, guard", sorted(GUARDED.items()))
def test_kazdy_zapis_okregowy_ma_bramke(route, guard):
    assert route in FUNCTIONS, f"brak trasy {route} - zmieniła nazwę?"
    assert guard in calls_in(route), f"{route} zapisuje bez sprawdzenia uprawnień"


@pytest.mark.parametrize("route", sorted(GUARDED))
def test_kazda_bramka_dostaje_token_a_nie_tresc_zadania(route):
    # Tożsamość ma pochodzić z tokenu. Gdyby zabrakło tej zależności, bramka
    # dostałaby `None` i w okresie przejściowym przepuszczała wszystko.
    assert "token_payload" in arg_names(route)
    assert "get_optional_jwt_payload" in SOURCE


@pytest.mark.parametrize("route", OPEN)
def test_glos_zwyklego_sedziego_zostaje_otwarty(route):
    assert route in FUNCTIONS
    assert "ensure_announcement_write" not in calls_in(route)
    assert "ensure_offtimes_write" not in calls_in(route)


def test_usuniecie_ogloszenia_czyta_wojewodztwo_wpisu():
    # Bramka pyta o okręg, w którym wpis LEŻY - nie o ten, który poda kasujący.
    source = ast.get_source_segment(SOURCE, FUNCTIONS["delete_announcement"]) or ""
    assert "announcements.c.province" in source

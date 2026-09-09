"""Bramka na liście młodych sędziów - czytana z drzewa składni, nie z importu.

`app.young_referees` ciągnie `app.db`, a ten żąda żywego Postgresa, więc ten
plik NIE importuje modułu. Czyta jego źródło, tak samo jak
`test_province_guard_wiring`.

Do 2026-09-09 te trzy trasy nie sprawdzały NICZEGO: listę okręgu mógł zmienić
i wyczyścić każdy, kto znał adres, bez logowania. Ograniczenie żyło wyłącznie
w aplikacji, w warunku rysującym kosz.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"
SOURCE = (APP_DIR / "young_referees.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)

FUNCTIONS = {
    node.name: node
    for node in ast.walk(TREE)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}

#: Zapisy na liście młodych sędziów - wszystkie przez tę samą bramkę.
GUARDED = (
    "create_young_referee",
    "update_young_referee",
    "delete_young_referee",
)

#: Odczyty zostają otwarte: listę czyta też młody sędzia, który patrzy na swoje
#: oceny, i ekran meczu przy obsadzie.
OPEN = ("list_young_referees", "get_young_referee")


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


def source_of(name: str) -> str:
    return ast.get_source_segment(SOURCE, FUNCTIONS[name]) or ""


@pytest.mark.parametrize("route", GUARDED)
def test_kazdy_zapis_ma_bramke(route):
    assert route in FUNCTIONS, f"brak trasy {route} - zmieniła nazwę?"
    assert "_ensure_young_referee_write" in calls_in(
        route
    ), f"{route} zapisuje bez sprawdzenia uprawnień"


@pytest.mark.parametrize("route", GUARDED)
def test_kazda_bramka_dostaje_token_a_nie_tresc_zadania(route):
    # Tożsamość ma pochodzić z tokenu. Gdyby zabrakło tej zależności, bramka
    # dostałaby `None` i w okresie przejściowym przepuszczała wszystko.
    assert "token_payload" in arg_names(route)
    assert "get_optional_jwt_payload" in SOURCE


@pytest.mark.parametrize("route", OPEN)
def test_odczyty_zostaja_otwarte(route):
    assert route in FUNCTIONS
    assert "_ensure_young_referee_write" not in calls_in(route)


def test_bramka_pyta_o_uprawnienie_teach():
    # Listę prowadzi Teach Master okręgu - nie News, nie Calendar, nie Match.
    helper = source_of("_ensure_young_referee_write")
    assert "MASTER_TEACH" in helper
    assert "ensure_province_write" in calls_in("_ensure_young_referee_write")


def test_usuniecie_czyta_wojewodztwo_z_bazy():
    # Przy usuwaniu okręg w ogóle nie przychodzi w żądaniu, więc musi zostać
    # odczytany z wiersza - i to PRZED skasowaniem, bo potem nie ma go skąd wziąć.
    source = source_of("delete_young_referee")
    assert "young_referees.c.province" in source
    guard_at = source.index("_ensure_young_referee_write")
    delete_at = source.index("delete(young_referees)")
    assert guard_at < delete_at, "bramka pada po skasowaniu wiersza"


def test_edycja_pyta_o_okreg_wpisu_a_nie_o_podany():
    # Okręg z treści żądania dałoby się podmienić i pisać po cudzej liście,
    # mając uprawnienie wyłącznie u siebie.
    source = source_of("update_young_referee")
    assert 'row["province"]' in source


def test_przeniesienie_do_innego_okregu_pyta_o_obie_listy():
    # Inaczej Master jednego okręgu wypychałby swoich młodych do cudzego.
    source = source_of("update_young_referee")
    assert source.count("_ensure_young_referee_write") >= 2
    assert "req.province" in source

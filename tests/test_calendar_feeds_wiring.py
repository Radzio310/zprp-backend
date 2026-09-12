"""Okablowanie kalendarzy sędziego - czytane ze źródła.

Moduły tras żądają żywej bazy przy imporcie (``app/db.py`` łączy się w
momencie importu), więc sprawdzamy je tak samo jak bramki admina: czytając
kod. Pilnujemy czterech rzeczy, które łatwo zepsuć i trudno zauważyć:

  1. link z kluczem nie wraca do aplikacji,
  2. router kalendarzy stoi PRZED trasami Google,
  3. wpisy z kalendarza są odcinane przy zapisie z telefonu i doklejane przy
     odczycie,
  4. nieudane pobranie nie kasuje planu i nie udaje udanej synchronizacji.
"""

from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def source(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def function_source(name: str, func: str) -> str:
    tree = ast.parse(source(name))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func:
            return ast.unparse(node)
    raise AssertionError(f"{name}: brak funkcji {func}")


# ── sekret w linku ───────────────────────────────────────────────


def test_odpowiedz_nie_wydaje_pelnego_adresu():
    body = function_source("app/calendar_feeds.py", "_public")
    assert "mask_feed_url" in body
    # Gdyby ktoś dołożył `"url": row["url"]`, klucz do planu zajęć poszedłby do
    # aplikacji i na każdy zrzut ekranu.
    assert "'url': row" not in body and '"url": row' not in body


def test_powod_bledu_nie_niesie_adresu():
    body = function_source("app/calendar_feed_sync.py", "_short_error")
    assert "url" not in body.lower()


# ── kolejność tras ───────────────────────────────────────────────


def test_router_kalendarzy_przed_trasami_google():
    main = source("main.py")
    feeds = main.index("app.include_router(calendar_feeds_router)")
    google = main.index("app.include_router(calendar_router)")
    assert feeds < google


def test_petla_synchronizacji_wystartowana():
    main = source("main.py")
    assert "run_calendar_feed_sync()" in main
    assert "asyncio.create_task(run_calendar_feed_sync())" in main


# ── składanie i ochrona zapisu ───────────────────────────────────


def test_zapis_z_telefonu_nie_dopisuje_wpisow_z_kalendarza():
    body = function_source("app/silesia.py", "set_offtimes")
    assert "_without_feed_entries" in body


def test_odczyt_doklada_kalendarze_jako_osobne_zrodlo():
    body = function_source("app/silesia.py", "_composed_offtime_records")
    assert "judge_calendar_feeds" in body
    assert "judge_feed_offtimes" in body
    # Widok okręgu pokazuje tylko udostępnione kalendarze.
    assert "shared_with_province" in body
    # Wpisy z telefonu nie mogą przemycić cudzego źródła.
    assert "_without_feed_entries" in body


def test_automat_obsady_bierze_tylko_blokujace_kalendarze():
    body = function_source("app/assignment_context.py", "load_roster")
    assert "blocks_assignment" in body
    assert "judge_feed_offtimes" in body


# ── nieudane pobranie ────────────────────────────────────────────


def _handler_source(name: str, func: str) -> str:
    """Sama gałąź `except` z funkcji - nie wszystko, co po niej następuje."""
    tree = ast.parse(source(name))
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != func:
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Try) and inner.handlers:
                return " ".join(ast.unparse(h) for h in inner.handlers)
    raise AssertionError(f"{name}: {func} nie ma bloku except")


def test_nieudane_pobranie_nie_kasuje_planu_i_nie_udaje_synchronizacji():
    handler = _handler_source("app/calendar_feed_sync.py", "sync_feed")
    # Awaria uczelni ma zostawić poprzedni plan i NIE liczyć się jako udana
    # synchronizacja, żeby kolejny przebieg spróbował ponownie.
    assert "synced=False" in handler
    assert "judge_feed_offtimes" not in handler
    assert "status='error'" in handler or 'status="error"' in handler


def test_usuniecie_kalendarza_kasuje_takze_wpisy():
    body = function_source("app/calendar_feeds.py", "remove_feed")
    assert "judge_feed_offtimes" in body
    assert body.index("judge_feed_offtimes") < body.index("judge_calendar_feeds")


def test_kalendarz_nalezy_do_numeru_sedziego_z_tokenu():
    body = function_source("app/calendar_feeds.py", "_owner")
    assert "judge_id" in body
    # Konto bez numeru (klub, związek) nie ma własnych niedyspozycji.
    assert "403" in body or "HTTP_403_FORBIDDEN" in body

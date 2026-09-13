"""Okablowanie meczów w kalendarzu okręgowym - czytane ze źródła.

`app/db.py` łączy się z bazą już przy imporcie, więc trasy sprawdzamy tak samo
jak bramki admina i kalendarze sędziego: czytając kod. Pilnujemy tego, co łatwo
zepsuć i trudno zauważyć, bo objawia się dopiero u mastera okręgowego:

  1. mecze doklejane są DOPIERO przy odczycie i tylko w widoku okręgowym,
  2. świeższy mecz z serwera wypiera ten sam mecz przysłany z telefonu,
  3. liść z regułą nie ciągnie bazy przy imporcie,
  4. odświeżenie meczów nie udaje, że sędzia zaktualizował niedyspozycje.
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


def test_odczyt_doklada_mecze_jako_osobne_zrodlo():
    body = function_source("app/silesia.py", "_composed_offtime_records")
    assert "province_match_entries" in body
    # Kubełek musi wejść do odpowiedzi, nie tylko zostać policzony.
    assert "'matches'" in body or '"matches"' in body


def test_mecze_tylko_w_widoku_okregowym():
    """Telefon rysuje swoje mecze sam - z `/self` dostałby je po raz drugi."""
    body = function_source("app/silesia.py", "_composed_offtime_records")
    call = body.index("province_match_entries")
    guard = body.rindex("judge_id is None", 0, call)
    # Warunek stoi tuż przed pobraniem, a nie gdzieś wyżej przy czymś innym.
    assert 0 < call - guard < 400


def test_serwer_wypiera_ten_sam_mecz_z_telefonu():
    body = function_source("app/silesia.py", "_composed_offtime_records")
    assert "without_client_duplicates" in body
    # Mecze z serwera idą PO danych okręgowych, więc przy scalaniu po
    # identyfikatorze to one są wersją ostateczną.
    district = body.index("without_client_duplicates")
    assert district < body.rindex("group.get('matches', [])")


def test_odswiezenie_meczow_nie_udaje_zapisu_sedziego():
    """`updated_at` mówi, kiedy sędzia ostatnio ruszył SWOJE niedyspozycje.

    Mecze odświeżają się same co kilkanaście minut. Gdyby podbijały ten
    znacznik, kalendarz zawsze wyglądałby na świeży i nie dałoby się poznać
    sędziego, który od pół roku niczego nie zaktualizował.
    """
    body = function_source("app/silesia.py", "_composed_offtime_records")
    tail = body[body.index("province_match_entries") :]
    assert "_newest_datetime" not in tail


def test_lisc_nie_ciagnie_bazy_przy_imporcie():
    tree = ast.parse(source("app/province_match_offtimes.py"))
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            name = getattr(node, "module", "") or ""
            assert name != "app.db", "app/db.py łączy się z bazą przy imporcie"


def test_zapytanie_pyta_o_wszystkie_pisownie_okregu():
    body = function_source("app/province_match_offtimes.py", "province_match_entries")
    assert "spellings" in body
    # Nieaktywna obsada i wygaszony mecz nie blokują nikomu terminu.
    assert "active" in body

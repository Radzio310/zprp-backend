"""
Czyszczenie urządzenia z innych kont ProEl - operator na kolumnie tablicowej.

DLACZEGO OSOBNY PLIK NA JEDEN WARUNEK
`device_ids.contains([installation_id])` wyglądał niewinnie i przeszedł
przegląd kodu, a wywracał trzy rzeczy naraz: ostatni krok zakładania konta,
zwykłe logowanie i ostatni krok resetu hasła - wszystkie trzy kończą się
wywołaniem `POST /proel/users/login`. `ARRAY` z rdzenia SQLAlchemy nie ma
własnego `contains`; zależnie od wersji biblioteki wywołanie albo wprost
odmawia, albo schodzi do wersji TEKSTOWEJ (LIKE) i wywraca się na liście
`TypeError`-em. Na produkcji trafił nam się ten drugi wariant, czyli 500.

Wspólne dla obu wariantów jest to, że błąd powstaje przy BUDOWANIU zapytania.
Wystarczy je więc zbudować, żeby go złapać - bez Postgresa, bez sieci, w
milisekundach.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from sqlalchemy import ARRAY, Column, Integer, MetaData, String, Table, and_, select

metadata = MetaData()

users_t = Table(
    "fake_proel_users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("device_ids", ARRAY(String)),
)


def test_any_buduje_warunek_tablicowy():
    stmt = select(users_t.c.id).where(
        and_(users_t.c.id != 7, users_t.c.device_ids.any("install-1"))
    )
    sql = str(stmt).upper()
    assert "ANY" in sql
    assert "LIKE" not in sql


def test_contains_na_liscie_dalej_jest_pulapka():
    """Dowód, że stary zapis NIE działa - gdyby kiedyś wrócił, test tłumaczy dlaczego."""
    with pytest.raises((TypeError, NotImplementedError)):
        users_t.c.device_ids.contains(["install-1"])


def _cleanup_source_without_docstring() -> str:
    """Ciało `_remove_device_from_other_users` bez opisu.

    Bez odsiania docstringu test łapałby własny komentarz, w którym pułapka
    jest opisana z nazwy.
    """
    path = Path(__file__).resolve().parents[1] / "app" / "proel_users" / "users.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    fn = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef)
        and node.name == "_remove_device_from_other_users"
    )
    body = [
        node
        for node in fn.body
        if not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
    ]
    return "\n".join(ast.unparse(node) for node in body)


def test_uzywamy_any_a_nie_contains():
    code = _cleanup_source_without_docstring()
    assert "device_ids.any(" in code
    assert "device_ids.contains(" not in code


def test_urzadzenie_znika_takze_z_opisow():
    """Telefon zdjęty z listy, ale zostawiony w `device_infos`, dalej wisiałby
    w panelu admina jako aktywny."""
    code = _cleanup_source_without_docstring()
    assert "device_infos" in code

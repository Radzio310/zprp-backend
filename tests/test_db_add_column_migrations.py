"""Kolumna dołożona do ISTNIEJĄCEJ tabeli wymaga własnej migracji.

`app/db.py` zakłada schemat przez `metadata.create_all`, a ten tworzy tylko
tabele, których jeszcze nie ma. Tabeli, która na produkcji już stoi, NIE
dotyka - więc kolumna dopisana w definicji `Table(...)` istnieje wyłącznie
w kodzie. Skutek jest natychmiastowy i całkowity: każdy `SELECT` po tej
tabeli kończy się błędem bazy.

Tak właśnie padł panel historii wersji (15.09.2026): tabela migawek powstała
wcześniej, cztery kolumny o ostatnim zdarzeniu doszły później, panel pokazał
„Nie udało się pobrać historii wersji", a `record_snapshot` - który z zasady
nigdy nie rzuca - po cichu przestał cokolwiek odkładać.

Dlatego każda taka kolumna musi mieć obok `ALTER TABLE ... ADD COLUMN IF NOT
EXISTS`. Ten test czyta źródło i pilnuje dwóch rzeczy naraz: że migracje nie
nazywają kolumn, których nie ma w definicji (literówka = martwa migracja),
i że kolumny dołożone do tabel z produkcji swoją migrację mają.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "app" / "db.py").read_text(encoding="utf-8")

#: `ALTER TABLE <tabela> ADD COLUMN IF NOT EXISTS <kolumna> <typ>`
_ALTER = re.compile(
    r"ALTER TABLE\s+(\w+)\s+ADD COLUMN IF NOT EXISTS\s+(\w+)",
    re.IGNORECASE,
)


def _columns_of(table: str) -> set:
    """Nazwy kolumn z definicji `Table("<table>", metadata, ...)`."""
    tree = ast.parse(SOURCE)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if getattr(node.func, "id", "") != "Table" or not node.args:
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and first.value == table):
            continue
        out = set()
        for arg in node.args[1:]:
            if (
                isinstance(arg, ast.Call)
                and getattr(arg.func, "id", "") == "Column"
                and arg.args
                and isinstance(arg.args[0], ast.Constant)
            ):
                out.add(arg.args[0].value)
        return out
    return set()


ALTERS = _ALTER.findall(SOURCE)


def test_sa_w_ogole_jakies_migracje_kolumn():
    """Gdyby wzorzec przestał pasować, reszta testów milczałaby na zielono."""
    assert len(ALTERS) > 20


@pytest.mark.parametrize("table,column", ALTERS)
def test_migracja_nazywa_kolumne_ktora_naprawde_istnieje(table, column):
    """Literówka w migracji to migracja, która nigdy niczego nie doda."""
    defined = _columns_of(table)
    if not defined:
        # Tabela z innego modułu (np. `app/mentoring_tables.py`) - nie mamy tu
        # jej definicji, więc nie ma czego porównywać.
        pytest.skip(f"{table}: definicja poza app/db.py")
    assert column in defined, f"{table}.{column} nie istnieje w definicji tabeli"


@pytest.mark.parametrize(
    "column",
    [
        "last_event_type",
        "last_event_team",
        "last_event_player",
        "last_event_ms",
        "last_event_tag",
    ],
)
def test_kolumny_ostatniego_zdarzenia_maja_migracje(column):
    """Tabela migawek stoi na produkcji od wdrożenia historii wersji."""
    assert ("proel_match_snapshots", column) in ALTERS, column

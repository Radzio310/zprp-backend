"""Każdy odczyt `actor.<pole>` w module ProEl musi trafiać w istniejące pole.

Powód powstania testu: `delete_proel_match` sięgał po `actor.install`, którego
`Actor` nie ma - dataclass trzyma `installation_id`, a nazwa `install` istnieje
wyłącznie w słowniku z `as_by()`. Efekt: `AttributeError` → 500 → aplikacja
mówiła „Nie udało się usunąć zapisu meczu" i nie kasowała nic, także lokalnie.

Dlaczego akurat tak, a nie testem end-to-end: ścieżka archiwum wymaga Postgresa,
więc `tests/test_proel_archive.py` pomija się na maszynie deweloperskiej i w CI.
Kod wykonał się pierwszy raz w hali. Ten test nie potrzebuje ani bazy, ani
importu `app.proel` (który przez `app.db` żąda żywego Postgresa) - czyta źródła
drzewem składni, więc chodzi ZAWSZE.

Świadome ograniczenie: rozpoznajemy tylko zmienne nazwane `actor` (tak nazywa
się parametr wstrzykiwany przez `Depends(proel_actor)` we wszystkich trasach).
Aliasowanie pod inną nazwą przejdzie niezauważone - i to jest w porządku, bo
test ma łapać literówkę w nazwie pola, a nie udawać kontroli typów.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

# `app.proel_auth` importuje `app.db` LENIWIE (wewnątrz funkcji), więc sam
# `Actor` jest dostępny bez bazy - patrz nota przy imporcie w tamtym module.
from app.proel_auth import Actor

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"

PROEL_SOURCES = sorted(
    p for p in APP_DIR.glob("proel*.py") if p.is_file()
)


def _actor_attribute_reads(path: pathlib.Path) -> list[tuple[str, int]]:
    """Wszystkie `actor.<pole>` w pliku, jako (pole, numer linii)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "actor"
        ):
            found.append((node.attr, node.lineno))
    return found


def _actor_members() -> set[str]:
    """Pola i metody `Actor` - jedno źródło prawdy dla asercji niżej."""
    sample = Actor(judge_id="1", installation_id="i")
    return {n for n in dir(sample) if not n.startswith("_")}


def test_proel_sources_found():
    """Gdyby pliki się przeniosły, test nie ma prawa przejść na pustej liście."""
    assert PROEL_SOURCES, "Nie znaleziono modułów app/proel*.py"


@pytest.mark.parametrize("path", PROEL_SOURCES, ids=lambda p: p.name)
def test_actor_attributes_exist(path: pathlib.Path):
    members = _actor_members()
    bad = [
        f"{path.name}:{line} -> actor.{attr}"
        for attr, line in _actor_attribute_reads(path)
        if attr not in members
    ]
    assert not bad, (
        "Odczyt nieistniejącego pola Actor (AttributeError w czasie żądania):\n"
        + "\n".join(bad)
        + f"\nDostępne pola: {sorted(members)}"
    )


def test_install_is_only_a_json_key():
    """`install` istnieje w kształcie JSON, a NIE jako atrybut - to była pułapka."""
    actor = Actor(judge_id="7", installation_id="abc")
    assert "install" in actor.as_by()
    assert actor.as_by()["install"] == "abc"
    assert not hasattr(actor, "install")

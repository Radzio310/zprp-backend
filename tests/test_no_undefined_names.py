"""
Żaden moduł nie wolno, żeby wołał nazwę, której nie ma.

Powód jest konkretny: `app/db.py` łączy się z Postgresem już przy imporcie,
więc importy bazy schodzą do WNĘTRZA funkcji (patrz nota w `app/one_time.py`).
Przy przenoszeniu takiego importu łatwo zgubić jedną nazwę - i wtedy moduł
kompiluje się, testy jednostkowe przechodzą, a `NameError` wychodzi dopiero
na produkcji, przy pierwszym wywołaniu tej jednej funkcji. Dokładnie to stało
się `load_roster` 12.09.2026 (brakowało `silesia_offtimes`).

Pilnujemy WYŁĄCZNIE nieznanych nazw. Nieużywane importy i inne drobiazgi
zostawiamy w spokoju - test ma mówić o błędach, a nie o stylu.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

pyflakes = pytest.importorskip("pyflakes", reason="pyflakes nie jest zainstalowany")

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _undefined(paths: list[str]) -> list[str]:
    result = subprocess.run(
        [sys.executable, "-m", "pyflakes", *paths],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    output = f"{result.stdout}\n{result.stderr}"
    return [line.strip() for line in output.splitlines() if "undefined name" in line]


def test_backend_has_no_undefined_names():
    problems = _undefined(["app", "main.py"])
    assert not problems, "Nieznane nazwy w kodzie:\n" + "\n".join(problems)


def test_the_guard_would_catch_a_lost_import(tmp_path):
    """Strażnik, który niczego nie łapie, jest gorszy niż jego brak."""
    broken = tmp_path / "broken.py"
    broken.write_text(
        "def f():\n    return zgubiona_nazwa\n",
        encoding="utf-8",
    )
    assert _undefined([str(broken)])


def _module_level_names(path: pathlib.Path) -> set[str]:
    """Nazwy, które moduł faktycznie wystawia - z AST, bez importowania go."""
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, (ast.AnnAssign,)) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


def test_every_import_from_app_db_points_at_something_real():
    """
    `from app.db import ...` z literówką przechodzi pyflakes bez słowa.

    Pyflakes patrzy na JEDEN plik i nie wie, co `app.db` naprawdę wystawia,
    a `app.db` nie da się zaimportować w teście (łączy się z Postgresem przy
    imporcie). Dlatego czytamy jego nazwy z AST i porównujemy z tym, o co
    proszą pozostałe moduły - tabela o zmyślonej nazwie wyszłaby inaczej
    dopiero na produkcji.
    """
    import ast

    available = _module_level_names(ROOT / "app" / "db.py")
    # `db.py` dostawia tabele mentoringu w krotce - AST tego nie rozpakuje.
    available |= {
        "mentoring_config",
        "mentoring_pairs",
        "mentoring_members",
        "mentoring_assignments",
        "mentoring_audit",
    }

    problems: list[str] = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        if path.name == "db.py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or node.module != "app.db":
                continue
            for alias in node.names:
                if alias.name not in available:
                    problems.append(
                        f"{path.relative_to(ROOT)}:{node.lineno}: "
                        f"app.db nie ma nazwy {alias.name!r}"
                    )
    assert not problems, "\n".join(problems)

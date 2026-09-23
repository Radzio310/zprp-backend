"""
Żadna trasa nie może być przesłonięta przez wcześniejszą trasę z parametrem.

FastAPI dopasowuje trasy w kolejności deklaracji. `PUT /clubs/{club_id}`
zapisany PRZED `PUT /clubs/bulk` łapie "bulk" jako numer klubu - akcja grupowa
zapisywała wtedy deklarację klubowi "bulk" i odpowiadała "OK" (23.09.2026,
4. stolikowy "wracał" w panelu i w skrypcie deklaracji).

Test czyta dekoratory z AST (bez importu - `app/db.py` łączy się z bazą).
"""

from __future__ import annotations

import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
METHODS = {"get", "post", "put", "patch", "delete"}


def _routes(path: pathlib.Path) -> list[tuple[str, str, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[tuple[str, str, int]] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            if not (isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute)):
                continue
            # Router jest częścią klucza: `router` i `admin_router` mają osobne
            # prefiksy i nie przesłaniają się nawzajem.
            owner = ast.unparse(deco.func.value)
            method = f"{owner}.{deco.func.attr}"
            if deco.func.attr not in METHODS or not deco.args:
                continue
            first = deco.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                found.append((method, first.value, deco.lineno))
    return found


def _pattern(route: str) -> re.Pattern[str]:
    # `{x}` = jeden segment, `{x:path}` = reszta ścieżki (jak w Starlette).
    parts = []
    for piece in re.split(r"(\{[^}]+\})", route):
        if piece.startswith("{"):
            parts.append(".+" if piece.endswith(":path}") else "[^/]+")
        else:
            parts.append(re.escape(piece))
    return re.compile("^" + "".join(parts) + "$")


def shadowed(routes: list[tuple[str, str, int]]) -> list[str]:
    problems = []
    for index, (method, route, line) in enumerate(routes):
        for earlier_method, earlier, earlier_line in routes[:index]:
            if earlier_method != method or "{" not in earlier or earlier == route:
                continue
            # Konkretna ścieżka późniejszej trasy (parametry jako "x").
            sample = re.sub(r"\{[^}]+\}", "x", route)
            if "{" not in route and _pattern(earlier).match(sample):
                problems.append(
                    f"{method.upper()} {route} (linia {line}) przesłonięta przez "
                    f"{earlier} (linia {earlier_line})"
                )
    return problems


def test_no_route_is_shadowed_by_an_earlier_parameter_route():
    problems = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        try:
            routes = _routes(path)
        except SyntaxError:
            continue
        problems += [f"{path.relative_to(ROOT)}: {p}" for p in shadowed(routes)]
    assert not problems, "\n".join(problems)


def test_the_guard_catches_the_bulk_case():
    routes = [("router.put", "/clubs/{club_id}", 1), ("router.put", "/clubs/bulk", 2)]
    assert shadowed(routes)
    assert not shadowed(list(reversed(routes)))

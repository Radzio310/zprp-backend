"""Wiazania modulu bomb - czytane z drzewa skladni, nie z importu.

`app.match_bombs` ciagnie `app.db`, a ten zada zywego Postgresa, wiec ten plik
NIE importuje modulu (ta sama droga, co w `test_match_market_wiring`). Lapie
pomylki, ktore inaczej wykonalyby sie pierwszy raz na produkcji: trasa bez
sprawdzenia, kto wola; regula przepisana w trasie zamiast wziecia jej z liscia;
powiadomienie bez oslony.
"""

from __future__ import annotations

import ast
import pathlib

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"
SOURCE = (APP_DIR / "match_bombs.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)

FUNCTIONS = {
    node.name: node
    for node in ast.walk(TREE)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}


def calls_in(name: str) -> set[str]:
    out: set[str] = set()
    for sub in ast.walk(FUNCTIONS[name]):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Name):
                out.add(func.id)
            elif isinstance(func, ast.Attribute):
                out.add(func.attr)
    return out


def code_of(name: str) -> str:
    node = FUNCTIONS[name]
    body = [
        sub
        for sub in node.body
        if not (
            isinstance(sub, ast.Expr)
            and isinstance(sub.value, ast.Constant)
            and isinstance(sub.value.value, str)
        )
    ]
    return chr(10).join(ast.unparse(sub) for sub in body)


def routes() -> list[tuple[str, str, str]]:
    found = []
    for node in TREE.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            func = dec.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == "router" and dec.args:
                    path = dec.args[0]
                    if isinstance(path, ast.Constant):
                        found.append((func.attr, path.value, node.name))
    return found


def test_all_routes_are_registered():
    paths = {(m, p) for m, p, _ in routes()}
    assert ("get", "/match/{match_id}") in paths
    assert ("post", "") in paths
    assert ("delete", "/{bomb_id}") in paths
    assert ("post", "/{bomb_id}/void") in paths
    assert ("get", "/registry/{province}") in paths
    # Lekkie pytanie dla menu - kafel rejestru pojawia sie tylko tym, ktorzy
    # maja go po co otwierac.
    assert ("get", "/me") in paths


def test_every_route_asks_who_is_calling():
    """Wpis mowi o CUDZEJ rzetelnosci - trasa bez aktora bylaby otwarta."""
    for _, path, name in routes():
        source = ast.unparse(FUNCTIONS[name])
        assert "market_actor" in source, f"{path} nie pyta, kto wola"


def test_reporting_checks_the_crew_and_the_window():
    """Dwie bramki, ktore trzymaja caly pomysl: kto tam byl i kiedy zglasza."""
    calls = calls_in("report_bomb")
    assert "may_report" in calls, "brak okna czasowego"
    assert "find_in_crew" in calls, "brak sprawdzenia obsady"
    assert "_match_crew" in calls


def test_crew_comes_from_the_province_schedule_first():
    """Obsady z telefonu nie da sie sprawdzic - terminarz okregu tak."""
    source = code_of("_match_crew")
    assert "province_matches" in source
    assert "crew_from_state" in source
    # Migawka z aplikacji zostaje dla meczow spoza okregu i jest OZNACZONA.
    assert "crew_from_payload" in source
    assert "'app'" in source


def test_registry_belongs_to_the_commission():
    source = code_of("registry")
    assert "_is_commission" in source
    # Komisja czyta wlasny okreg, administrator kazdy - i to musi byc w kodzie,
    # nie tylko w opisie ekranu.
    assert "is_admin" in source


def test_voiding_needs_a_reason_and_keeps_the_entry():
    """Uniewazniony wpis ZOSTAJE w rejestrze - inaczej rejestr klamie."""
    source = code_of("void_bomb")
    assert "may_void" in source
    assert "reason" in source
    assert "'voided'" in source
    assert "delete(" not in source


def test_withdrawal_is_only_for_the_author():
    source = code_of("withdraw_bomb")
    assert "may_withdraw" in source
    assert "'withdrawn'" in source
    assert "delete(" not in source


def test_author_is_never_shown_by_the_route_itself():
    """O widocznosci autora decyduje lisc, w JEDNYM miejscu."""
    assert "author_is_visible" in calls_in("_view")
    for name in ("bombs_for_match", "registry"):
        assert "_view" in calls_in(name), name


def test_notifications_never_break_the_action_they_came_from():
    node = FUNCTIONS["_notify"]
    assert any(isinstance(n, ast.Try) for n in ast.walk(node))


def test_subject_notice_waits_a_day_and_survives_a_restart():
    """Odroczenie w pamieci procesu zjadlby pierwszy restart Railway."""
    source = code_of("sweep_subject_notices")
    assert "SUBJECT_NOTICE_DELAY_HOURS" in source
    assert "subject_notified_at" in source
    # Znacznik stawiamy TAKZE wtedy, gdy nie bylo kogo powiadomic - inaczej
    # wiersz bez numeru sedziego wracalby w kazdym przejsciu.
    assert source.index("subject_notified_at=func.now()") > source.index("if target:")


def test_rules_live_in_the_leaf_not_in_the_routes():
    """Kazda regula ma jedno miejsce - inaczej ekran i serwer rozjada sie."""
    for name in ("REPORT_WINDOW_DAYS", "COUNTED_STATUSES", "SEASON_START_MONTH"):
        assert name not in SOURCE, f"{name} przepisane do trasy"

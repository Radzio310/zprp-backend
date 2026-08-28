"""Wiązania modułu giełdy meczów - czytane z drzewa składni, nie z importu.

`app.match_market` ciągnie `app.db`, a ten żąda żywego Postgresa, więc ten plik
NIE importuje modułu. Czyta jego źródło, tak samo jak `test_proel_actor_attrs`.
Dzięki temu chodzi na maszynie deweloperskiej i w CI, a łapie dokładnie te
pomyłki, które inaczej wykonałyby się pierwszy raz na produkcji:

* zapis do ZPRP puszczony inną drogą niż wspólny rdzeń z modułem obsadowego,
* trasa zmieniająca stan bez sprawdzenia uprawnień,
* wysyłka powiadomień z pominięciem osłony, która nigdy nie rzuca.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"
SOURCE = (APP_DIR / "match_market.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)

FUNCTIONS = {
    node.name: node
    for node in ast.walk(TREE)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
}


def calls_in(name: str) -> set[str]:
    """Nazwy wołanych funkcji wewnątrz danej funkcji modułu."""
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


def routes() -> list[tuple[str, str, str]]:
    """(metoda, ścieżka, nazwa funkcji) dla każdej trasy modułu."""
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
    assert ("get", "/context") in paths
    assert ("get", "/my-matches") in paths
    assert ("post", "/offers") in paths
    assert ("delete", "/offers/{offer_id}") in paths
    assert ("post", "/offers/{offer_id}/claims") in paths
    assert ("delete", "/offers/{offer_id}/claims/me") in paths
    assert ("post", "/offers/{offer_id}/approve") in paths
    assert ("post", "/offers/{offer_id}/reject") in paths
    assert ("get", "/admin/provinces") in paths
    assert ("put", "/admin/provinces/{province}") in paths


def test_every_route_asks_who_is_calling():
    # Trasa bez `market_actor` byłaby otwarta dla świata - a ten moduł zmienia
    # obsadę meczów, które naprawdę się odbędą.
    for _, path, name in routes():
        node = FUNCTIONS[name]
        args = [a.arg for a in node.args.args] + [a.arg for a in node.args.kwonlyargs]
        assert "actor" in args, f"{path} nie pyta, kto woła"


def test_only_the_shared_core_writes_to_zprp():
    # Zapis obsady ma JEDNĄ drogę: `apply_referee_assignment`. Druga ścieżka
    # znaczyłaby drugie miejsce, w którym można zapomnieć o `akcja_edycja`.
    writers = [name for name in FUNCTIONS if "apply_referee_assignment" in calls_in(name)]
    assert writers == ["approve_offer"], writers


def test_approval_locks_the_row_and_checks_the_badge():
    calls = calls_in("approve_offer")
    assert "_require_approver" in calls
    # `with_for_update` to jedyna rzecz, która nie pozwala dwóm obsadowym wejść
    # na to samo zgłoszenie w tej samej sekundzie.
    assert "with_for_update" in calls
    assert "transaction" in calls


def test_rejection_is_guarded_too():
    calls = calls_in("reject_offer")
    assert "_require_approver" in calls
    assert "with_for_update" in calls


def test_state_changes_go_through_the_transition_table():
    # Ręczne wpisanie statusu ominęłoby tabelę przejść, czyli jedyne miejsce,
    # w którym te reguły są opisane i przetestowane.
    for name in ("withdraw_offer", "reject_offer", "approve_offer"):
        assert "next_offer_status" in calls_in(name), name
    for name in ("withdraw_claim",):
        assert "next_claim_status" in calls_in(name), name


def test_notifications_never_escape_the_shield():
    # `_notify` łapie wyjątki - `send_push_to_judges` wołane wprost mogłoby
    # wywrócić operację, przy której powstało.
    senders = [
        name
        for name in FUNCTIONS
        if name != "_notify" and "send_push_to_judges" in calls_in(name)
    ]
    assert senders == [], senders


def test_config_endpoints_are_admin_only():
    for name in ("admin_provinces", "admin_set_province"):
        assert "may_manage_config" in calls_in(name), name


def test_offer_creation_verifies_ownership_and_threshold():
    calls = calls_in("create_offer")
    assert "slots_held_by" in calls, "kto inny mógłby oddać cudze gniazdo"
    assert "slot_is_tradeable" in calls, "delegat nie należy do giełdy"
    assert "can_offer" in calls, "próg czasowy okręgu"


def test_apply_uses_the_slot_guard():
    # `expect=` w wywołaniu rdzenia to strażnik przed nadpisaniem cudzej
    # decyzji, gdy obsada zmieniła się poza aplikacją.
    node = FUNCTIONS["approve_offer"]
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
            if sub.func.id == "apply_referee_assignment":
                assert "expect" in {kw.arg for kw in sub.keywords}
                return
    pytest.fail("nie znalazłem wywołania rdzenia zapisu")


def test_router_is_registered_in_main():
    main = (APP_DIR.parent / "main.py").read_text(encoding="utf-8")
    assert "from app.match_market import router as match_market_router" in main
    assert "app.include_router(match_market_router)" in main


def test_offer_creation_asks_whether_the_district_assigns_this_match():
    """Najważniejsza bramka w module.

    Sędzia widzi w aplikacji wszystkie swoje mecze, a okręg obsadza tylko część
    z nich. Bez tego wywołania dałoby się wystawić mecz ligi centralnej, którego
    konto wojewódzkie nie ma prawa tknąć - i wyszłoby to dopiero przy
    zatwierdzaniu, gdy oddający dawno przestał szukać zastępstwa.
    """
    assert "_require_assignable" in calls_in("create_offer")


def test_the_gate_is_the_last_check_not_the_first():
    # Sonda to wejście na serwer związku. Tanie sprawdzenia - gniazdo, próg,
    # duplikat - muszą odpaść wcześniej, żeby nie płacić za nie ruchem po sieci.
    body = ast.unparse(FUNCTIONS["create_offer"])
    gate = body.index("_require_assignable")
    for cheap in ("slot_is_tradeable", "slots_held_by", "can_offer"):
        assert body.index(cheap) < gate, f"{cheap} stoi po sondzie"


def test_probe_answers_are_cached_but_failures_are_not():
    # Zapisany błąd sieci wyglądałby w pamięci tak samo jak odmowa okręgu i
    # blokowałby mecz na całą dobę.
    source = ast.unparse(FUNCTIONS["_store_verdict"])
    assert "PROBE_FAILED" in source
    assert "return" in source


def test_probe_reads_rights_and_never_writes():
    # Sonda ma jedno zadanie: zapytać. Zapis idzie wyłącznie przez rdzeń.
    assert "apply_referee_assignment" not in calls_in("_probe")
    assert "probe_assignment_rights" in calls_in("_probe")


def test_my_matches_reports_what_it_did_not_check():
    # Zasada „bez cichych limitów": paczka sondy jest przycięta, więc liczba
    # niesprawdzonych meczów musi wyjść na zewnątrz.
    source = ast.unparse(FUNCTIONS["my_matches"])
    assert "PROBE_BATCH_LIMIT" in source
    assert "unchecked" in source


def test_the_gate_cannot_be_skipped_by_a_missing_account():
    # Okręg bez konta obsadowego nie zapisze niczego w ZPRP. Odmowa ma paść
    # przy wystawianiu, a nie po umowie dwóch sędziów.
    source = ast.unparse(FUNCTIONS["_require_assignable"])
    assert "assign_credentials" in source
    assert "NO_ACCOUNT" in source

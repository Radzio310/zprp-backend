"""Egzamin z przepisów - wiązania tras, bez importowania żywej bazy."""

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def source(*parts):
    return (ROOT.joinpath(*parts)).read_text(encoding="utf-8")


def functions(src):
    return {n.name: n for n in ast.walk(ast.parse(src)) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def test_router_zarejestrowany_i_sweep_podpiety_pod_petle_wydarzen():
    assert "app.include_router(exams_router)" in source("main.py")
    sweep = ast.get_source_segment(source("app", "province_events.py"), functions(source("app", "province_events.py"))["run_event_reminder_sweep"])
    assert "sweep_event_reminders()" in sweep and "run_exam_sweep" in sweep


def test_tabele_egzaminu_w_db():
    db = source("app", "db.py")
    for name in ("exam_banks", "exam_bank_questions", "exam_definitions", "exam_attempts", "exam_answers", "exam_events", "exam_reminders_sent"):
        assert name in db


def test_trasy_wymagaja_zalogowanego_i_nie_importuja_bazy_na_gorze():
    src = source("app", "exams.py")
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            assert node.module not in ("app.db", "app.province_events"), "importy bazy tylko wewnątrz funkcji"
    routes = [n for n in ast.walk(tree) if isinstance(n, (ast.AsyncFunctionDef,)) and n.decorator_list
              and any(isinstance(d, ast.Call) and getattr(d.func, "value", None) is not None and getattr(d.func.value, "id", "") == "router" for d in n.decorator_list)]
    assert len(routes) >= 25
    for fn in routes:
        assert "who" in {a.arg for a in fn.args.args}, f"{fn.name}: trasa bez _who (token)"


def test_trasy_komisji_przechodza_przez_bramke_uprawnien():
    svc = source("app", "exam_service.py")
    fns = functions(svc)
    for name in ("attempts_list", "attempt_card", "exam_stats", "missing", "void_question", "unvoid_question",
                 "allow_device", "room_code_for", "similarity_scan"):
        assert "_managed_exam" in ast.get_source_segment(svc, fns[name]), name
    for name in ("create_exam", "update_exam", "delete_exam", "list_manage"):
        assert "require_manage" in ast.get_source_segment(svc, fns[name]), name
    assert "_managed_exam" in ast.get_source_segment(svc, fns["_managed_exam"]) or "require_manage" in ast.get_source_segment(svc, fns["_managed_exam"])


def test_trasy_statyczne_przed_parametrem_exam_id():
    src = source("app", "exams.py")
    assert src.index('"/bank"') < src.index('"/{exam_id}"')
    assert src.index('"/attempts/{attempt_id}"') < src.index('"/{exam_id}"')
    assert src.index('"/manage"') < src.index('"/{exam_id}"')

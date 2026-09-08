"""Wiązania badań lekarskich w ProElu - czytane z drzewa składni.

`app.proel` i `app.proel_exams` ciągną `app.db`, a ten żąda żywego Postgresa,
więc ten plik NIE importuje modułów (ta sama droga, co w
`test_match_market_wiring`). Pilnuje trzech rzeczy, które inaczej wykonałyby
się pierwszy raz na produkcji:

* ręczne potwierdzenie z bloba wchodzi do overlaya PRZED reprojekcją - po
  niej karty niosłyby już stan overlaya i nie byłoby czego czytać,
* pytanie do związku nigdy nie stoi na drodze zapisu bloba - idzie w tle,
  z ryglem czasu, a zatwierdzonego protokołu nie rusza,
* generator PDF nakłada overlay na blob do wydruku, ale nie na ćwiczenie i
  nie na cudzy mecz o tym samym numerze.
"""

from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app"


def load(name: str):
    source = (APP_DIR / name).read_text(encoding="utf-8")
    tree = ast.parse(source)
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    return source, tree, functions


PROEL_SRC, PROEL_TREE, PROEL = load("proel.py")
EXAMS_SRC, EXAMS_TREE, EXAMS = load("proel_exams.py")
RESULTS_SRC, RESULTS_TREE, RESULTS = load("results.py")
MAIN_SRC = (ROOT / "main.py").read_text(encoding="utf-8")


def calls_in(node: ast.AST) -> set[str]:
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Name):
                out.add(func.id)
            elif isinstance(func, ast.Attribute):
                out.add(func.attr)
    return out


def code_of(node: ast.AST) -> str:
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


# ───────────────────────── zapis bloba ─────────────────────────


def test_both_blob_writes_absorb_manual_marks_before_reprojection():
    for name in ("create_proel_match", "update_proel_match"):
        source = code_of(PROEL[name])
        assert "absorb_blob_exams" in calls_in(PROEL[name]), name
        assert source.index("absorb_blob_exams") < source.index("_reproject_blob("), name
        # Blob bez wiersza stanu (starsza aplikacja) dostaje go, gdy niesie
        # ręczny ptaszek - inaczej nie ma gdzie zostawić śladu.
        assert "ensure_state_row" in calls_in(PROEL[name]), name
        assert "has_manual_exams" in calls_in(PROEL[name]), name


def test_blob_writes_journal_what_they_absorbed_and_kick_the_promotion():
    for name in ("create_proel_match", "update_proel_match"):
        calls = calls_in(PROEL[name])
        assert "journal_absorbed" in calls, name
        assert "kick_promotion" in calls, name


def test_promotion_never_waits_inside_the_blob_write():
    """Pytanie do cudzego serwera nie ma prawa wydłużać zapisu protokołu."""
    for name in ("create_proel_match", "update_proel_match"):
        for sub in ast.walk(PROEL[name]):
            if isinstance(sub, ast.Await) and isinstance(sub.value, ast.Call):
                func = sub.value.func
                called = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                assert called != "promote_manual_exams", name
    kick = code_of(EXAMS["kick_promotion"])
    assert "create_task" in kick
    # Referencja do zadania jest trzymana - `create_task` bez niej bywa
    # sprzątane przez GC w połowie pracy.
    assert "_kicked.add" in kick


def test_patch_route_names_exam_events_by_their_meaning():
    source = code_of(PROEL["patch_proel_state"])
    assert "exam_events_from_ops" in calls_in(PROEL["patch_proel_state"])
    # Mieszany patch (badania + coś jeszcze) zostaje ogólną zmianą pól.
    assert "'field.changed'" in source


# ───────────────────────── awans ─────────────────────────


def test_promotion_is_guarded_throttled_and_lattice_bound():
    source = code_of(EXAMS["promote_manual_exams"])
    calls = calls_in(EXAMS["promote_manual_exams"])
    assert "_throttled" in calls
    assert "'approved'" in source
    assert "isdigit" in calls, "mecz bez numeru ZPRP nie ma kogo pytać"
    # Ta sama krata, co przy zapisie z telefonu - i ten sam wyjątek.
    assert "merge_exam" in calls
    assert "PathRejected" in source
    assert "with_for_update" in calls
    assert "_apply_reprojection_to_doc" in calls
    assert "'exam.promoted'" in source
    # Nieodpowiadający związek to nie awaria zapisu.
    assert any(isinstance(n, ast.Try) for n in ast.walk(EXAMS["promote_manual_exams"]))


def test_roster_comes_from_the_monitors_fetcher_on_a_short_leash():
    source = code_of(EXAMS["_fetch_roster"])
    assert "_fetch_public_details" in calls_in(EXAMS["_fetch_roster"])
    assert "ROSTER_TIMEOUT_S" in source


def test_recheck_reaches_the_journal_from_the_blob():
    """Bez ANI JEDNEGO dodatkowego wywolania z hali.

    Telefon zapisuje wynik sprawdzenia w konfiguracji meczu, a blob i tak
    jedzie na serwer sekundy pozniej - stad wpis w dzienniku.
    """
    source = code_of(EXAMS["journal_exam_recheck"])
    assert "exam_recheck_from_blob" in calls_in(EXAMS["journal_exam_recheck"])
    assert "'exam.rechecked'" in source or '"exam.rechecked"' in source
    # Klucz z godzina sprawdzenia: blob co minute nie dopisze wpisu drugi raz.
    assert "event_key" in source
    # Oba wejscia zapisu bloba (POST i PUT) musza wolac ten sam slad.
    assert PROEL_SRC.count("journal_exam_recheck(") == 2
    """Decyzja z 2026-09-08: recznego ptaszka nadpisuje sie tylko PRZED meczem.

    Protokol ma mowic, co bylo wiadomo w chwili rozpoczecia meczu.
    """
    source = code_of(EXAMS["promote_manual_exams"])
    assert "phase_of" in calls_in(EXAMS["promote_manual_exams"])
    assert "PHASE_PRE" in source
    assert "'started'" in source


def test_promotion_respects_the_competition_threshold():
    """W Superlidze awans „reczne -> WZPR" odebralby prawo gry."""
    assert "exam_requirement_for_code" in calls_in(EXAMS["promote_manual_exams"])


def test_sweep_only_touches_matches_before_the_first_whistle():
    source = code_of(EXAMS["_sweep_once"])
    # Mecz jeszcze nierozpoczety czesto NIE MA wiersza w `saved_matches`,
    # wiec przebieg pyta o wiersze stanu bez `live_started_at`.
    assert "live_started_at" in source
    assert "manual_exam_candidates" in calls_in(EXAMS["_sweep_once"])
    assert "PROMOTION_SWEEP_BATCH" in source
    loop = code_of(EXAMS["run_exam_promotion_sweep"])
    assert "PROMOTION_SWEEP_S" in loop
    assert any(isinstance(n, ast.Try) for n in ast.walk(EXAMS["run_exam_promotion_sweep"]))


def test_sweep_is_registered_in_main_and_cancelled_on_shutdown():
    assert "run_exam_promotion_sweep" in MAIN_SRC
    assert "_exam_promotion_task = asyncio.create_task(run_exam_promotion_sweep())" in MAIN_SRC
    assert MAIN_SRC.count("_exam_promotion_task.cancel()") == 1


# ───────────────────────── PDF ─────────────────────────


def test_pdf_prints_the_overlay_but_never_a_foreign_or_training_match():
    route = RESULTS["generate_protocol_pdf"]
    source = code_of(route)
    assert "_with_exam_overlay" in calls_in(route)
    # Odcisk stanu liczy się z tego, co przysłał sędzia - PRZED nałożeniem.
    assert source.index("_sha256_bytes(state_bytes)") < source.index("_with_exam_overlay")
    helper = code_of(RESULTS["_with_exam_overlay"])
    assert "isTest" in helper
    assert "training" in helper
    assert "match_id_conflict" in calls_in(RESULTS["_with_exam_overlay"])
    # Tylko wpisy badań - reszta overlaya nie ma prawa podmieniać wydruku.
    assert "startswith('exam.')" in helper
    assert any(isinstance(n, ast.Try) for n in ast.walk(RESULTS["_with_exam_overlay"]))

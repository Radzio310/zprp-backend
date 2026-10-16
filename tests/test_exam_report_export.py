"""Egzamin - raport komisji z bazy (SQLite) i eksport HTML/PDF z limitem zadań."""

import asyncio
import os
from datetime import timedelta

import pytest

from app import exam_export as E
from app import exam_report_html as H
from app import exam_report_rules as R
from app import exam_report_service as RS
from app import exam_service as S
from app.exam_rules import ExamError
from tests.test_exam_service import (  # noqa: F401 - `st` to fiksura
    COMMISSION, CORRECT, DELEGATE, OPEN, OTHER_COMMISSION, PLAIN, answer_all, make, st,
)


async def _two_done(st):
    exam, _ = await make(st, result_release="immediate", pass_percent=60)
    t = OPEN + timedelta(minutes=5)
    for w, chooser in ((PLAIN, lambda q: [CORRECT[q]]), (DELEGATE, lambda q: ["a"])):
        state = await S.start_attempt(st, w, exam["id"], {}, now=t)
        await answer_all(st, w, state["attempt"]["id"], t, choose=chooser, state=state)
    return exam


async def test_raport_komisji_z_bazy(st):
    exam = await _two_done(st)
    rep = await RS.build_report(st, COMMISSION, exam["id"], with_scores=True)
    s = rep["summary"]
    assert s["people"] == 2 and s["passed"] == 1 and s["missing"] == 3 and s["invited"] == 5
    assert [r["place"] for r in rep["ranking"]] == [1, 2] and rep["ranking"][0]["judge_id"] == "3"
    assert len(rep["questions"]) == 3 and all(q["text"] for q in rep["questions"])
    assert rep["weakest_rules"][0]["rule"] == 1 and rep["provinces"] == []
    assert all(len(a["questions"]) == 3 for a in rep["attempts"])
    with pytest.raises(ExamError) as err:
        await RS.build_report(st, OTHER_COMMISSION, exam["id"])
    assert err.value.status == 403


async def test_podglad_unieważnienia_z_bazy_zgadza_sie_z_przeliczeniem(st):
    exam = await _two_done(st)
    prev = await RS.void_preview(st, COMMISSION, exam["id"], "q1-2")
    # Delegat ma tylko q1-1 dobrze (1/3): drop q1-2 -> 50% (dalej nie zalicza), credit -> 66,67% (zalicza).
    assert prev["drop"]["newly_passed"] == 0 and prev["credit"]["newly_passed"] == 1
    await S.void_question(st, COMMISSION, exam["id"], "q1-2", "credit")
    after = await RS.build_report(st, COMMISSION, exam["id"])
    assert after["summary"]["passed"] == 2
    with pytest.raises(ExamError) as err:
        await RS.void_preview(st, COMMISSION, exam["id"], "q1-2")
    assert err.value.code == "EXAM_ALREADY_VOIDED"


async def test_html_raportu_ma_sekcje_postep_i_anonimizacje(st):
    exam = await _two_done(st)
    rep = await RS.build_report(st, COMMISSION, exam["id"], with_scores=True)
    options = R.clean_export_options({"format": "html", "anonymize": True, "theme": "night",
                                      "sections": list(R.EXPORT_SECTIONS)}, national=False)
    rows = R.select_rows(rep["attempts"], options["range"])
    missing = [dict(m) for m in rep["missing"]]
    R.anonymize(rows, missing)
    seen = []
    html = H.render_report({**rep, "missing": missing}, rows, options, lambda *a: seen.append(a))
    assert html.startswith("<!doctype html>") and "Lista wyników" in html and "Karty zdających" in html
    assert "Jan Zwykły" not in html and "Zdający 00" in html and "próg 60%" in html
    assert {a[0] for a in seen} == {"rows", "cards"} and seen[-1][1] == seen[-1][2] == 2
    assert "Porównanie okręgów" not in html  # okręgowy egzamin: sekcja odpada


async def test_eksport_html_przez_zadanie_plik_pod_tokenem(st, tmp_path, monkeypatch):
    monkeypatch.setattr(E, "EXPORT_DIR", str(tmp_path))
    exam = await _two_done(st)
    options = R.clean_export_options({"format": "html"}, national=False)

    async def compose(progress):
        rep = await RS.build_report(st, COMMISSION, exam["id"])
        rows = R.select_rows(rep["attempts"], options["range"])
        return H.render_report(rep, rows, options, progress), "wyniki-test"

    job = E.new_job("2", exam["id"], "html")
    await E.run(job, compose)
    view = job.view()
    assert view["status"] == "ready" and view["file"]["name"] == "wyniki-test.html" and view["file"]["size"] > 1000
    assert view["names"] and view["file"]["url"].startswith("/exam-exports/files/")
    path, name, media = E.file_for(view["file"]["token"])
    assert os.path.exists(path) and media.startswith("text/html") and name == "wyniki-test.html"
    assert E.file_for("../../etc/passwd") is None
    with pytest.raises(ExamError) as err:
        E.get_job(job.id, "obcy")
    assert err.value.code == "EXPORT_JOB_GONE"


async def test_najwyzej_dwa_zadania_naraz_i_dwa_na_osobe(tmp_path, monkeypatch):
    monkeypatch.setattr(E, "EXPORT_DIR", str(tmp_path))
    gate = asyncio.Event()
    peak = {"now": 0, "max": 0}

    async def slow(progress):
        peak["now"] += 1
        peak["max"] = max(peak["max"], peak["now"])
        await gate.wait()
        peak["now"] -= 1
        return "<!doctype html><p>x</p>", "x"

    jobs = [E.new_job(f"owner{i}", "e", "html") for i in range(3)]
    tasks = [asyncio.create_task(E.run(j, slow)) for j in jobs]
    await asyncio.sleep(0.05)
    assert E.running() == 2 and [j.status for j in jobs].count("queued") == 1
    E.new_job("owner0", "e", "html")
    with pytest.raises(ExamError) as err:
        E.new_job("owner0", "e", "html")
    assert err.value.status == 429 and err.value.code == "EXPORT_BUSY"
    gate.set()
    await asyncio.gather(*tasks)
    assert peak["max"] == 2 and all(j.status == "ready" for j in jobs)
    E._JOBS.clear()


@pytest.mark.skipif(not E.pdf_available(), reason="weasyprint niedostępny lokalnie (jest w obrazie Dockera)")
async def test_pdf_przez_weasyprint(st):
    exam = await _two_done(st)
    rep = await RS.build_report(st, COMMISSION, exam["id"])
    options = R.clean_export_options({"format": "pdf"}, national=False)
    pdf = E.render_pdf(H.render_report(rep, R.select_rows(rep["attempts"], "best"), options))
    assert pdf[:4] == b"%PDF" and len(pdf) > 2000


def test_trasy_wynikow_podpiete_i_za_bramka():
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    assert "app.include_router(exam_results_router)" in (root / "main.py").read_text(encoding="utf-8")
    src = (root / "app" / "exam_results.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            assert node.module not in ("app.db", "app.province_events"), "importy bazy tylko wewnątrz funkcji"
    routes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.decorator_list}
    for name in ("report", "void_preview", "create_export", "export_job"):
        assert "who" in {a.arg for a in routes[name].args.args}, name
    # Plik pobiera przeglądarka bez nagłówka - jedynym sekretem jest token (UUID hex, 30 min).
    assert "who" not in {a.arg for a in routes["export_file"].args.args}
    svc = (root / "app" / "exam_report_service.py").read_text(encoding="utf-8")
    assert svc.count("S._managed_exam(") >= 2

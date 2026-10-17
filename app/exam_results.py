# app/exam_results.py
"""
Egzamin z przepisów - wyniki komisji i eksport (etap 4, 16.10.2026). Trasy cienkie.

  GET  /exams/{id}/report                      obraz egzaminu (te same liczby co plik)
  GET  /exams/{id}/questions/{qid}/void-preview skutki unieważnienia w trybie drop i credit
  POST /exams/{id}/exports                     plik HTML/PDF -> {url, name, size, expires_at}
                                               (`background: true` -> zadanie z postępem)
  GET  /exam-exports/jobs/{job_id}             postęp zadania (tylko zlecający)
  GET  /exam-exports/files/{token}             plik (bez logowania - token jest sekretem, 30 min)

Uprawnienia jak w komisji (`_managed_exam`): krajowy: admin (całość) albo komisja/Teach Master
okręgu (odczyt przycięty do jego okręgu, bez unieważniania); okręgowy admin / komisja TEGO okręgu / Teach Master. Kontrakt: BAZA/docs/egzamin-api.md.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app import exam_export as E
from app import exam_report_rules as R
from app.exam_rules import ExamError
from app.exams import _run, _store, _who
from app import exam_service as S

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Exams"])

#: Zadania w tle trzymamy w zbiorze - pętla zdarzeń ma tylko słabe referencje do zadań.
_TASKS: set = set()


class ExportBody(BaseModel):
    format: str = "pdf"
    range: str = "best"
    #: Brak = decyzja serwera: z kartami zdających domyślnie TAK (dane osobowe), bez nich NIE.
    anonymize: Optional[bool] = None
    sections: Optional[List[str]] = None
    theme: str = "paper"
    seal: bool = True
    background: bool = False
    #: {orientation: portrait|landscape, density: comfortable|compact, cover: bool}
    layout: Optional[Dict[str, Any]] = None
    #: {flags: any|only|none, min_percent, max_percent, provinces: [..], sort: place|name|percent_asc|integrity|province|duration}
    people: Optional[Dict[str, Any]] = None
    #: {rules: [int], difficulty: all|hard|medium|easy, weakest: int|null, voided: include|exclude|only}
    questions: Optional[Dict[str, Any]] = None


@router.get("/exams/{exam_id}/report", summary="Wyniki egzaminu dla komisji: agregaty, ranking ex aequo, okręgi")
async def report(exam_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    from app import exam_report_service as RS

    return await _run(RS.build_report(_store(), who, exam_id))


@router.get("/exams/{exam_id}/questions/{qid}/void-preview", summary="Skutki unieważnienia pytania (drop i credit)")
async def void_preview(exam_id: str, qid: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    from app import exam_report_service as RS

    return await _run(RS.void_preview(_store(), who, exam_id, qid))


def _compose(st: S.Store, who: S.Who, exam_id: str, options: Dict[str, Any]):
    async def compose(progress):
        from app import exam_report_html as H
        from app import exam_report_service as RS

        report = await RS.build_report(st, who, exam_id, with_scores="cards" in options["sections"])
        progress("collect", 1, 1, None)
        rows = R.select_rows(report["attempts"], options["range"])
        missing = [dict(m) for m in report["missing"]]
        # Kody „Zdający 001" z PEŁNEGO zakresu - filtr komisji nie przenumerowuje osób.
        if options["anonymize"]:
            R.anonymize(rows, missing)
        rows = R.apply_people(rows, options["people"])
        report = {**report, "missing": R.filter_missing(missing, options["people"])}
        html = await asyncio.to_thread(H.render_report, report, rows, options, progress)
        when = S.utcnow()
        name = R.export_filename(report["exam"]["name"], options["format"], when).rsplit(".", 1)[0]
        return html, name

    return compose


@router.post("/exams/{exam_id}/exports", summary="Eksport wyników komisji do HTML/PDF")
async def create_export(exam_id: str, body: ExportBody, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    st = _store()
    exam = await _run(S._managed_exam(st, who, exam_id, read=True))
    try:
        options = R.clean_export_options(body.model_dump(), national=exam["scope"] == "national" and not exam["cut_province"])
        if options["format"] == "pdf" and not E.pdf_available():
            raise ExamError("EXPORT_PDF_UNAVAILABLE",
                            "Serwer nie potrafi teraz złożyć PDF (brak biblioteki weasyprint). Wybierz HTML - da się go wydrukować do PDF.",
                            503)
        job = E.new_job(who.judge_id, exam_id, options["format"])
    except ExamError as error:
        raise HTTPException(error.status, detail={"code": error.code, "message": error.message, **error.extra})
    compose = _compose(st, who, exam_id, options)
    if body.background:
        task = asyncio.create_task(E.run(job, compose))
        _TASKS.add(task)
        task.add_done_callback(_TASKS.discard)
        return {**job.view(), "options": options}
    await E.run(job, compose)
    if job.status != "ready":
        raise HTTPException(500 if job.code == "EXPORT_FAILED" else 409,
                            detail={"code": job.code or "EXPORT_FAILED", "message": job.message or "Eksport nieudany."})
    return {**job.file, "job_id": job.id, "options": options}


@router.get("/exam-exports/jobs/{job_id}", summary="Postęp zadania eksportu")
async def export_job(job_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    try:
        return E.get_job(job_id, who.judge_id).view()
    except ExamError as error:
        raise HTTPException(error.status, detail={"code": error.code, "message": error.message})


@router.get("/exam-exports/files/{token}", summary="Pobierz gotowy plik (token z odpowiedzi eksportu)")
async def export_file(token: str):
    found = E.file_for(token)
    if not found:
        raise HTTPException(404, detail={"code": "EXPORT_FILE_GONE",
                                         "message": "Plik wygasł albo adres jest zły. Zleć eksport jeszcze raz."})
    path, name, media = found
    return FileResponse(path, media_type=media, filename=name)

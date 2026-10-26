# app/exam_results.py
"""
Egzamin z przepisów - wyniki komisji i eksport (etap 4, 16.10.2026). Trasy cienkie.

  GET  /exams/{id}/report                      obraz egzaminu (te same liczby co plik)
  GET  /exams/{id}/questions/{qid}/void-preview skutki unieważnienia w trybie drop i credit
  POST /exams/{id}/exports                     plik HTML/PDF -> {url, name, size, expires_at}
                                               (`background: true` -> zadanie z postępem)
  GET  /exam-exports/jobs/{job_id}             postęp zadania (tylko zlecający)
  GET  /exam-exports/files/{token}             plik (bez logowania - token jest sekretem, 30 min)
  GET  /exams/{id}/questions/{qid}/answers     kto jak odpowiedział na pytanie
  GET  /exams/{id}/signals                     sygnały rzetelności z czasem (kto, co, kiedy)
  POST /exams/{id}/remind                      przypomnienie push do niepiszących (okno otwarte)
  POST /exams/{id}/results/{judge_id}/extra-attempt  kolejne podejście ponad limit

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
    #: "exam" (raport komisji) | "judge" (karta jednego sędziego, studio 26.10.2026)
    kind: str = "exam"
    #: {judge_id, attempt_id, layout: diploma|player|analysis|sheet, blocks: [...]}
    judge: Optional[Dict[str, Any]] = None


@router.get("/exams/{exam_id}/report", summary="Wyniki egzaminu dla komisji: agregaty, ranking ex aequo, okręgi")
async def report(exam_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    from app import exam_report_service as RS

    return await _run(RS.build_report(_store(), who, exam_id))


@router.get("/exams/{exam_id}/questions/{qid}/answers", summary="Kto jak odpowiedział na pytanie (zakończone arkusze)")
async def question_answers(exam_id: str, qid: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    from app import exam_results_actions as A

    return await _run(A.question_answers(_store(), who, exam_id, qid))


@router.get("/exams/{exam_id}/signals", summary="Sygnały rzetelności z czasem: kto, co, kiedy")
async def signals(exam_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    from app import exam_results_actions as A

    return await _run(A.signals(_store(), who, exam_id))


@router.post("/exams/{exam_id}/remind", summary="Przypomnij niepiszącym (push, tylko gdy egzamin trwa)")
async def remind(exam_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    from app import exam_results_actions as A

    return await _run(A.remind_missing(_store(), who, exam_id))


@router.post("/exams/{exam_id}/results/{judge_id}/extra-attempt", summary="Kolejne podejście dla sędziego ponad limit egzaminu")
async def extra_attempt(exam_id: str, judge_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    from app import exam_results_actions as A

    return await _run(A.grant_attempt(_store(), who, exam_id, judge_id))


@router.get("/exams/{exam_id}/questions/{qid}/void-preview", summary="Skutki unieważnienia pytania (drop i credit)")
async def void_preview(exam_id: str, qid: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    from app import exam_report_service as RS

    return await _run(RS.void_preview(_store(), who, exam_id, qid))


async def _photo_uri(url: Optional[str]) -> str:
    """Zdjęcie sędziego z listy okręgu jako data URI (4 s, do 3 MB). Błąd = pusty napis -> monogram."""
    if not url:
        return ""
    try:
        import base64

        import httpx

        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True) as client:
            res = await client.get(url)
        kind = res.headers.get("content-type", "").split(";")[0].strip()
        if res.status_code != 200 or not kind.startswith("image/") or len(res.content) > 3_000_000:
            return ""
        return f"data:{kind};base64," + base64.b64encode(res.content).decode("ascii")
    except Exception:  # noqa: BLE001 - zdjęcie jest ozdobą, nie warunkiem pliku
        logger.info("eksport karty: zdjęcie niedostępne", exc_info=True)
        return ""


def _compose_judge(st: S.Store, who: S.Who, exam_id: str, options: Dict[str, Any]):
    async def compose(progress):
        from app import exam_judge_html as J
        from app import exam_report_html as H
        from app import exam_report_service as RS

        judge = options["judge"]
        report = await RS.build_report(st, who, exam_id)
        review = await S.committee_review(st, who, exam_id, judge["attempt_id"])
        if str((review.get("attempt") or {}).get("judge_id")) != judge["judge_id"]:
            raise ExamError("ATTEMPT_NOT_FOUND", "To podejście nie należy do tego sędziego.", 404)
        record = None
        if "form" in judge["blocks"]:
            try:
                from app import exam_record as RC
                from app.exam_stats import _stats_store

                prov = (report["exam"].get("cut_province") or None)
                record = await RC.judge_record(_stats_store(), who, judge["judge_id"], prov)
            except Exception:  # noqa: BLE001 - forma jest dodatkiem; bez kartoteki karta i tak wychodzi
                logger.info("eksport karty: kartoteka niedostępna", exc_info=True)
        progress("collect", 1, 1, None)
        photo = await _photo_uri((report.get("photos") or {}).get(judge["judge_id"])) if any(
            b == "photo" for b in judge["blocks"]) else ""
        exam = report["exam"]
        crest = "" if exam.get("scope") == "national" and not exam.get("cut_province") else H.crest_data_uri(exam.get("province") or exam.get("cut_province"))
        html = await asyncio.to_thread(J.render_judge, report, review, record, options, photo=photo, crest=crest, progress=progress)
        name = (review.get("attempt") or {}).get("judge_name") or judge["judge_id"]
        return html, J.judge_filename(name, exam.get("name") or "egzamin", options["format"], S.utcnow()).rsplit(".", 1)[0]

    return compose


def _compose(st: S.Store, who: S.Who, exam_id: str, options: Dict[str, Any]):
    if options.get("kind") == "judge":
        return _compose_judge(st, who, exam_id, options)

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

# app/exam_public.py
"""
Strona publiczna wyników egzaminu - trasy (26.10.2026). Logika: `app/exam_public_service.py`,
przycinanie do poziomu: `app/exam_public_rules.py`. Kontrakt: BAZA/docs/egzamin-api.md,
sekcja „Strona publiczna wyników”.
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel

from app import exam_service as S
from app.exam_public_service import disable_link, get_link, public_results, set_link
from app.exams import _run, _store, _who

router = APIRouter(tags=["Exams"])


class LinkBody(BaseModel):
    level: str = "stats"
    photos: bool = False
    hardest: bool = False
    #: province | elegant | premium
    theme: str = "province"
    #: true = nowy kod (stary przestaje działać). Domyślnie ponowne włączenie wraca do ostatniego kodu.
    new_code: bool = False


def _links():
    from app import db as D

    return D.exam_public_links


@router.get("/exams/{exam_id}/public-link", summary="Link strony publicznej wyników (teczka komisji)")
async def link_get(exam_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(get_link(_store(), _links(), who, exam_id))


@router.post("/exams/{exam_id}/public-link", summary="Włącz albo zmień stronę publiczną wyników")
async def link_set(exam_id: str, body: LinkBody, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(set_link(_store(), _links(), who, exam_id, body.model_dump()))


@router.delete("/exams/{exam_id}/public-link", summary="Wyłącz stronę publiczną wyników (od razu)")
async def link_delete(exam_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(disable_link(_store(), _links(), who, exam_id))


@router.get("/public/exam-results/{code}", summary="Publiczne wyniki egzaminu (bez logowania, przycięte do poziomu)")
async def public_get(code: str, request: Request, preview: int = Query(0)) -> Dict[str, Any]:
    return await _run(public_results(_store(), _links(), code, count=not preview,
                                     user_agent=request.headers.get("user-agent")))

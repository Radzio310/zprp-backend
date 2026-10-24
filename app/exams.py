# app/exams.py
"""
Egzamin z przepisów - trasy (etap 1, 16.10.2026).

Trasy są cienkie: cała logika w `app/exam_service.py` (baza) i `app/exam_rules.py`
(reguły bez bazy). Kontrakt dla aplikacji i komisji: BAZA/docs/egzamin-api.md.

Błędy: `HTTPException(status, detail={"code", "message", ...})`, więc globalna koperta
oddaje `{"error": {...}, "code": ..., "message": ...}`. Każda odmowa ma zdanie po polsku.
"""
from __future__ import annotations

import logging
from typing import Any, Awaitable, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app import exam_service as S
from app.deps import get_jwt_payload
from app.exam_rules import ExamError
from app.match_market import Actor, market_actor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/exams", tags=["Exams"])


# ---------------------------------------------------------------------------
# Pomocnicze (importy bazy dopiero w funkcjach - app/db.py łączy się przy imporcie)
# ---------------------------------------------------------------------------


def _store() -> S.Store:
    from app import db as D
    from app import province_events as PE
    from app.deps import get_settings
    from app.push.push import send_push_to_judges

    async def judges(province: str) -> List[Dict[str, Any]]:
        return await PE._judges(PE._province(province))

    async def push(ids: List[str], title: str, body: str, data: Dict[str, Any]) -> None:
        await send_push_to_judges(ids, title, body, data)

    return S.Store(
        database=D.database,
        t=S.Tables(
            banks=D.exam_banks, bank_questions=D.exam_bank_questions, definitions=D.exam_definitions,
            attempts=D.exam_attempts, answers=D.exam_answers, events=D.exam_events,
            reminders=D.exam_reminders_sent, province_events=D.province_events,
        ),
        judges=judges,
        push=push,
        secret=get_settings().SECRET_KEY,
    )


async def _who(payload: Dict[str, Any] = Depends(get_jwt_payload), actor: Actor = Depends(market_actor)) -> S.Who:
    async def teach(province: str) -> bool:
        from app.province_guard import ensure_province_write

        try:
            await ensure_province_write(payload, province=province, kind="teach", action="Zarządzanie egzaminami okręgu")
        except HTTPException:
            return False
        return True

    return S.Who(judge_id=actor.judge_id, name=actor.full_name, province=actor.province, is_admin=actor.is_admin,
                 badges=actor.badges, teach_check=teach)


async def _run(call: Awaitable[Any]) -> Any:
    """Zamienia `ExamError` na odpowiedź z kodem i zdaniem po polsku."""
    try:
        return await call
    except ExamError as error:
        raise HTTPException(error.status, detail={"code": error.code, "message": error.message, **error.extra})


async def _notify_published(published: List[Dict[str, Any]], actor_id: str) -> None:
    """Push „nowe wydarzenie" dla zaproszonych (tak jak przy zwykłym wydarzeniu okręgowym)."""
    from app import province_events as PE

    for event in published:
        try:
            invited = PE._invited(await PE._judges(event["province"]), event)
            await PE._notify_new(event, invited, 1, actor_id)
        except Exception:  # noqa: BLE001
            logger.warning("egzamin: powiadomienie o nowym wydarzeniu nieudane", exc_info=True)


async def _notify_moved(event_ids: Dict[str, Any], actor_id: str) -> None:
    from app import province_events as PE

    for event_id in (event_ids or {}).values():
        await PE._notify_changed_after_update(int(event_id), actor_id)


# ---------------------------------------------------------------------------
# Ciała żądań
# ---------------------------------------------------------------------------


class ExamBody(BaseModel):
    scope: str = "province"
    province: Optional[str] = None
    name: str
    description: Optional[str] = None
    template: Optional[str] = None
    config: Dict[str, Any] = Field(default_factory=dict)
    #: Idempotencja: localId szkicu. Ten sam autor + ten sam klucz = ten sam egzamin (bez drugiej publikacji).
    client_key: Optional[str] = None


class ExamPatch(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    config: Optional[Dict[str, Any]] = None


class PoolBody(BaseModel):
    scope: Dict[str, Any] = Field(default_factory=dict)
    province: Optional[str] = None


class StartBody(BaseModel):
    device_id: Optional[str] = None
    room_code: Optional[str] = None
    #: Kolejka offline z zabitej aplikacji (jak `answers`): przyjmowana PRZED zamknięciem pytań po czasie.
    buffered: Optional[List[Dict[str, Any]]] = None
    client_now_ms: Optional[float] = None


class AnswersBody(BaseModel):
    device_id: Optional[str] = None
    client_now_ms: Optional[float] = None
    #: true = paczka z kolejki offline. Tylko wtedy stempel starszy od odbioru jest uznany; zamknięte
    #: przez czas podejście przyjmuje wyłącznie taką paczkę (do 6 h po terminie).
    buffered: bool = False
    answers: List[Dict[str, Any]] = Field(default_factory=list)


class EventsBody(BaseModel):
    device_id: Optional[str] = None
    events: List[Dict[str, Any]] = Field(default_factory=list)


class VoidBody(BaseModel):
    mode: str = "drop"


class DeviceBody(BaseModel):
    device_id: str


class BankImportBody(BaseModel):
    data: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Bank pytań i trasy statyczne (PRZED /{exam_id})
# ---------------------------------------------------------------------------


@router.get("/bank", summary="Pytania banku bez kluczy odpowiedzi (dla zalogowanych)")
async def bank(
    since: Optional[str] = Query(None),
    rule: Optional[int] = Query(None),
    topic: Optional[str] = Query(None),
    who: S.Who = Depends(_who),
) -> Dict[str, Any]:
    return await _run(S.bank_public(_store(), since=since, rule=rule, topic=topic))


@router.post("/bank/import", summary="Wgraj katalog pytań jako nową wersję (admin)")
async def bank_import(body: BankImportBody, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    if not who.is_admin:
        raise HTTPException(403, detail={"code": "EXAM_FORBIDDEN", "message": "Bank pytań wgrywa tylko administrator aplikacji."})
    import json

    data = body.data
    if data is None:
        data = json.loads(S.SEED_PATH.read_text(encoding="utf-8"))
    return await _run(S.import_bank(_store(), data))


@router.get("/templates", summary="Szablony egzaminów")
async def templates(province: Optional[str] = Query(None), who: S.Who = Depends(_who)) -> Dict[str, Any]:
    from app import exam_rules as X

    await _run(S.require_any_manage(who, province))
    return {"templates": X.templates_view(), "defaults": X.DEFAULT_CONFIG}


@router.post("/pool", summary="Ile pytań mieści zakres (podgląd w kreatorze)")
async def pool(body: PoolBody, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    await _run(S.require_any_manage(who, body.province))
    return await _run(S.pool_preview(_store(), body.scope))


@router.get("/manage", summary="Egzaminy okręgu (albo krajowe) do zarządzania")
async def manage_list(province: Optional[str] = Query(None), who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.list_manage(_store(), who, province))


@router.get("/trash", summary="Kosz teczki: usunięte egzaminy i wyniki z 30 dni")
async def trash(province: Optional[str] = Query(None), who: S.Who = Depends(_who)) -> Dict[str, Any]:
    from app import exam_trash as T

    return await _run(T.trash_list(_store(), who, province))


@router.get("/mine", summary="Egzaminy widoczne dla mnie, z moimi podejściami")
async def mine(who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.list_for_judge(_store(), who))


# ---------------------------------------------------------------------------
# Sesja zdającego (trasy /attempts/... PRZED /{exam_id})
# ---------------------------------------------------------------------------


@router.get("/attempts/{attempt_id}", summary="Stan podejścia + bieżące pytanie")
async def attempt_state(
    attempt_id: str,
    index: Optional[int] = Query(None),
    device_id: Optional[str] = Query(None),
    who: S.Who = Depends(_who),
) -> Dict[str, Any]:
    return await _run(S.attempt_state(_store(), who, attempt_id, index, device_id))


@router.post("/attempts/{attempt_id}/answers", summary="Oddaj odpowiedzi (także z bufora ze stemplem)")
async def attempt_answers(attempt_id: str, body: AnswersBody, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.post_answers(_store(), who, attempt_id, body.model_dump()))


@router.post("/attempts/{attempt_id}/events", summary="Zdarzenia antyoszustwa z telefonu")
async def attempt_events(attempt_id: str, body: EventsBody, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.post_events(_store(), who, attempt_id, body.model_dump()))


@router.post("/attempts/{attempt_id}/finish", summary="Oddaj arkusz do urny")
async def attempt_finish(attempt_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.finish_attempt(_store(), who, attempt_id))


@router.get("/attempts/{attempt_id}/result", summary="Wynik wg polityki egzaminu")
async def attempt_result(attempt_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.attempt_result(_store(), who, attempt_id))


@router.get("/attempts/{attempt_id}/review", summary="Przegląd odpowiedzi z kluczem (wg ustawienia egzaminu answers_release)")
async def attempt_review(attempt_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.attempt_review(_store(), who, attempt_id))


# ---------------------------------------------------------------------------
# Definicje
# ---------------------------------------------------------------------------


@router.post("", summary="Utwórz egzamin (publikuje wydarzenie okręgowe)")
async def create(body: ExamBody, background: BackgroundTasks, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    exam, published = await _run(S.create_exam(_store(), who, body.model_dump()))
    background.add_task(_notify_published, published, who.judge_id)
    return exam


@router.get("/{exam_id}", summary="Egzamin: pełna konfiguracja dla zarządzających, streszczenie dla adresatów")
async def get_one(exam_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.get_exam(_store(), who, exam_id))


@router.patch("/{exam_id}", summary="Zmień egzamin (aktualizuje wydarzenia)")
async def patch(exam_id: str, body: ExamPatch, background: BackgroundTasks, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    exam, moved = await _run(S.update_exam(_store(), who, exam_id, body.model_dump(exclude_unset=True)))
    if moved:
        background.add_task(_notify_moved, exam.get("event_ids") or {}, who.judge_id)
    return exam


@router.delete("/{exam_id}", summary="Usuń egzamin (wydarzenia do kosza, wyniki zostają)")
async def delete_one(exam_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.delete_exam(_store(), who, exam_id))


@router.post("/{exam_id}/restore", summary="Przywróć egzamin z kosza teczki (z wynikami i wydarzeniami)")
async def restore_one(exam_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    from app import exam_trash as T

    return await _run(T.restore_exam(_store(), who, exam_id))


@router.delete("/{exam_id}/results/{judge_id}", summary="Wynik sędziego do kosza teczki (30 dni)")
async def delete_result(exam_id: str, judge_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    from app import exam_trash as T

    return await _run(T.delete_result(_store(), who, exam_id, judge_id))


@router.post("/{exam_id}/results/{judge_id}/restore", summary="Przywróć wynik sędziego z kosza teczki")
async def restore_result(exam_id: str, judge_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    from app import exam_trash as T

    return await _run(T.restore_result(_store(), who, exam_id, judge_id))


@router.post("/{exam_id}/start", summary="Zacznij albo wznów podejście")
async def start(exam_id: str, body: StartBody, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.start_attempt(_store(), who, exam_id, body.model_dump()))


# ---------------------------------------------------------------------------
# Komisja (podstawy pod etap 4)
# ---------------------------------------------------------------------------


@router.get("/{exam_id}/attempts", summary="Lista podejść egzaminu (komisja)")
async def attempts(exam_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.attempts_list(_store(), who, exam_id))


@router.get("/{exam_id}/attempts/{attempt_id}", summary="Karta zdającego: oś czasu, zdarzenia, rzetelność")
async def attempt_card(exam_id: str, attempt_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _with_web_extras(await _run(S.attempt_card(_store(), who, exam_id, attempt_id)), attempt_id)


@router.get("/{exam_id}/attempts/{attempt_id}/review", summary="Przegląd podejścia dla komisji: klucz, czasy, oś zdarzeń i flagi")
async def committee_review(exam_id: str, attempt_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _with_web_extras(await _run(S.committee_review(_store(), who, exam_id, attempt_id)), attempt_id)


async def _with_web_extras(body: Dict[str, Any], attempt_id: str) -> Dict[str, Any]:
    """Egzamin na komputerze (24.10.2026): `events[].t_ms/label`, `flags` (rytm, kliknięcia, strażnik...) i `web`.
    Błąd dodatków nie psuje karty - komisja dostaje wtedy kartę bez nich."""
    try:
        from app.exam_web import card_extras, merge_card

        return merge_card(body, await card_extras(attempt_id))
    except Exception:  # noqa: BLE001
        logger.warning("exam-web: dodatki karty podejścia nieudane", exc_info=True)
        return body


@router.post("/{exam_id}/attempts/{attempt_id}/allow-device", summary="Zgoda komisji na wznowienie na innym urządzeniu")
async def allow_device(exam_id: str, attempt_id: str, body: DeviceBody, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.allow_device(_store(), who, exam_id, attempt_id, body.device_id))


@router.get("/{exam_id}/stats", summary="Surowe statystyki per pytanie")
async def stats(exam_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.exam_stats(_store(), who, exam_id))


@router.get("/{exam_id}/missing", summary="Nie przystąpili")
async def missing(exam_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.missing(_store(), who, exam_id))


@router.post("/{exam_id}/questions/{qid}/void", summary="Unieważnij pytanie z przeliczeniem wyników")
async def void_question(exam_id: str, qid: str, body: VoidBody, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.void_question(_store(), who, exam_id, qid, body.mode))


@router.post("/{exam_id}/questions/{qid}/unvoid", summary="Cofnij unieważnienie pytania")
async def unvoid_question(exam_id: str, qid: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.unvoid_question(_store(), who, exam_id, qid))


@router.get("/{exam_id}/room-code", summary="Kod sali zmienny co 30 s (komisja)")
async def room_code(exam_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.room_code_for(_store(), who, exam_id))


@router.post("/{exam_id}/similarity-scan", summary="Szukaj par o podobnych błędach (komisja)")
async def similarity(exam_id: str, who: S.Who = Depends(_who)) -> Dict[str, Any]:
    return await _run(S.similarity_scan(_store(), who, exam_id))


# ---------------------------------------------------------------------------
# Przejście w tle (wołane z pętli przypomnień wydarzeń)
# ---------------------------------------------------------------------------


async def run_exam_sweep() -> int:
    try:
        from app.exam_web import cleanup as _web_cleanup

        await _web_cleanup()
    except Exception:  # noqa: BLE001 - sprzątanie kodów QR komputera nie może zatrzymać przypomnień
        logger.warning("exam-web: sprzątanie nieudane", exc_info=True)
    return await S.sweep_exam_reminders(_store())

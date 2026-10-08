"""Pakiet „Zapisz pełne dane meczu" wykonywany przez serwer.

    POST /proel/zprp/full-batch          -> {"job_id", "total"}  (od razu)
    GET  /proel/zprp/full-batch/{job_id} -> stan pakietu i każdej pozycji

Telefon oddaje cały plan jednym żądaniem, a serwer przechodzi go sam - po
jednym żądaniu do ZPRP naraz, jednym żywym połączeniem (`_upstream_client`),
bez czekania na dziennik. Telefon co ~350 ms pyta o postęp i zapala pozycje
na nakładce, jak dotąd. Reguły (ponowienia, pominięcia, zatrzymania) żyją
w liściu `app/proel_zprp_batch_rules.py` - tu jest tylko ich wykonanie.

Każda pozycja idzie przez TE SAME rdzenie co pojedyncze trasy
(`submit_player_stats`, `submit_officials_stats`), więc biała lista pól,
mapowanie odpowiedzi ZPRP na kody i zamek zapisu na mecz są wspólne. Pakiet
nie ma własnej wersji ani jednej z tych decyzji.

PAMIĘĆ PROCESU. Pakiety i zamki żyją w słowniku jednego procesu - serwer
chodzi jako `uvicorn main:app` bez `--workers` (patrz `assignment_board_cache`).
Pakiet, którego proces nie zna (restart, wdrożenie), odpowiada 404 i telefon
dosyła resztę po staremu, pozycja po pozycji. Nic się nie gubi, najwyżej
zwalnia.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

from app import proel_zprp as zprp
from app.proel_zprp_batch_rules import (
    ACTIVE,
    DONE,
    FAILED,
    JOB_TTL_S,
    JOURNAL_EVENT,
    MAX_JOBS,
    RUNNING,
    SENT,
    SESSION_MAX_ATTEMPTS,
    SKIPPED,
    STOP_INTERNAL,
    STOPPED,
    STOPPED_JOB,
    BatchItem,
    BatchJob,
    build_items,
    is_expired,
    is_transient,
    next_step,
    oldest_first,
    retry_delay_s,
    snapshot,
    step_after_failed_renew,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/proel/zprp", tags=["ProEl: ZPRP API"])

#: Pakiety w pamięci procesu (patrz nagłówek modułu).
_jobs: Dict[str, BatchJob] = {}
#: Pętle pakietów w locie - silna referencja, bo pętla zdarzeń trzyma zadania
#: słabo i pakiet bez niej potrafiłby zniknąć w połowie.
_job_tasks: Set["asyncio.Task[None]"] = set()

#: Przerwa między próbami. Zmienna modułu, żeby testy mogły ją wyzerować.
_sleep = asyncio.sleep


class FullBatchItemIn(BaseModel):
    #: Klucz nadany przez telefon - po nim zapala pozycję na nakładce.
    key: str
    #: Treść jak w `POST /proel/zprp/player-stats` / `officials-stats`,
    #: bez `hash_sesji` (ten dokłada pętla, bo bywa odnawiany w trakcie).
    payload: Dict[str, Any]


class FullBatchRequest(BaseModel):
    id_zawody: Union[int, str]
    hash_sesji: str
    #: Ciało `POST /proel/zprp/auth` (token albo IdZawody + nr sędziego) - tym
    #: serwer odnawia sesję sam, gdy ZPRP naprawdę ją zamknie. Brak = bez
    #: odnowienia, jak w telefonie bez zapamiętanego materiału.
    auth: Optional[Dict[str, Any]] = None
    numbers: List[FullBatchItemIn] = Field(default_factory=list)
    players: List[FullBatchItemIn] = Field(default_factory=list)
    officials: List[FullBatchItemIn] = Field(default_factory=list)


# ─────────────────────────── pamięć pakietów ───────────────────────────


def _purge(now: Optional[float] = None) -> None:
    """Wyrzuca pakiety po terminie, a przy przepełnieniu najstarsze skończone."""
    moment = time.monotonic() if now is None else now
    for job_id in [jid for jid, job in _jobs.items() if is_expired(job, moment)]:
        _jobs.pop(job_id, None)
    if len(_jobs) >= MAX_JOBS:
        for job in oldest_first(list(_jobs.values()))[: len(_jobs) - MAX_JOBS + 1]:
            _jobs.pop(job.job_id, None)


def _touch(job: BatchJob) -> None:
    job.touched_at = time.monotonic()


# ─────────────────────────── jedna pozycja ───────────────────────────


def _error_parts(exc: Exception) -> Dict[str, Any]:
    """Odmowa rdzenia sprowadzona do pól pozycji (status, kod, treść, ZPRP)."""
    if isinstance(exc, HTTPException):
        detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail or "")}
        sent = detail.get("sent")
        return {
            "status": int(exc.status_code),
            "code": str(detail.get("code") or "") or None,
            "message": str(detail.get("message") or "") or None,
            "upstream": (str(detail.get("upstream")) if detail.get("upstream") else None),
            "sent": sent if isinstance(sent, dict) else None,
        }
    if isinstance(exc, ValidationError):
        # Zły kształt pozycji to błąd planu, nie łącza - jak 422 pojedynczej
        # trasy: bez ponowień, pozycja nieudana, reszta idzie dalej.
        return {
            "status": 400,
            "code": "BAD_REQUEST",
            "message": "Niepoprawna pozycja pakietu.",
            "upstream": None,
            "sent": None,
        }
    # Nieprzewidziany wyjątek liczymy jak awarię przejściową (status 500) -
    # telefon tak samo traktował każdą odpowiedź 5xx z naszego serwera.
    return {
        "status": 500,
        "code": "INTERNAL",
        "message": "Błąd serwera BAZY przy zapisie pozycji.",
        "upstream": None,
        "sent": None,
    }


async def _submit(kind: str, hash_sesji: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Jedno żądanie przez rdzeń pojedynczej trasy - z jej zamkiem i białą listą."""
    body = {**payload, "hash_sesji": hash_sesji}
    if kind == "official":
        return await zprp.submit_officials_stats(zprp.ZprpOfficialsStatsRequest(**body))
    return await zprp.submit_player_stats(zprp.ZprpPlayerStatsRequest(**body))


async def _renew(job: BatchJob) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Nowa sesja z materiału telefonu - tą samą drogą co `POST /proel/zprp/auth`.

    Wspólna dla całego pakietu: nowy klucz dostają wszystkie kolejne pozycje.
    Odmowa trwała (zły materiał, brak w obsadzie) zostaje zapamiętana, żeby
    każda kolejna pozycja nie pukała z nim do `auth.php` i do limitera prób -
    przejściowa (sieć, 5xx) nie, bo ta ma prawo minąć.
    """
    if not job.auth:
        return None, None
    if job.renew_error is not None:
        return None, job.renew_error
    try:
        out = await zprp.authorize(zprp.ZprpAuthRequest(**job.auth), job.client_ip)
    except Exception as exc:  # noqa: BLE001 - odmowa to normalny wynik próby
        err = _error_parts(exc)
        if not is_transient(err["status"], err["code"]):
            job.renew_error = err
        return None, err
    fresh = str(out.get("hash_sesji") or "").strip()
    if not fresh:
        return None, {"status": 502, "code": "UPSTREAM_ERROR", "message": None, "upstream": None, "sent": None}
    job.hash_sesji = fresh
    job.renewed += 1
    return fresh, None


def _apply(item: BatchItem, parts: Dict[str, Any]) -> None:
    item.status = parts.get("status")
    item.code = parts.get("code")
    item.message = parts.get("message")
    item.upstream = parts.get("upstream")
    item.sent = parts.get("sent")


def _stop(job: BatchJob, item: BatchItem, code: str, message: Optional[str]) -> None:
    item.phase = STOPPED
    item.code = code
    if message:
        item.message = message
    job.state = STOPPED_JOB
    job.stop_code = code
    job.stop_message = message


def _journal_first_success(job: BatchJob, kind: str) -> None:
    """Jeden wpis w dzienniku na rodzaj pozycji - przy pierwszym udanym zapisie.

    Pojedyncze trasy zostawiają `zprp.players_sent` / `zprp.officials_sent` po
    każdym zawodniku, a klucz godzinowy zlewa je w jeden wiersz - POCZĄTEK
    serii, który dziennik paruje potem z `full-data-done`. Pakiet daje tę samą
    informację jednym zapisem, w tle, w chwili pierwszego sukcesu - czyli tam,
    gdzie pierwszy wiersz powstawał dotąd.
    """
    event = JOURNAL_EVENT.get(kind)
    if not event or event in job.journaled:
        return
    job.journaled.add(event)
    zprp._journal_send_later(
        event,
        id_zawody=job.id_zawody,
        judge_id=job.actor.get("judge_id"),
        install=job.actor.get("install"),
        actor_name=job.actor.get("actor_name"),
        authorization=job.actor.get("authorization"),
        elevation=job.actor.get("elevation"),
        details={"batch": True},
        event_key=zprp._hour_key(event, job.id_zawody),
    )


async def _run_item(job: BatchJob, item: BatchItem) -> None:
    """Jedna pozycja z polityką ponowień telefonu (`runOne` w `zprpPlayerStats`)."""
    item.phase = ACTIVE
    _touch(job)
    renewed = False

    for attempt in range(1, SESSION_MAX_ATTEMPTS + 1):
        item.attempts = attempt
        try:
            await _submit(item.kind, job.hash_sesji, item.payload)
        except Exception as exc:  # noqa: BLE001 - każda odmowa ma swoją decyzję
            parts = _error_parts(exc)
            _apply(item, parts)
            _touch(job)
            step = next_step(
                item.kind,
                status=parts["status"],
                code=parts["code"],
                attempt=attempt,
                renewed=renewed,
            )
            if step == "stop":
                _stop(job, item, str(parts["code"]), parts["message"])
                return
            if step == "skip":
                item.phase = SKIPPED
                return
            if step == "retry":
                await _sleep(retry_delay_s(attempt))
                continue
            if step == "renew":
                renewed = True
                fresh, renew_err = await _renew(job)
                if fresh:
                    # Jak w telefonie: po udanym odnowieniu od razu, bez przerwy.
                    continue
                if renew_err and str(renew_err.get("code") or "").upper() == "PROEL_INACTIVE":
                    # Stary klucz padł, a nowego ZPRP nie da: wyłączony ProEl.
                    _stop(job, item, "PROEL_INACTIVE", renew_err.get("message"))
                    return
                if step_after_failed_renew(
                    status=parts["status"], code=parts["code"], attempt=attempt
                ) == "retry":
                    await _sleep(retry_delay_s(attempt))
                    continue
            item.phase = FAILED
            if not item.message:
                item.message = "Nie udało się zapisać."
            return
        else:
            item.phase = SENT
            item.status = 200
            item.code = None
            item.message = None
            item.upstream = None
            item.sent = None
            _touch(job)
            _journal_first_success(job, item.kind)
            return

    # Pętla wyczerpana bez rozstrzygnięcia - w praktyce nieosiągalne, ale
    # pozycja nie może zostać „w locie" na zawsze.
    item.phase = FAILED
    if not item.message:
        item.message = "Nie udało się zapisać."


async def run_job(job: BatchJob) -> None:
    """Cały pakiet, pozycja po pozycji, w kolejności planu."""
    try:
        for item in job.items:
            if job.state != RUNNING:
                break
            await _run_item(job, item)
        if job.state == RUNNING:
            job.state = DONE
    except asyncio.CancelledError:
        # Zamknięcie procesu. Stan zostaje opisany, choć i tak zniknie z pamięcią.
        job.state = STOPPED_JOB
        job.stop_code = STOP_INTERNAL
        raise
    except Exception:
        logger.exception("ProEl ZPRP pakiet %s: awaria pętli", job.job_id)
        job.state = STOPPED_JOB
        job.stop_code = STOP_INTERNAL
        job.stop_message = "Pakiet przerwany po stronie serwera BAZY."
    finally:
        job.finished_at = time.monotonic()
        counts = {
            phase: sum(1 for i in job.items if i.phase == phase)
            for phase in (SENT, SKIPPED, FAILED)
        }
        logger.info(
            "ProEl ZPRP pakiet %s zawody=%s stan=%s stop=%s wyslane=%s pominiete=%s nieudane=%s z %s odnowienia=%s",
            job.job_id,
            job.id_zawody,
            job.state,
            job.stop_code,
            counts[SENT],
            counts[SKIPPED],
            counts[FAILED],
            len(job.items),
            job.renewed,
        )


def _job_task_done(task: "asyncio.Task[None]") -> None:
    _job_tasks.discard(task)


def start_job(job: BatchJob) -> None:
    """Rejestruje pakiet i puszcza jego pętlę w tle."""
    _jobs[job.job_id] = job
    task = asyncio.create_task(run_job(job))
    _job_tasks.add(task)
    task.add_done_callback(_job_task_done)


def get_job(job_id: str) -> Optional[BatchJob]:
    return _jobs.get(str(job_id or ""))


# ─────────────────────────── trasy ───────────────────────────


def _positive_int(raw: Any) -> int:
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return 0
    return value if value > 0 else 0


@router.post(
    "/full-batch",
    summary="Pełne dane meczu jednym pakietem - serwer wysyła pozycje do ZPRP sam",
)
async def zprp_full_batch_start(
    payload: FullBatchRequest,
    request: Request,
    x_forwarded_for: Optional[str] = Header(None),
    x_judge_id: Optional[str] = Header(None),
    x_installation_id: Optional[str] = Header(None),
    x_actor_name: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
    x_elevation: Optional[str] = Header(None),
):
    _purge()

    hash_sesji = (payload.hash_sesji or "").strip()
    if not hash_sesji:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Brak hash_sesji."},
        )
    id_zawody = _positive_int(payload.id_zawody)
    if not id_zawody:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": "Brak identyfikatora meczu w ZPRP."},
        )
    try:
        items = build_items(payload.numbers, payload.players, payload.officials)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": "BAD_REQUEST", "message": str(exc)},
        )

    # Brak klucza aplikacji kończy się tym samym 503 co pojedyncza trasa -
    # i od razu, zamiast pakietu z samymi nieudanymi pozycjami.
    zprp._require_app_key()

    job = BatchJob(
        job_id=secrets.token_urlsafe(16),
        id_zawody=id_zawody,
        hash_sesji=hash_sesji,
        items=items,
        auth=dict(payload.auth) if isinstance(payload.auth, dict) and payload.auth else None,
        # Ten sam adres, który dostałoby `POST /proel/zprp/auth` z telefonu -
        # limiter prób logowania liczy dalej per sędzia przy stoliku.
        client_ip=zprp._client_ip(request, x_forwarded_for),
        actor={
            "judge_id": x_judge_id,
            "install": x_installation_id,
            "actor_name": x_actor_name,
            "authorization": authorization,
            "elevation": x_elevation,
        },
    )
    start_job(job)
    return {"job_id": job.job_id, "total": len(items)}


@router.get(
    "/full-batch/{job_id}",
    summary="Postęp pakietu pełnych danych meczu",
)
async def zprp_full_batch_status(job_id: str):
    _purge()
    job = get_job(job_id)
    if job is None:
        # Telefon czyta 404 jako „pakietu nie ma" i dosyła resztę po staremu.
        raise HTTPException(
            status_code=404,
            detail={
                "code": "JOB_NOT_FOUND",
                "message": "Serwer nie zna tego pakietu - wysyłka pójdzie po kolei.",
            },
        )
    return snapshot(job)


__all__ = [
    "router",
    "run_job",
    "start_job",
    "get_job",
    "JOB_TTL_S",
]

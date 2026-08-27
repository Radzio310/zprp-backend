# app/training_runs.py
#
# Przebiegi ćwiczeń z kursokonferencji.
#
# Mecz szkoleniowy niesie `isTest: true`, więc cała droga do ProEla jest dla
# niego zamknięta - i tak ma zostać. Ten moduł jest ODDZIELNYM torem: te same
# dane, inne tabele, inne endpointy, inne prawa dostępu. Nic tutaj nie dotyka
# `proel_matches`, `proel_match_state` ani leasingu, więc pomyłka w tym pliku
# nie ma jak zepsuć meczu prowadzonego naprawdę.
#
# Zapis jest OTWARTY, tak jak zapis dokumentu meczu w ProElu. Sędzia w hali nie
# ma tokenu administratora, a JWT z `/auth/login` żyje 15 minut - wymaganie go
# tutaj oznaczałoby, że ćwiczenie przestaje się nagrywać w połowie. Tożsamość
# przychodzi w nagłówkach aktora i jest MIĘKKA: służy do podpisania wpisu, nie
# do wpuszczenia go.
#
# Odczyt jest wyłącznie dla administratora.

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.db import database, training_run, training_tick
from app.proel_auth import header_text
from app.release_stories import require_release_admin
from app.training_stage import (
    STAGE_ORDER,
    furthest_stage,
    normalize_stage,
    tick_is_new,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Szkolenia"])

#: Powyżej tego rozmiaru pełny stan meczu nie jest już stanem meczu, tylko
#: pomyłką. Odrzucamy zamiast przyjmować i psuć tabelę.
MAX_STATE_BYTES = 2_000_000

# Drabina etapów i reguła dopisywania punktów mieszkają w `app/training_stage.py`
# - bez bazy, więc z testem, który uruchomi się wszędzie.
__all__ = ["router", "STAGE_ORDER", "MAX_STATE_BYTES"]


class TrainingRunIn(BaseModel):
    """Jeden takt ćwiczenia. Wszystko poza `runId` bywa nieznane."""

    runId: str
    eventId: str
    matchNumber: str
    zprpMatchId: Optional[str] = None
    stage: str = "first_half"
    scoreHost: int = 0
    scoreGuest: int = 0
    eventsCount: int = 0
    matchMs: int = 0
    half: int = 1
    activeMs: int = 0
    ended: bool = False
    appVersion: Optional[str] = None
    #: Pełny stan meczu - ten sam kształt, który w prawdziwym meczu jedzie do
    #: ProEla. Nadpisywany, nie dopisywany.
    dataJson: Optional[Dict[str, Any]] = Field(default=None)


def _clean(v: Any, limit: int = 120) -> str:
    return str(v or "").strip()[:limit]


@router.post("/training/run", summary="Takt ćwiczenia szkoleniowego")
async def post_training_run(
    body: TrainingRunIn,
    x_judge_id: str = Header(default=""),
    x_installation_id: str = Header(default=""),
    x_actor_name: str = Header(default=""),
) -> Dict[str, Any]:
    run_id = _clean(body.runId, 80)
    event_id = _clean(body.eventId, 80)
    match_number = _clean(body.matchNumber, 40)
    if not run_id or not event_id or not match_number:
        raise HTTPException(
            status_code=400,
            detail="Takt bez identyfikatora przebiegu, wydarzenia albo numeru meczu.",
        )

    state = body.dataJson
    if state is not None:
        try:
            size = len(json.dumps(state).encode("utf-8"))
        except Exception:
            raise HTTPException(status_code=400, detail="Stan meczu nie jest poprawnym JSON-em.")
        if size > MAX_STATE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Stan meczu ma {size} bajtow, limit to {MAX_STATE_BYTES}.",
            )

    stage = normalize_stage(body.stage)
    # Nagłówki HTTP są przez Starlette czytane jak latin-1. Dla nazwisk z
    # polskimi znakami dawało to np. ``RadosÅ‚aw``. Używamy tej samej naprawy,
    # co dziennik ProEla i generator PDF; identyfikatory przechodzą przez nią
    # bez zmian, bo ASCII jest przypadkiem idempotentnym.
    judge_id = _clean(header_text(x_judge_id), 80)
    judge_name = _clean(header_text(x_actor_name), 120)
    install_id = _clean(header_text(x_installation_id), 120)

    existing = await database.fetch_one(
        select(
            training_run.c.id,
            training_run.c.stage,
            training_run.c.attempt,
            training_run.c.ended_at,
        ).where(training_run.c.run_id == run_id)
    )

    values: Dict[str, Any] = {
        "stage": stage,
        "score_host": int(body.scoreHost or 0),
        "score_guest": int(body.scoreGuest or 0),
        "events_count": int(body.eventsCount or 0),
        # Minuta meczu i czas prowadzenia tylko ROSNĄ.
        #
        # Takt z ekranu podsumowania nie zna pozycji zegara - wie, że mecz jest
        # zakończony, i tyle. Bez `greatest` domknięcie ćwiczenia cofałoby oba
        # liczniki do zera i kasowało dokładnie tę informację, dla której cała
        # analiza powstała. Przy pierwszym wstawieniu kolumny jeszcze nie ma,
        # więc tam idzie zwykła wartość (patrz `insert` niżej).
        "match_ms": int(body.matchMs or 0),
        "active_ms": int(body.activeMs or 0),
        "zprp_match_id": _clean(body.zprpMatchId, 40) or None,
        "app_version": _clean(body.appVersion, 40) or None,
    }
    # Brak stanu w takcie NIE kasuje stanu zapisanego wcześniej. Lekki takt
    # bez `dataJson` jest normalną drogą - pełny stan jedzie rzadziej.
    if state is not None:
        values["data_json"] = state

    if existing:
        row = dict(existing)
        values["stage"] = furthest_stage(stage, row.get("stage"))
        values["updated_at"] = func.now()
        if body.ended and not row.get("ended_at"):
            values["ended_at"] = func.now()
        # Tożsamość dopisujemy tylko wtedy, gdy przyszła - pusty nagłówek nie
        # ma prawa wymazać nazwiska zapisanego przy pierwszym takcie.
        if judge_id:
            values["judge_id"] = judge_id
        if judge_name:
            values["judge_name"] = judge_name
        if install_id:
            values["install_id"] = install_id
        grown = dict(values)
        grown["match_ms"] = func.greatest(
            training_run.c.match_ms, int(body.matchMs or 0)
        )
        grown["active_ms"] = func.greatest(
            training_run.c.active_ms, int(body.activeMs or 0)
        )
        await database.execute(
            training_run.update().where(training_run.c.id == row["id"]).values(**grown)
        )
        attempt = int(row.get("attempt") or 1)
    else:
        # Numer podejścia liczymy raz, przy zakładaniu sesji. Ten sam sędzia
        # podchodzi do tego samego meczu więcej niż raz i oba podejścia mają
        # zostać widoczne obok siebie - patrz panel administratora.
        attempt = 1
        if judge_id:
            prior = await database.fetch_val(
                select(func.count())
                .select_from(training_run)
                .where(
                    training_run.c.event_id == event_id,
                    training_run.c.match_number == match_number,
                    training_run.c.judge_id == judge_id,
                )
            )
            attempt = int(prior or 0) + 1
        await database.execute(
            training_run.insert().values(
                run_id=run_id,
                event_id=event_id,
                match_number=match_number,
                judge_id=judge_id or None,
                judge_name=judge_name or None,
                install_id=install_id or None,
                attempt=attempt,
                ended_at=func.now() if body.ended else None,
                **values,
            )
        )

    await _maybe_append_tick(run_id, body, stage)
    return {"ok": True, "runId": run_id, "attempt": attempt, "stage": stage}


async def _maybe_append_tick(run_id: str, body: TrainingRunIn, stage: str) -> None:
    """Punkt na osi czasu - ale tylko wtedy, gdy niesie coś nowego."""
    last = await database.fetch_one(
        select(
            training_tick.c.at,
            training_tick.c.stage,
            training_tick.c.score_host,
            training_tick.c.score_guest,
            training_tick.c.events_count,
        )
        .where(training_tick.c.run_id == run_id)
        .order_by(training_tick.c.at.desc())
        .limit(1)
    )

    prev = dict(last) if last else None
    gap: Any = None
    if prev is not None:
        gap = await database.fetch_val(
            select(func.extract("epoch", func.now() - prev["at"]))
        )
    cur = {
        "stage": stage,
        "score_host": int(body.scoreHost or 0),
        "score_guest": int(body.scoreGuest or 0),
        "events_count": int(body.eventsCount or 0),
    }
    if not tick_is_new(prev, cur, None if gap is None else float(gap)):
        return

    await database.execute(
        training_tick.insert().values(
            run_id=run_id,
            match_ms=int(body.matchMs or 0),
            half=int(body.half or 1),
            stage=stage,
            score_host=int(body.scoreHost or 0),
            score_guest=int(body.scoreGuest or 0),
            events_count=int(body.eventsCount or 0),
        )
    )


def _run_row(row: Any, *, with_state: bool = False) -> Dict[str, Any]:
    d = dict(row)
    out: Dict[str, Any] = {
        "runId": d.get("run_id"),
        "eventId": d.get("event_id"),
        "matchNumber": d.get("match_number"),
        "zprpMatchId": d.get("zprp_match_id"),
        "judgeId": d.get("judge_id"),
        # Naprawiamy również historyczne wiersze zapisane przed poprawką.
        # Dzięki temu administrator nie musi czekać na ponowne podejście
        # sędziego, żeby zobaczyć poprawne nazwisko.
        "judgeName": header_text(d.get("judge_name")),
        "attempt": int(d.get("attempt") or 1),
        "stage": d.get("stage"),
        "scoreHost": int(d.get("score_host") or 0),
        "scoreGuest": int(d.get("score_guest") or 0),
        "eventsCount": int(d.get("events_count") or 0),
        "matchMs": int(d.get("match_ms") or 0),
        "activeMs": int(d.get("active_ms") or 0),
        "startedAt": d.get("started_at").isoformat() if d.get("started_at") else None,
        "updatedAt": d.get("updated_at").isoformat() if d.get("updated_at") else None,
        "endedAt": d.get("ended_at").isoformat() if d.get("ended_at") else None,
        "appVersion": d.get("app_version"),
    }
    if with_state:
        out["dataJson"] = d.get("data_json")
    return out


@router.get(
    "/admin/training/runs",
    summary="Przebiegi ćwiczeń (administrator)",
)
async def list_training_runs(
    eventId: str = Query(default=""),
    matchNumber: str = Query(default=""),
    judge_id: str = Depends(require_release_admin),
) -> Dict[str, Any]:
    """Lista przebiegów BEZ pełnych stanów.

    Stan meczu potrafi ważyć setki kilobajtów, a lista pokazuje liczby - komplet
    dociągamy dopiero pod konkretny wpis. Statystyki grupowe liczy aplikacja
    (`utils/trainingStats.ts`): mediana i odchylenie to kilkanaście linijek,
    które łatwiej sprawdzić testem niż zapytaniem.
    """
    q = select(
        training_run.c.run_id,
        training_run.c.event_id,
        training_run.c.match_number,
        training_run.c.zprp_match_id,
        training_run.c.judge_id,
        training_run.c.judge_name,
        training_run.c.attempt,
        training_run.c.stage,
        training_run.c.score_host,
        training_run.c.score_guest,
        training_run.c.events_count,
        training_run.c.match_ms,
        training_run.c.active_ms,
        training_run.c.started_at,
        training_run.c.updated_at,
        training_run.c.ended_at,
        training_run.c.app_version,
    ).order_by(training_run.c.started_at.desc())

    ev = _clean(eventId, 80)
    mn = _clean(matchNumber, 40)
    if ev:
        q = q.where(training_run.c.event_id == ev)
    if mn:
        q = q.where(training_run.c.match_number == mn)

    rows = await database.fetch_all(q.limit(2000))
    return {"runs": [_run_row(r) for r in rows]}


@router.delete(
    "/admin/training/runs/{run_id}",
    summary="Usunięcie przebiegu ćwiczenia (administrator)",
)
async def delete_training_run(
    run_id: str,
    judge_id: str = Depends(require_release_admin),
) -> Dict[str, Any]:
    """Kasuje JEDEN przebieg razem z jego osią czasu.

    Twardo, bez archiwum - inaczej niż zapis prawdziwego meczu. To jest wpis
    ćwiczebny, który powstaje głównie po to, żeby ktoś sprawdził, czy przycisk
    działa; trzymanie takich śmieci przez rok byłoby kosztem bez powodu. Wpis
    znika też z liczb grupowych, bo te liczy się z tego, co zostało (patrz
    `utils/trainingStats.ts`), a nie z osobnej sumy.
    """
    row = await database.fetch_one(
        select(training_run.c.id).where(training_run.c.run_id == run_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Nie ma takiego przebiegu.")

    # Oś czasu najpierw: gdyby drugie polecenie padło, zostaje wiersz bez
    # punktów (da się usunąć ponownie), a nie punkty bez wiersza, których już
    # nic nie sprząta.
    await database.execute(
        training_tick.delete().where(training_tick.c.run_id == run_id)
    )
    await database.execute(
        training_run.delete().where(training_run.c.run_id == run_id)
    )
    return {"ok": True, "runId": run_id}


@router.get(
    "/admin/training/runs/{run_id}",
    summary="Jeden przebieg ćwiczenia (administrator)",
)
async def get_training_run(
    run_id: str,
    judge_id: str = Depends(require_release_admin),
) -> Dict[str, Any]:
    row = await database.fetch_one(
        select(training_run).where(training_run.c.run_id == run_id)
    )
    if not row:
        raise HTTPException(status_code=404, detail="Nie ma takiego przebiegu.")

    ticks = await database.fetch_all(
        select(
            training_tick.c.at,
            training_tick.c.match_ms,
            training_tick.c.half,
            training_tick.c.stage,
            training_tick.c.score_host,
            training_tick.c.score_guest,
            training_tick.c.events_count,
        )
        .where(training_tick.c.run_id == run_id)
        .order_by(training_tick.c.at.asc())
        .limit(5000)
    )

    return {
        "run": _run_row(row, with_state=True),
        "ticks": [
            {
                "at": dict(t)["at"].isoformat() if dict(t).get("at") else None,
                "matchMs": int(dict(t).get("match_ms") or 0),
                "half": int(dict(t).get("half") or 1),
                "stage": dict(t).get("stage"),
                "scoreHost": int(dict(t).get("score_host") or 0),
                "scoreGuest": int(dict(t).get("score_guest") or 0),
                "eventsCount": int(dict(t).get("events_count") or 0),
            }
            for t in ticks
        ],
    }

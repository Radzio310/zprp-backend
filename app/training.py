# app/training.py
#
# Okresy szkoleniowe (kursokonferencje i kolejne szkolenia).
#
# Każdy okres to osobne wydarzenie: własny tytuł, okno dat, flaga włączenia i
# własna lista pełnych meczów. Administrator zakłada nowy okres bez ruszania
# starych - wiersz na okres w `training_event`, klucz `event_key` równy
# `payload.id`. Stare okresy zostają w analizie, a te sprzed tej zmiany (gdy
# tabela trzymała jeden nadpisywany wiersz) odtwarzamy z `training_run`.
# Reguły bez bazy: `app/training_events_rules.py`.
#
# Odczyt dla sędziów jest OTWARTY. Ujawnia wyłącznie to, że kilka publicznych
# meczów da się poprowadzić na sucho - a aplikacja i tak nie zapisze z takiego
# meczu niczego, bo blokada siedzi po jej stronie w `isTest`. Wymaganie tokenu
# kosztowałoby kafelek u sędziego z wygasłą sesją i nie dałoby nic w zamian.

from __future__ import annotations

import logging
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select

from app.db import database, training_event, training_run
from app.release_stories import require_release_admin
from app.training_events_rules import (
    PeriodError,
    first_visible,
    normalize_period,
    period_status,
    recover_periods,
    sort_periods,
    valid_key,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Szkolenia"])


class TrainingMatchIn(BaseModel):
    zprpMatchId: str
    matchNumber: str
    label: Optional[str] = None


class TrainingEventIn(BaseModel):
    id: str
    enabled: bool = True
    title: str
    subtitle: Optional[str] = None
    #: Puste daty znaczą „bez ograniczenia" - patrz `utils/trainingEvent.ts`.
    visibleFrom: str = ""
    visibleTo: str = ""
    matches: List[TrainingMatchIn] = []


class ArchiveIn(BaseModel):
    archived: bool = True


def _today_pl() -> date:
    """Dzień w Polsce - okno widoczności liczy się datą sędziego, nie serwera."""
    try:
        return datetime.now(timezone.utc).astimezone(ZoneInfo("Europe/Warsaw")).date()
    except Exception:
        return date.today()


def _row_key(d: Dict[str, Any]) -> str:
    """Klucz wiersza; stary wiersz bez klucza rozpoznajemy po `payload.id`."""
    return str(d.get("event_key") or (d.get("payload") or {}).get("id") or "").strip()


async def _rows() -> List[Dict[str, Any]]:
    """Wszystkie okresy od najnowszego zapisu. Jeden wiersz na klucz."""
    rows = await database.fetch_all(
        select(
            training_event.c.id,
            training_event.c.event_key,
            training_event.c.archived,
            training_event.c.payload,
            training_event.c.updated_by,
            training_event.c.updated_at,
        ).order_by(training_event.c.id.desc())
    )
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for r in rows:
        d = dict(r)
        d["payload"] = d.get("payload") or {}
        key = _row_key(d)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


async def _find_row(key: str) -> Optional[Dict[str, Any]]:
    for d in await _rows():
        if _row_key(d) == key:
            return d
    return None


def _to_http(exc: PeriodError) -> HTTPException:
    return HTTPException(status_code=400, detail=str(exc))


def _check_key(event_key: str) -> str:
    key = (event_key or "").strip()
    if not valid_key(key):
        raise HTTPException(
            status_code=400,
            detail=(
                "Identyfikator okresu może zawierać tylko litery bez ogonków, cyfry, "
                "kropkę, dywiz i podkreślnik (do 80 znaków)."
            ),
        )
    return key


async def _upsert(payload: Dict[str, Any], judge_id: str) -> Dict[str, Any]:
    key = payload["id"]
    existing = await _find_row(key)
    if existing:
        await database.execute(
            training_event.update()
            .where(training_event.c.id == existing["id"])
            .values(payload=payload, event_key=key, updated_by=judge_id)
        )
    else:
        await database.execute(
            training_event.insert().values(
                payload=payload, event_key=key, archived=False, updated_by=judge_id
            )
        )
    return payload


# ─────────────────────────── odczyt dla sędziów ───────────────────────────


@router.get("/training/event", summary="Aktualne wydarzenie szkoleniowe (stare aplikacje)")
async def get_training_event() -> Dict[str, Any]:
    """Jeden okres dla aplikacji, które znają tylko jeden.

    Wygrywa okres widoczny dzisiaj; gdy żadnego nie ma, najnowszy
    niezarchiwizowany. Pusty obiekt to poprawna odpowiedź, nie błąd: aplikacja
    rozpozna go jako „nic nie skonfigurowano" i zejdzie do własnego zapasu.
    """
    try:
        rows = await _rows()
    except Exception:
        logger.warning("training_event: odczyt nieudany", exc_info=True)
        return {}
    return first_visible(rows, _today_pl()) or {}


@router.get("/training/events", summary="Okresy szkoleniowe dla aplikacji")
async def get_training_events() -> Dict[str, Any]:
    """Włączone i niezarchiwizowane okresy. Daty sprawdza też aplikacja.

    Okresy już zakończone odpadają tutaj, żeby lista nie rosła z każdym
    szkoleniem; zaplanowane zostają, bo telefon ma je znać z wyprzedzeniem
    (hala bywa bez zasięgu, a kopia lokalna musi wiedzieć o jutrze).
    """
    try:
        rows = await _rows()
    except Exception:
        logger.warning("training_event: odczyt listy nieudany", exc_info=True)
        return {"events": []}
    today = _today_pl()
    events: List[Dict[str, Any]] = []
    for d in rows:
        payload = d["payload"]
        if d.get("archived") or payload.get("enabled") is False:
            continue
        if period_status(payload, today=today) == "ended":
            continue
        events.append(payload)
    return {"events": events}


# ─────────────────────────── panel administratora ───────────────────────────


async def _run_aggregates() -> List[Dict[str, Any]]:
    title = training_run.c.data_json[("matchConfig", "training", "eventTitle")].astext
    rows = await database.fetch_all(
        select(
            training_run.c.event_id,
            training_run.c.match_number,
            func.max(training_run.c.zprp_match_id).label("zprp_match_id"),
            func.min(training_run.c.started_at).label("first_at"),
            func.max(training_run.c.started_at).label("last_at"),
            func.count().label("runs"),
            func.max(title).label("title"),
        ).group_by(training_run.c.event_id, training_run.c.match_number)
    )
    return [dict(r) for r in rows]


@router.get(
    "/admin/training/events",
    summary="Wszystkie okresy szkoleniowe, także archiwalne (administrator)",
)
async def list_admin_training_events(
    judge_id: str = Depends(require_release_admin),
) -> Dict[str, Any]:
    """Okresy z zapisu oraz odtworzone z przebiegów (`recovered: true`).

    Przy okresie z zapisu `extraMatches` to mecze, które mają przebiegi, ale
    wypadły z listy okresu (np. po edycji) - analiza musi je dalej pokazać.
    """
    rows = await _rows()
    try:
        aggs = await _run_aggregates()
    except Exception:
        logger.warning("training_run: agregaty okresów nieudane", exc_info=True)
        aggs = []

    today = _today_pl()
    by_key: Dict[str, List[Dict[str, Any]]] = {}
    for a in aggs:
        by_key.setdefault(str(a.get("event_id") or ""), []).append(a)

    periods: List[Dict[str, Any]] = []
    for d in rows:
        payload = dict(d["payload"])
        key = _row_key(d)
        archived = bool(d.get("archived"))
        mine = by_key.get(key, [])
        listed = {str(m.get("matchNumber") or "") for m in payload.get("matches") or []}
        extra = [
            {
                "zprpMatchId": str(a.get("zprp_match_id") or ""),
                "matchNumber": str(a.get("match_number") or ""),
                "label": None,
            }
            for a in mine
            if str(a.get("match_number") or "") not in listed
        ]
        updated_at = d.get("updated_at")
        periods.append(
            {
                **payload,
                "id": key,
                "archived": archived,
                "recovered": False,
                "status": period_status(payload, archived=archived, today=today),
                "runsCount": sum(int(a.get("runs") or 0) for a in mine),
                "extraMatches": extra,
                "updatedAt": updated_at.isoformat() if updated_at else None,
                "updatedBy": d.get("updated_by"),
            }
        )

    recovered = recover_periods(aggs, known_keys=[_row_key(d) for d in rows])
    for p in recovered:
        p["extraMatches"] = []
    return {"events": sort_periods(periods + recovered)}


@router.put(
    "/admin/training/events/{event_key}",
    summary="Zapis jednego okresu szkoleniowego (administrator)",
)
async def put_admin_training_event(
    event_key: str,
    body: TrainingEventIn,
    judge_id: str = Depends(require_release_admin),
) -> Dict[str, Any]:
    key = _check_key(event_key)
    try:
        payload = normalize_period(body.model_dump() if hasattr(body, "model_dump") else body.dict())
    except PeriodError as exc:
        raise _to_http(exc)
    if payload["id"] != key:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Identyfikator w treści ({payload['id']}) różni się od adresu ({key}). "
                "Identyfikatora okresu nie zmienia się po zapisie - przebiegi są do niego "
                "przypięte. Załóż nowy okres zamiast zmieniać stary."
            ),
        )
    return await _upsert(payload, judge_id)


@router.post(
    "/admin/training/events/{event_key}/archive",
    summary="Archiwizacja okresu szkoleniowego (administrator)",
)
async def archive_admin_training_event(
    event_key: str,
    body: ArchiveIn,
    judge_id: str = Depends(require_release_admin),
) -> Dict[str, Any]:
    key = _check_key(event_key)
    row = await _find_row(key)
    if not row:
        raise HTTPException(
            status_code=404,
            detail=(
                "Tego okresu nie ma w zapisie - jest odtworzony z przebiegów i "
                "archiwalny z natury. Zapisz go najpierw, jeśli chcesz nim zarządzać."
            ),
        )
    await database.execute(
        training_event.update()
        .where(training_event.c.id == row["id"])
        .values(archived=bool(body.archived), event_key=key, updated_by=judge_id)
    )
    return {"ok": True, "id": key, "archived": bool(body.archived)}


@router.delete(
    "/admin/training/events/{event_key}",
    summary="Usunięcie okresu bez przebiegów (administrator)",
)
async def delete_admin_training_event(
    event_key: str,
    judge_id: str = Depends(require_release_admin),
) -> Dict[str, Any]:
    key = _check_key(event_key)
    runs = int(
        await database.fetch_val(
            select(func.count()).select_from(training_run).where(training_run.c.event_id == key)
        )
        or 0
    )
    if runs:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Okres ma {runs} przebiegów sędziów - usunięcie odcięłoby je od opisu. "
                "Zarchiwizuj go zamiast usuwać: zniknie z aplikacji, a zostanie w analizie."
            ),
        )
    row = await _find_row(key)
    if not row:
        raise HTTPException(status_code=404, detail="Nie ma takiego okresu.")
    await database.execute(
        training_event.delete().where(
            (training_event.c.event_key == key) | (training_event.c.id == row["id"])
        )
    )
    return {"ok": True, "id": key}


@router.put(
    "/admin/training/event",
    summary="Zapis wydarzenia szkoleniowego (stare wersje panelu)",
)
async def put_training_event(
    body: TrainingEventIn,
    judge_id: str = Depends(require_release_admin),
) -> Dict[str, Any]:
    """Stary panel zna jeden okres. Zapis idzie po `payload.id`, więc nowy
    identyfikator zakłada nowy okres zamiast nadpisywać poprzedni."""
    try:
        payload = normalize_period(body.model_dump() if hasattr(body, "model_dump") else body.dict())
    except PeriodError as exc:
        raise _to_http(exc)
    return await _upsert(payload, judge_id)

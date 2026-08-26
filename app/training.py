# app/training.py
#
# Wydarzenia szkoleniowe (kursokonferencje).
#
# Jedna konfiguracja naraz: które mecze wolno poprowadzić w trybie ćwiczenia i
# w jakim oknie dat kafelek ma być widoczny w aplikacji. Trzymana jako JSONB w
# jednym wierszu, bo to ustawienie, nie zbiór danych - a kształt będzie się
# jeszcze zmieniał i migracja kolumn przy każdym polu byłaby kosztem bez zysku.
#
# Odczyt jest OTWARTY. Ujawnia wyłącznie to, że dwa publiczne mecze da się
# poprowadzić na sucho - a aplikacja i tak nie zapisze z takiego meczu niczego,
# bo blokada siedzi po jej stronie w `isTest`. Wymaganie tokenu na tym
# endpointcie kosztowałoby kafelek u sędziego z wygasłą sesją i nie dałoby nic
# w zamian.

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from app.db import database, training_event
from app.release_stories import require_release_admin

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Szkolenia"])

_YMD = re.compile(r"^\d{4}-\d{2}-\d{2}$")


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


def _clean_date(value: str, field: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if not _YMD.match(text):
        raise HTTPException(
            status_code=400,
            detail=f"Pole {field} ma mieć postać RRRR-MM-DD albo zostać puste.",
        )
    return text


@router.get("/training/event", summary="Aktualne wydarzenie szkoleniowe")
async def get_training_event() -> Dict[str, Any]:
    """Konfiguracja albo pusty obiekt.

    Pusty obiekt to poprawna odpowiedź, nie błąd: aplikacja rozpozna go jako
    „nic nie skonfigurowano" i zejdzie do własnego zapasu. Wyjątek zamiast tego
    zabrałby kafelek wszystkim, gdyby tabela była jeszcze pusta.
    """
    try:
        row = await database.fetch_one(
            select(training_event.c.payload).order_by(training_event.c.id.desc()).limit(1)
        )
    except Exception:
        logger.warning("training_event: odczyt nieudany", exc_info=True)
        return {}
    payload = (dict(row).get("payload") if row else None) or {}
    return payload


@router.put(
    "/admin/training/event",
    summary="Zapis wydarzenia szkoleniowego (administrator)",
)
async def put_training_event(
    body: TrainingEventIn,
    judge_id: str = Depends(require_release_admin),
) -> Dict[str, Any]:
    if not body.id.strip() or not body.title.strip():
        raise HTTPException(status_code=400, detail="Wydarzenie musi mieć identyfikator i tytuł.")

    visible_from = _clean_date(body.visibleFrom, "visibleFrom")
    visible_to = _clean_date(body.visibleTo, "visibleTo")
    if visible_from and visible_to and visible_from > visible_to:
        raise HTTPException(
            status_code=400,
            detail="Początek okna widoczności jest późniejszy niż koniec.",
        )

    matches: List[Dict[str, Any]] = []
    for m in body.matches:
        zprp_id = (m.zprpMatchId or "").strip()
        number = (m.matchNumber or "").strip()
        if not zprp_id or not number:
            continue
        if not zprp_id.isdigit():
            raise HTTPException(
                status_code=400,
                detail=(
                    f"IdZawody {zprp_id} nie jest liczba - w bazie ZPRP to zawsze liczba."
                ),
            )
        matches.append(
            {
                "zprpMatchId": zprp_id,
                "matchNumber": number,
                "label": (m.label or "").strip() or None,
            }
        )

    payload = {
        "id": body.id.strip(),
        "enabled": bool(body.enabled),
        "title": body.title.strip(),
        "subtitle": (body.subtitle or "").strip() or None,
        "visibleFrom": visible_from,
        "visibleTo": visible_to,
        "matches": matches,
    }

    # Jeden wiersz na całą tabelę: nadpisujemy istniejący albo zakładamy pierwszy.
    existing = await database.fetch_one(
        select(training_event.c.id).order_by(training_event.c.id.desc()).limit(1)
    )
    if existing:
        await database.execute(
            training_event.update()
            .where(training_event.c.id == dict(existing)["id"])
            .values(payload=payload, updated_by=judge_id)
        )
    else:
        await database.execute(
            training_event.insert().values(payload=payload, updated_by=judge_id)
        )
    return payload

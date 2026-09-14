"""Potwierdzenia zapoznania się z klauzulą informacyjną RODO.

Reguły mieszkają w `app/privacy_consent_rules.py` (moduł-liść bez bazy);
tutaj jest tylko warstwa HTTP i zapis.

Po co to w ogóle jest: administrator musi umieć odpowiedzieć, KTO i KIEDY
został poinformowany o przetwarzaniu danych. Flaga w pamięci telefonu tego nie
udowodni - znika z aplikacją i nie widać jej z drugiej strony.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.proel_admin_guard import proel_admin_guard
from app.privacy_consent_rules import (
    CONTROLLER_EMAIL,
    CONTROLLER_NAME,
    CONTROLLER_TAX_ID,
    CURRENT_CLAUSE_VERSION,
    accepted_version,
    needs_consent,
    normalize_source,
    normalize_subject_id,
    normalize_subject_type,
    normalize_version,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/privacy", tags=["Privacy"])


class ConsentRequest(BaseModel):
    subject_type: str                      # "proel" | "zprp"
    subject_id: str
    version: Optional[int] = None          # domyślnie bieżąca
    full_name: Optional[str] = None
    phone_consent: bool = False
    source: Optional[str] = None           # signup | login | in_app
    app_version: Optional[str] = None


class ConsentState(BaseModel):
    """Stan zgody dla jednego podmiotu.

    `needs_consent` jest tym, po co aplikacja tu przychodzi: sama nie musi
    wiedzieć, jak liczymy wersje.
    """
    subject_type: str
    subject_id: str
    current_version: int
    accepted_version: int
    needs_consent: bool
    accepted_at: Optional[datetime] = None
    phone_consent: bool = False


class ControllerInfo(BaseModel):
    name: str
    tax_id: str
    email: str
    clause_version: int


@router.get("/controller", response_model=ControllerInfo, summary="Kto jest administratorem danych")
async def get_controller() -> ControllerInfo:
    """Dane administratora prosto z serwera.

    Aplikacja nosi je też u siebie (żeby klauzula wyświetliła się bez sieci),
    ale gdy adres kontaktowy się zmieni, starsze wydania mają skąd wziąć nowy
    bez czekania na aktualizację w sklepie.
    """
    return ControllerInfo(
        name=CONTROLLER_NAME,
        tax_id=CONTROLLER_TAX_ID,
        email=CONTROLLER_EMAIL,
        clause_version=CURRENT_CLAUSE_VERSION,
    )


async def consent_state(subject_type: str, subject_id: str) -> Dict[str, Any]:
    """Stan zgody jednego podmiotu. Import bazy w ciele - `app/db.py` łączy
    się z bazą już przy imporcie, więc reguły nie mogą go ciągnąć."""
    from app.db import database, privacy_consents

    stype = normalize_subject_type(subject_type)
    sid = normalize_subject_id(subject_id)

    rows = await database.fetch_all(
        select(privacy_consents).where(
            and_(
                privacy_consents.c.subject_type == stype,
                privacy_consents.c.subject_id == sid,
            )
        )
    )
    items = [dict(row) for row in rows]
    best = accepted_version(items)
    newest = None
    phone = False
    for item in items:
        if normalize_version(item.get("version")) == best:
            newest = item.get("accepted_at")
            phone = bool(item.get("phone_consent"))

    return {
        "subject_type": stype,
        "subject_id": sid,
        "current_version": CURRENT_CLAUSE_VERSION,
        "accepted_version": best,
        "needs_consent": needs_consent(best),
        "accepted_at": newest,
        "phone_consent": phone,
    }


@router.get("/consent", response_model=ConsentState, summary="Czy podmiot zna klauzulę")
async def get_consent(subject_type: str, subject_id: str) -> ConsentState:
    try:
        state = await consent_state(subject_type, subject_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ConsentState(**state)


@router.get(
    "/consents",
    summary="[admin] Kto i kiedy potwierdził klauzulę",
    dependencies=[Depends(proel_admin_guard)],
)
async def list_consents(
    subject_type: Optional[str] = None,
    version: Optional[int] = None,
    limit: int = 500,
    offset: int = 0,
) -> Dict[str, Any]:
    """Lista potwierdzeń - po to w ogóle je zapisujemy.

    Bez tego widoku tabela byłaby zbiorem wierszy, których nikt nie umie
    odczytać, a pytanie „kto został poinformowany" nadal zostawałoby bez
    odpowiedzi. Za bramką administratora, bo to dane osobowe.
    """
    from app.db import database, privacy_consents

    query = select(privacy_consents)
    if subject_type:
        try:
            query = query.where(
                privacy_consents.c.subject_type == normalize_subject_type(subject_type)
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    if version is not None:
        query = query.where(privacy_consents.c.version == normalize_version(version))

    query = query.order_by(privacy_consents.c.accepted_at.desc())
    query = query.limit(max(1, min(int(limit or 500), 2000))).offset(max(0, int(offset or 0)))

    rows = [dict(row) for row in await database.fetch_all(query)]
    for row in rows:
        row["id"] = str(row.get("id"))
    return {"items": rows, "count": len(rows), "current_version": CURRENT_CLAUSE_VERSION}


@router.post("/consent", response_model=ConsentState, summary="Zapisz potwierdzenie klauzuli")
async def post_consent(req: ConsentRequest) -> ConsentState:
    from app.db import database, privacy_consents

    try:
        stype = normalize_subject_type(req.subject_type)
        sid = normalize_subject_id(req.subject_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    version = normalize_version(req.version) or CURRENT_CLAUSE_VERSION
    now = datetime.now(timezone.utc)

    values = {
        "id": uuid.uuid4(),
        "subject_type": stype,
        "subject_id": sid,
        "version": version,
        "full_name": (req.full_name or "").strip() or None,
        "phone_consent": bool(req.phone_consent),
        "source": normalize_source(req.source),
        "app_version": (req.app_version or "").strip() or None,
        "accepted_at": now,
    }

    # Ponowne kliknięcie tej samej wersji odświeża wpis zamiast zakładać nowy -
    # inaczej lista audytowa zamieniłaby się w dziennik wejść. Wcześniejsze
    # WERSJE zostają nietknięte: to one są dowodem, na co ktoś zgodził się
    # kiedyś.
    statement = (
        pg_insert(privacy_consents)
        .values(**values)
        .on_conflict_do_update(
            index_elements=["subject_type", "subject_id", "version"],
            set_={
                "full_name": values["full_name"],
                "phone_consent": values["phone_consent"],
                "source": values["source"],
                "app_version": values["app_version"],
                "accepted_at": now,
            },
        )
    )
    await database.execute(statement)

    return ConsentState(**await consent_state(stype, sid))

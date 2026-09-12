"""Kalendarze sędziego (iCal): dodawanie, ustawienia, odświeżanie na żądanie.

Trasy pod ``/calendar/feeds``. Właścicielem kalendarza jest NUMER SĘDZIEGO z
tokenu BAZY - nie login i nie numer z nagłówka. Dzięki temu nikt nie podejrzy
ani nie podmieni cudzego planu, a wpisy trafiają dokładnie tam, gdzie leżą
niedyspozycje tego sędziego.

⚠ LINK TO SEKRET. Adres planu zajęć zawiera klucz, więc:

  * pełny adres NIE wraca do aplikacji (oddajemy zamaskowany),
  * nie trafia do logów ani do komunikatów błędów,
  * usunięcie kalendarza kasuje też pobrane wpisy.

Router musi być zarejestrowany PRZED ``app/calendar.py``: tamten ma trasy
``/calendar/events/{match_id:path}``, a kolejność w FastAPI rozstrzyga
pierwszeństwo dopasowania.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select

from app.calendar_feed_rules import (
    MAX_FEEDS_PER_JUDGE,
    FeedUrlError,
    mask_feed_url,
    normalize_feed_url,
)
from app.calendar_feed_sync import sync_feed
from app.db import database, judge_calendar_feeds, judge_feed_offtimes
from app.deps import get_jwt_payload

router = APIRouter(prefix="/calendar/feeds", tags=["Kalendarze sędziego"])


class FeedIn(BaseModel):
    name: str = Field(default="", max_length=60)
    url: str = ""
    color: Optional[str] = None
    blocks_assignment: bool = True
    shared_with_province: bool = True


class FeedPatch(BaseModel):
    name: Optional[str] = Field(default=None, max_length=60)
    url: Optional[str] = None
    color: Optional[str] = None
    enabled: Optional[bool] = None
    blocks_assignment: Optional[bool] = None
    shared_with_province: Optional[bool] = None


def _owner(payload: Dict[str, Any]) -> str:
    """Numer sędziego z tokenu. Konto bez numeru nie ma własnych niedyspozycji."""
    judge_id = str((payload or {}).get("judge_id") or "").strip()
    if not judge_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "To konto nie ma numeru sędziego, więc nie ma własnych "
                "niedyspozycji. Zaloguj się swoim kontem sędziego."
            ),
        )
    return judge_id


def _public(row: Any) -> Dict[str, Any]:
    """Kalendarz w postaci, którą wolno pokazać - BEZ pełnego adresu."""
    return {
        "id": str(row["id"]),
        "name": str(row["name"] or ""),
        "url_masked": mask_feed_url(str(row["url"] or "")),
        "color": row["color"],
        "enabled": bool(row["enabled"]),
        "blocks_assignment": bool(row["blocks_assignment"]),
        "shared_with_province": bool(row["shared_with_province"]),
        "last_status": row["last_status"],
        "last_error": row["last_error"],
        "last_sync_at": row["last_sync_at"],
        "entry_count": int(row["entry_count"] or 0),
    }


async def _row(feed_id: str, judge_id: str) -> Any:
    row = await database.fetch_one(
        select(judge_calendar_feeds).where(
            (judge_calendar_feeds.c.id == feed_id)
            & (judge_calendar_feeds.c.judge_id == judge_id)
        )
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nie znaleziono takiego kalendarza.",
        )
    return row


@router.get("", summary="Moje kalendarze (iCal)")
async def list_feeds(payload: dict = Depends(get_jwt_payload)) -> Dict[str, Any]:
    judge_id = _owner(payload)
    rows = await database.fetch_all(
        select(judge_calendar_feeds)
        .where(judge_calendar_feeds.c.judge_id == judge_id)
        .order_by(judge_calendar_feeds.c.created_at)
    )
    return {"feeds": [_public(row) for row in rows]}


@router.post("", status_code=status.HTTP_201_CREATED, summary="Dodaj kalendarz")
async def add_feed(
    body: FeedIn, payload: dict = Depends(get_jwt_payload)
) -> Dict[str, Any]:
    judge_id = _owner(payload)

    try:
        url = normalize_feed_url(body.url)
    except FeedUrlError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    used = await database.fetch_val(
        select(func.count()).select_from(judge_calendar_feeds).where(
            judge_calendar_feeds.c.judge_id == judge_id
        )
    )
    if int(used or 0) >= MAX_FEEDS_PER_JUDGE:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Możesz mieć najwyżej {MAX_FEEDS_PER_JUDGE} kalendarzy. "
                "Usuń jeden, żeby dodać nowy."
            ),
        )

    feed_id = uuid.uuid4().hex
    await database.execute(
        judge_calendar_feeds.insert().values(
            id=feed_id,
            judge_id=judge_id,
            name=(body.name or "").strip() or "Mój kalendarz",
            url=url,
            color=body.color,
            enabled=True,
            blocks_assignment=bool(body.blocks_assignment),
            shared_with_province=bool(body.shared_with_province),
            created_at=datetime.now(timezone.utc),
        )
    )

    # Pierwsze pobranie od razu: sędzia ma zobaczyć plan teraz, a nie za sześć
    # godzin. Nieudane nie cofa dodania - powód zostaje przy kalendarzu.
    row = await _row(feed_id, judge_id)
    result = await sync_feed(row)
    return {"feed": _public(await _row(feed_id, judge_id)), "sync": result}


@router.patch("/{feed_id}", summary="Zmień ustawienia kalendarza")
async def update_feed(
    body: FeedPatch,
    feed_id: str = Path(...),
    payload: dict = Depends(get_jwt_payload),
) -> Dict[str, Any]:
    judge_id = _owner(payload)
    row = await _row(feed_id, judge_id)

    values: Dict[str, Any] = {}
    if body.name is not None:
        values["name"] = body.name.strip() or "Mój kalendarz"
    if body.color is not None:
        values["color"] = body.color
    if body.enabled is not None:
        values["enabled"] = bool(body.enabled)
    if body.blocks_assignment is not None:
        values["blocks_assignment"] = bool(body.blocks_assignment)
    if body.shared_with_province is not None:
        values["shared_with_province"] = bool(body.shared_with_province)
    url_changed = False
    if body.url is not None and body.url.strip():
        try:
            values["url"] = normalize_feed_url(body.url)
        except FeedUrlError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        url_changed = values["url"] != str(row["url"] or "")

    if values:
        await database.execute(
            judge_calendar_feeds.update()
            .where(judge_calendar_feeds.c.id == feed_id)
            .values(**values)
        )

    fresh = await _row(feed_id, judge_id)
    result = None
    # Nowy adres albo zmieniona nazwa (wchodzi w treść wpisów) = nowe wpisy.
    if url_changed or "name" in values or "color" in values:
        if bool(fresh["enabled"]):
            result = await sync_feed(fresh)
            fresh = await _row(feed_id, judge_id)
    return {"feed": _public(fresh), "sync": result}


@router.delete(
    "/{feed_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Usuń kalendarz"
)
async def remove_feed(
    feed_id: str = Path(...), payload: dict = Depends(get_jwt_payload)
) -> None:
    judge_id = _owner(payload)
    await _row(feed_id, judge_id)
    # Najpierw wpisy: kalendarz bez wpisów to nic, wpisy bez kalendarza to
    # niedyspozycje, których nikt już nie odświeży ani nie usunie.
    await database.execute(
        delete(judge_feed_offtimes).where(judge_feed_offtimes.c.feed_id == feed_id)
    )
    await database.execute(
        delete(judge_calendar_feeds).where(judge_calendar_feeds.c.id == feed_id)
    )


@router.post("/{feed_id}/refresh", summary="Odśwież teraz")
async def refresh_feed(
    feed_id: str = Path(...), payload: dict = Depends(get_jwt_payload)
) -> Dict[str, Any]:
    judge_id = _owner(payload)
    row = await _row(feed_id, judge_id)
    if not bool(row["enabled"]):
        raise HTTPException(
            status_code=400,
            detail="Ten kalendarz jest wyłączony - włącz go, żeby pobrać wpisy.",
        )
    result = await sync_feed(row)
    return {"feed": _public(await _row(feed_id, judge_id)), "sync": result}

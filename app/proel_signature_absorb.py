# app/proel_signature_absorb.py
#
# Podpisy, które przyszły pełną treścią protokołu, a nie mają wpisu w overlayu,
# trafiają do overlaya - patrz `adopt_blob_signatures` w `app/proel_fields.py`
# (tam reguła i historia SM/61). Ten moduł to tylko jej podpięcie do zapisu:
# wołany WEWNĄTRZ transakcji `PUT`/`POST`, PRZED reprojekcją, tak jak
# `absorb_blob_exams`.

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Sequence

from sqlalchemy import func, update

from app.db import database, proel_match_state
from app.proel_auth import Actor
from app.proel_fields import adopt_blob_signatures
from app.proel_journal import log_match_event, signature_who

logger = logging.getLogger(__name__)


def _by_of(actor: Optional[Actor], install: str) -> Dict[str, Any]:
    if actor is not None:
        return actor.as_by()
    return {"judge_id": "", "name": "", "install": install, "verified": False}


async def absorb_blob_signatures(
    match_number: str,
    state: Dict[str, Any],
    blobs: Sequence[Any],
    actor: Optional[Actor],
    install: str,
) -> Dict[str, Any]:
    """Wciągnij do overlaya podpisy obecne wyłącznie w treści. Nigdy nie rzuca.

    Zwraca `{"state", "paths", "rev"}` - stan po zmianie (do reprojekcji) i ścieżki
    do dziennika. Gdy nic nie weszło, stan jest nietknięty, a `paths` puste.
    """
    untouched = {"state": state, "paths": [], "rev": int(state.get("rev") or 0)}
    try:
        overlay = state.get("fields_json") if isinstance(state.get("fields_json"), dict) else {}
        rev = int(state.get("rev") or 0) + 1
        new_overlay, paths = adopt_blob_signatures(
            overlay,
            blobs,
            rev=rev,
            at=datetime.now(timezone.utc).isoformat(),
            by=_by_of(actor, install),
        )
    except Exception:  # noqa: BLE001 - ślad w overlayu jest dodatkiem do zapisu, nie jego warunkiem
        logger.warning("podpisy: nie wchłonięto podpisów z treści %s", match_number, exc_info=True)
        return untouched
    if not paths:
        return untouched
    await database.execute(
        update(proel_match_state)
        .where(proel_match_state.c.match_number == str(match_number or "").strip())
        .values(fields_json=new_overlay, rev=rev, updated_at=func.now())
    )
    refreshed = dict(state)
    refreshed["fields_json"] = new_overlay
    refreshed["rev"] = rev
    return {"state": refreshed, "paths": paths, "rev": rev}


async def journal_absorbed_signatures(
    match_number: str,
    zprp_match_id: Optional[str],
    absorbed: Dict[str, Any],
    actor: Optional[Actor],
    *,
    app_version: Optional[str] = None,
    ip: Optional[str] = None,
) -> None:
    """Wpis „Podpis" w dzienniku za podpisy wciągnięte z treści - PO transakcji."""
    paths = list((absorbed or {}).get("paths") or [])
    if not paths:
        return
    rev = int(absorbed.get("rev") or 0)
    await log_match_event(
        match_number=match_number,
        event="match.signed",
        actor=actor,
        zprp_match_id=zprp_match_id,
        details={
            "signatures": [{"path": p, "who": signature_who(p)} for p in paths],
            "source": "blob",
            "rev": rev,
        },
        event_key=f"sigblob:{match_number}:{rev}",
        app_version=app_version,
        ip=ip,
    )

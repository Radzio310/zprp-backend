"""Statystyki ProEla - panel administratora.

Cienka warstwa: zbiera wiersze z bazy i woła `build_stats` z
`app/proel_stats_rules.py`, gdzie mieszka cała logika (i gdzie da się ją
sprawdzić testem bez Postgresa).

Koszt. Najcięższe są statystyki sportowe - wymagają przebiegu każdego meczu.
Dlatego czytamy go przez pamięć podręczną `proel_match_stats`: blob idzie do
przeliczenia wyłącznie wtedy, gdy mecz zmienił się od ostatniego razu. Gotową
odpowiedź trzymamy dodatkowo przez chwilę w pamięci procesu, bo przełączanie
zakładek i filtrów zwykle wraca do tego samego zestawu parametrów.

Router musi stać w `main.py` PRZED `proel_router`: tamten ma trasę
`/proel/{match_number}`, która zjadłaby „stats" jako numer meczu.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, delete, select

from app.proel_auth import Actor, proel_actor
from app.proel_journal import _effective_event, _require_admin
from app.proel_stats_rules import (
    as_dict,
    build_stats,
    learn_prefix_provinces,
    match_summary,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/proel/stats", tags=["ProEl: statystyki"])

#: Ile sekund żyje gotowa odpowiedź. Krótko, bo panel ma pokazywać także mecz
#: sprzed chwili - ale dość, żeby przełączenie zakładki nie liczyło wszystkiego
#: od nowa.
RESPONSE_TTL_S = 45

#: Po tyle blobów sięgamy naraz przy przeliczaniu podsumowań.
_BLOB_CHUNK = 40

_response_cache: Dict[Tuple[Any, ...], Tuple[float, Dict[str, Any]]] = {}
_refresh_lock = asyncio.Lock()


async def _refresh_summaries() -> List[Dict[str, Any]]:
    """Podsumowania wszystkich meczów, przeliczone tylko tam, gdzie trzeba."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.db import database, proel_match_stats, saved_matches

    async with _refresh_lock:
        heads = await database.fetch_all(
            select(saved_matches.c.match_number, saved_matches.c.updated_at)
        )
        cached = await database.fetch_all(
            select(
                proel_match_stats.c.match_number,
                proel_match_stats.c.source_updated_at,
                proel_match_stats.c.summary_json,
            )
        )
        cache = {row["match_number"]: row for row in cached}

        out: List[Dict[str, Any]] = []
        stale: List[str] = []
        for head in heads:
            hit = cache.get(head["match_number"])
            if hit is not None and hit["source_updated_at"] == head["updated_at"]:
                summary = as_dict(hit["summary_json"])
                if summary:
                    out.append(summary)
                    continue
            stale.append(head["match_number"])

        for i in range(0, len(stale), _BLOB_CHUNK):
            chunk = stale[i : i + _BLOB_CHUNK]
            rows = await database.fetch_all(
                select(
                    saved_matches.c.match_number,
                    saved_matches.c.status,
                    saved_matches.c.data_json,
                    saved_matches.c.updated_at,
                ).where(saved_matches.c.match_number.in_(chunk))
            )
            for row in rows:
                try:
                    summary = match_summary(
                        row["match_number"], row["status"], row["data_json"]
                    )
                except Exception:  # noqa: BLE001 - jeden zepsuty blob nie gasi panelu
                    logger.warning(
                        "proel stats: nie policzono meczu %s",
                        row["match_number"],
                        exc_info=True,
                    )
                    continue
                out.append(summary)
                await database.execute(
                    pg_insert(proel_match_stats)
                    .values(
                        match_number=row["match_number"],
                        source_updated_at=row["updated_at"],
                        summary_json=summary,
                        computed_at=datetime.now(timezone.utc),
                    )
                    .on_conflict_do_update(
                        index_elements=[proel_match_stats.c.match_number],
                        set_={
                            "source_updated_at": row["updated_at"],
                            "summary_json": summary,
                            "computed_at": datetime.now(timezone.utc),
                        },
                    )
                )

        # Mecze usunięte z `proel_matches` - ich podsumowania nie mają już czego
        # opisywać. Dziennik zostaje nietknięty, to jest inna księga.
        known = {head["match_number"] for head in heads}
        orphans = [key for key in cache if key not in known]
        if orphans:
            await database.execute(
                delete(proel_match_stats).where(
                    proel_match_stats.c.match_number.in_(orphans)
                )
            )
        return out


async def _journal_rows() -> List[Dict[str, Any]]:
    """Dziennik zdarzeń do statystyk - z poprawioną nazwą zdarzenia.

    `_effective_event` prostuje wiersze sprzed poprawek emitera: znacznik
    wysyłki zapisany dawniej jako „Zmiana pól" wraca jako właściwe zdarzenie.
    Po wyprostowaniu zostają same zdarzenia obiegu - zwykłe zmiany pól nic nie
    mówią o tym, na którym etapie jest mecz.
    """
    from app.db import database, proel_activity_log as log

    rows = await database.fetch_all(
        select(
            log.c.match_number,
            log.c.event,
            log.c.actor_judge_id,
            log.c.actor_name,
            log.c.app_version,
            log.c.details_json,
            log.c.created_at,
        )
    )
    out: List[Dict[str, Any]] = []
    for row in rows:
        details = as_dict(row["details_json"])
        event = _effective_event(str(row["event"] or ""), details)
        if event == "field.changed":
            continue
        out.append(
            {
                "match_number": row["match_number"],
                "event": event,
                "actor_judge_id": row["actor_judge_id"],
                "actor_name": row["actor_name"],
                "app_version": row["app_version"],
                "details": details,
                "created_at": row["created_at"],
            }
        )
    return out


async def _people_provinces() -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
    from app.db import database, login_records, proel_users, province_judges

    judges = {
        str(r["judge_id"]): str(r["province"] or "")
        for r in await database.fetch_all(
            select(province_judges.c.judge_id, province_judges.c.province)
        )
    }
    logins = {
        str(r["judge_id"]): str(r["province"] or "")
        for r in await database.fetch_all(
            select(login_records.c.judge_id, login_records.c.province)
        )
    }
    accounts = {
        str(r["id"]): str(r["province"] or "")
        for r in await database.fetch_all(
            select(proel_users.c.id, proel_users.c.province)
        )
    }
    return judges, logins, accounts


async def _learned_prefixes() -> Dict[str, str]:
    """Mapa przedrostków okręgów wyuczona z terminarzy - patrz liść."""
    from app.db import database, province_matches

    rows = await database.fetch_all(
        select(province_matches.c.province, province_matches.c.match_code).where(
            province_matches.c.match_code.isnot(None)
        )
    )
    return learn_prefix_provinces((r["province"], r["match_code"]) for r in rows)


async def _live_now() -> List[str]:
    """Mecze, których leasing prowadzenia jest teraz ważny."""
    from app.db import database, proel_match_state

    now = datetime.now(timezone.utc)
    rows = await database.fetch_all(
        select(proel_match_state.c.match_number).where(
            and_(
                proel_match_state.c.lease_until.isnot(None),
                proel_match_state.c.lease_until > now,
            )
        )
    )
    return [str(r["match_number"]) for r in rows]


async def _training_pdfs() -> int:
    from sqlalchemy import func

    from app.db import database, protocol_audit

    value = await database.fetch_val(
        select(func.count()).select_from(protocol_audit).where(protocol_audit.c.training.is_(True))
    )
    return int(value or 0)


@router.get("", summary="Statystyki ProEla - tylko administrator")
async def proel_stats(
    season: Optional[int] = Query(None, description="Rok początku sezonu, np. 2025"),
    competition: Optional[str] = Query(None, description="Rozgrywki, np. superliga"),
    level: Optional[str] = Query(None, description="central | district | cup | unknown"),
    match_province: Optional[str] = Query(None, description="Województwo meczu"),
    person_province: Optional[str] = Query(None, description="Województwo prowadzącego"),
    training: bool = Query(False, description="Czy liczyć mecze szkoleniowe i testowe"),
    actor: Actor = Depends(proel_actor),
):
    await _require_admin(actor)

    filters = {
        "season": season,
        "competition": (competition or "").strip() or None,
        "level": (level or "").strip() or None,
        "match_province": (match_province or "").strip() or None,
        "person_province": (person_province or "").strip() or None,
        "training": bool(training),
    }
    cache_key = tuple(sorted(filters.items()))
    hit = _response_cache.get(cache_key)
    if hit and hit[0] > time.monotonic():
        return hit[1]

    summaries = await _refresh_summaries()
    events = await _journal_rows()
    judges, logins, accounts = await _people_provinces()
    learned = await _learned_prefixes()
    live = await _live_now()
    training_pdfs = await _training_pdfs()

    payload = build_stats(
        summaries=summaries,
        events=events,
        learned_prefixes=learned,
        judge_provinces=judges,
        login_provinces=logins,
        account_provinces=accounts,
        live_now=live,
        training_pdfs=training_pdfs,
        filters=filters,
    )
    _response_cache[cache_key] = (time.monotonic() + RESPONSE_TTL_S, payload)
    # Pamięć nie rośnie bez końca: kombinacji filtrów jest niewiele, ale
    # administrator potrafi przeklikać wszystkie.
    if len(_response_cache) > 64:
        oldest = min(_response_cache, key=lambda k: _response_cache[k][0])
        _response_cache.pop(oldest, None)
    return payload

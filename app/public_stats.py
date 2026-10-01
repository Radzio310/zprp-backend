"""Publiczne liczby BAZY dla strony bazaapp.online - `GET /public/baza-stats`.

Cienka warstwa: czyta z bazy tylko kolumny potrzebne do policzenia sum i woła
reguły z `app/public_stats_rules.py` (liść testowalny bez Postgresa). Bez
logowania, bez danych osobowych - na zewnątrz wychodzą same liczby.

Koszt i odporność:

* gotowa odpowiedź żyje w pamięci procesu 10 minut, więc odświeżanie strony
  produktu nie czyta za każdym razem całych tabel;
* każda sekcja liczy się osobno - gdy jedna tabela zawiedzie, jej pole bierze
  wartość z poprzedniej odpowiedzi, a reszta jest świeża;
* gdy nie uda się nic, zwracamy ostatnią znaną odpowiedź z `"stale": true`,
  a bez niej 503 w kopercie `{"error": ...}` (handler w `main.py`).

Importy bazy siedzą w funkcjach: `app.db` łączy się z Postgresem przy imporcie.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Response
from sqlalchemy import func, select

from app.proel_training_key import TRAINING_KEY_LIKE
from app.public_stats_rules import (
    StatsCache,
    build_payload,
    summarize_panel,
    summarize_judges,
    summarize_matches,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/public", tags=["Publiczne"])

#: Przeglądarka i ewentualny CDN mogą trzymać odpowiedź 5 minut - i tak jest
#: liczona najwyżej raz na 10 minut po stronie serwera.
_CLIENT_MAX_AGE_S = 300

_cache = StatsCache()
_lock = asyncio.Lock()


async def _judges_section() -> Dict[str, int]:
    from app.db import database, login_records

    rows = await database.fetch_all(
        select(
            login_records.c.judge_id,
            login_records.c.province,
            login_records.c.last_login_at,
            login_records.c.last_open_at,
        )
    )
    return summarize_judges(
        (dict(r) for r in rows), datetime.now(timezone.utc)
    )


async def _panel_section() -> Dict[str, Any]:
    from app.db import active_provinces, database

    rows = await database.fetch_all(
        select(active_provinces.c.province, active_provinces.c.enabled)
    )
    # Liczba i lista z jednego odczytu - nie mogą się rozjechać.
    return summarize_panel(dict(r) for r in rows)


async def _matches_section() -> Dict[str, int]:
    from app.db import database, saved_matches

    # Tylko `matchConfig`, nie cały blob - przebieg meczu potrafi ważyć setki KB.
    rows = await database.fetch_all(
        select(
            saved_matches.c.match_number,
            saved_matches.c.status,
            saved_matches.c.data_json["matchConfig"].label("config"),
        )
    )
    return summarize_matches(dict(r) for r in rows)


async def _pdfs_section() -> Dict[str, int]:
    from app.db import database, protocol_audit

    # Wygenerowane protokoły PDF z prawdziwych meczów (bez ćwiczeń z kursów),
    # liczone po meczu - kolejne wydruki tego samego meczu to jeden protokół.
    value = await database.fetch_val(
        select(func.count(func.distinct(protocol_audit.c.match_number))).where(
            protocol_audit.c.training.is_(False),
            protocol_audit.c.match_number.isnot(None),
            protocol_audit.c.match_number != "",
            protocol_audit.c.match_number.notlike(TRAINING_KEY_LIKE),
        )
    )
    return {"protocol_pdfs": int(value or 0)}


_SECTIONS = (
    ("judges", _judges_section),
    ("panel", _panel_section),
    ("matches", _matches_section),
    ("pdfs", _pdfs_section),
)


async def _compute() -> Dict[str, Any]:
    """Świeże sumy. Rzuca wyjątek dopiero wtedy, gdy nie udała się ŻADNA sekcja."""
    fresh: Dict[str, Any] = {}
    failed = 0
    for name, section in _SECTIONS:
        try:
            fresh.update(await section())
        except Exception:  # noqa: BLE001 - jedna tabela nie gasi całej strony
            failed += 1
            logger.warning("public stats: sekcja %s nie policzona", name, exc_info=True)
    if failed == len(_SECTIONS):
        raise RuntimeError("public stats: żadna sekcja się nie policzyła")
    return build_payload(fresh, _cache.last(), datetime.now(timezone.utc))


@router.get("/baza-stats", summary="Publiczne liczby BAZY (bez auth, same sumy)")
async def baza_stats(response: Response) -> Dict[str, Any]:
    response.headers["Cache-Control"] = f"public, max-age={_CLIENT_MAX_AGE_S}"

    hit = _cache.fresh(time.monotonic())
    if hit is not None:
        return hit

    async with _lock:
        # Drugie żądanie, które czekało na zamku, dostaje to, co policzyło pierwsze.
        hit = _cache.fresh(time.monotonic())
        if hit is not None:
            return hit
        if not _cache.in_backoff(time.monotonic()):
            try:
                payload = await _compute()
            except Exception as exc:  # noqa: BLE001
                # Ślady sekcji są już w logu - tu wystarczy jedna linia.
                logger.error("public stats: liczenie nie powiodło się: %s", exc)
                _cache.mark_failure(time.monotonic())
            else:
                _cache.put(payload, time.monotonic())
                return payload
        stale = _cache.stale()
        if stale is not None:
            return stale
        raise HTTPException(503, "Statystyki są chwilowo niedostępne")

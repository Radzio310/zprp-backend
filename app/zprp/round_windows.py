"""Zakresy dat kolejek dla meczów bez ustalonego terminu.

Źródłem są publiczne endpointy ZPRP ``pokaz_rundy.php`` i
``pokaz_kolejki.php``.  Nie zapisujemy początku kolejki jako daty meczu:
aplikacja dostaje osobne pola i może użyć ich wyłącznie do prezentacji oraz
sortowania.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import unicodedata
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import httpx
from fastapi import APIRouter
from pydantic import BaseModel, Field

from app import archive_rules as AR

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/zprp/round-windows", tags=["zprp"])

API = "https://rozgrywki.zprp.pl/api/"
CACHE_TTL_SECONDS = 6 * 60 * 60
STALE_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_BATCH = 200


class RoundWindowRequestItem(BaseModel):
    match_id: str = Field(min_length=1, max_length=80)
    competition_id: str = Field(min_length=1, max_length=80)
    round_name: str = Field(min_length=1, max_length=200)
    series_name: str = Field(min_length=1, max_length=200)


class RoundWindowRequest(BaseModel):
    items: list[RoundWindowRequestItem] = Field(max_length=MAX_BATCH)


class RoundWindowResult(BaseModel):
    match_id: str
    start_date: str
    end_date: str
    round_id: str
    series_id: str


class RoundWindowResponse(BaseModel):
    items: list[RoundWindowResult]
    unresolved: list[str]


@dataclass
class _CachedRows:
    stored_at: float
    rows: list[dict[str, Any]]


_cache: dict[str, _CachedRows] = {}
_cache_lock = asyncio.Lock()
_inflight: dict[str, asyncio.Task[list[dict[str, Any]]]] = {}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _normal(value: Any) -> str:
    text = unicodedata.normalize("NFKD", _text(value).casefold())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", text).strip()


def _round_key(value: Any) -> str:
    return re.sub(r"\brunda\b", " ", _normal(value)).strip()


def _series_key(value: Any) -> str:
    return re.sub(r"\b(?:kolejka|seria)\b", " ", _normal(value)).strip()


def _number(value: Any) -> str:
    match = re.search(r"\d+", _normal(value))
    return match.group(0) if match else ""


def _find_named(rows: list[dict[str, Any]], wanted: str, *, round_: bool) -> dict[str, Any] | None:
    key = _round_key if round_ else _series_key
    exact = key(wanted)
    for row in rows:
        if key(row.get("Nazwa")) == exact:
            return row

    # Awaryjnie numer, ale wyłącznie gdy wskazuje dokładnie jeden element.
    # Chroni to przed przypadkowym wyborem przy nietypowych nazwach faz.
    wanted_number = _number(wanted)
    if not wanted_number:
        return None
    hits = [row for row in rows if _number(row.get("Nazwa") or row.get("Nr")) == wanted_number]
    return hits[0] if len(hits) == 1 else None


def _valid_iso_date(value: Any) -> str:
    text = _text(value)
    return text if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text) else ""


async def _download_rows(client: httpx.AsyncClient, path: str) -> list[dict[str, Any]]:
    for attempt in range(3):
        try:
            response = await client.get(API + path, timeout=20.0)
            if response.status_code in (408, 425, 429, 500, 502, 503, 504) and attempt < 2:
                await asyncio.sleep(0.35 * (2**attempt))
                continue
            response.raise_for_status()
            return [row for row in AR.as_rows(AR.decode_api_bytes(response.content)) if isinstance(row, dict)]
        except Exception:
            if attempt >= 2:
                raise
            await asyncio.sleep(0.35 * (2**attempt))
    return []


async def _cached_rows(client: httpx.AsyncClient, path: str) -> list[dict[str, Any]]:
    now = time.monotonic()
    cached = _cache.get(path)
    if cached and now - cached.stored_at <= CACHE_TTL_SECONDS:
        return cached.rows

    owner = False
    async with _cache_lock:
        # Drugi request mógł uzupełnić cache, zanim dostaliśmy blokadę.
        cached = _cache.get(path)
        if cached and time.monotonic() - cached.stored_at <= CACHE_TTL_SECONDS:
            return cached.rows
        task = _inflight.get(path)
        if task is None:
            task = asyncio.create_task(_download_rows(client, path))
            _inflight[path] = task
            owner = True

    try:
        rows = await task
    except Exception:
        if cached and now - cached.stored_at <= STALE_TTL_SECONDS:
            logger.warning("[round-windows] ZPRP niedostępne, używam starego cache dla %s", path)
            return cached.rows
        raise
    finally:
        if owner:
            async with _cache_lock:
                if _inflight.get(path) is task:
                    _inflight.pop(path, None)

    async with _cache_lock:
        _cache[path] = _CachedRows(stored_at=time.monotonic(), rows=rows)
    return rows


RowsGetter = Callable[[str], Awaitable[list[dict[str, Any]]]]


async def resolve_items(
    items: list[RoundWindowRequestItem],
    get_rows: RowsGetter,
) -> RoundWindowResponse:
    """Rozwiązuje paczkę i współdzieli zapytania dla tych samych rozgrywek."""

    round_paths = {
        item.competition_id: f"pokaz_rundy.php?Rozgrywki={item.competition_id}"
        for item in items
    }
    round_payloads = await asyncio.gather(
        *(get_rows(path) for path in round_paths.values()),
        return_exceptions=True,
    )
    rounds_by_competition: dict[str, list[dict[str, Any]]] = {}
    for competition_id, payload in zip(round_paths, round_payloads):
        rounds_by_competition[competition_id] = [] if isinstance(payload, Exception) else payload

    round_for_item: dict[str, dict[str, Any]] = {}
    needed_round_ids: set[str] = set()
    for item in items:
        found = _find_named(rounds_by_competition.get(item.competition_id, []), item.round_name, round_=True)
        round_id = _text(found.get("Id")) if found else ""
        if round_id:
            round_for_item[item.match_id] = found
            needed_round_ids.add(round_id)

    series_paths = {round_id: f"pokaz_kolejki.php?Runda={round_id}" for round_id in needed_round_ids}
    series_payloads = await asyncio.gather(
        *(get_rows(path) for path in series_paths.values()),
        return_exceptions=True,
    )
    series_by_round: dict[str, list[dict[str, Any]]] = {}
    for round_id, payload in zip(series_paths, series_payloads):
        series_by_round[round_id] = [] if isinstance(payload, Exception) else payload

    resolved: list[RoundWindowResult] = []
    unresolved: list[str] = []
    for item in items:
        round_row = round_for_item.get(item.match_id)
        round_id = _text(round_row.get("Id")) if round_row else ""
        series = _find_named(series_by_round.get(round_id, []), item.series_name, round_=False)
        start = _valid_iso_date(series.get("DataStart")) if series else ""
        end = _valid_iso_date(series.get("DataKoniec")) if series else ""
        # W rozgrywkach okregowych ZPRP czesto zapisuje tylko DataStart. To
        # poprawny jednodniowy termin kolejki, a nie brak danych.
        if start and not end:
            end = start
        series_id = _text(series.get("ID_kolejka")) if series else ""
        if not (round_id and series_id and start and end and start <= end):
            unresolved.append(item.match_id)
            continue
        resolved.append(
            RoundWindowResult(
                match_id=item.match_id,
                start_date=start,
                end_date=end,
                round_id=round_id,
                series_id=series_id,
            )
        )
    return RoundWindowResponse(items=resolved, unresolved=unresolved)


@router.post("/resolve", response_model=RoundWindowResponse)
async def resolve_round_windows(payload: RoundWindowRequest) -> RoundWindowResponse:
    # Ostatni wpis dla powtórzonego ID wygrywa. Zwykła lista sędziego nie ma
    # duplikatów, ale takie zachowanie utrzymuje jednoznaczną odpowiedź mapy.
    unique = {item.match_id: item for item in payload.items}
    async with httpx.AsyncClient() as client:
        return await resolve_items(
            list(unique.values()),
            lambda path: _cached_rows(client, path),
        )

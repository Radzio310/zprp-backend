"""Nagrania Veo w Mentorze - odczyt stanu z `app.veo.co`, odświeżanie w tle, trasa „Sprawdź ponownie” (`docs/mentor-panel.md` 11).

Reguły (kształty, statusy, bezpieczeństwo adresów): `app/mentor_veo_rules.py`. Tu jest tylko sieć i baza.
  - stan nagrania leży w `mentor_match_videos.veo_json`; odczyt listy używa zapisu (TTL 6 h) i NIE czeka na Veo, gdy zapis
    już jest - odświeża w tle. Nagranie sprawdzane pierwszy raz dostaje do 4 s na odpowiedź, potem też dokończy się w tle,
  - błąd sieci / 5xx Veo nie zmienia dobrego stanu (`gone` tylko po 404, `private` po 401/403 lub is_accessible=false),
  - zapytania tylko do https `app.veo.co`, odpowiedź JSON do 512 KB i 8 s, przekierowania ręcznie i sprawdzane.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from fastapi import APIRouter, Depends
from sqlalchemy import select, update

from app import mentor_panel_core as C
from app import mentor_panel_media as M
from app import mentor_panel_rules as R
from app import mentor_veo_rules as V
from app.db import database, mentor_match_videos
from app.mentor_panel_auth import mentor_actor

logger = logging.getLogger("app.mentor_veo")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor"])
Actor = C.MentorActor

#: Ile pierwsze (jeszcze bez stanu) sprawdzenia mogą wstrzymać odpowiedź listy.
FIRST_CHECK_BUDGET_S = 4.0
#: „Sprawdź ponownie” częściej niż co tyle sekund nie woła Veo (zwraca zapis).
MANUAL_COOLDOWN_S = 10.0

_inflight: Dict[str, "asyncio.Task[Dict[str, Any]]"] = {}


class VeoError(Exception):
    """Nagrania nie da się teraz przeczytać; `status` jak w `STATUSES`, `args[0]` po polsku."""

    def __init__(self, status: str, message: Optional[str] = None):
        super().__init__(message or V.clip_error(status))
        self.status = status


def _client():
    """Fabryka klienta HTTP (testy podmieniają ją na atrapę z `httpx.MockTransport`)."""
    import httpx

    return httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(V.REQUEST_TIMEOUT_S, connect=4.0),
                             headers={"Accept": "application/json", "User-Agent": "BAZA-Mentor/1.0"})


async def _get_json(url: str) -> Tuple[Optional[int], Any]:
    """(status HTTP, JSON). (None, None) = brak odpowiedzi, za duża albo nie-JSON przy 2xx."""
    import httpx

    current = url
    try:
        async with _client() as client:
            for _hop in range(V.MAX_REDIRECTS + 1):
                if not V.api_url_ok(current):
                    logger.warning("veo: adres poza app.veo.co odrzucony")
                    return None, None
                async with client.stream("GET", current) as response:
                    code = response.status_code
                    if code in (301, 302, 303, 307, 308):
                        target = response.headers.get("location")
                        if not target:
                            return None, None
                        current = urljoin(current, target)
                        continue
                    if not 200 <= code < 300:
                        return code, None
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > V.MAX_JSON_BYTES:
                            return None, None
                try:
                    return code, json.loads(bytes(body).decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    return None, None
    except (httpx.HTTPError, OSError, asyncio.TimeoutError):
        return None, None
    return None, None


async def fetch_state(slug: str) -> Dict[str, Any]:
    """Wynik `classify` dla nagrania (dwa zapytania równolegle)."""
    (mc, md), (vc, vd) = await asyncio.gather(_get_json(V.match_api_url(slug)), _get_json(V.videos_api_url(slug)))
    return V.classify(mc, md, vc, vd)


def _state_of(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = R.json_value(row.get("veo_json"), {})
    return raw if isinstance(raw, dict) and raw.get("status") else None


def slug_of(row: Dict[str, Any]) -> Optional[str]:
    return V.parse_slug(row.get("url")) or V.parse_slug(row.get("normalized_url"))


async def check(row: Dict[str, Any]) -> Dict[str, Any]:
    """Odświeża stan jednego nagrania i zapisuje go. Zwraca świeży wiersz. Jeden równoległy odczyt na nagranie."""
    video_id = row["id"]
    running = _inflight.get(video_id)
    if running is not None and not running.done():
        return await asyncio.shield(running)
    task = asyncio.ensure_future(_check_now(row))
    _inflight[video_id] = task
    task.add_done_callback(lambda t: (_inflight.pop(video_id, None), t.cancelled() or t.exception()))
    return await asyncio.shield(task)


async def _check_now(row: Dict[str, Any]) -> Dict[str, Any]:
    slug = slug_of(row)
    if not slug:
        return row
    prev = _state_of(row)
    try:
        result = await fetch_state(slug)
    except Exception:  # noqa: BLE001 - nieczytelna odpowiedź to błąd tymczasowy, nie koniec nagrania
        logger.warning("veo: odczyt nagrania nieudany", exc_info=True)
        result = {"kind": "error", "status": "unavailable"}
    state = V.merge_state(prev, result, C.now(), slug)
    values: Dict[str, Any] = {"veo_json": json.dumps(state, ensure_ascii=False), "updated_at": C.now()}
    if row.get("provider") != V.PROVIDER:
        values["provider"] = V.PROVIDER
    if not row.get("title") and state.get("title"):
        values["title"] = state["title"][:200]
    if not row.get("thumbnail_url") and state.get("thumbnail_url"):
        values["thumbnail_url"] = state["thumbnail_url"]
    if not row.get("duration_s") and state.get("duration_s"):
        values["duration_s"] = state["duration_s"]
    await database.execute(update(mentor_match_videos).where(mentor_match_videos.c.id == row["id"]).values(**values))
    return {**row, **values}


def _background(coro_factory) -> None:
    task = asyncio.ensure_future(coro_factory())
    task.add_done_callback(lambda t: t.cancelled() or t.exception())


async def ensure_fresh(rows: List[Dict[str, Any]], budget_s: float = FIRST_CHECK_BUDGET_S) -> List[Dict[str, Any]]:
    """Wiersze nagrań z odświeżonym stanem Veo tam, gdzie nigdy go nie było (do `budget_s`); przeterminowany zapis
    zostaje bez zmian, a jego odświeżenie rusza w tle. Nie rzuca wyjątków."""
    now = C.now()
    first, later = [], []
    for row in rows:
        if row.get("provider") != V.PROVIDER and not V.is_veo_url(row.get("url")):
            continue
        if row.get("kind") == "upload" or row.get("deleted_at") is not None or not slug_of(row):
            continue
        state = _state_of(row)
        if not V.needs_refresh(state, now):
            continue
        (later if state else first).append(row)
    for row in later:
        _background(lambda r=row: check(r))
    if not first:
        return rows
    tasks = {row["id"]: asyncio.ensure_future(check(row)) for row in first}
    done, pending = await asyncio.wait(tasks.values(), timeout=budget_s)
    for t in pending:  # dokończą się same; błąd nie ginie w pętli zdarzeń
        t.add_done_callback(lambda x: x.cancelled() or x.exception())
    fresh: Dict[str, Dict[str, Any]] = {}
    for video_id, task in tasks.items():
        if task in done and not task.cancelled() and task.exception() is None:
            fresh[video_id] = task.result()
    return [fresh.get(r["id"], r) for r in rows]


async def resolve_media(row: Dict[str, Any]) -> str:
    """Świeży adres MP4 do cięcia: odświeża stan, potem sprawdza łańcuch przekierowań (każdy krok https `c.veocdn.com`).
    Rzuca `VeoError` (po polsku) dla prywatnego, usuniętego, przetwarzanego i niedostępnego nagrania."""
    fresh = await check(row)
    state = _state_of(fresh) or {}
    status = state.get("status") or "unavailable"
    if status != "ok" or not V.cdn_url_ok(state.get("play_url")):
        raise VeoError(status if status != "ok" else "unavailable")
    final = await _final_media_url(state["play_url"])
    if not final:
        raise VeoError("unavailable")
    return final


async def _final_media_url(url: str) -> Optional[str]:
    """Pierwsze bajty pliku (Range 0-0) z ręcznym śledzeniem przekierowań; zwraca adres, z którego ffmpeg ma czytać."""
    import httpx

    current = url
    try:
        async with _client() as client:
            for _hop in range(V.MAX_REDIRECTS + 1):
                if not V.cdn_url_ok(current):
                    return None
                async with client.stream("GET", current, headers={"Range": "bytes=0-0", "Accept": "*/*"}) as response:
                    if response.status_code in (301, 302, 303, 307, 308):
                        target = response.headers.get("location")
                        if not target:
                            return None
                        current = urljoin(current, target)
                        continue
                    return current if response.status_code in (200, 206) else None
    except (httpx.HTTPError, OSError, asyncio.TimeoutError):
        return None
    return None


# ─── Trasa ──────────────────────────────────────────────────────────────────


@router.post("/pairs/{pair_id}/matches/{match_id}/videos/{video_id}/veo/check")
async def veo_check(pair_id: str, match_id: str, video_id: str, actor: Actor = Depends(mentor_actor)):
    """„Sprawdź ponownie”: odświeża stan nagrania Veo i zwraca obiekt Video (jak `PATCH .../videos/{id}`).
    Częściej niż co 10 s zwraca zapis bez wołania Veo. 422 `NOT_VEO`, gdy to nagranie nie jest z Veo."""
    ctx = await C.pair_context(pair_id, actor)
    row = await M._pair_video(ctx, match_id, video_id)
    if not slug_of(row):
        raise C.err(422, "NOT_VEO", "To nagranie nie jest linkiem z Veo.")
    state = _state_of(row)
    attempt = V._when((state or {}).get("attempt_at"))
    if not (attempt and (C.now() - attempt).total_seconds() < MANUAL_COOLDOWN_S):
        row = await check(row)
    return await M._video_payload(ctx, video_id)

"""
Katalog sezonów związku i dopytywanie o sezon pojedynczego meczu.

Reguły siedzą w liściu `app/assignment_scope.py`; tu jest tylko sieć i pamięć.

  - `season_catalog()` - `pokaz_sezony.php`, pamiętany 12 godzin. Nieudane
    pobranie nie jest awarią: zostaje zapas z liścia i ponawiamy za 10 minut.
  - `lookup_season_ids()` - `pokaz_mecze_szczegoly.php` dla meczów, których
    sezonu migawka nie zna. Krótka smycz i budżet, bo pytamy przy OTWARTYM
    panelu; odpowiedź pamiętamy w procesie (sezon meczu się nie zmienia).
    ⚠ Nic nie piszemy do `province_matches` - migawkę pisze wyłącznie monitor.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, Iterable, Optional

from httpx import AsyncClient

from app.assignment_scope import Season, season_catalog as build_catalog

logger = logging.getLogger(__name__)

SEASONS_URL = "https://rozgrywki.zprp.pl/api/pokaz_sezony.php"

CATALOG_TTL_SECONDS = 12 * 3600
CATALOG_RETRY_SECONDS = 600

#: Dopytywanie o sezon meczu przy otwartym panelu.
LOOKUP_REQUEST_SECONDS = 5.0
LOOKUP_BUDGET_SECONDS = 6.0
LOOKUP_LIMIT = 40
LOOKUP_CONCURRENCY = 6
#: Nieudaną odpowiedź pamiętamy krótko - związek mógł się tylko potknąć.
LOOKUP_MISS_SECONDS = 600

_catalog: Optional[Dict[str, Season]] = None
_catalog_until = 0.0
_catalog_lock = asyncio.Lock()

#: match_id -> (ID_sezon albo "", chwila zapisu). Pusty napis = nie wiemy.
_known: Dict[str, tuple[str, float]] = {}


async def season_catalog() -> Dict[str, Season]:
    global _catalog, _catalog_until
    now = time.monotonic()
    if _catalog is not None and now < _catalog_until:
        return _catalog
    async with _catalog_lock:
        now = time.monotonic()
        if _catalog is not None and now < _catalog_until:
            return _catalog
        try:
            async with AsyncClient(follow_redirects=True) as client:
                response = await client.get(SEASONS_URL, timeout=8.0)
                response.raise_for_status()
                rows = response.json()
            _catalog = build_catalog(rows)
            _catalog_until = now + CATALOG_TTL_SECONDS
        except Exception as exc:  # noqa: BLE001 - brak katalogu to nie awaria listy
            logger.warning("pokaz_sezony.php niedostępne: %s", exc)
            _catalog = _catalog or build_catalog(None)
            _catalog_until = now + CATALOG_RETRY_SECONDS
        return _catalog


async def lookup_season_ids(
    match_ids: Iterable[str],
    *,
    budget: float = LOOKUP_BUDGET_SECONDS,
    limit: int = LOOKUP_LIMIT,
) -> Dict[str, str]:
    """`ID_sezon` dla meczów, których sezonu nie zna migawka. Co nie zdążyło - nie wraca."""
    from app.province_match_monitor import _fetch_public_details

    now = time.monotonic()
    out: Dict[str, str] = {}
    ask: list[str] = []
    for match_id in match_ids:
        mid = str(match_id or "").strip()
        if not mid.isdigit():
            # `synthetic:...` z terminarza nie ma numeru zawodów - API go nie zna.
            continue
        cached = _known.get(mid)
        if cached is not None:
            sid, at = cached
            if sid:
                out[mid] = sid
                continue
            if now - at < LOOKUP_MISS_SECONDS:
                continue
        if len(ask) < limit:
            ask.append(mid)
    if not ask:
        return out

    semaphore = asyncio.Semaphore(LOOKUP_CONCURRENCY)

    async with AsyncClient(follow_redirects=True) as client:

        async def one(mid: str) -> None:
            async with semaphore:
                payload = await _fetch_public_details(
                    client, mid, timeout=LOOKUP_REQUEST_SECONDS, retries=0
                )
            rows = (payload or {}).get("0") if isinstance(payload, dict) else None
            match = rows[0] if isinstance(rows, list) and rows else None
            sid = str((match or {}).get("ID_sezon") or "").strip() if isinstance(match, dict) else ""
            _known[mid] = (sid, time.monotonic())
            if sid:
                out[mid] = sid

        tasks = [asyncio.ensure_future(one(mid)) for mid in ask]
        _done, pending = await asyncio.wait(tasks, timeout=budget)
        for task in pending:
            task.cancel()
        if pending:
            # Dokończyć anulowanie PRZED zamknięciem klienta, inaczej zadanie
            # budzi się na zamkniętym połączeniu.
            await asyncio.gather(*pending, return_exceptions=True)
    return out

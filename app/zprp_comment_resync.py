"""Jednorazowe uzupełnienie `comment` w portalu publicznym (zprp_public_matches).

Do poprawki dopisku `&ProEl=...` sync zapisywał puste uwagi meczów. To zadanie
po starcie przechodzi po meczach z pustym/NULL `comment`, pobiera szczegóły z
dopiskiem i aktualizuje rekord tą samą drogą co sync (`_sync_match_details`).

Postęp i znacznik końca: `beach_app_settings["zprp_comment_resync_v1"]` (JSON z
kursorem `last_id`), więc restart wznawia. Jedna instancja naraz: advisory lock
Postgresa. Mecz, który po pobraniu nadal nie ma uwag, to nie błąd - kursor
idzie dalej i nie wraca do niego.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, insert, or_, select, text, update

log = logging.getLogger("zprp_comment_resync")

STATE_KEY = "zprp_comment_resync_v1"
LOCK_ID = 7419077
BATCH = 200
LOG_EVERY = 100


async def load_state() -> Dict[str, Any]:
    from app.db import beach_app_settings, database

    row = await database.fetch_one(
        select(beach_app_settings.c.value).where(beach_app_settings.c.key == STATE_KEY)
    )
    try:
        data = json.loads(row["value"]) if row and row["value"] else {}
    except (TypeError, ValueError):
        data = {}
    return data if isinstance(data, dict) else {}


async def save_state(state: Dict[str, Any]) -> None:
    from app.db import beach_app_settings, database

    cond = beach_app_settings.c.key == STATE_KEY
    now = datetime.now(timezone.utc)
    value = json.dumps(state, ensure_ascii=False)
    if await database.fetch_one(select(beach_app_settings.c.key).where(cond)):
        await database.execute(update(beach_app_settings).where(cond).values(value=value, updated_at=now))
    else:
        await database.execute(insert(beach_app_settings).values(key=STATE_KEY, value=value, updated_at=now))


async def pick_batch(after_id: str, limit: int = BATCH) -> List[str]:
    """Kolejne match_id z pustym/NULL `comment`, rosnąco, za kursorem."""
    from app.db import database, zprp_public_matches as m

    rows = await database.fetch_all(
        select(m.c.match_id)
        .where(m.c.match_id > after_id)
        .where(or_(m.c.comment.is_(None), m.c.comment == ""))
        .order_by(m.c.match_id)
        .limit(limit)
    )
    return [str(r["match_id"]) for r in rows if r["match_id"]]


async def run_resync(*, pause: float = 0.4, fetch=None) -> Dict[str, Any]:
    """Jedno przejście. `fetch(client, match_id, counters)` podmienialne w testach."""
    state = await load_state()
    if state.get("done"):
        return state
    if fetch is None:
        # Importy bazy w funkcji (app.db łączy się przy imporcie).
        from app.zprp_public import sync as S

        fetch = S._sync_match_details
        counters: Any = S.Counters()
    else:
        counters = {}
    from app.zprp_public.client import PublicZprpClient

    client = PublicZprpClient(min_interval=pause, concurrency=1, retries=3)
    state.setdefault("last_id", "")
    for k in ("seen", "errors"):
        state.setdefault(k, 0)
    started = state["seen"]
    try:
        while True:
            ids = await pick_batch(state["last_id"])
            if not ids:
                break
            for mid in ids:
                for attempt in range(3):
                    try:
                        await fetch(client, mid, counters)
                        break
                    except Exception as exc:
                        if attempt == 2:
                            state["errors"] += 1
                            log.warning("[comment_resync] mecz %s: %s", mid, exc)
                        else:
                            await asyncio.sleep(2.0 * (attempt + 1))
                state["seen"] += 1
                state["last_id"] = mid
                if (state["seen"] - started) % LOG_EVERY == 0:
                    await save_state(state)
                    log.info("[comment_resync] postęp: %s meczów (błędy %s, kursor %s)",
                             state["seen"], state["errors"], mid)
        state["done"] = True
        state["finished_at"] = datetime.now(timezone.utc).isoformat()
        await save_state(state)
        log.info("[comment_resync] koniec: %s meczów, błędy %s", state["seen"], state["errors"])
    finally:
        await client.close()
    return state


async def run_comment_resync_once(startup_delay: float = 90.0) -> None:
    """Zadanie startowe: opóźnienie, lock instancji, przejście, brak wyjątków na zewnątrz."""
    try:
        await asyncio.sleep(startup_delay)
        from app.db import DATABASE_URL, database

        if (await load_state()).get("done"):
            return
        if str(DATABASE_URL).startswith("postgres"):
            async with database.connection() as conn:
                got = await conn.fetch_val(text("SELECT pg_try_advisory_lock(:k)").bindparams(k=LOCK_ID))
                if not got:
                    log.info("[comment_resync] inna instancja już pracuje")
                    return
                try:
                    await run_resync()
                finally:
                    await conn.execute(text("SELECT pg_advisory_unlock(:k)").bindparams(k=LOCK_ID))
        else:
            await run_resync()
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("[comment_resync] przerwane - wznowi się po restarcie")

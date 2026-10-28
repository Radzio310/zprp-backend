"""Trybuna: miniatury kaset Bastionu trzymane w magazynie BAZY (runda 2, 28.10.2026).

Connector robi klatkę (`POST /frame`: ~5 min meczu albo 10% długości) przez przeglądarkę z sesją połączenia, BAZA zapisuje ją
na stałe w magazynie nagrań pod kluczem `<prefiks>/trybuna/thumbs/<bunny_item_id>.jpg` (jedna klatka na kasetę, wspólna dla
wszystkich par). Zlecenie powstaje przy pierwszym pokazaniu kasety w wynikach (`attach`), robi je pętla w tle (kolejka w bazie,
jedna klatka naraz, ponowienia z odstępem). Do czasu wykonania `thumbnail_url` jest null, a `thumb_pending` = true. Adres w
odpowiedziach to stały, podpisany (HMAC) link do `GET /mentor-panel/trybuna/thumb/{id}.jpg`, który przekierowuje na krótko ważny
adres pliku - dzięki temu przeglądarka i aplikacja mogą go cache'ować i nie potrzebują logowania do obrazka.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import os
import tempfile
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Optional

from fastapi import APIRouter, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select, update

from app import mentor_bastion_rules as BR
from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app.db import database, mentor_trybuna_thumbs as TH

logger = logging.getLogger("app.mentor_panel")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor Trybuna"])

MAX_ATTEMPTS = 5
BACKOFF_S = 300
ENQUEUE_LIMIT = 12
IDLE_S = 20.0
_wake: Optional[asyncio.Event] = None


def sign(item: int) -> str:
    from app.mentor_panel_auth import _secret

    return hmac.new(_secret().encode(), f"thumb:{int(item)}".encode(), hashlib.sha256).hexdigest()[:20]


def thumb_url(item: int) -> str:
    """Stały adres (względem API) miniatury kasety; ważność = istnienie pliku."""
    return f"/mentor-panel/trybuna/thumb/{int(item)}.jpg?s={sign(item)}"


def storage_ok() -> bool:
    try:
        from app.mentor_panel_media import storage_ready

        return bool(storage_ready())
    except Exception:  # noqa: BLE001
        return False


def wake() -> None:
    if _wake is not None:
        _wake.set()


async def attach(real: Any, games: Iterable[Dict[str, Any]], limit: int = ENQUEUE_LIMIT) -> None:
    """Ustawia `thumbnail_url` (nasz plik, gdy gotowy) i `thumb_pending`; brakujące klatki kolejkuje. Nigdy nie rzuca."""
    try:
        targets = {int(g["bunny_item_id"]): g for g in games if isinstance(g, dict) and g.get("bunny_item_id")}
        if not targets:
            return
        found = {int(r["bunny_item_id"]): r for r in await C.rows(select(TH).where(TH.c.bunny_item_id.in_(list(targets))))}
        flags = BR.load_flags()
        can_make = bool(flags.enabled and flags.configured and storage_ok())
        queued = 0
        for item, game in targets.items():
            row = found.get(item)
            game.setdefault("thumb_pending", False)
            if row and row.get("status") == "ready" and row.get("storage_key"):
                game["thumbnail_url"], game["thumb_pending"] = thumb_url(item), False
                game["duration_s"] = game.get("duration_s") or row.get("duration_s")
            elif game.get("thumbnail_url"):
                game["thumb_pending"] = False  # miniatura z game-context wystarcza
            elif row and row.get("status") == "failed":
                game["thumb_pending"] = False
            elif can_make:
                if row is None and queued < limit:
                    try:
                        await database.execute(TH.insert().values(bunny_item_id=item, status="pending", attempts=0,
                                                                  requested_by=R_s(getattr(real, "judge_id", "")), updated_at=C.now()))
                        queued += 1
                    except Exception:  # noqa: BLE001 - wyścig: ktoś już zakolejkował
                        pass
                game["thumb_pending"] = True
        if queued:
            wake()
    except Exception:  # noqa: BLE001
        logger.warning("trybuna: miniatury kaset (kolejka) nieudane", exc_info=True)


def R_s(value: Any) -> str:
    return "" if value is None else str(value).strip()


def pick_scopes(flags: BR.Flags, requested_by: str):
    """(scope, judge_id) do zrobienia klatki: połączenie domyślne, potem osobiste zlecającego."""
    out = []
    for scope in BR.candidate_scopes(flags):
        if scope == "personal":
            if requested_by:
                out.append((scope, requested_by))
        else:
            out.append((scope, None))
    return out


async def make_one(row: Dict[str, Any]) -> bool:
    """Jedna klatka: connector -> plik -> magazyn. True = gotowa (albo trwale nieudana), False = spróbować później."""
    from app import mentor_bastion_client as CL
    from app import mentor_panel_media as M
    from app.mentor_bastion import _client

    item = int(row["bunny_item_id"])
    flags = BR.load_flags()
    if not flags.enabled or not flags.configured or not M.storage_ready():
        return False
    client = _client()
    error = "BASTION_AUTH_REQUIRED"
    body: Optional[Dict[str, Any]] = None
    for scope, judge in pick_scopes(flags, R_s(row.get("requested_by"))):
        try:
            reply = await client.request("POST", "/frame", json={"scope": scope, "judge_id": judge, "bunny_item_id": item}, timeout=80.0)
        except CL.ConnectorUnavailable:
            error = "BASTION_UNAVAILABLE"
            break
        if reply.status == 200 and isinstance(reply.body.get("jpeg_b64"), str):
            body = reply.body
            break
        error = R_s(reply.body.get("code") or reply.body.get("error")) or f"HTTP {reply.status}"
        if reply.status in (429, 503):
            break
    attempts = int(row.get("attempts") or 0) + 1
    if body is None:
        failed = attempts >= MAX_ATTEMPTS
        await database.execute(update(TH).where(TH.c.bunny_item_id == item).values(
            status="failed" if failed else "pending", attempts=attempts, error=error[:200], updated_at=C.now(),
            next_attempt_at=C.now() + timedelta(seconds=BACKOFF_S * (2 ** min(attempts, 5)))))
        return failed
    key = M.object_key("trybuna", "thumbs", f"{item}.jpg")
    fd, path = tempfile.mkstemp(suffix=".jpg")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(base64.b64decode(body["jpeg_b64"]))
        await asyncio.to_thread(M.put_file, path, key, "image/jpeg")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    await database.execute(update(TH).where(TH.c.bunny_item_id == item).values(
        status="ready", storage_key=key, attempts=attempts, error=None, duration_s=body.get("duration_s"), updated_at=C.now()))
    return True


async def run_once() -> bool:
    now = C.now()
    rows = await C.rows(select(TH).where(TH.c.status == "pending").order_by(TH.c.updated_at.asc()).limit(10))
    row = next((r for r in rows if r.get("next_attempt_at") is None or R.aware(r["next_attempt_at"]) <= now), None)
    if row is None:
        return False
    claimed = await database.fetch_one(update(TH).where(TH.c.bunny_item_id == row["bunny_item_id"]).where(TH.c.status == "pending")
                                       .values(status="working", updated_at=now).returning(TH.c.bunny_item_id))
    if claimed is None:
        return True
    try:
        done = await make_one(row)
    except Exception:  # noqa: BLE001
        logger.warning("trybuna: klatka kasety %s nieudana", row["bunny_item_id"], exc_info=True)
        await database.execute(update(TH).where(TH.c.bunny_item_id == row["bunny_item_id"]).values(
            status="pending", attempts=int(row.get("attempts") or 0) + 1, updated_at=C.now(),
            next_attempt_at=C.now() + timedelta(seconds=BACKOFF_S)))
        return True
    if not done:
        await database.execute(update(TH).where(TH.c.bunny_item_id == row["bunny_item_id"]).where(TH.c.status == "working")
                               .values(status="pending", next_attempt_at=C.now() + timedelta(seconds=BACKOFF_S), updated_at=C.now()))
    return True


async def run_thumb_worker() -> None:
    """Pętla w tle (jedna klatka naraz): budzi ją nowe zlecenie, inaczej sprawdza co 20 s."""
    global _wake
    if _wake is None:
        _wake = asyncio.Event()
    await asyncio.sleep(40)
    while True:
        try:
            busy = await run_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("trybuna: pętla miniatur")
            busy = False
        if not busy:
            try:
                await asyncio.wait_for(_wake.wait(), IDLE_S)
            except asyncio.TimeoutError:
                pass
            _wake.clear()
        else:
            await asyncio.sleep(1.0)


@router.get("/trybuna/thumb/{item}.jpg")
async def thumb(item: int, s: str = ""):
    """Stały adres miniatury: podpis w `s`, przekierowanie na krótko ważny adres pliku. Bez logowania (obrazek w `<img>`)."""
    from app import mentor_panel_media as M

    if not hmac.compare_digest(R_s(s), sign(item)):
        return Response(status_code=404)
    row = await C.one(select(TH).where(TH.c.bunny_item_id == item))
    url = M.presign_get(row.get("storage_key"), 3600) if row and row.get("status") == "ready" else None
    if not url:
        return Response(status_code=404)
    return RedirectResponse(url, status_code=302, headers={"Cache-Control": "public, max-age=1800"})

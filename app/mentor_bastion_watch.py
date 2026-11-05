"""Bastion: podtrzymywanie sesji i powiadomienie o rozłączeniu (decyzja właściciela 05.11.2026).

Wniosek z 3-5.11: połączenie domyślne zalogowane 3.11 było rozłączone 5.11, choć ciasteczko portalu ma
termin +7 dni - sesja po stronie Bastionu gaśnie wcześniej (najpewniej bez ruchu). Dlatego:
  - co `BASTION_KEEPALIVE_SECONDS` (domyślnie 3 h) serwer czyta każde zapamiętane połączenie (game-context
    bez embedu). Odczyt odświeża ciasteczka (connector zapisuje rotację), a wygasłą sesję connector próbuje
    po cichu odnowić zapamiętaną sesją Discorda (`bastion_connector`, `renew`);
  - przejście `ready -> reauth_required` (z dowolnego odczytu, nie tylko stąd) wysyła JEDEN push:
    połączenie osobiste - właścicielowi, domyślne - administratorom. Stuknięcie otwiera połączenie z Bastionem
    w panelu Mentora (`target=bastion`).
Pętla nie zmienia niczego przy awarii connectora (awaria to nie dowód wygaśnięcia sesji).
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Mapping

from sqlalchemy import select

logger = logging.getLogger("app.mentor_bastion_watch")

KEEPALIVE_S = 3 * 3600
FIRST_RUN_S = 600
#: Odstęp między połączeniami w jednym przebiegu (connector i portal bez serii).
STAGGER_S = 5.0


def keepalive_interval() -> float:
    try:
        return float(os.environ.get("BASTION_KEEPALIVE_SECONDS", KEEPALIVE_S))
    except ValueError:
        return float(KEEPALIVE_S)


def push_text(scope: str) -> tuple[str, str]:
    if scope == "default":
        return ("Bastion: połączenie domyślne wygasło",
                "Nagrania z Bastionu czekają na ponowne połączenie. Stuknij, aby zalogować się jeszcze raz.")
    return ("Bastion się rozłączył", "Twoje konto Bastionu wymaga ponownego logowania. Stuknij - zajmie to chwilę.")


async def _admins() -> list[str]:
    from app.db import admin_settings, database

    row = await database.fetch_one(select(admin_settings).limit(1))
    return [str(a).strip() for a in ((row["allowed_admins"] if row else None) or []) if str(a).strip()]


async def notify_disconnected(row: Mapping[str, Any]) -> None:
    """Jeden push o rozłączeniu (tag zwija powtórki w jedno powiadomienie na urządzeniu)."""
    try:
        from app.mentor_panel_notify import PREFERENCE_KEY, push_data
        from app.push.push import send_push_to_judges_report

        scope = str(row.get("scope") or "personal")
        owner = str(row.get("owner_judge_id") or "")
        judges = await _admins() if scope == "default" else ([owner] if owner else [])
        if not judges:
            return
        title, body = push_text(scope)
        data = push_data("", target="bastion", tag=f"mentor-bastion-{row.get('connection_key') or scope}", extra={"scope": scope})
        await send_push_to_judges_report(judges, title, body, data, app_variant="baza", preference_key=PREFERENCE_KEY)
    except Exception:  # noqa: BLE001 - push to grzeczność, nie może psuć zapisu stanu
        logger.warning("bastion: push o rozłączeniu nieudany", exc_info=True)


async def keepalive_once() -> int:
    """Jeden przebieg: każde połączenie z sesją (ready) i każde czekające na odnowę (reauth_required)."""
    from app import mentor_bastion as MB
    from app import mentor_bastion_client as CL
    from app import mentor_bastion_rules as BR
    from app.db import database, mentor_bastion_connections as CONN

    flags = BR.load_flags()
    if not flags.enabled or not flags.configured:
        return 0
    try:
        client = CL.get_client()
    except CL.ConnectorUnavailable:
        return 0
    rows = await database.fetch_all(select(CONN).where(CONN.c.status.in_(("ready", "reauth_required"))))
    done = 0
    for raw in rows:
        row = dict(raw)
        scope = str(row["scope"])
        owner = row.get("owner_judge_id")
        if not flags.scope_on(scope):
            continue
        try:
            if flags.probe_bunny_item_id:
                reply = await client.playback(scope, owner, flags.probe_bunny_item_id, include_embed=False)
                verdict = BR.classify_playback(reply.status, reply.body)
                if verdict.kind in ("ok", "forbidden", "auth_required"):
                    await MB.apply_verdict(scope, owner, verdict)
            await MB.sync_connection(client, scope, owner, fresh=True)
            done += 1
        except CL.ConnectorUnavailable:
            logger.info("bastion: connector niedostępny, podtrzymanie przerwane")
            break
        except Exception:  # noqa: BLE001
            logger.warning("bastion: podtrzymanie %s nieudane", row.get("connection_key"), exc_info=True)
        await asyncio.sleep(STAGGER_S)
    return done


async def run_bastion_keepalive() -> None:
    """Pętla w tle (start z main.py). `BASTION_KEEPALIVE_SECONDS=0` wyłącza."""
    interval = keepalive_interval()
    if interval <= 0:
        return
    await asyncio.sleep(FIRST_RUN_S)
    while True:
        try:
            n = await keepalive_once()
            if n:
                logger.info("bastion: podtrzymano %s połączeń", n)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.warning("bastion: przebieg podtrzymania nieudany", exc_info=True)
        await asyncio.sleep(interval)

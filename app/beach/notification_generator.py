"""
Beach Notification Generator — periodic task that creates time-based notifications.

Runs every 5 minutes. Currently handles:
  - tournament_reminder_24h:      tournament starts in ~24h  (for participants)
  - tournament_reminder_5h:       tournament starts in ~5h   (for participants)
  - tournament_reminder_general:  tournament starts in ~5h   (for NON-participants)

Deduplicated per (type, user_id, tournament_id, day).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select

from app.db import database, beach_tournaments, beach_users, beach_notifications
from app.beach.notifications import create_notification

logger = logging.getLogger(__name__)


def _normalize_event_data(data_json: Any) -> Dict[str, Any]:
    """Extract invited_ids from tournament data_json (local copy to avoid circular import)."""
    if data_json is None:
        return {}
    if isinstance(data_json, dict):
        base = data_json
    else:
        try:
            base = json.loads(data_json)
        except Exception:
            return {}
    invited_ids = base.get("invited_ids") or []
    if not isinstance(invited_ids, list):
        invited_ids = []
    return {"invited_ids": [str(x).strip() for x in invited_ids if str(x).strip()]}


async def _get_existing_notif_keys(notif_type: str, day_str: str) -> set:
    """Get set of (type, tournament_id) keys already generated today to avoid dupes."""
    rows = await database.fetch_all(
        select(beach_notifications.c.type, beach_notifications.c.data_json)
        .where(beach_notifications.c.type == notif_type)
        .where(beach_notifications.c.created_at >= datetime.fromisoformat(f"{day_str}T00:00:00+00:00"))
    )
    keys = set()
    for r in rows:
        data = r["data_json"] or {}
        tid = data.get("tournament_id")
        if tid is not None:
            keys.add((notif_type, tid))
    return keys


def _normalize_event_data(raw: Any) -> dict:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return {}


async def _generate_tournament_reminders():
    """Generate participant reminders (24h, 5h) and general reminders (5h for non-participants)."""
    now = datetime.now(timezone.utc)
    day_str = now.strftime("%Y-%m-%d")

    # Load existing keys to avoid duplicates
    existing_24h = await _get_existing_notif_keys("tournament_reminder_24h", day_str)
    existing_5h = await _get_existing_notif_keys("tournament_reminder_5h", day_str)
    existing_general = await _get_existing_notif_keys("tournament_reminder_general", day_str)

    # Fetch tournaments in the next 25h window
    window_start = now + timedelta(hours=4)
    window_end = now + timedelta(hours=25)

    rows = await database.fetch_all(
        select(beach_tournaments)
        .where(beach_tournaments.c.event_date >= window_start)
        .where(beach_tournaments.c.event_date <= window_end)
    )

    # Load all active users once (used for general reminder)
    all_active_users = await database.fetch_all(
        select(beach_users.c.id).where(beach_users.c.is_active == True)  # noqa: E712
    )
    all_active_ids = {int(r["id"]) for r in all_active_users}

    for r in rows:
        r_d = dict(r)
        tid = r_d["id"]
        event_date = r_d["event_date"]
        if not event_date:
            continue

        if event_date.tzinfo is None:
            event_date = event_date.replace(tzinfo=timezone.utc)

        delta = (event_date - now).total_seconds() / 3600  # hours until event

        data = _normalize_event_data(r_d["data_json"])
        invited = data.get("invited_ids") or []
        target_ids = [int(uid) for uid in invited if uid is not None]

        tour_name = r_d.get("name", "Turniej")

        # ── Participant reminders ──────────────────────────────
        if target_ids:
            # 24h reminder: 22-25h before event
            if 22 <= delta <= 25 and ("tournament_reminder_24h", tid) not in existing_24h:
                await create_notification(
                    notif_type="tournament_reminder_24h",
                    title="Turniej jutro!",
                    body=f"{tour_name} — startuje za ok. 24h",
                    data={"tournament_id": tid},
                    target_user_ids=target_ids,
                )
                logger.info(f"🔔 tournament_reminder_24h for tournament #{tid}")

            # 5h reminder: 4-6h before event
            if 4 <= delta <= 6 and ("tournament_reminder_5h", tid) not in existing_5h:
                await create_notification(
                    notif_type="tournament_reminder_5h",
                    title="Turniej dziś!",
                    body=f"{tour_name} — startuje za ok. 5h",
                    data={"tournament_id": tid},
                    target_user_ids=target_ids,
                )
                logger.info(f"🔔 tournament_reminder_5h for tournament #{tid}")

        # ── General reminder (non-participants, 4-6h window) ──
        if 4 <= delta <= 6 and ("tournament_reminder_general", tid) not in existing_general:
            invited_set = {int(uid) for uid in invited if uid is not None}
            non_participant_ids = list(all_active_ids - invited_set)
            if non_participant_ids:
                await create_notification(
                    notif_type="tournament_reminder_general",
                    title="Zbliżający się turniej",
                    body=f"{tour_name} — startuje za ok. 5h",
                    data={"tournament_id": tid},
                    target_user_ids=non_participant_ids,
                )
                logger.info(
                    f"🔔 tournament_reminder_general for tournament #{tid} "
                    f"({len(non_participant_ids)} non-participants)"
                )


async def run_notification_generator():
    """Main loop — runs every 5 minutes."""
    interval = 5 * 60  # 5 minutes

    while True:
        try:
            await _generate_tournament_reminders()
        except Exception as e:
            logger.error(f"notification_generator error: {e}")

        await asyncio.sleep(interval)

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


def _get_effective_start_dt(data: dict, event_date: datetime) -> datetime:
    """Return the effective tournament start datetime for 24h reminder scheduling.

    Priority:
    1. startTime of the earliest match on day 0 from the generated schedule
       (interpreted as Polish local time: CEST=UTC+2 in summer, CET=UTC+1 in winter)
    2. Fallback: event_date date at 08:00 UTC (≈09/10 AM Polish time)
    """
    schedule = data.get("schedule") or {}
    matches = schedule.get("matches") or []
    config = schedule.get("config") or {}
    days_cfg = config.get("days") or []

    day0_matches = [
        m for m in matches
        if (m.get("dayIndex") or 0) == 0 and m.get("startTime")
    ]

    if day0_matches and days_cfg:
        day0_matches.sort(key=lambda m: m.get("startTime", "99:99"))
        first_time_str = day0_matches[0].get("startTime", "")
        day0_date_str = days_cfg[0].get("date") if days_cfg else None

        if day0_date_str and first_time_str and ":" in first_time_str:
            try:
                hh, mm = first_time_str.split(":")
                month = int(day0_date_str[5:7])
                utc_offset = 2 if 3 <= month <= 10 else 1  # CEST vs CET
                tz = timezone(timedelta(hours=utc_offset))
                naive = datetime(
                    int(day0_date_str[:4]),
                    int(day0_date_str[5:7]),
                    int(day0_date_str[8:10]),
                    int(hh),
                    int(mm),
                )
                return naive.replace(tzinfo=tz).astimezone(timezone.utc)
            except Exception:
                pass

    # Fallback: event_date date at 08:00 UTC
    d = event_date.date()
    return datetime(d.year, d.month, d.day, 8, 0, 0, tzinfo=timezone.utc)


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

        data = _normalize_event_data(r_d["data_json"])
        invited = data.get("invited_ids") or []
        target_ids = [int(uid) for uid in invited if uid is not None]

        effective_start_dt = _get_effective_start_dt(data, event_date)
        delta = (effective_start_dt - now).total_seconds() / 3600  # hours until effective start

        tour_name = r_d.get("name", "Turniej")
        location = (r_d.get("location") or "").strip().split("|", 1)[0].strip()
        category = (r_d.get("category") or "").strip()
        competition_type = (r_d.get("competition_type") or "").strip()

        # Build compact detail line: "Kategoria · Miejsce" or "Kategoria" or "Miejsce"
        detail_parts = [p for p in [category, competition_type] if p]
        detail_line = " · ".join(detail_parts)
        if location:
            detail_line = f"{detail_line} · 📍 {location}" if detail_line else f"📍 {location}"

        # ── Participant reminders ──────────────────────────────
        if target_ids:
            # 24h reminder: 22-25h before event
            if 22 <= delta <= 25 and ("tournament_reminder_24h", tid) not in existing_24h:
                body_24h = f"Jutro grasz! {tour_name}"
                if detail_line:
                    body_24h += f"\n{detail_line}"
                await create_notification(
                    notif_type="tournament_reminder_24h",
                    title="⏰ Turniej jutro!",
                    body=body_24h,
                    data={"tournament_id": tid},
                    target_user_ids=target_ids,
                )
                logger.info(f"🔔 tournament_reminder_24h for tournament #{tid}")

            # 5h reminder: 4-6h before event
            if 4 <= delta <= 6 and ("tournament_reminder_5h", tid) not in existing_5h:
                body_5h = f"Startuje za ok. 5h — {tour_name}"
                if detail_line:
                    body_5h += f"\n{detail_line}"
                await create_notification(
                    notif_type="tournament_reminder_5h",
                    title="🏖️ Turniej dziś — za 5h!",
                    body=body_5h,
                    data={"tournament_id": tid},
                    target_user_ids=target_ids,
                )
                logger.info(f"🔔 tournament_reminder_5h for tournament #{tid}")

        # ── General reminder (non-participants, 4-6h window) ──
        if 4 <= delta <= 6 and ("tournament_reminder_general", tid) not in existing_general:
            invited_set = {int(uid) for uid in invited if uid is not None}
            non_participant_ids = list(all_active_ids - invited_set)
            if non_participant_ids:
                body_gen = f"Dziś startuje: {tour_name}"
                if detail_line:
                    body_gen += f"\n{detail_line}"
                await create_notification(
                    notif_type="tournament_reminder_general",
                    title="🏐 Turniej w toku",
                    body=body_gen,
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

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import (
    database,
    province_match_events,
    province_match_notifications,
    push_tokens,
)
from app.province_match_monitor import notification_title
from app.push.scheduler import wake_push_scheduler


logger = logging.getLogger("app.push.deploy_test_notifications")

TEST_MATCH_CODE = "TEST/5124/2026"
TEST_MESSAGES: List[Dict[str, str]] = [
    {
        "event_type": "match_added",
        "body": (
            f"Dodano nowy mecz {TEST_MATCH_CODE} • SPR Górnik Zabrze – "
            "KS Azoty-Puławy • 09.08.2026, 18:00 • Hala Pogoń, Zabrze"
        ),
    },
    {
        "event_type": "match_date_changed",
        "body": f"Zmieniono datę meczu {TEST_MATCH_CODE} na 09.08.2026, 19:30",
    },
    {
        "event_type": "lineup_changed",
        "body": (
            f"Zmieniono sędziów głównych w meczu {TEST_MATCH_CODE}: "
            "Jan Kowalski, Piotr Nowak"
        ),
    },
    {
        "event_type": "match_data_changed",
        "body": (
            f"Zmieniono adres hali w meczu {TEST_MATCH_CODE} na "
            "Hala Pogoń, Zabrze, ul. Wolności 406"
        ),
    },
    {
        "event_type": "assignment_removed",
        "body": f"Usunięto Twój mecz {TEST_MATCH_CODE}",
    },
]


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def _event_key(batch_key: str, judge_id: str, position: int) -> str:
    raw = f"deploy-push-test|{batch_key}|{judge_id}|{position}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def _registered_devices(judge_id: str):
    return await database.fetch_all(
        select(push_tokens.c.installation_id)
        .where(push_tokens.c.judge_id == judge_id)
        .where(push_tokens.c.app_variant == "baza")
        .where(push_tokens.c.token_type == "device_fcm")
    )


async def run_deploy_test_notifications() -> None:
    """Kolejkuje raz pięć realistycznych alertów po starcie wskazanego wdrożenia.

    PUSH_DEPLOY_TEST_BATCH_KEY jest trwałym kluczem idempotencji. Ten sam klucz
    nie wyśle paczki ponownie po restarcie procesu ani na drugiej replice.
    """
    batch_key = os.getenv("PUSH_DEPLOY_TEST_BATCH_KEY", "").strip()
    if not batch_key:
        return

    judge_id = os.getenv("PUSH_DEPLOY_TEST_JUDGE_ID", "5124").strip() or "5124"
    marker_key = _event_key(batch_key, judge_id, 0)
    already_queued = await database.fetch_val(
        select(province_match_events.c.id).where(
            province_match_events.c.event_key == marker_key
        )
    )
    if already_queued:
        logger.info(
            "Deploy push test batch %s for judge %s was already queued; skipping",
            batch_key,
            judge_id,
        )
        return

    wait_seconds = _env_int("PUSH_DEPLOY_TEST_WAIT_SECONDS", 1800, 0, 86400)
    poll_seconds = min(10, max(1, wait_seconds or 1))
    deadline = asyncio.get_running_loop().time() + wait_seconds
    devices = await _registered_devices(judge_id)
    while not devices and asyncio.get_running_loop().time() < deadline:
        await asyncio.sleep(poll_seconds)
        devices = await _registered_devices(judge_id)

    if not devices:
        logger.warning(
            "Deploy push test batch %s not queued: judge %s has no BAZA device_fcm token",
            batch_key,
            judge_id,
        )
        return

    interval_seconds = _env_int("PUSH_DEPLOY_TEST_INTERVAL_SECONDS", 10, 1, 3600)
    now = datetime.now(timezone.utc)
    deployment_id = os.getenv("RAILWAY_DEPLOYMENT_ID", "local")
    installation_ids = sorted({str(row["installation_id"]) for row in devices})

    # Jedna transakcja zapobiega pozostawieniu niepełnej paczki po restarcie.
    # Konflikty są ignorowane, więc kilka replik nadal utworzy tylko jeden zestaw.
    async with database.transaction():
        for position, message in enumerate(TEST_MESSAGES):
            event_type = message["event_type"]
            event_key = _event_key(batch_key, judge_id, position)
            data = {
                "kind": "province_match_change",
                "event_type": event_type,
                "province": "TEST",
                "match_id": f"deploy-test:{batch_key}",
                "matchNumber": TEST_MATCH_CODE,
                "event_key": event_key,
                "is_test": "true",
                "test_batch_key": batch_key,
                "railway_deployment_id": deployment_id,
            }
            title = notification_title(event_type)
            event_id = await database.fetch_val(
                pg_insert(province_match_events)
                .values(
                    event_key=event_key,
                    province="TEST",
                    match_id=f"deploy-test:{batch_key}",
                    match_code=TEST_MATCH_CODE,
                    event_type=event_type,
                    title=title,
                    body=message["body"],
                    data_json=data,
                    target_judge_ids=[judge_id],
                )
                .on_conflict_do_nothing(
                    index_elements=[province_match_events.c.event_key]
                )
                .returning(province_match_events.c.id)
            )
            if not event_id:
                event_id = await database.fetch_val(
                    select(province_match_events.c.id).where(
                        province_match_events.c.event_key == event_key
                    )
                )
            if not event_id:
                raise RuntimeError(f"Could not persist deploy push test event {position}")

            send_at = now + timedelta(seconds=1 + position * interval_seconds)
            for installation_id in installation_ids:
                await database.execute(
                    pg_insert(province_match_notifications)
                    .values(
                        event_id=int(event_id),
                        installation_id=installation_id,
                        judge_id=judge_id,
                        title=title,
                        body=message["body"],
                        data_json=data,
                        send_at_utc=send_at,
                        status="pending",
                    )
                    .on_conflict_do_nothing(
                        constraint="uq_province_match_notification_event_installation"
                    )
                )

    wake_push_scheduler()
    logger.info(
        "Queued deploy push test batch %s: %d notifications x %d device(s), interval=%ds",
        batch_key,
        len(TEST_MESSAGES),
        len(installation_ids),
        interval_seconds,
    )

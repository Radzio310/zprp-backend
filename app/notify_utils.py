# app/notify_utils.py
import logging
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import delete, insert, select

from app.db import database, login_records, push_schedules

logger = logging.getLogger(__name__)


def norm_province(s: str) -> str:
    """Normalizacja TYLKO do porównywania – polskie litery nigdy nie trafiają do payloadu."""
    t = unicodedata.normalize("NFD", (s or "").upper().strip())
    return "".join(c for c in t if unicodedata.category(c) != "Mn")


def _send_hour_utc(dt: datetime) -> int:
    return int(dt.timestamp() // 3600)


async def schedule_province_push(
    province: str,
    title: str,
    body: str,
    data: Optional[Dict[str, Any]] = None,
    seconds_from_now: int = 60,
    preference_key: Optional[str] = None,
) -> dict:
    """
    Planuje push do wszystkich urządzeń z danego województwa.
    province jest przekazywane do payloadu bez zmian (pełne polskie litery),
    normalizacja służy wyłącznie do filtrowania login_records.
    """
    now = datetime.now(timezone.utc)
    dt_utc = datetime.fromtimestamp(now.timestamp() + max(1, seconds_from_now), tz=timezone.utc)
    hour = _send_hour_utc(dt_utc)
    province_norm = norm_province(province)

    rows = await database.fetch_all(
        select(
            login_records.c.judge_id,
            login_records.c.province,
            login_records.c.config_json,
        )
    )

    installation_ids: set[str] = set()
    for row in rows:
        if norm_province(row["province"] or "") != province_norm:
            continue
        config = row["config_json"] or {}
        devices = config.get("devices") if isinstance(config, dict) else None
        if not devices or not isinstance(devices, dict):
            continue
        for device_key, device_payload in devices.items():
            payload_installation_id = ""
            if isinstance(device_payload, dict):
                payload_installation_id = str(
                    device_payload.get("installation_id") or ""
                ).strip()

            if payload_installation_id:
                installation_ids.add(payload_installation_id)
                continue

            # Backward compatibility: jeżeli starszy zapis trzymał installation_id
            # jako klucz, zaakceptuj go tylko gdy wygląda jak prawdziwe ID instalacji.
            legacy_installation_id = str(device_key or "").strip()
            if legacy_installation_id.startswith("ins_"):
                installation_ids.add(legacy_installation_id)

    muted = 0
    if preference_key and installation_ids:
        # Przełącznik z ustawień telefonu (np. „Ogłoszenia okręgu"): urządzenie,
        # które go wyłączyło, wypada z wysyłki. Brak klucza = zgoda.
        installation_ids, muted = await _without_muted(installation_ids, preference_key)

    targeted = len(installation_ids)
    ok = 0
    failed = 0

    push_data = {
        **(data or {}),
        "province": province,           # oryginalne polskie litery
        "planned_from": "backend_announcement",
    }

    for installation_id in installation_ids:
        try:
            # Deduplikacja: max 1 push / godzina / installation_id (jak w /push/schedule/bulk)
            await database.execute(
                delete(push_schedules).where(
                    (push_schedules.c.installation_id == installation_id)
                    & (push_schedules.c.send_hour_utc == hour)
                    & (push_schedules.c.status == "pending")
                )
            )
            await database.execute(
                insert(push_schedules).values(
                    installation_id=installation_id,
                    send_at_utc=dt_utc,
                    send_hour_utc=hour,
                    title=title,
                    body=body,
                    data_json=push_data,
                    status="pending",
                    attempts=0,
                    last_error=None,
                    created_at=now,
                    updated_at=now,
                )
            )
            ok += 1
        except Exception as e:
            logger.warning(
                "[notify_utils] failed for installation_id=%s: %s",
                installation_id,
                e,
            )
            failed += 1

    logger.info(
        "[notify_utils] province=%r (norm=%r) targeted=%d ok=%d failed=%d muted=%d",
        province,
        province_norm,
        targeted,
        ok,
        failed,
        muted,
    )
    return {"targeted": targeted, "ok": ok, "failed": failed, "muted": muted}


async def _without_muted(installation_ids: set, preference_key: str) -> "tuple[set, int]":
    """Instalacje bez wyłączonego przełącznika `preference_key` (push_tokens.notification_prefs)."""
    from app.db import push_tokens
    from app.push.preferences import notification_type_allowed

    try:
        rows = await database.fetch_all(
            select(push_tokens.c.installation_id, push_tokens.c.notification_prefs).where(
                push_tokens.c.installation_id.in_(sorted(installation_ids))
            )
        )
    except Exception:  # noqa: BLE001 - bez preferencji wysyłamy jak dotąd
        logger.warning("[notify_utils] odczyt preferencji nieudany", exc_info=True)
        return installation_ids, 0
    muted = {
        str(r["installation_id"])
        for r in rows
        if not notification_type_allowed(r["notification_prefs"], preference_key)
    }
    return {i for i in installation_ids if i not in muted}, len(muted & installation_ids)

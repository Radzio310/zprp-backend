"""Jedna polityka wyboru buildu dla wszystkich zewnętrznych pushy BAZY."""
from __future__ import annotations

from typing import Any, Mapping

DEV_APP_SUFFIX = ".dev"


def is_dev_device(row: Mapping[str, Any] | Any | None) -> bool:
    """DEV poznajemy po applicationId, nigdy po `app_variant`.

    Pusty `app_id` oznacza starsze wydanie sklepowe. Takie urządzenia muszą
    nadal dostawać powiadomienia po wdrożeniu tej funkcji.
    """
    if not row:
        return False
    try:
        value = row["app_id"]
    except (KeyError, TypeError):
        value = getattr(row, "app_id", None)
    return str(value or "").strip().lower().endswith(DEV_APP_SUFFIX)


async def dev_pushes_enabled() -> bool:
    try:
        from sqlalchemy import select
        from app.db import admin_settings, database

        row = await database.fetch_one(
            select(admin_settings.c.allow_dev_pushes).where(admin_settings.c.id == 1)
        )
        return bool(row and row["allow_dev_pushes"])
    except Exception:
        # Awaria odczytu polityki nie może przypadkiem włączyć dublowania na DEV.
        return False


def device_allowed(row: Mapping[str, Any] | Any | None, allow_dev: bool) -> bool:
    return allow_dev or not is_dev_device(row)

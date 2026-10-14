"""Minimalne alerty Discord dla publicznej hurtowni ZPRP.

Webhook jest wyłącznie sekretem środowiskowym. Alert nie zawiera treści
wyjątków, danych źródłowych, URL-a webhooka ani treści odpowiedzi Discorda.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx

from app.extra_report_discord import normalize_webhook_url

log = logging.getLogger(__name__)
_last_delivery: dict[str, float] = {}
_failed_kinds: set[str] = set()


def webhook_configured() -> bool:
    return bool(os.getenv("POD_REKA_DISCORD_WEBHOOK_URL", "").strip())


def alert_payload(
    *, kind: str, run_id: int | str, error_count: int, recovered: bool = False,
) -> dict[str, Any]:
    return {
        "username": "BAZA pod RĘKĄ",
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": "✅ Synchronizacja wróciła do normy" if recovered else "🚨 Problem synchronizacji danych",
            "description": (
                "Kolejny przebieg zakończył się poprawnie."
                if recovered
                else "Publiczna hurtownia zachowała poprzednie poprawne dane. Szczegóły są w Centrum dowodzenia."
            ),
            "color": 0x2EAF72 if recovered else 0xD94B55,
            "fields": [
                {"name": "Proces", "value": kind[:128], "inline": True},
                {"name": "Przebieg", "value": str(run_id)[:128], "inline": True},
                {"name": "Liczba błędów", "value": str(max(0, error_count)), "inline": True},
            ],
            "footer": {"text": "BAZA pod RĘKĄ • monitoring zprp-backend"},
        }],
    }


async def _deliver(*, fingerprint: str, payload: dict[str, Any], force: bool = False) -> bool:
    raw = os.getenv("POD_REKA_DISCORD_WEBHOOK_URL", "")
    if not raw.strip():
        return False
    try:
        url = normalize_webhook_url(raw)
    except ValueError:
        log.error("[zprp_public] nieprawidłowa konfiguracja webhooka Discord")
        return False
    now = time.monotonic()
    window = max(60, int(os.getenv("POD_REKA_DISCORD_DEDUP_SECONDS", "1800")))
    if not force and now - _last_delivery.get(fingerprint, 0.0) < window:
        return False
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
            response = await client.post(url, json=payload, headers={"User-Agent": "BAZA-Pod-Reka/1.0"})
        if response.status_code < 200 or response.status_code >= 300:
            log.warning("[zprp_public] Discord odrzucił alert (HTTP %s)", response.status_code)
            return False
    except Exception:
        log.warning("[zprp_public] nie potwierdzono dostarczenia alertu Discord")
        return False
    _last_delivery[fingerprint] = now
    return True


async def notify_failure(kind: str, run_id: int | str, error_count: int) -> bool:
    sent = await _deliver(
        fingerprint=f"failure:{kind}",
        payload=alert_payload(kind=kind, run_id=run_id, error_count=error_count),
    )
    _failed_kinds.add(kind)
    return sent


async def notify_recovery(kind: str, run_id: int | str) -> bool:
    if kind not in _failed_kinds:
        return False
    sent = await _deliver(
        fingerprint=f"recovery:{kind}",
        payload=alert_payload(kind=kind, run_id=run_id, error_count=0, recovered=True),
        force=True,
    )
    if sent:
        _failed_kinds.discard(kind)
    return sent

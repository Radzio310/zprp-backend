"""Lekki klient publicznego API ZPRP z ograniczeniem obciążenia i prywatności."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from typing import Any

from httpx import AsyncClient

from app.archive_rules import decode_api_bytes

API_BASE = "https://rozgrywki.zprp.pl/api/"
TRANSIENT_STATUSES = {408, 425, 429, 500, 502, 503, 504}

# Pełna data urodzenia i status badań nie mogą trafić ani do tabel właściwych,
# ani do skompresowanych migawek. Rok jest wyliczany osobno przez synchronizator.
PRIVATE_KEYS = {
    "dataur",
    "data_ur",
    "birth_date",
    "date_of_birth",
    "badania_zprp",
    "badania_wzpr",
    "medical",
    "medical_status",
}


def text_value(value: Any) -> str:
    return str(value or "").strip()


def int_value(value: Any, default: int | None = None) -> int | None:
    try:
        text = str(value).strip()
        if not text:
            return default
        return int(float(text.replace(",", ".")))
    except (TypeError, ValueError):
        return default


def bool_value(value: Any) -> bool:
    return text_value(value).lower() in {"1", "true", "yes", "tak", "on"}


def birth_year(value: Any) -> int | None:
    raw = text_value(value)
    if len(raw) < 4 or not raw[:4].isdigit():
        return None
    year = int(raw[:4])
    return year if 1900 <= year <= 2100 else None


def sanitize(value: Any) -> Any:
    """Rekurencyjnie usuwa zakazane pola, zachowując resztę odpowiedzi API."""
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if not isinstance(value, dict):
        return value
    clean: dict[str, Any] = {}
    for key, item in value.items():
        normalized = str(key).strip().lower()
        if normalized in PRIVATE_KEYS or normalized.startswith("badania_"):
            continue
        clean[str(key)] = sanitize(item)
    return clean


def canonical_json(value: Any) -> bytes:
    return json.dumps(sanitize(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def checksum(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [item for item in payload.values() if isinstance(item, dict)]
    return []


class PublicZprpClient:
    """Klient współdzielący jedną sesję i globalny limit równoległości."""

    def __init__(self) -> None:
        concurrency = max(1, min(6, int(os.getenv("ZPRP_PUBLIC_API_CONCURRENCY", "3"))))
        self._gate = asyncio.Semaphore(concurrency)
        self._spacing = max(0.05, float(os.getenv("ZPRP_PUBLIC_API_MIN_INTERVAL", "0.18")))
        self._last_started = 0.0
        self._start_lock = asyncio.Lock()
        self._client = AsyncClient(
            base_url=API_BASE,
            follow_redirects=True,
            timeout=float(os.getenv("ZPRP_PUBLIC_API_TIMEOUT", "25")),
            headers={"User-Agent": "BAZA-ZPRP-public-sync/1.0"},
        )
        self.requests = 0
        self.errors = 0

    async def close(self) -> None:
        await self._client.aclose()

    async def _wait_for_slot(self) -> None:
        async with self._start_lock:
            elapsed = time.monotonic() - self._last_started
            if elapsed < self._spacing:
                await asyncio.sleep(self._spacing - elapsed)
            self._last_started = time.monotonic()

    async def get(self, path: str) -> Any:
        retries = max(0, min(4, int(os.getenv("ZPRP_PUBLIC_API_RETRIES", "2"))))
        async with self._gate:
            for attempt in range(retries + 1):
                await self._wait_for_slot()
                self.requests += 1
                try:
                    response = await self._client.get(path)
                    if response.status_code in TRANSIENT_STATUSES and attempt < retries:
                        await asyncio.sleep(0.5 * (2**attempt))
                        continue
                    response.raise_for_status()
                    return decode_api_bytes(response.content)
                except Exception:
                    if attempt >= retries:
                        self.errors += 1
                        raise
                    await asyncio.sleep(0.5 * (2**attempt))
        return None


"""Adres `pokaz_mecze_szczegoly.php` i konfigurowalny dopisek ProEl.

Bez dopisku `&ProEl=...` publiczne API ZPRP zwraca PUSTY `komentarz` meczu.
Dopisek trzymamy w `beach_app_settings` (ogólna tabela klucz/wartość), z wartością
domyślną w kodzie, żeby zmiana po stronie ZPRP nie wymagała wydania backendu.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

DETAILS_BASE = "https://rozgrywki.zprp.pl/api/pokaz_mecze_szczegoly.php"
DEFAULT_SUFFIX = "&ProEl=ToKeN135@$"
SETTING_KEY = "zprp_details_suffix"
_TTL_S = 60.0

_cache: Optional[tuple[float, str]] = None


def normalize_suffix(value: object) -> str:
    """Pusty/None -> domyślny. Dopisek zawsze zaczyna się od `&`."""
    text = str(value or "").strip()
    if not text:
        return DEFAULT_SUFFIX
    if not text.startswith("&"):
        text = "&" + text.lstrip("?")
    return text


def cache_clear() -> None:
    global _cache
    _cache = None


async def zprp_details_suffix() -> str:
    """Aktualny dopisek (cache 60 s). Awaria bazy = ostatnia znana / domyślna wartość."""
    global _cache
    now = time.monotonic()
    if _cache is not None and now - _cache[0] < _TTL_S:
        return _cache[1]
    value = _cache[1] if _cache is not None else DEFAULT_SUFFIX
    try:
        from sqlalchemy import select

        from app.db import beach_app_settings, database

        row = await database.fetch_one(
            select(beach_app_settings.c.value).where(beach_app_settings.c.key == SETTING_KEY)
        )
        value = normalize_suffix(row["value"] if row else None)
    except Exception:
        log.debug("zprp_details_suffix: odczyt ustawienia nieudany", exc_info=True)
    _cache = (now, value)
    return value


async def save_suffix(raw: object) -> str:
    """Zapisuje dopisek; pusty/None kasuje wpis (wraca domyślny)."""
    from sqlalchemy import delete, insert, update

    from app.db import beach_app_settings, database

    text = str(raw or "").strip()
    cond = beach_app_settings.c.key == SETTING_KEY
    if not text:
        await database.execute(delete(beach_app_settings).where(cond))
    else:
        text = normalize_suffix(text)
        exists = await database.fetch_one(beach_app_settings.select().where(cond))
        now = datetime.now(timezone.utc)
        if exists:
            await database.execute(
                update(beach_app_settings).where(cond).values(value=text, updated_at=now)
            )
        else:
            await database.execute(
                insert(beach_app_settings).values(key=SETTING_KEY, value=text, updated_at=now)
            )
    cache_clear()
    return await zprp_details_suffix()


async def details_url(match_id: object) -> str:
    """Pełny adres szczegółów meczu z dopiskiem (bez `params=`)."""
    return f"{DETAILS_BASE}?Zawody={match_id}{await zprp_details_suffix()}"


async def details_path(match_id: object) -> str:
    """Ścieżka względna do `PublicZprpClient.get` (base = .../api/)."""
    return f"pokaz_mecze_szczegoly.php?Zawody={match_id}{await zprp_details_suffix()}"


# ── Trasy ────────────────────────────────────────────────────────────────────
from typing import Any, Dict  # noqa: E402

from fastapi import APIRouter  # noqa: E402
from pydantic import BaseModel  # noqa: E402

public_router = APIRouter(tags=["ZPRP"])


class DetailsSuffixBody(BaseModel):
    suffix: Optional[str] = None


@public_router.get("/zprp/details-suffix", summary="Dopisek do pokaz_mecze_szczegoly (publiczny)")
async def get_details_suffix() -> Dict[str, Any]:
    return {"suffix": await zprp_details_suffix()}

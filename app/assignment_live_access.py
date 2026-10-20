"""Odczyt praw przed sugestią. Nigdy nie wysyła pola zapisu formularza."""
from __future__ import annotations

import asyncio
import hashlib
import time

from app.assignment_access import AUTO_SLOTS, FORM_SLOTS, form_editable

_cache: dict[tuple[str, str], tuple[float, dict]] = {}
TTL = 120


async def verify_matches(province: str, states: dict[str, dict]) -> dict[str, dict]:
    from httpx import AsyncClient
    from fastapi import HTTPException
    from app.deps import get_settings
    from app.zprp_accounts import credentials_for
    from app.zprp.assignments import _parse_referee_form
    from app.zprp.schedule import _login_zprp_and_get_cookies
    from app.utils import fetch_with_correct_encoding

    # Każda sugestia wymaga aktualnych praw, również dla starej migawki.
    pending = {mid: state for mid, state in states.items()
               if state.get("assignment_access", {}).get("recommended") is True}
    if not pending:
        return states
    credentials = credentials_for(province, "sync")
    if not credentials:
        raise HTTPException(409, "Nie można potwierdzić praw do nowych meczów: brak konta monitora ZPRP.")
    username, password = credentials
    account = hashlib.sha256((province + '\0' + username + '\0' + password).encode()).hexdigest()
    uncached = []
    result = dict(states)
    for mid, state in pending.items():
        entry = _cache.get((account, mid))
        if entry and time.monotonic() - entry[0] < TTL:
            result[mid] = _merge(state, entry[1])
        else:
            uncached.append(mid)
    if not uncached:
        return result
    settings = get_settings()
    semaphore = asyncio.Semaphore(3)
    async with AsyncClient(base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=20) as client:
        try:
            cookies = await _login_zprp_and_get_cookies(client, username, password)
        except Exception as exc:
            raise HTTPException(503, "Nie udało się zalogować do ZPRP; sugestie wstrzymano.") from exc

        async def one(mid):
            async with semaphore:
                try:
                    _, html = await fetch_with_correct_encoding(client, "/zawody_UstawSedziow.php",
                        method="POST", cookies=cookies,
                        data={"IdZawody": mid, "akcja": "UstawSedziow", "user": ""})
                    parsed = _parse_referee_form(html)
                    if parsed.get("IdZawody") != mid:
                        raise ValueError("Formularz nie potwierdza tożsamości meczu")
                    slots = parsed["slots"]
                    allowed = [s for s in form_editable(slots) if s in AUTO_SLOTS]
                    info = {"auto_slots": allowed, "verified": True,
                            "allowed_names": {s: [o["name"] for o in slots[FORM_SLOTS[s]]["options"]
                                                  if not o.get("disabled")] for s in allowed}}
                    if len(_cache) >= 2000:
                        _cache.clear()
                    _cache[(account, mid)] = (time.monotonic(), info)
                except Exception as exc:
                    raise HTTPException(503, "Nie udało się potwierdzić uprawnień ZPRP; sugestie wstrzymano.") from exc
                state = pending[mid]
                result[mid] = _merge(state, info)
        await asyncio.gather(*(one(mid) for mid in uncached))
    return result


def _merge(state: dict, info: dict) -> dict:
    access = state["assignment_access"]
    allowed = [slot for slot in info["auto_slots"] if slot in access.get("auto_slots", [])]
    return {**state, "assignment_access": {**access, **info, "auto_slots": allowed,
            "allowed_names": {slot: info["allowed_names"].get(slot, []) for slot in allowed}}}

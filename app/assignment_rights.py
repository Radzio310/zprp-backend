"""Pamięć potwierdzonych praw do formularza obsady: (konto ZPRP, mecz).

Po co: panel po otwarciu meczu czekał szeregowo na logowanie i odczyt
formularza ZPRP, zanim pokazał, które role wolno zmienić. Prawa z ostatniego
odczytu zapamiętujemy (pamięć procesu + tabela), więc kolejne wejście zna je
od razu, a świeży odczyt tylko je odświeża albo zawęża.

Zasady bezpieczeństwa (bez zmian względem zapisu):
  - pamięć służy WYŁĄCZNIE do pokazania gniazd i do wyliczania kandydatów;
    zapis w ZPRP dalej czyta formularz na żywo (FORM_INCOMPLETE, chronione role,
    niedostępne nazwisko),
  - zapamiętane prawa nie poszerzają zakresu ponad maskę z terminarza
    (to robi `assignment_live_access._merge` i front),
  - czytamy wyłącznie formularz (POST z `akcja=UstawSedziow` jest tylko
    otwarciem widoku), nic nie zapisujemy w ZPRP.

Konto to skrót pary login + hasło (HMAC) - jawnego hasła nie ma w bazie.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import time
from typing import Any, Awaitable, Callable, Iterable, Mapping, Optional

logger = logging.getLogger(__name__)

#: Do ilu minut prawa uznajemy za świeże (dalej odświeżamy w tle).
FRESH_SECONDS = 30 * 60
#: Po tylu dniach wpis znika z tabeli.
KEEP_SECONDS = 14 * 24 * 3600
#: Najwyżej tylu formularzy czytamy naraz - ZPRP to cudza strona.
WARM_CONCURRENCY = 2
#: Ile meczów przyjmuje jedno wołanie rozgrzewające.
WARM_MAX_IDS = 8
#: Budżet czasu jednego wołania rozgrzewającego.
WARM_BUDGET_SECONDS = 40.0
WARM_FORM_TIMEOUT = 20.0

FORM_KEYS = ("sedzia1", "sedzia2", "delegat", "delegat2", "sekretarz", "czas")

_memory: dict[tuple[str, str], dict] = {}
_MEMORY_LIMIT = 4000
_warming: set[str] = set()


def account_key(username: str, password: str) -> str:
    """
    Skrót pary login + hasło (z solą serwera). Hasło w kluczu sprawia, że
    odczyt cudzych praw wymaga znajomości hasła, a nie samego loginu.
    """
    pepper = os.getenv("EMAIL_CODE_SECRET", "") or "assignment-rights"
    message = str(username or "").strip().lower() + "|" + str(password or "")
    return hmac.new(pepper.encode(), message.encode(), hashlib.sha256).hexdigest()


def compact(parsed: Mapping[str, Any]) -> dict:
    """Sparsowany formularz -> to, co wystarcza do praw (bez wartości opcji)."""
    slots = {}
    for key in FORM_KEYS:
        slot = (parsed.get("slots") or {}).get(key) or {}
        editable = slot.get("editable") is True
        slots[key] = {
            "editable": editable,
            "field_kind": slot.get("field_kind") or "absent",
            "names": [o["name"] for o in slot.get("options") or []
                      if editable and o.get("name") and not o.get("disabled")],
        }
    return {"at": time.time(), "slots": slots}


def public_view(rights: Mapping[str, Any]) -> dict:
    """Co wraca do panelu: bez list nazwisk (te zostają na serwerze)."""
    return {"at": rights.get("at", 0),
            "slots": {key: {"editable": bool(slot.get("editable")), "field_kind": slot.get("field_kind") or "absent"}
                      for key, slot in (rights.get("slots") or {}).items()}}


def info_from_rights(rights: Mapping[str, Any]) -> dict:
    """Kształt `info` z `assignment_live_access` (role Automatu + dozwolone nazwiska)."""
    from app.assignment_access import AUTO_SLOTS, FORM_SLOTS

    slots = rights.get("slots") or {}
    allowed = [s for s, key in FORM_SLOTS.items() if s in AUTO_SLOTS and (slots.get(key) or {}).get("editable")]
    return {"auto_slots": allowed, "verified": True,
            "allowed_names": {s: list(slots[FORM_SLOTS[s]].get("names") or []) for s in allowed}}


def fresh(rights: Optional[Mapping[str, Any]], max_age: float = FRESH_SECONDS) -> bool:
    return bool(rights) and time.time() - float(rights.get("at") or 0) < max_age


def _db():
    try:
        from app.db import database, assignment_form_rights
    except Exception:  # noqa: BLE001 - bez bazy (testy) zostaje sama pamięć procesu
        return None
    return (database, assignment_form_rights) if getattr(database, "is_connected", False) else None


async def recall_many(account: str, match_ids: Iterable[str], max_age: Optional[float] = None) -> dict[str, dict]:
    """Zapamiętane prawa; `max_age=None` = każde (panel pokazuje też nieświeże)."""
    wanted = [str(m) for m in match_ids if str(m)]
    out: dict[str, dict] = {}
    missing = []
    for mid in wanted:
        hit = _memory.get((account, mid))
        if hit is not None and (max_age is None or fresh(hit, max_age)):
            out[mid] = hit
        else:
            missing.append(mid)
    handle = _db() if missing else None
    if handle:
        database, table = handle
        try:
            from sqlalchemy import and_, select
            rows = await database.fetch_all(select(table).where(
                and_(table.c.account_key == account, table.c.match_id.in_(missing))))
            for row in rows:
                rights = row["rights"] if isinstance(row["rights"], dict) else {}
                if not rights.get("slots"):
                    continue
                rights = {**rights, "at": row["read_at"].timestamp() if row["read_at"] else rights.get("at", 0)}
                if max_age is None or fresh(rights, max_age):
                    out[row["match_id"]] = rights
                    _memory[(account, row["match_id"])] = rights
        except Exception:  # noqa: BLE001
            logger.exception("obsada: nie udało się odczytać zapamiętanych praw")
    return out


async def remember(account: str, match_id: str, rights: dict) -> None:
    if len(_memory) >= _MEMORY_LIMIT:
        _memory.clear()
    _memory[(account, match_id)] = rights
    handle = _db()
    if not handle:
        return
    database, table = handle
    try:
        from datetime import datetime, timezone
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        read_at = datetime.fromtimestamp(rights["at"], tz=timezone.utc)
        await database.execute(pg_insert(table).values(
            account_key=account, match_id=match_id, rights=rights, read_at=read_at
        ).on_conflict_do_update(index_elements=[table.c.account_key, table.c.match_id],
                                set_={"rights": rights, "read_at": read_at}))
    except Exception:  # noqa: BLE001 - zapis pamięci nie może psuć odczytu formularza
        logger.exception("obsada: nie udało się zapamiętać praw")


async def prune() -> None:
    handle = _db()
    if not handle:
        return
    database, table = handle
    try:
        from datetime import datetime, timedelta, timezone
        from sqlalchemy import delete
        await database.execute(delete(table).where(
            table.c.read_at < datetime.now(timezone.utc) - timedelta(seconds=KEEP_SECONDS)))
    except Exception:  # noqa: BLE001
        logger.exception("obsada: sprzątanie zapamiętanych praw")


FormReader = Callable[[str], Awaitable[Mapping[str, Any]]]


async def warm(account: str, match_ids: list[str], read_form: FormReader, *,
               max_age: float = FRESH_SECONDS, concurrency: int = WARM_CONCURRENCY,
               budget: float = WARM_BUDGET_SECONDS) -> dict:
    """
    Czyta formularze meczów bez świeżych praw, w podanej kolejności (pierwszy
    najpierw), po `concurrency` naraz. Zwraca `{"rights": {...}, "failed": [...],
    "skipped": [...]}`. Jedno konto = jedno rozgrzewanie naraz (kolejne wołanie
    dostaje `busy`), żeby nie mnożyć ruchu do ZPRP.
    """
    ids = list(dict.fromkeys(str(m) for m in match_ids if str(m)))[:WARM_MAX_IDS]
    if account in _warming:
        return {"busy": True, "rights": {}, "failed": [], "skipped": ids}
    _warming.add(account)
    try:
        known = await recall_many(account, ids, max_age)
        todo = [m for m in ids if m not in known]
        got: dict[str, dict] = {}
        failed: list[str] = []
        queue: asyncio.Queue = asyncio.Queue()
        for mid in todo:
            queue.put_nowait(mid)
        deadline = time.monotonic() + budget

        async def worker():
            while time.monotonic() < deadline:
                try:
                    mid = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    parsed = await asyncio.wait_for(read_form(mid), WARM_FORM_TIMEOUT)
                    if str(parsed.get("IdZawody") or "") != mid:
                        raise ValueError("Formularz nie potwierdza tożsamości meczu")
                    rights = compact(parsed)
                    await remember(account, mid, rights)
                    got[mid] = rights
                except Exception as exc:  # noqa: BLE001 - jeden mecz nie wstrzymuje reszty
                    logger.info("obsada: rozgrzewanie praw %s nie wyszło: %s", mid, exc)
                    failed.append(mid)

        await asyncio.gather(*(worker() for _ in range(max(1, concurrency))))
        skipped = [m for m in todo if m not in got and m not in failed]
        return {"busy": False, "rights": {**known, **got}, "failed": failed, "skipped": skipped}
    finally:
        _warming.discard(account)

"""Kalendarz Google w tle (16.11.2026, BAZA 2.1.8).

Decyzja właściciela: serwer sam dodaje nowe mecze, poprawia zmienione (godzina,
hala, drużyny) i USUWA mecze odwołane albo zabrane z obsady - bez otwierania
aplikacji. Reguły (tytuł, przypomnienia, plan) leżą w ``calendar_auto_sync_rules``.

SKĄD SERWER WIE, CO ROBIĆ
  * mecze: monitor okręgu (``province_matches`` + aktywne ``province_match_judges``),
  * jak wpis ma wyglądać: profil z aplikacji (``PUT /calendar/auto-sync``) - kolory
    ról i reguły przypomnień; numer sędziego bierzemy z tokenu, nie z treści,
  * co już jest w kalendarzu: ``event_mappings`` + odcisk ostatniego zapisu
    (``calendar_event_prints``), zapisywany też przy każdym zapisie z telefonu.

ZAPIS IDZIE TĄ SAMĄ DROGĄ CO Z TELEFONU (funkcje tras z ``app/calendar.py``):
kalendarze drugorzędne, stałe identyfikatory wydarzeń i mapowania działają
identycznie, więc telefon i serwer nie tworzą duplikatów.

BEZPIECZNIKI
  * usuwamy wyłącznie PRZYSZŁE mecze, które monitor zna - mecz spoza monitora
    (inny okręg, liga centralna) zostaje nietknięty,
  * wpis z telefonu bez odcisku dostaje odcisk bez zapisu do Google (nie
    nadpisujemy kalendarza na ślepo przy pierwszym przebiegu po wdrożeniu),
  * limit zapisów na sędziego w jednym przebiegu; błąd jednego konta nie
    zatrzymuje pozostałych.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import and_, delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.deps import get_jwt_payload
from app.calendar_auto_sync_rules import (
    Known,
    Profile,
    clean_color,
    desired_event,
    fingerprint_of,
    normalize_reminder_rules,
    plan_sync,
)

logger = logging.getLogger("app.calendar_auto_sync")

DEFAULT_INTERVAL_SECONDS = 900
MAX_WRITES_PER_USER = 40
STARTUP_DELAY_SECONDS = 120

router = APIRouter(prefix="/calendar/auto-sync", tags=["Calendar"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _state(raw: Any) -> Dict[str, Any]:
    from app.match_market_rules import state_dict

    return state_dict(raw)


# ── Odciski (wołane także z tras zapisu w app/calendar.py) ──────────────────


async def remember_print(user_login: str, event: Mapping[str, Any]) -> None:
    """Zapamiętaj odcisk właśnie zapisanego wpisu. Nigdy nie rzuca - zapis do Google już się udał."""
    try:
        from app.db import calendar_event_prints, database

        fp = fingerprint_of(event)
        stmt = pg_insert(calendar_event_prints).values(user_login=user_login, match_id=str(event["matchId"]), fingerprint=fp)
        stmt = stmt.on_conflict_do_update(
            index_elements=[calendar_event_prints.c.user_login, calendar_event_prints.c.match_id],
            set_={"fingerprint": fp, "updated_at": _now()},
        )
        await database.execute(stmt)
    except Exception:  # noqa: BLE001
        logger.debug("calendar print not saved", exc_info=True)


async def forget_print(user_login: str, match_id: str) -> None:
    try:
        from app.db import calendar_event_prints, database

        await database.execute(
            delete(calendar_event_prints).where(
                and_(calendar_event_prints.c.user_login == user_login, calendar_event_prints.c.match_id == str(match_id))
            )
        )
    except Exception:  # noqa: BLE001
        logger.debug("calendar print not removed", exc_info=True)


def payload_event(payload: Any, match_id: Optional[str] = None) -> Dict[str, Any]:
    """`EventCreate` z telefonu -> słownik do odcisku."""
    return {
        "matchId": match_id or payload.matchId,
        "summary": payload.summary,
        "start": payload.start,
        "location": payload.location,
        "reminders": payload.reminders,
    }


def records_print(kind: str):
    """Dekorator tras zapisu kalendarza: po udanym zapisie/usunięciu - odcisk wpisu (kalendarz w tle).

    Ciało trasy zostaje nietknięte; odcisk nie ma prawa zepsuć odpowiedzi (``remember_print`` nie rzuca).
    """

    def wrap(fn):
        @functools.wraps(fn)
        async def inner(*args, **kwargs):
            result = await fn(*args, **kwargs)
            bound = inspect.signature(fn).bind_partial(*args, **kwargs).arguments
            user_login = bound.get("user_login")
            if isinstance(user_login, str) and user_login:
                if kind == "delete":
                    await forget_print(user_login, str(bound.get("match_id") or ""))
                else:
                    payload = bound.get("payload")
                    if payload is not None:
                        await remember_print(user_login, payload_event(payload, bound.get("match_id")))
            return result

        return inner

    return wrap


# ── Profil z aplikacji ──────────────────────────────────────────────────────


class AutoSyncSettings(BaseModel):
    enabled: bool = True
    matchColorId: Optional[str] = None
    tableColorId: Optional[str] = None
    #: Reguły przypomnień z ustawień (brak = domyślne 24 h, 3 h i 7:00; [] = bez przypomnień).
    reminderRules: Optional[List[Dict[str, Any]]] = None


@router.put("", summary="Ustawienia kalendarza w tle (aplikacja wysyła przy zmianie i przy starcie)")
async def put_auto_sync(body: AutoSyncSettings, claims: dict = Depends(get_jwt_payload)):
    from app.db import calendar_auto_sync, database

    user_login = str(claims.get("sub") or "")
    judge_id = str(claims.get("judge_id") or "").strip()
    if not user_login or not judge_id.isdigit():
        raise HTTPException(403, "Kalendarz w tle działa dla kont sędziowskich.")
    rules = normalize_reminder_rules(body.reminderRules) if body.reminderRules is not None else None
    values = {
        "judge_id": judge_id,
        "enabled": bool(body.enabled),
        "match_color": clean_color(body.matchColorId, "9"),
        "table_color": clean_color(body.tableColorId, "10"),
        "reminder_rules": rules,
    }
    stmt = pg_insert(calendar_auto_sync).values(user_login=user_login, **values)
    stmt = stmt.on_conflict_do_update(index_elements=[calendar_auto_sync.c.user_login], set_={**values, "updated_at": _now()})
    await database.execute(stmt)
    return {"enabled": values["enabled"]}


@router.get("", summary="Stan kalendarza w tle")
async def get_auto_sync(claims: dict = Depends(get_jwt_payload)):
    from app.db import calendar_auto_sync, database

    row = await database.fetch_one(select(calendar_auto_sync).where(calendar_auto_sync.c.user_login == str(claims.get("sub") or "")))
    if not row:
        return {"enabled": False, "last_run_at": None, "last_error": None}
    return {
        "enabled": bool(row["enabled"]),
        "last_run_at": row["last_run_at"].isoformat() if row["last_run_at"] else None,
        "last_error": row["last_error"],
    }


# ── Silnik (porty: testy podstawiają atrapy) ────────────────────────────────


@dataclass
class Deps:
    #: mecze sędziego z monitora: [(match_id, state)] - przyszłe, aktywne, z aktywnym przydziałem
    my_matches: Callable[[str, datetime], Awaitable[List[tuple[str, Dict[str, Any]]]]]
    #: mapowania wpisów konta z odciskami: [Known]
    known: Callable[[str], Awaitable[List[Known]]]
    #: które z podanych meczów monitor zna jako PRZYSZŁE (niezależnie od obsady i aktywności)
    monitored_future: Callable[[List[str], datetime], Awaitable[set[str]]]
    write: Callable[[str, Dict[str, Any]], Awaitable[None]]
    remove: Callable[[str, str], Awaitable[None]]
    seed: Callable[[str, Dict[str, Any]], Awaitable[None]]


@dataclass
class Result:
    created: int = 0
    updated: int = 0
    deleted: int = 0
    seeded: int = 0
    errors: int = 0
    first_error: Optional[str] = None


async def sync_user(profile: Profile, deps: Deps, *, now: Optional[datetime] = None, limit: int = MAX_WRITES_PER_USER) -> Result:
    now = now or _now()
    result = Result()
    rows = await deps.my_matches(profile.judge_id, now)
    desired: Dict[str, Optional[Dict[str, Any]]] = {}
    for match_id, state in rows:
        desired[match_id] = desired_event(state, match_id, profile)
    known = await deps.known(profile.user_login)
    candidates = [k.match_id for k in known if k.match_id not in desired]
    monitored = await deps.monitored_future(candidates, now) if candidates else set()
    plan = plan_sync(desired=desired, known=known, monitored_future=monitored)

    budget = limit

    async def run(kind: str, fn: Callable[[], Awaitable[None]]) -> None:
        nonlocal budget
        if budget <= 0:
            return
        budget -= 1
        try:
            await fn()
            setattr(result, kind, getattr(result, kind) + 1)
        except Exception as exc:  # noqa: BLE001 - jeden mecz nie zatrzymuje reszty
            result.errors += 1
            if result.first_error is None:
                result.first_error = f"{type(exc).__name__}: {getattr(exc, 'detail', None) or exc}"[:300]

    for event in plan.seed:
        try:
            await deps.seed(profile.user_login, event)
            result.seeded += 1
        except Exception:  # noqa: BLE001
            pass
    for event in plan.update:
        await run("updated", lambda e=event: deps.write(profile.user_login, e))
    for match_id in plan.delete:
        await run("deleted", lambda m=match_id: deps.remove(profile.user_login, m))
    for event in plan.create:
        await run("created", lambda e=event: deps.write(profile.user_login, e))
    return result


# ── Porty produkcyjne ───────────────────────────────────────────────────────


async def _my_matches(judge_id: str, now: datetime) -> List[tuple[str, Dict[str, Any]]]:
    from app.db import database, province_match_judges, province_matches

    query = (
        select(province_matches.c.match_id, province_matches.c.state_json)
        .select_from(
            province_matches.join(
                province_match_judges,
                and_(
                    province_match_judges.c.province == province_matches.c.province,
                    province_match_judges.c.match_id == province_matches.c.match_id,
                ),
            )
        )
        .where(
            province_match_judges.c.judge_id == judge_id,
            province_match_judges.c.active.is_(True),
            province_matches.c.active.is_(True),
            province_matches.c.match_at > now,
        )
    )
    out: Dict[str, Dict[str, Any]] = {}
    for row in await database.fetch_all(query):
        out.setdefault(str(row["match_id"]), _state(row["state_json"]))
    return list(out.items())


async def _known(user_login: str) -> List[Known]:
    from app.db import calendar_event_prints, database, event_mappings

    query = select(event_mappings.c.match_id, calendar_event_prints.c.fingerprint).select_from(
        event_mappings.outerjoin(
            calendar_event_prints,
            and_(
                calendar_event_prints.c.user_login == event_mappings.c.user_login,
                calendar_event_prints.c.match_id == event_mappings.c.match_id,
            ),
        )
    ).where(event_mappings.c.user_login == user_login)
    return [Known(match_id=str(r["match_id"]), fingerprint=r["fingerprint"]) for r in await database.fetch_all(query)]


async def _monitored_future(match_ids: List[str], now: datetime) -> set[str]:
    from app.db import database, province_matches

    if not match_ids:
        return set()
    rows = await database.fetch_all(
        select(province_matches.c.match_id).where(province_matches.c.match_id.in_(match_ids), province_matches.c.match_at > now)
    )
    return {str(r["match_id"]) for r in rows}


def _production_deps(settings: Any) -> Deps:
    async def write(user_login: str, event: Dict[str, Any]) -> None:
        from app.calendar import EventCreate, create_event

        payload = EventCreate(
            matchId=event["matchId"],
            summary=event["summary"],
            start=event["start"],
            end=event["end"],
            location=event["location"],
            colorId=event["colorId"],
            reminders=event["reminders"],
        )
        # Ta sama droga co POST z telefonu (odcisk zapisuje trasa).
        await create_event(payload, settings, user_login)

    async def remove(user_login: str, match_id: str) -> None:
        from app.calendar import delete_event

        await delete_event(match_id, settings, user_login)

    return Deps(
        my_matches=_my_matches,
        known=_known,
        monitored_future=_monitored_future,
        write=write,
        remove=remove,
        seed=remember_print,
    )


async def _profiles() -> List[Profile]:
    from app.db import calendar_auto_sync, calendar_tokens, database

    rows = await database.fetch_all(
        select(calendar_auto_sync).select_from(
            calendar_auto_sync.join(calendar_tokens, calendar_tokens.c.user_login == calendar_auto_sync.c.user_login)
        ).where(calendar_auto_sync.c.enabled.is_(True))
    )
    return [
        Profile(
            user_login=str(r["user_login"]),
            judge_id=str(r["judge_id"]),
            match_color=r["match_color"] or "9",
            table_color=r["table_color"] or "10",
            reminder_rules=r["reminder_rules"],
        )
        for r in rows
    ]


async def _note(user_login: str, result: Result) -> None:
    from sqlalchemy import update

    from app.db import calendar_auto_sync, database

    await database.execute(
        update(calendar_auto_sync)
        .where(calendar_auto_sync.c.user_login == user_login)
        .values(last_run_at=_now(), last_error=result.first_error)
    )


async def run_once(settings: Any) -> Dict[str, int]:
    deps = _production_deps(settings)
    totals = {"users": 0, "created": 0, "updated": 0, "deleted": 0, "errors": 0}
    for profile in await _profiles():
        totals["users"] += 1
        try:
            res = await sync_user(profile, deps)
        except Exception as exc:  # noqa: BLE001
            logger.warning("calendar auto-sync failed for %s: %s", profile.user_login, exc)
            res = Result(errors=1, first_error=f"{type(exc).__name__}: {exc}"[:300])
        for k in ("created", "updated", "deleted", "errors"):
            totals[k] += getattr(res, k)
        try:
            await _note(profile.user_login, res)
        except Exception:  # noqa: BLE001
            logger.debug("calendar auto-sync note skipped", exc_info=True)
    return totals


async def run_calendar_auto_sync() -> None:
    if os.getenv("CALENDAR_AUTO_SYNC_ENABLED", "true").strip().lower() not in ("1", "true", "yes", "on"):
        logger.info("Calendar auto-sync disabled")
        return
    interval = max(300, int(os.getenv("CALENDAR_AUTO_SYNC_SECONDS", str(DEFAULT_INTERVAL_SECONDS))))
    from app.deps import get_settings

    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        try:
            totals = await run_once(get_settings())
            if totals["created"] or totals["updated"] or totals["deleted"] or totals["errors"]:
                logger.info("calendar auto-sync: %s", totals)
        except Exception:  # noqa: BLE001 - pętla nie może umrzeć
            logger.exception("calendar auto-sync run failed")
        await asyncio.sleep(interval)

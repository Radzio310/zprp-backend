"""
Nazwiska sedziow do rozliczen: trzy zrodla i latanie dziur.

Od najslabszego:
  1. `zprp_judges_seen` - nazwisko z publicznego API meczu (w obsadzie numer
     stoi obok nazwiska). Numer sedziego jest w ZPRP globalny,
  2. `province_settlement_judges` - kopia listy „Sedziowie i Delegaci",
  3. `province_judges` - lista prowadzona przez okreg; wygrywa, gdy ma nazwisko.

Nazwisko, ktore jest samym numerem („465"), nie jest nazwiskiem - takie wpisy
pomijamy, zeby nie zaslonily prawdziwego z nizszego zrodla.

Dziury lata `fill_missing_names`: najpierw terminarz okregu (`province_matches`
trzyma obsade z nazwiskami - bez sieci), potem po jednym meczu sedziego
z publicznego API. Wynik zostaje w bazie na stale. Wola to pobieranie okregu
(wszyscy bez nazwiska, ze wszystkich sezonow) i samo zestawienie przy odczycie
(tylko ci z miesiaca, z limitem czasu) - nazwisko pojawia sie bez czekania na
dobowe odswiezenie.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from httpx import AsyncClient
from sqlalchemy import and_, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import (
    database,
    province_judges,
    province_matches,
    province_settlement_judges,
    province_settlement_matches,
    zprp_judges_seen,
)
from app.settlement_names_rules import (
    given_first,
    is_missing_name,
    officials_from_payload,
    officials_from_record,
    pick_unnamed,
)
from app.settlement_province import spellings
from app.settlement_venues import fetch_details_payload

logger = logging.getLogger(__name__)

#: Ile zapytan o mecze naraz - to samo publiczne API, co hale.
CONCURRENCY = 6

#: Sedziego, ktorego API nie umialo nazwac, nie pytamy znow przez tyle godzin -
#: inaczej kazde otwarcie zestawienia pukaloby do API o to samo.
RETRY_HOURS = 1

_ATTEMPTS: dict[str, datetime] = {}
_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _clean(value: Any) -> str:
    return " ".join(str(value if value is not None else "").split())


def _state(raw: Any) -> dict:
    """JSONB potrafi wrocic napisem - wtedy trzeba go rozpakowac."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except Exception:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


async def judge_names(province: str) -> dict[str, str]:
    """Numer sedziego -> nazwisko, z trzech zrodel (patrz naglowek modulu)."""
    out: dict[str, str] = {}

    def put(judge_id: Any, name: Any) -> None:
        key = _clean(judge_id)
        if key and not is_missing_name(name, key):
            out[key] = _clean(name)

    for row in await database.fetch_all(
        select(zprp_judges_seen.c.judge_id, zprp_judges_seen.c.full_name)
    ):
        put(row["judge_id"], row["full_name"])

    for row in await database.fetch_all(
        select(
            province_settlement_judges.c.judge_id,
            province_settlement_judges.c.full_name,
        ).where(province_settlement_judges.c.province == province)
    ):
        put(row["judge_id"], row["full_name"])

    for row in await database.fetch_all(
        select(province_judges.c.judge_id, province_judges.c.full_name).where(
            province_judges.c.province.in_(spellings(province))
        )
    ):
        put(row["judge_id"], row["full_name"])
    return out


async def judge_cities(judge_ids: Iterable[str]) -> dict[str, str]:
    """Miasta z obsad meczow - dla sedziow, ktorym lista okregu miasta nie podala."""
    ids = sorted({_clean(judge_id) for judge_id in judge_ids if _clean(judge_id)})
    if not ids:
        return {}
    out: dict[str, str] = {}
    for start in range(0, len(ids), 500):
        rows = await database.fetch_all(
            select(zprp_judges_seen.c.judge_id, zprp_judges_seen.c.home_city).where(
                zprp_judges_seen.c.judge_id.in_(ids[start : start + 500])
            )
        )
        for row in rows:
            city = _clean(row["home_city"])
            if city:
                out[_clean(row["judge_id"])] = city
    return out


async def remember_officials(
    officials: list[dict], *, match_id: Any, now: Optional[datetime] = None
) -> int:
    """Zapis obsady meczu do katalogu nazwisk. Zwraca, ile wpisow poszlo."""
    stamp = now or _now()
    saved = 0
    for item in officials:
        judge_id = _clean(item.get("judge_id"))
        name = given_first(item.get("name"))
        if not judge_id or is_missing_name(name, judge_id):
            continue
        statement = pg_insert(zprp_judges_seen).values(
            judge_id=judge_id,
            full_name=name,
            home_city=_clean(item.get("city")) or None,
            match_id=_clean(match_id) or None,
            seen_at=stamp,
        )
        await database.execute(
            statement.on_conflict_do_update(
                index_elements=[zprp_judges_seen.c.judge_id],
                set_={
                    "full_name": statement.excluded.full_name,
                    # Obsada bez miasta nie zamazuje miasta, ktore juz znamy.
                    "home_city": func.coalesce(
                        statement.excluded.home_city, zprp_judges_seen.c.home_city
                    ),
                    "match_id": statement.excluded.match_id,
                    "seen_at": statement.excluded.seen_at,
                },
            )
        )
        saved += 1
    return saved


async def _unnamed(
    province: str, names: dict[str, str], only: Optional[set[str]], limit: int
) -> dict[str, list[str]]:
    query = select(
        province_settlement_matches.c.judge_id,
        province_settlement_matches.c.match_key,
        province_settlement_matches.c.match_at,
    ).where(
        and_(
            province_settlement_matches.c.province == province,
            province_settlement_matches.c.active.is_(True),
        )
    )
    if only:
        query = query.where(province_settlement_matches.c.judge_id.in_(sorted(only)))
    rows = await database.fetch_all(query)
    return pick_unnamed(
        ((row["judge_id"], row["match_key"], row["match_at"]) for row in rows),
        names,
        only=only,
        limit=limit,
    )


async def _from_schedule(province: str, wanted: dict[str, list[str]], now: datetime) -> set[str]:
    """Terminarz okregu trzyma obsade razem z nazwiskami - najpierw on, bez sieci."""
    ids = sorted({match_id for matches in wanted.values() for match_id in matches})
    found: set[str] = set()
    for start in range(0, len(ids), 500):
        rows = await database.fetch_all(
            select(province_matches.c.match_id, province_matches.c.state_json).where(
                and_(
                    province_matches.c.province.in_(spellings(province)),
                    province_matches.c.match_id.in_(ids[start : start + 500]),
                )
            )
        )
        for row in rows:
            hits = [
                item
                for item in officials_from_record(_state(row["state_json"]))
                if item["judge_id"] in wanted
            ]
            if hits:
                await remember_officials(hits, match_id=row["match_id"], now=now)
                found.update(item["judge_id"] for item in hits)
    return found


async def fill_missing_names(
    province: str,
    *,
    client: Optional[AsyncClient] = None,
    only: Optional[set[str]] = None,
    limit: int = 60,
) -> int:
    """
    Nazwiska dla sedziow z obsadami, ktorzy ich nie maja. Zwraca, ilu nazwalismy.

    `only` zaweza do konkretnych numerow (zestawienie jednego miesiaca), `limit`
    pilnuje, zeby jedno wywolanie nie zaczelo pytac API o setki meczow.
    """
    names = await judge_names(province)
    wanted = await _unnamed(province, names, only, limit)
    if not wanted:
        return 0

    now = _now()
    found = await _from_schedule(province, wanted, now)
    pending = {
        judge_id: matches
        for judge_id, matches in wanted.items()
        if judge_id not in found
        and now - _ATTEMPTS.get(judge_id, _EPOCH) > timedelta(hours=RETRY_HOURS)
    }

    async def ask(http: AsyncClient) -> None:
        semaphore = asyncio.Semaphore(CONCURRENCY)

        async def one(judge_id: str, matches: list[str]) -> None:
            async with semaphore:
                for match_id in matches:
                    payload = await fetch_details_payload(http, match_id, timeout=10.0)
                    officials = officials_from_payload(payload) if payload is not None else []
                    if officials:
                        # Cala obsada meczu - reszta nazwisk przyda sie za darmo.
                        await remember_officials(officials, match_id=match_id, now=now)
                    if any(item["judge_id"] == judge_id for item in officials):
                        found.add(judge_id)
                        return
                # Znacznik dopiero PO przejsciu meczow: pytanie przerwane limitem
                # czasu zestawienia ma sprobowac jeszcze raz przy nastepnym otwarciu.
                _ATTEMPTS[judge_id] = now

        await asyncio.gather(*(one(judge_id, matches) for judge_id, matches in pending.items()))

    if pending:
        if client is not None:
            await ask(client)
        else:
            async with AsyncClient(follow_redirects=True, timeout=15.0) as http:
                await ask(http)

    if found:
        logger.info("[settlement] %s: nazwiska z obsad meczow dla %d sedziow", province, len(found))
    return len(found)

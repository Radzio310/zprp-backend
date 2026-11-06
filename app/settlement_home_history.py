"""
Historia miejsca zamieszkania - baza i przeliczenie meczów sędziego (06.11.2026).

Reguły (dobór miasta dla dnia, odczyt listy przejazdów) siedzą w `settlement_home_rules`.
Tu: odczyt i zapis wpisów oraz `recompute_judge`, który od razu przestawia mecze sędziego
na właściwe miasto i liczy kilometry - panel i aplikacja widzą zmianę bez czekania na nocne
odświeżanie. Kolejność ważności: wpis okręgu > blokada z chwili rozliczenia > miasto z ZPRP.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timezone
from typing import Any

from sqlalchemy import and_, delete, select, update

from app import settlement_home_rules as H

logger = logging.getLogger(__name__)

#: Ile nowych pomiarów Google wolno zrobić przy jednym przeliczeniu sędziego.
GOOGLE_LIMIT = 20


def _s(value: Any) -> str:
    return " ".join(str(value or "").split())


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def load(province: str, judge_id: str | None = None) -> dict[str, list[tuple[date, str]]]:
    """judge_id -> [(ostatni dzień, miasto)] okręgu."""
    from app.db import database
    from app.db import province_settlement_home_history as T

    query = select(T.c.judge_id, T.c.valid_until, T.c.city).where(T.c.province == province)
    if judge_id:
        query = query.where(T.c.judge_id == _s(judge_id))
    out: dict[str, list[tuple[date, str]]] = {}
    for row in await database.fetch_all(query):
        out.setdefault(_s(row["judge_id"]), []).append((row["valid_until"], _s(row["city"])))
    return out


async def entries(province: str) -> list[dict]:
    from app.db import database
    from app.db import province_settlement_home_history as T

    rows = await database.fetch_all(
        select(T).where(T.c.province == province).order_by(T.c.judge_id, T.c.valid_until)
    )
    return [
        {
            "id": int(row["id"]),
            "judge_id": _s(row["judge_id"]),
            "city": _s(row["city"]),
            "until": row["valid_until"].isoformat() if row["valid_until"] else None,
            "source": _s(row["source"]) or H.SOURCE_MANUAL,
            "ref": _s(row["source_ref"]) or None,
            "created_by": _s(row["created_by"]) or None,
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        }
        for row in rows
    ]


async def save(
    province: str,
    judge_id: str,
    city: str,
    until: date,
    *,
    source: str = H.SOURCE_MANUAL,
    ref: str | None = None,
    user: str | None = None,
) -> int:
    """Wpis „do dnia `until` mieszkał w `city`" - ten sam dzień nadpisuje poprzedni wpis."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.db import database
    from app.db import province_settlement_home_history as T

    values = {
        "province": province,
        "judge_id": _s(judge_id),
        "city": _s(city),
        "valid_until": until,
        "source": source if source in H.SOURCES else H.SOURCE_MANUAL,
        "source_ref": _s(ref)[:120] or None,
        "created_by": _s(user)[:120] or None,
        "created_at": _now(),
    }
    statement = pg_insert(T).values(**values)
    await database.execute(
        statement.on_conflict_do_update(
            index_elements=[T.c.province, T.c.judge_id, T.c.valid_until],
            set_={k: statement.excluded[k] for k in ("city", "source", "source_ref", "created_by", "created_at")},
        )
    )
    row = await database.fetch_one(
        select(T.c.id).where(and_(T.c.province == province, T.c.judge_id == _s(judge_id), T.c.valid_until == until))
    )
    return int(row["id"]) if row else 0


async def remove(province: str, entry_id: int) -> str | None:
    """Usunięcie wpisu; zwraca numer sędziego (do przeliczenia) albo None."""
    from app.db import database
    from app.db import province_settlement_home_history as T

    row = await database.fetch_one(
        select(T.c.judge_id).where(and_(T.c.id == int(entry_id), T.c.province == province))
    )
    if row is None:
        return None
    await database.execute(delete(T).where(and_(T.c.id == int(entry_id), T.c.province == province)))
    return _s(row["judge_id"])


async def recompute_judge(province: str, judge_id: str) -> dict:
    """
    Mecze sędziego na właściwe miasto zamieszkania, z kilometrami - od razu.

    Mecz objęty wpisem okręgu dostaje miasto z wpisu (także rozliczony - to jawna
    korekta). Mecz bez wpisu: rozliczony zostaje, jak jest; nierozliczony bierze
    miasto z ZPRP. Wydane PDF-y się nie zmieniają (rejestr trzyma ich treść).
    """
    from app import national_lookup_rules as NL
    from app import route_atlas as RA
    from app import settlement_rates as R
    from app.db import database, okreg_distances
    from app.db import province_settlement_matches as M
    from app.national_distances import load_national_pairs
    from app.national_place_rules import province_label, province_slug
    from app.province_settlement_sync import _state
    from app.route_atlas_rules import Endpoint
    from app.settlement_distances import VersionedDistanceIndex, normalize_city
    from app.settlement_home_lock import current_home
    from app.settlement_province import spellings

    judge_id = _s(judge_id)
    history = (await load(province, judge_id)).get(judge_id) or []
    current = await current_home(province, judge_id)
    rows = await database.fetch_all(
        select(M).where(and_(M.c.province == province, M.c.judge_id == judge_id, M.c.active.is_(True)))
    )
    distance_row = await database.fetch_one(
        select(okreg_distances.c.content).where(okreg_distances.c.province.in_(spellings(province)))
    )
    book = VersionedDistanceIndex(_state(distance_row["content"]) if distance_row else None)
    national = await load_national_pairs()

    todo: list[dict] = []
    for row in rows:
        day = H.local_day(row["match_at"])
        declared = H.home_for(history, day)
        if declared:
            home = declared
        elif row["home_locked_at"] is not None:
            continue
        else:
            home = current
        if not home:
            continue
        if _s(row["home_city"]) == home and row["distance_km"] is not None:
            continue
        city = _s(row["city"])
        km, source = None, "none"
        if city:
            central = R.is_central_level_competition(row["match_code"])
            table_km = None if central else book.for_day(row["match_at"]).lookup(home, city)
            hit = NL.pick_distance(central, home=home, city=city, table_km=table_km, national=national, province=province)
            if hit is not None:
                km, source = hit
        todo.append({"key": row["match_key"], "home": home, "city": city, "km": km, "source": source})

    google = [item for item in todo if item["km"] is None and item["city"]]
    if google:
        try:
            from app.province_settlement_sync import _route_locator

            locate = _route_locator(province)
            region = province_label(province_slug(province))
            pairs: dict[tuple[str, str], Any] = {}
            for item in google:
                pair_key = (item["home"], item["city"])
                if pair_key in pairs:
                    continue
                start, end = locate(item["home"], item["city"])
                pairs[pair_key] = RA.Pair(
                    Endpoint(name=item["home"], region=region, hint=start),
                    Endpoint(
                        name=item["city"], directional=True, hint=end,
                        key=normalize_city(item["city"])[0] if "," in item["city"] else "",
                    ),
                )
            keys = list(pairs)
            measured = await RA.resolve([pairs[k] for k in keys], max_new=GOOGLE_LIMIT, need_shape=False)
            found = {k: r.km for k, r in zip(keys, measured) if r.km is not None}
            for item in google:
                km = found.get((item["home"], item["city"]))
                if km is not None:
                    item["km"], item["source"] = km, "google"
        except Exception:
            logger.warning("[settlement] %s: pomiar Google przy zmianie zamieszkania %s", province, judge_id, exc_info=True)

    if todo:
        from app.settlement_live import lock_province

        now = _now()
        async with database.transaction():
            await lock_province(province)
            for item in todo:
                await database.execute(
                    update(M)
                    .where(and_(M.c.province == province, M.c.judge_id == judge_id, M.c.match_key == item["key"]))
                    .values(home_city=item["home"], distance_km=item["km"], distance_source=item["source"], updated_at=now)
                )
    return {
        "judge_id": judge_id,
        "matches": len(todo),
        "missing_km": sum(1 for item in todo if item["km"] is None),
    }

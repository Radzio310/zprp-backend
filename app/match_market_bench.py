# app/match_market_bench.py
#
# Ławka rezerwowych zwykłej giełdy (decyzje 26.10.2026): przy każdym chętnym
# DOJAZD z domu do hali tego meczu i jego sezon (boisko, stolik).
#
# Kilometry idą tym samym łańcuchem, co przy ofertach obsadowego i w
# rozliczeniach: to samo miasto -> tabela okręgu wybrana DATĄ MECZU -> tabela
# ogólnopolska ZPRP -> pamięć Google. Brak danych = `None`, nigdy zmyślone zero.
#
# Dwie prędkości:
#  * lista ofert (`ask_google=False`) - tylko tablice i pamięć, żadnych
#    zapytań na zewnątrz; z tego powstaje „najbliższy dojazd" na kaflu;
#  * szczegóły oferty (`ask_google=True`) - brakujące pary dopytujemy w budżecie
#    3 s, a do tego sezon chętnych z rejestru rozliczeń.
#
# Część czysta (bez bazy) stoi na górze i jest testowana; baza i sieć są
# importowane w funkcjach, bo `app.db` łączy się przy imporcie.

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Mapping, Optional

logger = logging.getLogger("app.match_market")


def _s(value: Any) -> str:
    return str(value or "").strip()


# ───────────────────────────── część czysta ─────────────────────────────


def km_value(entry: Optional[Mapping[str, Any]]) -> Optional[float]:
    """Kilometry z wpisu ławki albo `None`, gdy źródła nie było."""
    if not entry:
        return None
    km = entry.get("km")
    if km is None:
        return None
    try:
        value = float(km)
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def nearest_km(bench: Mapping[str, Mapping[str, Any]], judge_ids: Iterable[str]) -> Optional[float]:
    """Najkrótszy znany dojazd spośród podanych chętnych (brak = None)."""
    known = [km_value(bench.get(_s(j))) for j in judge_ids]
    values = [v for v in known if v is not None]
    return min(values) if values else None


def bench_fields(entry: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Pola wiersza ławki w kształcie odpowiedzi HTTP (camelCase)."""
    entry = entry or {}
    season = entry.get("season")
    return {
        "km": km_value(entry),
        "kmSource": _s(entry.get("source")) or "unknown",
        "fromCity": _s(entry.get("from")) or None,
        "season": (
            {
                "field": int(season.get("field", 0) or 0),
                "table": int(season.get("table", 0) or 0),
                "total": int(season.get("field", 0) or 0) + int(season.get("table", 0) or 0),
            }
            if isinstance(season, Mapping)
            else None
        ),
    }


# ───────────────────────────── baza i sieć ─────────────────────────────


async def bench_metrics(
    province: str,
    jobs: List[Dict[str, Any]],
    *,
    ask_google: bool = False,
    with_season: bool = False,
) -> Dict[int, Dict[str, Dict[str, Any]]]:
    """
    `jobs` = [{"offer_id", "match_at", "state", "judge_ids"}] -> offer_id ->
    judge_id -> {"km", "source", "from", "season"}.

    Każdy błąd zamienia się w brak liczb, nie w błąd odpowiedzi - ławka bez
    kilometrów jest gorsza, ale oferta bez ławki byłaby awarią.
    """
    jobs = [j for j in jobs if j.get("judge_ids")]
    if not jobs:
        return {}
    try:
        return await _bench_metrics(province, jobs, ask_google=ask_google, with_season=with_season)
    except Exception:  # noqa: BLE001 - liczby to dodatek, nie warunek
        logger.warning("giełda: ławka bez kilometrów (%s)", province, exc_info=True)
        return {}


async def _bench_metrics(
    province: str,
    jobs: List[Dict[str, Any]],
    *,
    ask_google: bool,
    with_season: bool,
) -> Dict[int, Dict[str, Dict[str, Any]]]:
    from app import match_market_crew_rules as R
    from app import offtime_rules as O
    from app.db import database, okreg_distances
    from app.match_market_rules import state_dict
    from app.national_distances import load_national_pairs
    from app.national_lookup_rules import national_km
    from app.province_assignment_board import _world
    from app.settlement_distances import DistanceIndex, normalize_city, pick_distance_table
    from app.settlement_province import spellings
    from sqlalchemy import select

    world = await _world(province)
    roster, book = world.roster, world.book

    row = await database.fetch_one(
        select(okreg_distances.c.content).where(
            okreg_distances.c.province.in_(spellings(province) or [province])
        )
    )
    content: Any = row["content"] if row else None
    if isinstance(content, str):
        import json

        try:
            content = json.loads(content)
        except ValueError:
            content = None
    national = await load_national_pairs()

    def same_city(a: Any, b: Any) -> bool:
        left, right = normalize_city(a), normalize_city(b)
        return bool(left[0]) and (left[0] == right[0] or left[1] == right[1])

    indexes: Dict[Any, Any] = {}

    def index_for(day: Any) -> Any:
        if day not in indexes:
            indexes[day] = DistanceIndex(pick_distance_table(content, day))
        return indexes[day]

    def chain(index: Any, origin: Any, dest: Any) -> Dict[str, Any]:
        return R.km_chain(
            origin,
            dest,
            district=index.lookup,
            national=lambda a, b: national_km(national, a, b, province),
            remembered=lambda a, b: book._cache.get(book.key(a, b)) if book.key(a, b) else None,
            same_city=same_city,
        )

    prepared = []
    for job in jobs:
        moment = O.match_moment(job.get("match_at")) if job.get("match_at") else None
        day = moment.date() if moment else None
        city = _s(state_dict(job.get("state")).get("Hala_miasto"))
        origins = {_s(j): roster.city_of(_s(j), day) for j in job["judge_ids"] if _s(j)}
        prepared.append((job, day, city, origins))

    if ask_google:
        missing = [
            (origin, city)
            for _job, day, city, origins in prepared
            for origin in origins.values()
            if origin and city and chain(index_for(day), origin, city)["source"] == "unknown"
        ]
        if missing:
            try:
                import asyncio

                from app.assignment_distances import fill_missing

                await asyncio.wait_for(fill_missing(book, missing, budget=20), timeout=3.0)
            except Exception:  # noqa: BLE001 - brak km to unknown, nie błąd
                logger.info("giełda: kilometry ławki bez dopytania Google")

    season: Dict[str, Dict[str, int]] = {}
    if with_season:
        from app.province_settlements import season_load

        everyone = sorted({j for _job, _d, _c, origins in prepared for j in origins})
        try:
            season = await season_load(province, everyone)
        except Exception:  # noqa: BLE001
            logger.info("giełda: ławka bez liczników sezonu")
            season = {}

    out: Dict[int, Dict[str, Dict[str, Any]]] = {}
    for job, day, city, origins in prepared:
        rows: Dict[str, Dict[str, Any]] = {}
        for jid, origin in origins.items():
            km = chain(index_for(day), origin, city)
            rows[jid] = {
                "km": km.get("km"),
                "source": km.get("source"),
                "from": origin,
                "season": (season.get(jid) or {"field": 0, "table": 0}) if with_season else None,
            }
        out[int(job["offer_id"])] = rows
    return out

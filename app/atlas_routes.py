"""
POST /atlas/routes - Atlas tras dla klientow (BAZA, BAZA_web).

Wejscie: pary miejsc. Wyjscie: km + polilinia + zrodlo + data pomiaru. Pary
znane odpowiadaja z bazy bez kosztu; brakujace (i starsze niz 6 miesiecy)
mierzymy w Google ta sama metoda co rozliczenia, z limitem NOWYCH pomiarow na
zadanie. Logika w `app/route_atlas.py`.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app import route_atlas as RA
from app.deps import get_current_user
from app.route_atlas_rules import Endpoint

router = APIRouter(prefix="/atlas", tags=["Atlas tras"])

#: Par w jednym zadaniu.
MAX_PAIRS = 200
#: Twardy sufit NOWYCH pomiarow Google na zadanie (klient moze tylko zmniejszyc).
MAX_NEW_MEASUREMENTS = 25


class PlaceIn(BaseModel):
    name: str = Field("", max_length=200)
    lat: Optional[float] = Field(None, ge=-90, le=90)
    lon: Optional[float] = Field(None, ge=-180, le=180)
    #: Wojewodztwo rozstrzygajace imienniki (np. "slaskie"); wchodzi do klucza.
    region: str = Field("", max_length=60)


class RoutePairIn(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_: PlaceIn = Field(alias="from")
    to: PlaceIn


class RoutesIn(BaseModel):
    pairs: list[RoutePairIn]
    #: false = tylko odczyt z atlasu, zero pomiarow.
    measure: bool = True
    #: Ile nowych pomiarow wolno wykonac (przycinane do MAX_NEW_MEASUREMENTS).
    max_new: int = Field(MAX_NEW_MEASUREMENTS, ge=0)
    polyline: bool = True


def endpoint_of(place: PlaceIn) -> Endpoint:
    return Endpoint(
        name=place.name.strip(), lat=place.lat, lon=place.lon, region=place.region.strip()
    )


def _row(index: int, result: RA.Result, polyline: bool) -> dict:
    ok = result.km is not None
    return {
        "index": index,
        "status": result.status,
        "km": round(result.km, 1) if ok else None,
        "polyline": (result.encoded or None) if (ok and polyline) else None,
        "source": result.source or None,
        "measured_at": result.measured_at.isoformat() if result.measured_at else None,
        "reason": result.reason or None,
    }


async def run(data: RoutesIn, *, store: Optional[RA.AtlasStore] = None, client=None, measure=None) -> dict:
    if len(data.pairs) > MAX_PAIRS:
        raise HTTPException(400, f"Maksymalnie {MAX_PAIRS} par w jednym zadaniu")
    pairs = [RA.Pair(endpoint_of(p.from_), endpoint_of(p.to)) for p in data.pairs]
    limit = min(data.max_new, MAX_NEW_MEASUREMENTS) if data.measure else 0
    results = await RA.resolve(pairs, store=store, client=client, max_new=limit, measure=measure)
    rows = [_row(i, r, data.polyline) for i, r in enumerate(results)]
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return {
        "routes": rows,
        "stats": {
            "requested": len(rows),
            "cached": counts.get("cached", 0),
            "measured": counts.get("measured", 0),
            "stale": counts.get("stale", 0),
            "same": counts.get("same", 0),
            "missing": counts.get("missing", 0),
            "max_new": limit,
        },
    }


@router.post("/routes", summary="Odleglosci drogowe z Atlasu tras (km + polilinia)")
async def atlas_routes(data: RoutesIn, _user: str = Depends(get_current_user)):
    return await run(data)

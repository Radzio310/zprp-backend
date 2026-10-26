"""Mapa przejazdu w rozliczeniach - współrzędne końców tras (liść, bez bazy i sieci).

Panel BAZA_web rysuje trasę „skąd - dokąd" przy meczu sędziego. Serwer
dokłada tylko to, co ma w pamięci (skorowidz GeoNames): żadnych zapytań do
Google przy oglądaniu. Brak współrzędnych = `None`, ekran mówi to wprost.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

from app.national_place_rules import Gazetteer, haversine_km, province_slug


def place_point(
    gaz: Gazetteer,
    name: Any,
    province: Any = None,
    near: Optional[tuple[float, float]] = None,
) -> Optional[dict]:
    """
    Punkt miejscowości o tej nazwie.

    Imienników rozstrzyga: województwo okręgu (dom sędziego), potem
    najbliżej `near` (hala względem domu), potem największa liczba mieszkańców.
    """
    candidates = gaz.candidates(name) if name else []
    if not candidates:
        return None
    slug = province_slug(province)
    pool = [p for p in candidates if slug and p.province == slug] or candidates
    if near is not None and len(pool) > 1 and not (slug and any(p.province == slug for p in pool)):
        best = min(pool, key=lambda p: haversine_km(p.point, near))
    else:
        best = max(pool, key=lambda p: p.population)
    return {
        "lat": best.lat,
        "lon": best.lon,
        "province": best.province,
        "ambiguous": len({(p.province, round(p.lat, 1), round(p.lon, 1)) for p in candidates}) > 1,
    }


def build_route_map(rows: Iterable[Mapping[str, Any]], gaz: Gazetteer, province: Any) -> dict:
    """
    {"home": {...}|None, "home_city": str, "points": {miasto: punkt|None}}
    dla meczów jednego sędziego (dom = najczęstsze `home_city`).
    """
    rows = [r for r in rows if r]
    homes = [str(r.get("home_city") or "") for r in rows if r.get("home_city")]
    home_city = max(set(homes), key=homes.count) if homes else ""
    home = place_point(gaz, home_city, province) if home_city else None
    near = (home["lat"], home["lon"]) if home else None
    points: dict[str, Optional[dict]] = {}
    for row in rows:
        city = str(row.get("city") or "")
        if city and city not in points:
            points[city] = place_point(gaz, city, None, near)
    return {"home_city": home_city, "home": home, "points": points}

"""Mapa przejazdu w rozliczeniach - współrzędne końców tras (liść, bez bazy i sieci).

Panel BAZA_web rysuje trasę „skąd - dokąd" przy meczu sędziego. Serwer
dokłada tylko to, co ma w pamięci (skorowidz GeoNames): żadnych zapytań do
Google przy oglądaniu. Brak współrzędnych = `None`, ekran mówi to wprost.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

from app.national_place_rules import Gazetteer, haversine_km, province_slug


def _plain(value: Any) -> str:
    """Nazwa do porównania Z polskimi znakami (skorowidz składa „Gródków" z „Grodków")."""
    return " ".join(str(value or "").lower().replace("-", " ").replace(".", " ").split())


def _strict(candidates: list, name: Any) -> list:
    """Kandydaci o DOKŁADNEJ nazwie (z diakrytykami); gdy żaden - wszyscy."""
    exact = [p for p in candidates if _plain(p.name) == _plain(name)]
    return exact or candidates


def unique_point(gaz: Gazetteer, name: Any, province: Any = None) -> Optional[tuple[float, float]]:
    """
    Środek miejscowości TYLKO gdy nazwa wskazuje jedno miejsce (w województwie
    sędziego, gdy je podano). Imiennik = None: wołający pyta Google tekstem
    z adresem/województwem, zamiast zgadywać punkt.
    """
    candidates = _strict(gaz.candidates(name) if name else [], name)
    slug = province_slug(province)
    pool = [p for p in candidates if slug and p.province == slug] or candidates
    places = {(round(p.lat, 1), round(p.lon, 1)) for p in pool}
    if len(places) != 1:
        return None
    best = pool[0]
    return (best.lat, best.lon)


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
    candidates = _strict(gaz.candidates(name) if name else [], name)
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


def locator(gaz: Gazetteer, province: Any):
    """
    (dom, hala) -> (punkt domu, punkt hali) jako (lat, lon); None przy imienniku.

    Punkt tylko dla nazw jednoznacznych (`unique_point`) - skorowidz bywa
    nieostry, więc przy wątpliwości Google dostaje tekst, nie zgadnięty punkt.
    """

    def locate(origin: Any, destination: Any):
        return unique_point(gaz, origin, province), unique_point(gaz, destination)

    return locate

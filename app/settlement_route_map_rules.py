"""Mapa przejazdu w rozliczeniach - współrzędne końców tras (liść, bez bazy i sieci).

Panel BAZA_web rysuje trasę „skąd - dokąd" przy meczu sędziego. Serwer
dokłada tylko to, co ma w pamięci (skorowidz GeoNames): żadnych zapytań do
Google przy oglądaniu. Brak współrzędnych = `None`, ekran mówi to wprost.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

from app.national_place_rules import Gazetteer, haversine_km, province_label, province_slug


def _plain(value: Any) -> str:
    """Nazwa do porównania Z polskimi znakami (skorowidz składa „Gródków" z „Grodków")."""
    return " ".join(str(value or "").lower().replace("-", " ").replace(".", " ").split())


def _strict(candidates: list, name: Any) -> list:
    """Kandydaci o DOKŁADNEJ nazwie (z diakrytykami); gdy żaden - wszyscy."""
    exact = [p for p in candidates if _plain(p.name) == _plain(name)]
    return exact or candidates


#: Przymiotniki regionu doklejane do nazwy miejscowości („Nakło Śląskie").
_REGION_QUALIFIERS = frozenset({
    "slaskie", "slaska", "slaski", "wielkopolskie", "mazowieckie", "malopolskie",
    "podlaskie", "lubelskie", "pomorskie", "opolskie", "lubuskie",
})
#: Ile razy największa miejscowość musi przeważać nad drugą, by uznać ją za tę właściwą.
_DOMINANCE = 3


def _qualified_point(gaz: Gazetteer, name: Any, province: Any) -> Optional[tuple[float, float]]:
    """
    „Nakło Śląskie" nie ma w skorowidzu pod pełną nazwą (jest „Nakło" x2 w
    województwie), a goły tekst do Google trafiał w imiennika ok. 80 km dalej.
    Przymiotnik regionu zdejmujemy i bierzemy miejscowość z województwa
    sędziego, ale TYLKO gdy wyraźnie przeważa ludnością nad imiennikiem.
    """
    slug = province_slug(province)
    tokens = _plain(name).split(" ")
    if not slug or len(tokens) < 2:
        return None
    from app.national_place_rules import name_key

    if name_key(tokens[-1]) not in _REGION_QUALIFIERS:
        return None
    base = " ".join(tokens[:-1])
    pool = [p for p in _strict(gaz.candidates(base), base) if p.province == slug]
    if not pool:
        return None
    pool.sort(key=lambda p: p.population, reverse=True)
    if len(pool) > 1 and pool[0].population < _DOMINANCE * max(pool[1].population, 1):
        return None
    return (pool[0].lat, pool[0].lon)


def unique_point(gaz: Gazetteer, name: Any, province: Any = None) -> Optional[tuple[float, float]]:
    """
    Środek miejscowości TYLKO gdy nazwa wskazuje jedno miejsce (w województwie
    sędziego, gdy je podano). Imiennik = None: wołający pyta Google tekstem
    z adresem/województwem, zamiast zgadywać punkt.
    """
    found = gaz.candidates(name) if name else []
    if name and not found:
        return _qualified_point(gaz, name, province)
    candidates = _strict(found, name)
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


#: Największa odległość hali od miasta gospodarza, przy której ufamy, że wieloznaczna
#: nazwa hali („Dąbrowa" x96) to miejscowość z okolicy klubu.
HOST_RADIUS_KM = 60.0


def host_place(gaz: Gazetteer, teams: Any):
    """
    Miejscowość gospodarza z nazwy drużyny („GTV BUS Gwardia II Opole" -> Opole).
    Próbujemy końcówek nazwy (1-3 słowa), największa miejscowość wygrywa.
    """
    host = str(teams or "").split(" - ")[0].strip()
    words = host.replace(",", " ").split()
    for size in (3, 2, 1):
        if len(words) < size:
            continue
        tail = " ".join(words[-size:])
        pool = _strict(gaz.candidates(tail), tail)
        if pool:
            return max(pool, key=lambda p: p.population)
    return None


def hall_place(gaz: Gazetteer, city: Any, teams: Any):
    """
    Wieloznaczna nazwa hali rozstrzygnięta kontekstem: imiennik NAJBLIŻSZY
    miasta gospodarza (do HOST_RADIUS_KM). None = brak podstaw, nie zgadujemy.
    """
    pool = _strict(gaz.candidates(city) if city else [], city)
    if len({(round(p.lat, 1), round(p.lon, 1)) for p in pool}) < 2:
        return pool[0] if pool else None
    host = host_place(gaz, teams)
    if host is None:
        return None
    best = min(pool, key=lambda p: haversine_km(p.point, host.point))
    return best if haversine_km(best.point, host.point) <= HOST_RADIUS_KM else None


def hall_destination(gaz: Gazetteer, city: Any, address: Any, teams: Any = None) -> str:
    """
    Cel dla Google. Nazwa jednoznaczna zostaje sama. Wieloznaczna dostaje
    województwo imiennika bliskiego gospodarzowi: „Szkolna 9, Dąbrowa, opolskie".
    Bez kontekstu - jak dotąd: adres + miasto (albo samo miasto).
    """
    name = str(city or "").strip()
    street = str(address or "").strip()
    if unique_point(gaz, name) is not None:
        return name
    place = hall_place(gaz, name, teams)
    region = province_label(place.province) if place else ""
    if region:
        return ", ".join(x for x in (street, name, f"woj. {region}") if x)
    return f"{street} {name}" if street else name

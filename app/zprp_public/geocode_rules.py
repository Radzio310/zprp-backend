"""Reguły geokodera miejscowości (Nominatim) - bez bazy i bez sieci.

* `query_params`     - parametry zapytania strukturalnego (`city=`, `countrycodes=pl`),
* `parse_nominatim`  - odpowiedź jsonv2 -> punkt albo None (lepiej bez pinezki
                       niż pinezka w złym miejscu: tylko Polska, tylko miejscowość
                       albo jej część, nazwa musi się zgadzać),
* `due_for_lookup`   - czy nazwę wolno (znów) odpytać: brak wpisu albo porażka
                       starsza niż 30 dni; trafienia zostają na zawsze,
* `RateLimiter`      - najwyżej 1 zapytanie na sekundę na cały proces,
* `order_candidates` - kolejność: mecze najbliższe w czasie, potem kluby, potem reszta hal.

Adresy hal (pinezka na hali, nie w środku miasta) - niski priorytet, po miastach:

* `venue_addr_key`        - klucz pamięci: znormalizowane (miasto, ulica z numerem),
* `address_queries`       - co pytamy: ulica z numerem, potem sama ulica,
* `address_query_params`  - zapytanie strukturalne (`street=`, `city=`, `countrycodes=pl`),
* `parse_address`         - wynik przyjęty tylko jako budynek / obiekt / ulica
                            najwyżej ~15 km od punktu miasta (bez powiatów,
                            województw i środków miejscowości).
"""

from __future__ import annotations

import asyncio
import math
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, AsyncIterator, Awaitable, Callable, Iterable, Optional

from app.national_distance_parser import normalize_city_key

NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"
USER_AGENT = "BAZA-pod-Reka/1.0 (bazapodreka.app)"
RETRY_AFTER = timedelta(days=30)
MIN_INTERVAL = 1.1  # s - zasady Nominatim: najwyżej 1 zapytanie/s (z zapasem)

# Polska z marginesem (49,00-54,84 N, 14,12-24,15 E).
_LAT = (48.9, 55.0)
_LON = (14.0, 24.3)

# Miejscowość albo jej część. Bez powiatów, województw i gmin wiejskich -
# ich środek to nie miasto (lepiej bez pinezki niż w polu).
PLACE_TYPES = frozenset({
    "city", "town", "village", "hamlet", "suburb", "quarter", "neighbourhood", "city_district",
    "borough", "isolated_dwelling", "locality", "allotments",
})


def city_norm(name: object) -> str:
    return normalize_city_key(str(name or ""))


def query_params(city: str, state: str = "") -> dict[str, Any]:
    params: dict[str, Any] = {"format": "jsonv2", "countrycodes": "pl", "city": city, "limit": 1}
    if state:
        params["state"] = state
    return params


def _same_name(found: object, wanted: str) -> bool:
    """Nazwa wyniku musi pasować do pytanej: równa, albo jedna to końcówka/początek
    drugiej po całych słowach („Warszawa Bemowo" ~ „Bemowo")."""
    a, b = city_norm(found), city_norm(wanted)
    if not a or not b:
        return False
    if a == b:
        return True
    wa, wb = a.split(), b.split()
    short, long_ = (wa, wb) if len(wa) <= len(wb) else (wb, wa)
    n = len(short)
    return long_[:n] == short or long_[-n:] == short


def parse_nominatim(payload: Any, city: str) -> Optional[dict[str, Any]]:
    """Pierwszy sensowny wynik jsonv2 -> {lat, lon, name, display_name, place_type} albo None."""
    if not isinstance(payload, list):
        return None
    for item in payload[:3]:
        if not isinstance(item, dict):
            continue
        try:
            lat, lon = float(item["lat"]), float(item["lon"])
        except (KeyError, TypeError, ValueError):
            continue
        if not (_LAT[0] <= lat <= _LAT[1] and _LON[0] <= lon <= _LON[1]):
            continue
        kind = str(item.get("addresstype") or item.get("type") or "")
        if kind not in PLACE_TYPES:
            continue
        name = item.get("name") or str(item.get("display_name") or "").split(",")[0]
        if not _same_name(name, city):
            continue
        return {"lat": round(lat, 6), "lon": round(lon, 6), "name": str(name), "display_name": item.get("display_name"),
                "place_type": kind}
    return None


# ---------------------------------------------------------------------------
# Adres hali (ulica)
# ---------------------------------------------------------------------------

# Klasa wyniku Nominatim, która może być halą albo jej ulicą.
ADDRESS_CLASSES = frozenset({"building", "amenity", "leisure", "highway", "place"})
# Jednostki administracyjne - ich środek to nie hala.
ADDRESS_REJECT_TYPES = frozenset({
    "county", "state", "province", "region", "country", "municipality", "administrative", "district",
    "state_district", "postcode",
})
ADDRESS_MAX_KM = 15.0

_STREET_PREFIX = re.compile(r"^\s*(ul\.?|ulica)\s+", re.IGNORECASE)
_STREET_ABBR = (
    (re.compile(r"^\s*al\.?\s+", re.IGNORECASE), "aleja "),
    (re.compile(r"^\s*os\.?\s+", re.IGNORECASE), "osiedle "),
    (re.compile(r"^\s*pl\.?\s+", re.IGNORECASE), "plac "),
)


def clean_street(street: object) -> str:
    """„ul. Sportowa” -> „Sportowa”, „al. Pokoju” -> „aleja Pokoju” (Nominatim nie zna skrótów)."""
    text = re.sub(r"\s+", " ", str(street or "")).strip(" ,.;")
    text = _STREET_PREFIX.sub("", text)
    for pattern, full in _STREET_ABBR:
        text = pattern.sub(full, text)
    return text.strip()


def _street_line(street: object, number: object) -> str:
    base = clean_street(street)
    num = str(number or "").strip(" ,.;")
    if not base:
        return ""
    # Numer bywa już w polu ulicy („Sportowa 5”).
    if num and not re.search(r"\d", base):
        return f"{base} {num}"
    return base


def venue_addr_key(city: object, street: object, number: object = None) -> str:
    """Klucz pamięci adresu hali: „kielce|sportowa 5” (pusty, gdy brak miasta albo ulicy)."""
    c = city_norm(city)
    s = city_norm(_street_line(street, number))
    return f"{c}|{s}" if c and s else ""


def address_queries(street: object, number: object = None) -> list[str]:
    """Ulica z numerem (Nominatim: „5 Sportowa” / „Sportowa 5” - podajemy jak w danych),
    potem sama ulica (punkt ulicy też leży przy hali, lepiej niż środek miasta)."""
    full = _street_line(street, number)
    bare = re.sub(r"\s+\d+[\w/-]*$", "", full).strip()
    out = [q for q in (full, bare) if q]
    return list(dict.fromkeys(out))


def address_query_params(street: str, city: str) -> dict[str, Any]:
    return {"format": "jsonv2", "countrycodes": "pl", "street": street, "city": city, "limit": 1}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))


def parse_address(payload: Any, city_lat: float, city_lon: float, max_km: float = ADDRESS_MAX_KM) -> Optional[dict[str, Any]]:
    """Wynik jsonv2 zapytania o ulicę -> {lat, lon, display_name, place_class, place_type, km} albo None.

    Przyjmujemy tylko budynek / obiekt / teren sportowy / ulicę (klasa) w Polsce,
    najwyżej `max_km` od punktu miasta hali. Powiat, województwo, gmina albo
    środek samej miejscowości (`place=city/town/...`) odpadają - to nie hala."""
    if not isinstance(payload, list):
        return None
    for item in payload[:3]:
        if not isinstance(item, dict):
            continue
        try:
            lat, lon = float(item["lat"]), float(item["lon"])
        except (KeyError, TypeError, ValueError):
            continue
        if not (_LAT[0] <= lat <= _LAT[1] and _LON[0] <= lon <= _LON[1]):
            continue
        klass = str(item.get("category") or item.get("class") or "")
        kind = str(item.get("type") or "")
        addresstype = str(item.get("addresstype") or "")
        if klass not in ADDRESS_CLASSES:
            continue
        if kind in ADDRESS_REJECT_TYPES or addresstype in ADDRESS_REJECT_TYPES:
            continue
        if klass == "place" and (kind in PLACE_TYPES or addresstype in PLACE_TYPES):
            continue
        km = haversine_km(lat, lon, city_lat, city_lon)
        if km > max_km:
            continue
        return {"lat": round(lat, 6), "lon": round(lon, 6), "display_name": item.get("display_name"),
                "place_class": klass, "place_type": kind or addresstype or None, "km": round(km, 2)}
    return None


def due_for_lookup(row: Optional[dict], now: datetime) -> bool:
    if not row:
        return True
    if not row.get("failed") and row.get("lat") is not None:
        return False
    at = row.get("looked_up_at")
    if not isinstance(at, datetime):
        return True
    if at.tzinfo is None and now.tzinfo is not None:
        at = at.replace(tzinfo=now.tzinfo)
    return now - at >= RETRY_AFTER


def query_names(display: str) -> list[str]:
    """Co pytamy: pełna nazwa, a dla „Warszawa-Bemowo" także człon przed łącznikiem
    (pinezka w mieście dzielnicy jest prawdziwa, tylko mniej dokładna)."""
    names = [display.strip()]
    if "-" in display:
        head = display.split("-", 1)[0].strip()
        if len(head) >= 3 and head not in names:
            names.append(head)
    return [n for n in names if n]


def order_candidates(
    match_rows: Iterable[dict],
    club_rows: Iterable[dict],
    venue_rows: Iterable[dict],
    now: datetime,
) -> list[dict]:
    """Kandydaci bez duplikatów (po `city_norm`), w kolejności ważności.

    `match_rows`: {city, hint, scheduled_at} - mecze z okna wokół dziś,
    najbliższe w czasie najpierw (nadchodzące przed dawnymi przy remisie odległości);
    `club_rows`: {city, hint}; `venue_rows`: {city, hint, n} - reszta hal wg liczby meczów."""
    out: list[dict] = []
    seen: set[str] = set()

    def push(city: object, hint: str, reason: str) -> None:
        key = city_norm(city)
        if not key or key in seen:
            return
        seen.add(key)
        out.append({"city": str(city), "hint": hint or "", "reason": reason})

    def dist(row: dict) -> tuple[float, int]:
        at = row.get("scheduled_at")
        if not isinstance(at, datetime):
            return (float("inf"), 1)
        if at.tzinfo is not None and now.tzinfo is None:
            at = at.replace(tzinfo=None)
        delta = (at - now).total_seconds()
        return (abs(delta), 0 if delta >= 0 else 1)

    for row in sorted(match_rows, key=dist):
        push(row.get("city"), row.get("hint") or "", "match")
    for row in club_rows:
        push(row.get("city"), row.get("hint") or "", "club")
    for row in sorted(venue_rows, key=lambda r: -int(r.get("n") or 0)):
        push(row.get("city"), row.get("hint") or "", "venue")
    return out


class RateLimiter:
    """Odstęp >= `interval` s między początkami kolejnych zapytań, w całym procesie.

    `clock`/`sleep` do podmiany w testach. `slot()` trzyma blokadę przez całe
    zapytanie, więc dwa równoległe geokodery nie przepchną dwóch naraz."""

    def __init__(self, interval: float = MIN_INTERVAL,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep):
        self.interval = interval
        self._clock = clock
        self._sleep = sleep
        self._last: Optional[float] = None
        self._lock: Optional[asyncio.Lock] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _get_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._lock is None or self._loop is not loop:  # nowa pętla (testy) = nowa blokada
            self._lock, self._loop = asyncio.Lock(), loop
        return self._lock

    async def _wait(self) -> None:
        if self._last is not None:
            pause = self._last + self.interval - self._clock()
            if pause > 0:
                await self._sleep(pause)
        self._last = self._clock()

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        async with self._get_lock():
            await self._wait()
            yield


# Jeden ogranicznik na proces - dzielą go geokoder portalu i tabela odległości.
NOMINATIM_LIMITER = RateLimiter()

"""
Atlas tras - czyste reguly: klucze par, swiezosc, terminy ponowien.

Bez bazy i bez sieci, zeby dalo sie je sprawdzic samym testem.

KLUCZ KANONICZNY PARY
  * koniec trasy ("miejsce") ma klucz:
      - wspolrzedne zaokraglone do 3 miejsc ("@50.294,18.655", ok. 100 m), gdy sa;
      - inaczej nazwa po `normalize_city` (bez diakrytykow, skrotow, wielkosci
        liter), z dopiskiem "|<wojewodztwo>" gdy podano region (imienniki:
        "Lipnik" ze slaskiego to nie "Lipnik" z malopolskiego);
      - albo klucz narzucony (`Endpoint.key`) - tylko dla zgodnosci z pomiarami
        sprzed atlasu.
  * para BEZ adresu kierunkowego jest symetryczna: "a~b" z a <= b.
  * para z adresem (hala), z `directional` albo narzuconym kluczem jest
    kierunkowa: "a>b" (dom -> hala).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional

from app.settlement_distances import normalize_city

#: Pomiar starszy niz to jest mierzony od nowa przy NASTEPNYM uzyciu (leniwie).
#: Nowy wynik dotyczy przyszlych wyliczen, zapisanych rozliczen nie ruszamy.
MAX_AGE = timedelta(days=183)

#: Czas, przez ktory nie ponawiamy pomiaru po porazce. Blad przejsciowy
#: (timeout, limit, siec) rosnie wykladniczo: 1 h, 2 h, 4 h ... do doby.
TRANSIENT_BASE = timedelta(hours=1)
TRANSIENT_MAX = timedelta(hours=24)
#: Google jednoznacznie: trasy nie ma (ZERO_RESULTS / NOT_FOUND).
NO_ROUTE_RETRY = timedelta(days=30)
#: Km znane, geometrii Google nie dal.
NO_SHAPE_RETRY = timedelta(days=30)

#: Zrodlo pomiaru metoda produkcyjna (4 zapytania Directions, minimum).
SOURCE_MEASURED = "google-shortest-r3"
#: Zrodlo wierszy przejetych z `city_distances` (obsada, ta sama metoda bez regionu).
SOURCE_LEGACY = "google-legacy"

COORD_DECIMALS = 3


@dataclass(frozen=True)
class Endpoint:
    """Jeden koniec trasy. Tylko `name` albo wspolrzedne sa wymagane."""

    name: str = ""
    lat: Optional[float] = None
    lon: Optional[float] = None
    region: str = ""
    #: Adres (np. hali) - czyni pare kierunkowa i wchodzi do klucza.
    address: str = ""
    #: Para kierunkowa mimo braku adresu (dom -> hala).
    directional: bool = False
    #: Narzucony klucz - zgodnosc z pomiarami sprzed atlasu. Nie z API.
    key: str = ""
    #: Punkt do pomiaru, gdy nie ma lat/lon - NIE wchodzi do klucza.
    hint: Optional[tuple[float, float]] = None


def valid_point(lat: Any, lon: Any) -> Optional[tuple[float, float]]:
    try:
        a, b = float(lat), float(lon)
    except (TypeError, ValueError):
        return None
    if not (math.isfinite(a) and math.isfinite(b)) or abs(a) > 90 or abs(b) > 180:
        return None
    return a, b


def _label(text: Any) -> str:
    """Nazwa -> postac znormalizowana; czlony po przecinku normalizowane osobno."""
    parts = [normalize_city(part)[0] for part in str(text or "").split(",")]
    return ",".join(part for part in parts if part)


def _region_slug(region: str) -> str:
    text = str(region or "").strip()
    if not text:
        return ""
    try:
        from app.national_place_rules import province_slug

        slug = province_slug(text)
    except Exception:
        slug = ""
    return slug or normalize_city(text.replace("woj.", ""))[0].replace(" ", "-")


def endpoint_key(endpoint: Endpoint) -> str:
    if endpoint.key:
        return endpoint.key
    point = valid_point(endpoint.lat, endpoint.lon)
    if point is not None:
        base = f"@{point[0]:.{COORD_DECIMALS}f},{point[1]:.{COORD_DECIMALS}f}"
    else:
        base = _label(endpoint.name)
        if not base:
            return ""
        region = _region_slug(endpoint.region)
        if region:
            base = f"{base}|{region}"
    address = _label(endpoint.address)
    return f"{base}#{address}" if address else base


def is_directional(a: Endpoint, b: Endpoint) -> bool:
    return any(e.address or e.directional or e.key for e in (a, b))


def pair_key(a: Endpoint, b: Endpoint) -> str:
    """Klucz kanoniczny pary albo "" gdy ktorys koniec jest pusty."""
    left, right = endpoint_key(a), endpoint_key(b)
    if not left or not right:
        return ""
    if is_directional(a, b):
        return f"{left}>{right}"
    return f"{left}~{right}" if left <= right else f"{right}~{left}"


def is_fresh(measured_at: Optional[datetime], now: datetime) -> bool:
    return measured_at is not None and (now - measured_at) <= MAX_AGE


def transient_delay(attempts: int) -> timedelta:
    n = max(1, int(attempts))
    return min(TRANSIENT_BASE * (2 ** (n - 1)), TRANSIENT_MAX)


def retry_after(kind: str, attempts: int, now: datetime) -> datetime:
    if kind == "no_route":
        return now + NO_ROUTE_RETRY
    if kind == "noshape":
        return now + NO_SHAPE_RETRY
    return now + transient_delay(attempts)

"""
Odleglosci miasto-miasto: tabela okregowa, a gdy pary w niej nie ma - Google.

Port `extractPairsFromDistanceContent` i `findDistanceInOkregTable`
z `BAZA/utils/okreg.ts`, z jedna zmiana: indeks budujemy RAZ. Oryginal
przebudowuje go przy KAZDYM zapytaniu, co przy jednym sedzim jest bez
znaczenia, ale tutaj pytan sa tysiace (kazdy sedzia x kazdy mecz).

MODUL-LISC w czesci tabelarycznej - Google siedzi w osobnej funkcji, ktora
przyjmuje gotowego klienta HTTP, zeby reszte dalo sie sprawdzic testem.
"""

from __future__ import annotations

import logging
import os
import re
import unicodedata
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

GOOGLE_MAPS_API_KEY = (os.getenv("GOOGLE_MAPS_API_KEY") or "").strip()

#: Rozwiniecia skrotow, ktore ZPRP zapisuje przy miastach.
_ABBREV = (
    (r"\([^)]*\)", " "),
    (r"\bś[lł]\.?\b", "Śląskie"),
    (r"\bsl\.?\b", "Śląskie"),
    (r"\bwlkp\.?\b", "Wielkopolskie"),
    (r"\bwlk\.?\b", "Wielkie"),
    (r"\bmaz\.?\b", "Mazowieckie"),
    (r"\bmal\.?\b", "Małopolskie"),
    (r"\bpodl\.?\b", "Podlaskie"),
    (r"\bzach[- ]?pom\.?\b", "Zachodniopomorskie"),
    (r"\bkuj[- ]?pom\.?\b", "Kujawsko-Pomorskie"),
)


def _strip_dia(value: str) -> str:
    text = str(value or "").replace("Ł", "L").replace("ł", "l")
    return "".join(
        ch for ch in unicodedata.normalize("NFD", text)
        if unicodedata.category(ch) != "Mn"
    )


def normalize_city(raw: Any) -> tuple[str, str]:
    """
    Miasto w dwoch postaciach: „bazowej" (ze spacjami) i „scisnietej".

    Dwie, bo ta sama miejscowosc bywa zapisana i „Piekary Sl." i „PiekarySl" -
    a tabela odleglosci i terminarz nie musza sie co do znaku zgadzac.
    """
    text = str(raw or "").split(",")[0]
    text = re.sub(r"^\d{2}-\d{3}\s*", "", text).strip()
    for pattern, replacement in _ABBREV:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    text = _strip_dia(text).lower()
    text = re.sub(r"['’\"]", "", text)
    text = text.replace(".", " ")
    text = re.sub(r"[-–—/]", " ", text)
    base = " ".join(text.split()).strip()
    return base, base.replace(" ", "")


def extract_pairs(content: Any) -> list[tuple[str, str, float]]:
    """Cztery formaty, ktorymi bywa karmiony panel administracyjny."""
    out: list[tuple[str, str, float]] = []
    if not content:
        return out

    if isinstance(content, dict) and isinstance(content.get("cities"), list):
        cities = content["cities"]
        # { cities, edges }
        if isinstance(content.get("edges"), list):
            for edge in content["edges"]:
                if not isinstance(edge, dict):
                    continue
                a = edge.get("from") or edge.get("A") or edge.get("cityA")
                b = edge.get("to") or edge.get("B") or edge.get("cityB")
                value = edge.get("distance_km", edge.get("km", edge.get("distance", edge.get("odleglosc"))))
                if a and b and isinstance(value, (int, float)):
                    out.append((str(a), str(b), float(value)))
            return out
        # { cities, matrix }
        if isinstance(content.get("matrix"), list):
            matrix = content["matrix"]
            for i, city_a in enumerate(cities):
                row = matrix[i] if i < len(matrix) else None
                if not isinstance(row, list):
                    continue
                for j, city_b in enumerate(cities):
                    value = row[j] if j < len(row) else None
                    if isinstance(value, (int, float)):
                        out.append((str(city_a), str(city_b), float(value)))
            return out

    # mapa -> mapa
    if isinstance(content, dict):
        for a, row in content.items():
            if not isinstance(row, dict):
                continue
            for b, value in row.items():
                if isinstance(value, (int, float)):
                    out.append((str(a), str(b), float(value)))
        return out

    # tablica rekordow
    if isinstance(content, list):
        for record in content:
            if not isinstance(record, dict):
                continue
            a = record.get("from") or record.get("A") or record.get("miastoA") or record.get("start")
            b = record.get("to") or record.get("B") or record.get("miastoB") or record.get("end")
            value = record.get("distance_km", record.get("km", record.get("distance", record.get("odleglosc"))))
            if a and b and isinstance(value, (int, float)):
                out.append((str(a), str(b), float(value)))
    return out


class DistanceIndex:
    """Indeks budowany RAZ, odpytywany tysiace razy."""

    __slots__ = ("_map", "pairs")

    def __init__(self, content: Any = None) -> None:
        self._map: dict[tuple[str, str], float] = {}
        pairs = extract_pairs(content)
        for a, b, km in pairs:
            na_base, na_tight = normalize_city(a)
            nb_base, nb_tight = normalize_city(b)
            for left in (na_base, na_tight):
                for right in (nb_base, nb_tight):
                    if not left or not right:
                        continue
                    self._map[(left, right)] = km
                    self._map[(right, left)] = km
        self.pairs = len(pairs)

    def lookup(self, origin: Any, destination: Any) -> Optional[float]:
        a_base, a_tight = normalize_city(origin)
        b_base, b_tight = normalize_city(destination)
        if not a_base or not b_base:
            return None
        # To samo miasto = 0 km. Sprawdzamy PRZED tabela, bo pary „miasto do
        # samego siebie" zwykle w niej nie ma, a odleglosc jest oczywista.
        if a_base == b_base or a_tight == b_tight:
            return 0.0
        for left in (a_base, a_tight):
            for right in (b_base, b_tight):
                hit = self._map.get((left, right))
                if hit is not None:
                    return hit
        return None


async def google_distance(client: Any, origin: str, destination: str) -> Optional[float]:
    """
    Jedna para przez Google Distance Matrix.

    `client` to gotowy `httpx.AsyncClient` - dzieki temu wolajacy panuje nad
    limitem czasu i liczba polaczen, a modul nie otwiera wlasnych.
    """
    if not GOOGLE_MAPS_API_KEY:
        return None
    if not origin or not destination:
        return None
    try:
        response = await client.get(
            "https://maps.googleapis.com/maps/api/distancematrix/json",
            params={
                "origins": f"{origin}, Polska",
                "destinations": f"{destination}, Polska",
                "mode": "driving",
                "avoid": "tolls",
                "language": "pl",
                "region": "PL",
                "key": GOOGLE_MAPS_API_KEY,
            },
        )
        data = response.json()
        if data.get("status") != "OK":
            return None
        element = ((data.get("rows") or [{}])[0].get("elements") or [{}])[0]
        if element.get("status") != "OK":
            return None
        meters = (element.get("distance") or {}).get("value")
        return round(float(meters) / 1000.0, 1) if isinstance(meters, (int, float)) else None
    except Exception as exc:
        logger.debug("[settlement] google distance %s->%s: %s", origin, destination, exc)
        return None


async def resolve_distances(
    pairs: Iterable[tuple[str, str]],
    index: DistanceIndex,
    *,
    client: Any = None,
    cache: Optional[dict[tuple[str, str], Optional[float]]] = None,
) -> dict[tuple[str, str], tuple[Optional[float], str]]:
    """
    Para miast -> (kilometry, zrodlo).

    Zrodlo: "same-city" | "table" | "google" | "none". Brak wyniku NIE jest
    zerem: mecz bez odleglosci dostaje status „brak dojazdu" i widac, ze kwoty
    trzeba uzupelnic, zamiast po cichu placic 0 zl.
    """
    cache = cache if cache is not None else {}
    out: dict[tuple[str, str], tuple[Optional[float], str]] = {}

    for origin, destination in pairs:
        key = (normalize_city(origin)[0], normalize_city(destination)[0])
        if key in out:
            continue
        if key in cache:
            value = cache[key]
            out[(origin, destination)] = (value, "google" if value is not None else "none")
            continue

        table_hit = index.lookup(origin, destination)
        if table_hit is not None:
            out[(origin, destination)] = (table_hit, "same-city" if table_hit == 0 else "table")
            continue

        value = await google_distance(client, origin, destination) if client is not None else None
        cache[key] = value
        out[(origin, destination)] = (value, "google" if value is not None else "none")

    return out

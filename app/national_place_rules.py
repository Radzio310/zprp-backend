"""Położenie miejscowości ogólnopolskiej tabeli odległości - liść bez bazy.

PROBLEM (15.10.2026). Serwer geokodował każdą nazwę z ryczałtu RAZ, przez
Nominatim, bez województwa („Gać, Polska", limit 1). Polska ma kilkadziesiąt
Dąbrów, kilka Gaci i Mirosławic, więc część miejscowości stała na mapie
o 100-300 km od miejsca, do którego naprawdę jeżdżą sędziowie, a dwie różne
Krzywe (i dwie Mirosławice) zlewały się w jeden punkt.

ROZWIĄZANIE. Tożsamość miejscowości = nazwa + rozpoznane miejsce (węzeł).
Kandydaci na miejsce pochodzą ze skorowidza GeoNames (`app/data/pl_places.tsv.gz`).
Głównym dowodem są kilometry z ryczałtów: droga ma zwykle ok. 1,22-1,27 długości
odcinka w linii prostej (zmierzone na tabeli: mediana 1,22, IQR 1,16-1,28),
więc trasa „X - Wrocław 160 km" wskazuje, która z Gaci to ta właściwa.
Wskazówki z dokumentu (województwo sędziego, kod pocztowy, związek prowadzący
rozgrywki) są tylko słabym priorytetem, który rozstrzyga remisy.

Tu siedzą wyłącznie reguły i algorytm. Baza, Nominatim i OSRM są w
`app/national_distances.py` / `app/national_places.py` (`app.db` łączy się przy
imporcie, więc liść da się sprawdzić testem bez bazy).

Dane miejscowości: GeoNames (www.geonames.org), licencja Creative Commons
Attribution 4.0 (https://creativecommons.org/licenses/by/4.0/). Plik budujemy
skryptem `scripts/build_pl_places.py`.
"""

from __future__ import annotations

import gzip
import math
import re
import statistics
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

from app.national_distance_parser import clean_city, normalize_city_key

GAZETTEER_PATH = Path(__file__).resolve().parent / "data" / "pl_places.tsv.gz"

# ---------------------------------------------------------------------------
# Województwa
# ---------------------------------------------------------------------------

VOIVODESHIPS: dict[str, str] = {
    "dolnoslaskie": "dolnośląskie",
    "kujawsko-pomorskie": "kujawsko-pomorskie",
    "lubelskie": "lubelskie",
    "lubuskie": "lubuskie",
    "lodzkie": "łódzkie",
    "malopolskie": "małopolskie",
    "mazowieckie": "mazowieckie",
    "opolskie": "opolskie",
    "podkarpackie": "podkarpackie",
    "podlaskie": "podlaskie",
    "pomorskie": "pomorskie",
    "slaskie": "śląskie",
    "swietokrzyskie": "świętokrzyskie",
    "warminsko-mazurskie": "warmińsko-mazurskie",
    "wielkopolskie": "wielkopolskie",
    "zachodniopomorskie": "zachodniopomorskie",
}

#: Kolejność ma znaczenie: „dolnośląskie" przed „śląskie", obie odmiany
#: pomorskiego przed samym „pomorskie" (tak samo jak `utils/matchLocation.ts`).
_PROVINCE_MARKERS: tuple[tuple[str, str], ...] = (
    ("dolnosl", "dolnoslaskie"),
    ("kujawsko pomors", "kujawsko-pomorskie"),
    ("kujawskopomors", "kujawsko-pomorskie"),
    ("lubelsk", "lubelskie"),
    ("lubusk", "lubuskie"),
    ("lodz", "lodzkie"),
    ("malopolsk", "malopolskie"),
    ("mazowieck", "mazowieckie"),
    ("opolsk", "opolskie"),
    ("podkarpack", "podkarpackie"),
    ("podlask", "podlaskie"),
    ("zachodniopomors", "zachodniopomorskie"),
    ("warminsko mazur", "warminsko-mazurskie"),
    ("warminskomazur", "warminsko-mazurskie"),
    ("pomorsk", "pomorskie"),
    ("slask", "slaskie"),
    ("swietokrzys", "swietokrzyskie"),
    ("wielkopolsk", "wielkopolskie"),
)


def province_slug(value: object) -> str:
    """Dowolny zapis województwa / związku („Śląski ZPRP", „ŚLĄSKIE",
    „warmińsko-mazurskie") -> klucz z `VOIVODESHIPS` albo pusty napis.

    Rozgrywki centralne (departament, „centralne") nie mają województwa."""
    text = normalize_city_key(str(value or ""))
    if not text:
        return ""
    if text.replace(" ", "-") in VOIVODESHIPS:
        return text.replace(" ", "-")
    if "departament" in text or "central" in text:
        return ""
    for marker, slug in _PROVINCE_MARKERS:
        if marker in text:
            return slug
    return ""


def province_label(slug: str) -> str:
    return VOIVODESHIPS.get(slug or "", "")


#: Dwie pierwsze cyfry kodu pocztowego -> województwa, w których taki kod
#: występuje. Zgrubne (okręgi pocztowe nie pokrywają się z granicami), dlatego
#: to tylko słaba wskazówka - nigdy rozstrzygnięcie.
_POSTAL_RANGES: tuple[tuple[int, int, tuple[str, ...]], ...] = (
    (0, 9, ("mazowieckie",)),
    (10, 14, ("warminsko-mazurskie",)),
    (15, 18, ("podlaskie",)),
    (19, 19, ("podlaskie", "warminsko-mazurskie")),
    (20, 24, ("lubelskie",)),
    (25, 25, ("swietokrzyskie",)),
    (26, 26, ("swietokrzyskie", "mazowieckie")),
    (27, 29, ("swietokrzyskie",)),
    (30, 33, ("malopolskie",)),
    (34, 34, ("malopolskie", "slaskie")),
    (35, 39, ("podkarpackie",)),
    (40, 44, ("slaskie",)),
    (45, 46, ("opolskie",)),
    (47, 47, ("opolskie", "slaskie")),
    (48, 49, ("opolskie",)),
    (50, 59, ("dolnoslaskie",)),
    (60, 64, ("wielkopolskie",)),
    (65, 66, ("lubuskie",)),
    (67, 67, ("lubuskie", "dolnoslaskie")),
    (68, 69, ("lubuskie",)),
    (70, 75, ("zachodniopomorskie",)),
    (76, 77, ("zachodniopomorskie", "pomorskie")),
    (78, 78, ("zachodniopomorskie",)),
    (80, 81, ("pomorskie",)),
    (82, 82, ("pomorskie", "warminsko-mazurskie")),
    (83, 84, ("pomorskie",)),
    (85, 88, ("kujawsko-pomorskie",)),
    (89, 89, ("kujawsko-pomorskie", "pomorskie", "wielkopolskie")),
    (90, 95, ("lodzkie",)),
    (96, 96, ("lodzkie", "mazowieckie")),
    (97, 99, ("lodzkie",)),
)


def postal_provinces(code: object) -> tuple[str, ...]:
    """Województwa możliwe dla kodu pocztowego („43-300" -> („slaskie",))."""
    match = re.search(r"(\d{2})\s*-?\s*\d{3}", str(code or ""))
    if not match:
        return ()
    prefix = int(match.group(1))
    for low, high, provinces in _POSTAL_RANGES:
        if low <= prefix <= high:
            return provinces
    return ()


def hint_provinces(*values: object, postal: object = None) -> frozenset[str]:
    """Zbiór województw ze wskazówek dokumentu (pusty = brak wskazówki).

    Jawne województwo wygrywa z kodem pocztowym - kod dokłada tylko wtedy,
    gdy nic innego nie ma."""
    out = {province_slug(v) for v in values}
    out.discard("")
    if not out and postal:
        out.update(postal_provinces(postal))
    return frozenset(out)


# ---------------------------------------------------------------------------
# Geometria i miara zgodności kilometrów
# ---------------------------------------------------------------------------

#: Droga / odcinek w linii prostej. Mediana z tabeli to 1,22; trochę wyżej,
#: bo ryczałty liczą dojazd do hali, a nie do środka miejscowości.
ROAD_FACTOR = 1.24
#: Wygładzenie krótkich tras (10 km drogi przy 5 km odcinka to norma).
_SMOOTH_KM = 6.0

#: Trasa „pasuje" do kandydata (ok. +-13 %).
GOOD_FIT = 0.12
#: Trasa na pewno nie prowadzi do tego kandydata (ok. +-35 %).
BAD_FIT = 0.30
#: Dla jednej trasy rozdzielamy miejscowość tylko przy rażącej niezgodności.
SPLIT_SINGLE = 0.60
#: Kandydaci bliżej niż tyle to ta sama miejscowość (osada + wieś).
SAME_PLACE_KM = 4.0
#: Węzeł, który przesunął się o mniej niż tyle, „nie ruszył się".
MOVE_KM = 2.0
#: Stary punkt bliżej niż tyle od rozpoznanego miejsca zostaje, jak był
#: (Nominatim i GeoNames różnią się o kilka km środka miasta - nie ma po co
#: przeliczać setek tras OSRM dla kosmetyki).
KEEP_KM = 15.0
#: Inne miejsce w sensie „remisu" - bliżej to i tak ta sama okolica na mapie.
DISTINCT_KM = 25.0
#: Miasto od tej liczby mieszkańców nie rozdziela się z powodu jednej trasy
#: i nie bywa „przybliżone", gdy trasy pasują.
TOWN_POPULATION = 20000


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * 6371.0 * math.asin(min(1.0, math.sqrt(h)))


def route_error(km: float, straight_km: float) -> float:
    """|ln(km drogi / spodziewane km)| - 0 to idealna zgodność."""
    return abs(math.log((max(float(km), 0.0) + _SMOOTH_KM) / (ROAD_FACTOR * max(straight_km, 0.0) + _SMOOTH_KM)))


# ---------------------------------------------------------------------------
# Skorowidz miejscowości (GeoNames)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Place:
    gid: str
    name: str
    lat: float
    lon: float
    province: str = ""
    population: int = 0

    @property
    def point(self) -> tuple[float, float]:
        return (self.lat, self.lon)


def name_key(name: object) -> str:
    """Klucz nazwy - ten sam, którym harvester zawsze kluczował miasta."""
    return normalize_city_key(clean_city(str(name or "")))


def _dedupe(places: Iterable[Place]) -> list[Place]:
    """Wpisy bliżej niż `SAME_PLACE_KM` to jedna miejscowość (zostaje większa)."""
    ordered = sorted(places, key=lambda p: (-p.population, p.gid))
    out: list[Place] = []
    for place in ordered:
        if all(haversine_km(place.point, kept.point) > SAME_PLACE_KM for kept in out):
            out.append(place)
    return out


class Gazetteer:
    """Kandydaci po kluczu nazwy. Zbudowany raz na proces."""

    def __init__(self, entries: Iterable[tuple[Place, Iterable[str]]]):
        raw: dict[str, list[Place]] = {}
        self.places: dict[str, Place] = {}
        for place, keys in entries:
            self.places[place.gid] = place
            for key in {name_key(place.name), *keys}:
                if key:
                    raw.setdefault(key, []).append(place)
        self._by_key = {key: _dedupe(items) for key, items in raw.items()}
        self._by_first: dict[str, list[str]] = {}
        for key in self._by_key:
            self._by_first.setdefault(key.split(" ")[0], []).append(key)
        self._grid: dict[tuple[int, int], list[Place]] = {}
        for place in self.places.values():
            self._grid.setdefault(self._cell(place.lat, place.lon), []).append(place)

    @staticmethod
    def _cell(lat: float, lon: float) -> tuple[int, int]:
        return (int(math.floor(lat * 5)), int(math.floor(lon * 5)))

    @classmethod
    def from_file(cls, path: Path | str = GAZETTEER_PATH) -> "Gazetteer":
        def rows():
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                for line in handle:
                    if not line or line.startswith("#"):
                        continue
                    f = line.rstrip("\n").split("\t")
                    if len(f) < 6:
                        continue
                    place = Place(
                        gid=f[0],
                        name=f[1],
                        lat=float(f[2]),
                        lon=float(f[3]),
                        province=f[4],
                        population=int(f[5] or 0),
                    )
                    extra = [k for k in (f[6].split("|") if len(f) > 6 and f[6] else []) if k]
                    yield place, extra

        return cls(rows())

    def candidates(self, name: object) -> list[Place]:
        """Miejscowości o tej nazwie. Bez dokładnego trafienia - skróty
        („Tomaszów Maz." -> „Tomaszów Mazowiecki", „Piekary Śl.")."""
        key = name_key(name)
        if not key:
            return []
        hit = self._by_key.get(key)
        if hit:
            return list(hit)
        tokens = key.split(" ")
        if len(tokens) < 2:
            return []
        found: list[Place] = []
        for other in self._by_first.get(tokens[0], []):
            parts = other.split(" ")
            if len(parts) == len(tokens) and all(p.startswith(t) for p, t in zip(parts, tokens)):
                found.extend(self._by_key[other])
        return _dedupe(found)

    def nearest(self, lat: float, lon: float, max_km: float = 25.0) -> Optional[Place]:
        """Najbliższa miejscowość skorowidza (do opisu starego położenia)."""
        cy, cx = self._cell(lat, lon)
        best: Optional[Place] = None
        best_km = max_km
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                for place in self._grid.get((cy + dy, cx + dx), []):
                    km = haversine_km((lat, lon), place.point)
                    if km < best_km:
                        best, best_km = place, km
        return best


#: Oficjalne nazwy z przymiotnikiem, których GeoNames nie ma pod pełnym brzmieniem
#: (jest samo „Nakło" x6): (klucz nazwy, szerokość, długość) miejscowości, której
#: nazwa jest ich skrótem. Klucz dostaje ten wpis, który leży w promieniu 1 km od
#: punktu. Jawna pozycja zamiast zgadywania po przymiotniku.
MANUAL_ALIASES: tuple[tuple[str, float, float], ...] = (
    # gm. Świerklaniec, pow. tarnogórski
    ("Nakło Śląskie", 50.4369, 18.9106),
    # gm. Oława (tabela odległości dolnośląskiego pisze „Siedlce k. Oławy")
    ("Siedlce k. Oławy", 50.998, 17.278),
)


def _with_manual_aliases(gaz: "Gazetteer") -> "Gazetteer":
    for alias, lat, lon in MANUAL_ALIASES:
        key = name_key(alias)
        near = [p for p in gaz.places.values() if abs(p.lat - lat) < 0.02 and abs(p.lon - lon) < 0.02
                and haversine_km(p.point, (lat, lon)) <= 1.0]
        if not near:
            continue
        place = max(near, key=lambda p: p.population)
        gaz._by_key[key] = _dedupe([*gaz._by_key.get(key, []), place])
        gaz._by_first.setdefault(key.split(" ")[0], [])
        if key not in gaz._by_first[key.split(" ")[0]]:
            gaz._by_first[key.split(" ")[0]].append(key)
    return gaz


@lru_cache(maxsize=1)
def default_gazetteer() -> Gazetteer:
    return _with_manual_aliases(Gazetteer.from_file(GAZETTEER_PATH))


# ---------------------------------------------------------------------------
# Jeden nowy dokument: który węzeł z każdej strony
# ---------------------------------------------------------------------------

#: Kara za województwo spoza wskazówek dokumentu.
HINT_PENALTY = 0.12
#: Kara za założenie nowego węzła obok już znanych (nowy węzeł wymaga dowodu).
NEW_NODE_PENALTY = 0.06
#: Różnica kosztu, poniżej której wybór uznajemy za remis („przybliżone").
TIE_MARGIN = 0.05


@dataclass
class NodeInfo:
    """Węzeł tabeli w postaci, jakiej potrzebuje algorytm (wiersz miasta)."""

    key: str
    name_key: str
    name: str
    lat: Optional[float]
    lon: Optional[float]
    observations: int = 0
    pinned: bool = False
    approximate: bool = False
    province: str = ""
    gid: str = ""

    @property
    def point(self) -> Optional[tuple[float, float]]:
        if self.lat is None or self.lon is None:
            return None
        return (float(self.lat), float(self.lon))


@dataclass
class Option:
    """Możliwe położenie jednej strony dokumentu: znany węzeł albo kandydat."""

    place: Place
    node: Optional[NodeInfo] = None

    @property
    def is_new(self) -> bool:
        return self.node is None


@dataclass
class SidePick:
    option: Optional[Option]
    approximate: bool
    margin: float
    error: float


def side_options(nodes: Sequence[NodeInfo], candidates: Sequence[Place]) -> list[Option]:
    """Znane węzły tej nazwy + kandydaci skorowidza, których żaden węzeł
    jeszcze nie zajmuje."""
    out: list[Option] = []
    taken: list[tuple[float, float]] = []
    for node in nodes:
        point = node.point
        if point is None:
            continue
        place = Place(
            gid=node.gid or f"node:{node.key}",
            name=node.name,
            lat=point[0],
            lon=point[1],
            province=node.province,
        )
        out.append(Option(place=place, node=node))
        taken.append(point)
    for place in candidates:
        if all(haversine_km(place.point, p) > SAME_PLACE_KM * 2 for p in taken):
            out.append(Option(place=place))
    return out


def _option_cost(option: Option, hints: frozenset[str]) -> float:
    cost = 0.0
    if hints and option.place.province and option.place.province not in hints:
        cost += HINT_PENALTY
    if option.node is None:
        cost += NEW_NODE_PENALTY
        # Remis między wsiami rozstrzyga większa miejscowość - minimalnie.
        cost -= 0.008 * math.log10(option.place.population + 1)
    else:
        cost -= 0.01 * min(math.log1p(option.node.observations), 4.0)
        if option.node.pinned:
            cost -= 0.03
    return cost


def choose_document_nodes(
    km: float,
    a_options: Sequence[Option],
    b_options: Sequence[Option],
    a_hints: frozenset[str] = frozenset(),
    b_hints: frozenset[str] = frozenset(),
) -> tuple[SidePick, SidePick]:
    """Najlepsza para położeń dla jednego ryczałtu (A - B, `km` w jedną stronę).

    Strona bez żadnej opcji wraca z `option=None` - wołający geokoduje ją
    wtedy Nominatimem i pyta jeszcze raz."""
    if not a_options or not b_options:
        def lone(options: Sequence[Option], hints: frozenset[str]) -> SidePick:
            if not options:
                return SidePick(None, True, 0.0, 0.0)
            ranked = sorted(options, key=lambda o: _option_cost(o, hints))
            best = ranked[0]
            margin = (
                _option_cost(ranked[1], hints) - _option_cost(best, hints) if len(ranked) > 1 else 1.0
            )
            approx = (best.node.approximate if best.node else len(ranked) > 1) and not (
                best.node and best.node.pinned
            )
            return SidePick(best, approx, margin, 0.0)

        return lone(a_options, a_hints), lone(b_options, b_hints)

    a_costs = [_option_cost(o, a_hints) for o in a_options]
    b_costs = [_option_cost(o, b_hints) for o in b_options]
    totals: list[tuple[float, int, int, float]] = []
    for i, a in enumerate(a_options):
        for j, b in enumerate(b_options):
            err = route_error(km, haversine_km(a.place.point, b.place.point))
            totals.append((err + a_costs[i] + b_costs[j], i, j, err))
    totals.sort(key=lambda t: t[0])
    best_total, bi, bj, best_err = totals[0]

    def pick(options: Sequence[Option], index: int, side: int) -> SidePick:
        chosen = options[index]
        alt = next(
            (
                t[0]
                for t in totals[1:]
                if haversine_km(options[t[side]].place.point, chosen.place.point) > DISTINCT_KM
            ),
            None,
        )
        margin = (alt - best_total) if alt is not None else 1.0
        if chosen.node is not None:
            approx = chosen.node.approximate and not chosen.node.pinned
        else:
            approx = (len(options) > 1 and margin < TIE_MARGIN) or best_err > BAD_FIT
        return SidePick(chosen, approx, margin, best_err)

    return pick(a_options, bi, 1), pick(b_options, bj, 2)


# ---------------------------------------------------------------------------
# Cała sieć: rozpoznanie (i rozdzielenie) miejscowości po wszystkich trasach
# ---------------------------------------------------------------------------


@dataclass
class EdgeInfo:
    """Połączenie z tabeli (wiersz connections) + wskazówki jego dokumentów."""

    a_key: str
    b_key: str
    km: float
    observations: int = 1
    hints_a: frozenset[str] = frozenset()
    hints_b: frozenset[str] = frozenset()


@dataclass
class ResolvedNode:
    name_key: str
    name: str
    place: Place
    edges: list[int] = field(default_factory=list)
    approximate: bool = False
    fit_error: Optional[float] = None
    margin: Optional[float] = None
    source: str = "gazetteer"  # gazetteer | geocoder | pinned
    pinned_key: Optional[str] = None
    candidates: list[tuple[Place, Optional[float]]] = field(default_factory=list)
    observations: int = 0


@dataclass
class NetworkResult:
    nodes: list[ResolvedNode]
    #: Dla każdej krawędzi (w kolejności wejścia): (indeks węzła A, indeks węzła B).
    edge_nodes: list[tuple[int, int]]


def _median(values: Sequence[float]) -> float:
    return float(statistics.median(values)) if values else 0.0


def fit_point(routes: Sequence[tuple[tuple[float, float], float]]) -> tuple[tuple[float, float], float]:
    """Punkt Polski, do którego trasy (punkt drugiego końca, km) pasują
    najlepiej (mediana błędu). Siatka zgrubna, potem doprecyzowanie."""

    def cost(lat: float, lon: float) -> float:
        return _median([route_error(km, haversine_km((lat, lon), other)) for other, km in routes])

    coarse = [
        (cost(lat / 10, lon / 10), lat / 10, lon / 10)
        for lat in range(490, 550, 2)
        for lon in range(141, 242, 2)
    ]
    coarse.sort()
    best = coarse[0]
    for _, lat0, lon0 in coarse[:5]:
        for dy in range(-10, 11):
            for dx in range(-10, 11):
                lat, lon = lat0 + dy * 0.02, lon0 + dx * 0.02
                value = cost(lat, lon)
                if value < best[0]:
                    best = (value, lat, lon)
    return (round(best[1], 4), round(best[2], 4)), round(best[0], 4)


def resolve_network(
    nodes: Sequence[NodeInfo],
    edges: Sequence[EdgeInfo],
    lookup: Callable[[str], list[Place]],
    *,
    rounds: int = 6,
    nearest: Optional[Callable[[float, float], Optional[Place]]] = None,
) -> NetworkResult:
    """Rozpoznaje położenie każdej nazwy z tabeli po kilometrach wszystkich tras.

    1. Kandydaci nazwy = skorowidz (`lookup(nazwa)`). Nazwa spoza skorowidza
       zostaje tam, gdzie postawił ją geokoder (`source="geocoder"`).
    2. Kotwice: nazwy z jednym kandydatem i węzły przypięte przez admina.
    3. Nazwy niejednoznaczne (od najczęściej jeżdżonych) dostają kandydata
       z najmniejszą medianą błędu tras do miejsc już ustalonych; kilka rund,
       bo sąsiedzi też się ustalają.
    4. Rozdzielenie: trasy, które do wybranego miejsca rażąco nie pasują,
       a do innego kandydata tak (dwie różne trasy - albo jedna bardzo rażąca),
       zakładają osobny węzeł o tej samej nazwie.
    5. Przybliżone: remis kandydatów, jedna trasa przy wielu kandydatach,
       albo nic nie pasuje. Przypięte nigdy.
    """
    by_key = {n.key: n for n in nodes}
    names: dict[str, list[NodeInfo]] = {}
    for node in nodes:
        names.setdefault(node.name_key, []).append(node)

    display: dict[str, str] = {}
    for nk, group in names.items():
        display[nk] = max(group, key=lambda n: (n.observations, n.name)).name

    options: dict[str, list[Place]] = {}
    source: dict[str, str] = {}
    for nk, group in names.items():
        found: list[Place] = []
        for spelling in {n.name for n in group} | {nk}:
            for place in lookup(spelling):
                if all(place.gid != f.gid for f in found):
                    found.append(place)
        found = _dedupe(found)
        if found:
            options[nk] = found
            source[nk] = "gazetteer"
        else:
            options[nk] = [
                Place(gid=f"node:{n.key}", name=n.name, lat=n.point[0], lon=n.point[1], province=n.province)
                for n in group
                if n.point is not None and not n.pinned
            ]
            source[nk] = "geocoder"

    # Końce krawędzi: (indeks krawędzi, strona) -> nazwa, przypięcie, położenie.
    incident: dict[str, list[tuple[int, int]]] = {}
    pinned_end: dict[tuple[int, int], NodeInfo] = {}
    position: dict[tuple[int, int], Place] = {}
    edge_names: list[tuple[str, str]] = []
    for i, edge in enumerate(edges):
        ends = []
        for side, key in ((0, edge.a_key), (1, edge.b_key)):
            node = by_key.get(key)
            nk = node.name_key if node else name_key(key.split("|")[0])
            ends.append(nk)
            incident.setdefault(nk, []).append((i, side))
            if node is not None and node.pinned and node.point is not None:
                pinned_end[(i, side)] = node
                position[(i, side)] = Place(
                    gid=node.gid or f"pin:{node.key}",
                    name=node.name,
                    lat=node.point[0],
                    lon=node.point[1],
                    province=node.province,
                )
        edge_names.append((ends[0], ends[1]))
    for nk in incident:
        names.setdefault(nk, [])
        options.setdefault(nk, [])
        display.setdefault(nk, nk)
        source.setdefault(nk, "geocoder")

    def hints_of(i: int, side: int) -> frozenset[str]:
        return edges[i].hints_a if side == 0 else edges[i].hints_b

    # Kotwice: jedyny kandydat.
    fixed_names = {nk for nk, opts in options.items() if len(opts) == 1}
    for nk in fixed_names:
        for end in incident.get(nk, []):
            if end not in pinned_end:
                position[end] = options[nk][0]

    ambiguous = sorted(
        (nk for nk, opts in options.items() if len(opts) > 1),
        key=lambda nk: (-len(incident.get(nk, [])), nk),
    )

    # Wynik per nazwa: grupy {gid kandydata: [końce]} + statystyki.
    groups: dict[str, dict[str, list[tuple[int, int]]]] = {}
    stats: dict[tuple[str, str], tuple[Optional[float], Optional[float], list[tuple[Place, Optional[float]]]]] = {}

    def other_point(i: int, side: int) -> Optional[Place]:
        return position.get((i, 1 - side))

    def evaluate(nk: str) -> None:
        opts = options[nk]
        ends = [e for e in incident.get(nk, []) if e not in pinned_end]
        usable = [(e, other_point(*e)) for e in ends]
        usable = [(e, p) for e, p in usable if p is not None]
        name_hints: dict[str, int] = {}
        for e in ends:
            for prov in hints_of(*e):
                name_hints[prov] = name_hints.get(prov, 0) + 1
        hint_total = sum(name_hints.values())

        def prior(place: Place) -> float:
            value = -0.008 * math.log10(place.population + 1)
            if hint_total:
                share = name_hints.get(place.province, 0) / hint_total
                value += HINT_PENALTY * (1.0 - share)
            return value

        err: dict[str, dict[tuple[int, int], float]] = {}
        for place in opts:
            row: dict[tuple[int, int], float] = {}
            for e, other in usable:
                value = route_error(edges[e[0]].km, haversine_km(place.point, other.point))
                end_hints = hints_of(*e)
                if end_hints and place.province and place.province not in end_hints:
                    value += HINT_PENALTY / 2
                row[e] = value
            err[place.gid] = row

        def score(place: Place, subset: Sequence[tuple[int, int]]) -> float:
            row = err[place.gid]
            values = [row[e] for e in subset if e in row]
            return (_median(values) if values else 0.0) + prior(place)

        usable_ends = [e for e, _ in usable]
        ranked = sorted(opts, key=lambda p: (score(p, usable_ends), p.gid))
        primary = ranked[0]
        assignment: dict[str, list[tuple[int, int]]] = {primary.gid: list(ends)}

        if len(usable_ends) >= 1:
            remaining = [e for e in usable_ends if err[primary.gid][e] > BAD_FIT]
            used = {primary.gid}
            while remaining:
                best_cover: list[tuple[int, int]] = []
                best_place: Optional[Place] = None
                best_sum = 0.0
                for place in opts:
                    if place.gid in used or haversine_km(place.point, primary.point) <= SAME_PLACE_KM * 4:
                        continue
                    cover = [e for e in remaining if err[place.gid][e] < GOOD_FIT]
                    total = sum(err[place.gid][e] for e in cover)
                    if len(cover) > len(best_cover) or (
                        cover and len(cover) == len(best_cover) and total < best_sum
                    ):
                        best_cover, best_place, best_sum = cover, place, total
                if best_place is None or not best_cover:
                    break
                distinct = {other_point(*e).gid for e in best_cover if other_point(*e) is not None}
                # Jedna trasa rozdziela tylko wsie: jeden dziwny ryczałt
                # z Ostrołęki nie może zrobić drugiej Ostrołęki.
                strong = len(distinct) >= 2 or (
                    primary.population < TOWN_POPULATION
                    and any(err[primary.gid][e] > SPLIT_SINGLE for e in best_cover)
                )
                if not strong:
                    break
                used.add(best_place.gid)
                assignment[best_place.gid] = list(best_cover)
                for e in best_cover:
                    assignment[primary.gid].remove(e)
                remaining = [e for e in remaining if e not in best_cover]

        groups[nk] = assignment
        by_gid = {p.gid: p for p in opts}
        for gid, group_ends in assignment.items():
            place = by_gid[gid]
            for e in group_ends:
                position[e] = place
            subset = [e for e in group_ends if e in err[gid]]
            fit = _median([err[gid][e] for e in subset]) if subset else None
            own = score(place, subset) if subset else prior(place)
            alts = [
                score(p, subset) if subset else prior(p)
                for p in opts
                if haversine_km(p.point, place.point) > DISTINCT_KM
            ]
            margin = (min(alts) - own) if alts else None
            listing = sorted(
                ((p, (_median([err[p.gid][e] for e in subset]) if subset else None)) for p in opts),
                key=lambda item: (item[1] if item[1] is not None else 9.0, -item[0].population),
            )[:6]
            stats[(nk, gid)] = (fit, margin, listing)

    for _ in range(max(1, rounds)):
        for nk in ambiguous:
            evaluate(nk)

    # Nazwy jednoznaczne i spoza skorowidza: jedna grupa (poza przypiętymi).
    for nk, opts in options.items():
        if nk in groups:
            continue
        ends = [e for e in incident.get(nk, []) if e not in pinned_end]
        if not opts:
            continue
        if source[nk] == "geocoder" and len(opts) > 1:
            # Kilka węzłów bez skorowidza (np. ręcznie rozdzielone) - każdy
            # koniec zostaje przy węźle, przy którym był.
            assignment: dict[str, list[tuple[int, int]]] = {}
            for e in ends:
                key = edges[e[0]].a_key if e[1] == 0 else edges[e[0]].b_key
                gid = f"node:{key}" if any(o.gid == f"node:{key}" for o in opts) else opts[0].gid
                assignment.setdefault(gid, []).append(e)
            groups[nk] = assignment
        else:
            groups[nk] = {opts[0].gid: list(ends)}
        by_gid = {p.gid: p for p in opts}
        for gid, group_ends in groups[nk].items():
            place = by_gid[gid]
            errs = [
                route_error(edges[i].km, haversine_km(place.point, other_point(i, side).point))
                for i, side in group_ends
                if other_point(i, side) is not None
            ]
            fit = _median(errs) if errs else None
            stats[(nk, gid)] = (fit, None, [(place, fit)])

    # Węzły wyniku.
    result: list[ResolvedNode] = []
    index_of: dict[tuple[str, str], int] = {}
    edge_nodes: list[list[int]] = [[-1, -1] for _ in edges]

    for nk in sorted(groups):
        opts = {p.gid: p for p in options[nk]}
        for gid, group_ends in groups[nk].items():
            if not group_ends:
                continue
            fit, margin, listing = stats.get((nk, gid), (None, None, []))
            evidence = sum(1 for e in group_ends if other_point(*e) is not None)
            approximate = False
            if source[nk] == "geocoder":
                approximate = evidence == 0 or (fit is not None and fit > 0.25)
            elif (
                opts[gid].population >= TOWN_POPULATION
                and fit is not None
                and fit <= GOOD_FIT
            ):
                approximate = False
            elif len(options[nk]) > 1:
                approximate = (
                    evidence == 0
                    or (margin is not None and margin < TIE_MARGIN)
                    or (evidence == 1 and (margin is None or margin < 0.15))
                    or (fit is not None and fit > BAD_FIT)
                )
            else:
                approximate = evidence >= 2 and fit is not None and fit > 0.35
            listing = list(listing)
            routes = [
                (other_point(*e).point, edges[e[0]].km)
                for e in group_ends
                if other_point(*e) is not None
            ]
            if fit is not None and fit > BAD_FIT and len(routes) >= 3:
                # Żaden kandydat skorowidza nie pasuje - dla admina dokładamy
                # punkt wyliczony z samych tras (automat go nie wybiera).
                spot, spot_err = fit_point(routes)
                near = nearest(spot[0], spot[1]) if nearest else None
                listing.append(
                    (
                        Place(
                            gid=f"fit:{spot[0]:.4f},{spot[1]:.4f}",
                            name=f"punkt z tras (okolice: {near.name})" if near else "punkt z tras",
                            lat=spot[0],
                            lon=spot[1],
                            province=near.province if near else "",
                        ),
                        spot_err,
                    )
                )
            node = ResolvedNode(
                name_key=nk,
                name=display.get(nk, nk),
                place=opts[gid],
                edges=sorted({e[0] for e in group_ends}),
                approximate=approximate,
                fit_error=None if fit is None else round(fit, 4),
                margin=None if margin is None else round(margin, 4),
                source=source[nk],
                candidates=listing,
                observations=sum(edges[e[0]].observations for e in group_ends),
            )
            index_of[(nk, gid)] = len(result)
            result.append(node)
            for i, side in group_ends:
                edge_nodes[i][side] = index_of[(nk, gid)]

    # Przypięte węzły - stoją, gdzie postawił je admin, z własnymi trasami.
    pinned_index: dict[str, int] = {}
    for (i, side), node in pinned_end.items():
        if node.key not in pinned_index:
            pinned_index[node.key] = len(result)
            result.append(
                ResolvedNode(
                    name_key=node.name_key,
                    name=node.name,
                    place=position[(i, side)],
                    approximate=False,
                    source="pinned",
                    pinned_key=node.key,
                    candidates=[(position[(i, side)], None)],
                )
            )
        idx = pinned_index[node.key]
        result[idx].edges.append(i)
        result[idx].observations += edges[i].observations
        edge_nodes[i][side] = idx

    # Przypięte bez tras też zostają (admin postawił je świadomie).
    for node in nodes:
        if node.pinned and node.key not in pinned_index and node.point is not None:
            pinned_index[node.key] = len(result)
            result.append(
                ResolvedNode(
                    name_key=node.name_key,
                    name=node.name,
                    place=Place(gid=node.gid or f"pin:{node.key}", name=node.name, lat=node.point[0], lon=node.point[1], province=node.province),
                    source="pinned",
                    pinned_key=node.key,
                )
            )

    return NetworkResult(nodes=result, edge_nodes=[(a, b) for a, b in edge_nodes])


# ---------------------------------------------------------------------------
# Klucze węzłów i plan zmian w bazie
# ---------------------------------------------------------------------------


def secondary_key(nk: str, province: str, gid: str, used: set[str]) -> str:
    """Klucz drugiego (trzeciego...) węzła tej samej nazwy."""
    key = f"{nk}|{province or 'pl'}"
    if key not in used:
        return key
    return f"{nk}|{province or 'pl'}|{gid}"


def assign_keys(resolved: Sequence[ResolvedNode], existing: Sequence[NodeInfo]) -> list[str]:
    """Klucze węzłów wyniku - stabilne między przebiegami.

    * przypięty zachowuje swój klucz,
    * węzeł wyniku dziedziczy klucz istniejącego węzła tej nazwy, który stoi
      bliżej niż 15 km (albo ma ten sam identyfikator skorowidza),
    * pozostali: najczęściej jeżdżony dostaje gołą nazwę (jeśli wolna -
      tak było dotąd i tak szukają starsze klienty), reszta `nazwa|województwo`.
    """
    keys: list[Optional[str]] = [None] * len(resolved)
    used: set[str] = set()
    for i, node in enumerate(resolved):
        if node.pinned_key:
            keys[i] = node.pinned_key
            used.add(node.pinned_key)

    existing_by_name: dict[str, list[NodeInfo]] = {}
    for node in existing:
        if not node.pinned:
            existing_by_name.setdefault(node.name_key, []).append(node)

    by_name: dict[str, list[int]] = {}
    for i, node in enumerate(resolved):
        if keys[i] is None:
            by_name.setdefault(node.name_key, []).append(i)

    for nk, indexes in by_name.items():
        pairs: list[tuple[float, int, str]] = []
        for i in indexes:
            for old in existing_by_name.get(nk, []):
                if old.key in used:
                    continue
                if old.gid and old.gid == resolved[i].place.gid:
                    pairs.append((-1.0, i, old.key))
                elif old.point is not None:
                    km = haversine_km(old.point, resolved[i].place.point)
                    if km <= 15.0:
                        pairs.append((km, i, old.key))
        for _, i, key in sorted(pairs):
            if keys[i] is None and key not in used:
                keys[i] = key
                used.add(key)

    for nk, indexes in by_name.items():
        free = sorted(
            (i for i in indexes if keys[i] is None),
            key=lambda i: (-resolved[i].observations, resolved[i].place.gid),
        )
        for i in free:
            if nk not in used:
                keys[i] = nk
            else:
                keys[i] = secondary_key(nk, resolved[i].place.province, resolved[i].place.gid, used)
            used.add(keys[i])
        # Goła nazwa nikomu nie przypadła (np. stary węzeł stał w złym miejscu,
        # a nowy dokument założył „gac|dolnoslaskie") - dostaje ją najczęściej
        # jeżdżony węzeł tej nazwy, żeby starsze klienty dalej go znajdowały.
        if nk not in used:
            mine = [i for i in indexes if not resolved[i].pinned_key]
            if mine:
                best = max(mine, key=lambda i: (resolved[i].observations, resolved[i].place.gid))
                used.discard(keys[best])
                keys[best] = nk
                used.add(nk)
    return [str(k) for k in keys]


def canonical(a: str, b: str) -> tuple[str, str]:
    return (a, b) if a <= b else (b, a)


@dataclass
class PlacePlan:
    """Co zmienić w bazie po rozpoznaniu sieci (wynik `plan_relocation`)."""

    #: key -> wartości wiersza miasta (name, name_key, lat, lon, province, gid,
    #: approximate, fit_error, observations, candidates, moved_km, previous).
    nodes: dict[str, dict]
    #: klucze miast do usunięcia (bez tras, nieprzypięte)
    drop_nodes: list[str]
    #: (stary a, stary b) -> (nowy klucz za stary a, nowy klucz za stary b),
    #: tylko gdy coś się zmienia (nowa para nie musi być ułożona rosnąco)
    edge_moves: dict[tuple[str, str], tuple[str, str]]
    #: nowe klucze tras, których geometrię trzeba policzyć od nowa
    reroute: set[tuple[str, str]]


def plan_relocation(
    existing_nodes: Sequence[NodeInfo],
    edges: Sequence[EdgeInfo],
    result: NetworkResult,
    keys: Sequence[str],
    *,
    only_names: Optional[set[str]] = None,
) -> PlacePlan:
    """Różnica między bazą a wynikiem. `only_names` ogranicza zmiany do tych
    nazw (przebieg po nowym dokumencie nie rusza reszty kraju)."""
    old_by_key = {n.key: n for n in existing_nodes}
    allowed = (lambda nk: True) if only_names is None else (lambda nk: nk in only_names)

    # Punkt końcowy węzła: stary, gdy rozpoznane miejsce leży bliżej niż
    # `KEEP_KM` (to ta sama miejscowość, tylko inny „środek"), inaczej nowy.
    final_point: list[tuple[float, float]] = []
    for i, node in enumerate(result.nodes):
        old = old_by_key.get(keys[i])
        point = node.place.point
        if (
            node.source != "pinned"
            and old is not None
            and old.point is not None
            and haversine_km(old.point, point) <= KEEP_KM
        ):
            point = old.point
        final_point.append(point)

    edge_moves: dict[tuple[str, str], tuple[str, str]] = {}
    reroute: set[tuple[str, str]] = set()
    nodes_out: dict[str, dict] = {}
    # Skąd węzeł „przyszedł": punkt starego węzła jego pierwszej trasy.
    previous_point: dict[int, Optional[tuple[float, float]]] = {}

    for e, edge in enumerate(edges):
        ia, ib = result.edge_nodes[e]
        ends = ((ia, edge.a_key), (ib, edge.b_key))
        new_keys = [
            keys[idx] if idx >= 0 and allowed(result.nodes[idx].name_key) else old_key
            for idx, old_key in ends
        ]
        old_pair = canonical(edge.a_key, edge.b_key)
        new_pair = canonical(new_keys[0], new_keys[1])
        if new_pair != old_pair:
            # Wartość w orientacji STAREJ pary: [0] zastępuje old_pair[0].
            renamed = {edge.a_key: new_keys[0], edge.b_key: new_keys[1]}
            edge_moves[old_pair] = (renamed[old_pair[0]], renamed[old_pair[1]])
        moved = False
        for idx, old_key in ends:
            if idx < 0 or not allowed(result.nodes[idx].name_key):
                continue
            old = old_by_key.get(old_key)
            before = old.point if old else None
            previous_point.setdefault(idx, before)
            if before is None or haversine_km(before, final_point[idx]) > MOVE_KM:
                moved = True
        if moved:
            reroute.add(new_pair)

    for i, node in enumerate(result.nodes):
        if not allowed(node.name_key):
            continue
        key = keys[i]
        old = old_by_key.get(key)
        before = old.point if old is not None and old.point is not None else previous_point.get(i)
        point = final_point[i]
        moved_km = haversine_km(before, point) if before else None
        nodes_out[key] = {
            "name": old.name if old else node.name,
            "name_key": node.name_key,
            "latitude": point[0],
            "longitude": point[1],
            "province": node.place.province or (old.province if old else "") or None,
            "gid": node.place.gid,
            "approximate": bool(node.approximate),
            "fit_error": node.fit_error,
            "observations": node.observations or (int(old.observations) if old else 0),
            "candidates": [
                {
                    "gid": p.gid,
                    "name": p.name,
                    "lat": p.lat,
                    "lon": p.lon,
                    "province": p.province,
                    "population": p.population,
                    "error": None if err is None else round(err, 4),
                }
                for p, err in node.candidates
            ],
            "moved_km": None if moved_km is None else round(moved_km, 1),
            "previous": list(before) if before else None,
            "pinned": node.source == "pinned",
            "source": node.source,
        }

    used_by_edges: set[str] = set()
    for edge in edges:
        old_pair = canonical(edge.a_key, edge.b_key)
        used_by_edges.update(edge_moves.get(old_pair, old_pair))
    drop = [
        n.key
        for n in existing_nodes
        if allowed(n.name_key)
        and not n.pinned
        and n.key not in nodes_out
        and n.key not in used_by_edges
    ]
    return PlacePlan(nodes=nodes_out, drop_nodes=sorted(drop), edge_moves=edge_moves, reroute=reroute)


# ---------------------------------------------------------------------------
# Wyszukiwanie po samej nazwie (wołający, którzy znają tylko napis)
# ---------------------------------------------------------------------------


def pick_node(nodes: Sequence[NodeInfo], province: object = None) -> Optional[NodeInfo]:
    """Węzeł dla samej nazwy: z podanego województwa, inaczej najczęściej
    jeżdżony (przypięty i nieprzybliżony wygrywa remis)."""
    if not nodes:
        return None
    slug = province_slug(province) if province else ""

    def rank(node: NodeInfo):
        return (
            1 if slug and node.province == slug else 0,
            int(node.observations or 0),
            1 if node.pinned else 0,
            0 if node.approximate else 1,
            node.key == node.name_key,
        )

    return max(nodes, key=rank)

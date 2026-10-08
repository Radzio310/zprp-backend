"""Odchudzona geometria tras dla przeglądu ogólnopolskiej mapy odległości.

Liść bez bazy i bez sieci - testowany wprost.

Przegląd mapy (`GET /national-distances`) oddawał każdą trasę w pełnej
geometrii OSRM (do ok. 140 węzłów), czyli przy 1500 trasach kilka megabajtów
JSON-a. Telefon czekał na nie przy każdym wejściu, potem parsował je w wątku
JS i pchał drugi raz do WebView mapy - stąd długa cisza po dotknięciu kafla
i zacięcie przy otwieraniu. Na mapie kraju (przybliżenie do ok. 5x) trasa
uproszczona z tolerancją ok. kilometra wygląda tak samo, a waży kilka razy mniej.
Pełna geometria jednej trasy dalej idzie z `/national-distances/connection`.
"""

from __future__ import annotations

import json
import math
from typing import Any, Optional

#: Tolerancja uproszczenia w stopniach (~0,7-1,1 km w Polsce).
SLIM_TOLERANCE_DEG = 0.01
#: Górny limit węzłów po uproszczeniu - kręta trasa i tak nie urośnie ponad to.
SLIM_MAX_POINTS = 40
#: Trzy miejsca po przecinku to ok. 100 m - poniżej piksela na mapie kraju.
SLIM_DECIMALS = 3

ROUTE_MODES = ("full", "slim", "none")


def route_mode(value: Optional[str]) -> str:
    """Tryb geometrii z zapytania; nieznany = `full` (zachowanie starszej aplikacji)."""
    mode = str(value or "").strip().lower()
    return mode if mode in ROUTE_MODES else "full"


def _points(geometry: Any) -> Optional[list[tuple[float, float]]]:
    """Punkty [lon, lat] z kolumny JSON - także gdy baza oddała ją jako napis."""
    if isinstance(geometry, str):
        try:
            geometry = json.loads(geometry)
        except ValueError:
            return None
    if not isinstance(geometry, list):
        return None
    out: list[tuple[float, float]] = []
    for item in geometry:
        if not isinstance(item, (list, tuple)) or len(item) < 2:
            continue
        try:
            lon, lat = float(item[0]), float(item[1])
        except (TypeError, ValueError):
            continue
        if math.isfinite(lon) and math.isfinite(lat):
            out.append((lon, lat))
    return out if len(out) >= 2 else None


def _segment_distance(p: tuple[float, float], a: tuple[float, float], b: tuple[float, float]) -> float:
    # Długość geograficzna ściśnięta cosinusem szerokości - jak rzut mapy.
    k = math.cos(math.radians((a[1] + b[1]) / 2))
    ax, ay, bx, by, px, py = a[0] * k, a[1], b[0] * k, b[1], p[0] * k, p[1]
    dx, dy = bx - ax, by - ay
    length = dx * dx + dy * dy
    if length == 0:
        return math.hypot(px - ax, py - ay)
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / length))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def _douglas_peucker(points: list[tuple[float, float]], tolerance: float) -> list[tuple[float, float]]:
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    while stack:
        start, end = stack.pop()
        best, index = 0.0, -1
        for i in range(start + 1, end):
            d = _segment_distance(points[i], points[start], points[end])
            if d > best:
                best, index = d, i
        if index >= 0 and best > tolerance:
            keep[index] = True
            stack.append((start, index))
            stack.append((index, end))
    return [p for p, k in zip(points, keep) if k]


def slim_route(
    geometry: Any,
    *,
    tolerance: float = SLIM_TOLERANCE_DEG,
    max_points: int = SLIM_MAX_POINTS,
    decimals: int = SLIM_DECIMALS,
) -> Optional[list[list[float]]]:
    """Trasa uproszczona do kształtu widocznego na mapie kraju.

    Początek i koniec zostają dokładnie (na nich stoją kropki miast). Gdy
    nawet po uproszczeniu węzłów jest za dużo, bierzemy równe odstępy z wyniku.
    """
    points = _points(geometry)
    if not points:
        return None
    simple = _douglas_peucker(points, tolerance) if len(points) > 2 else points
    if len(simple) > max_points:
        step = (len(simple) - 1) / (max_points - 1)
        simple = [simple[round(i * step)] for i in range(max_points)]
    out: list[list[float]] = []
    for lon, lat in simple:
        point = [round(lon, decimals), round(lat, decimals)]
        if not out or out[-1] != point:
            out.append(point)
    return out if len(out) >= 2 else None


def route_for_mode(geometry: Any, mode: str) -> Any:
    """Geometria trasy w odpowiedzi przeglądu wg trybu z zapytania."""
    if mode == "none":
        return None
    if mode == "slim":
        return slim_route(geometry)
    return geometry

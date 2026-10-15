"""Reguły postępu czytania ryczałtów - liść bez importów bazy.

Trasa `/national-distances/progress` tylko pobiera wiersze; co z nich wynika,
rozstrzyga ten moduł, żeby dało się to sprawdzić testem bez łączenia z bazą
(`app.db` łączy się już przy imporcie).
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

MAX_ATTEMPTS = 3


def summarize_sources(rows: Iterable[tuple[Any, Any, Any]]) -> dict[str, int]:
    """Wiersze (status, attempts, liczba) -> liczniki dla overlaya.

    Porażka po ostatniej próbie to koniec - serwer już po ten dokument nie
    sięgnie. Porażka przed nią jeszcze czeka na ponowienie, więc jest „w toku".
    """
    counts = {"total": 0, "done": 0, "failed": 0, "pending": 0}
    for state, attempts, n in rows:
        n = int(n or 0)
        counts["total"] += n
        if str(state or "") == "done":
            counts["done"] += n
        elif str(state or "") == "failed" and int(attempts or 0) >= MAX_ATTEMPTS:
            counts["failed"] += n
        else:
            counts["pending"] += n
    return counts


def point_of(node: Optional[Mapping[str, Any]]) -> Optional[dict[str, Any]]:
    """Wiersz węzła -> położenie do odpowiedzi (albo None)."""
    if not node:
        return None
    return {
        "key": node.get("city_key"),
        "name": node.get("name"),
        "latitude": node.get("latitude"),
        "longitude": node.get("longitude"),
        "province": node.get("province"),
        "approximate": bool(node.get("approximate")),
    }


def pick_home_node(
    home_nodes: Iterable[Mapping[str, Any]],
    rows: Iterable[Any],
    provinces: Iterable[str] = (),
) -> Optional[str]:
    """Który z węzłów o nazwie domu to dom sędziego.

    Od 15.10.2026 nazwa nie jest tożsamością (dwie Krzywe). Wygrywa węzeł
    z województwa ze wskazówki (ustawienia sędziego), potem ten, z którego
    prowadzi najwięcej potwierdzonych tras do miast jego meczów."""
    nodes = list(home_nodes)
    if not nodes:
        return None
    wanted = set(provinces or ())
    weight: dict[str, int] = {}
    for row in rows:
        for key in (row["city_a_key"], row["city_b_key"]):
            weight[key] = weight.get(key, 0) + int(row["observations"] or 1)

    def rank(node: Mapping[str, Any]):
        key = node.get("city_key")
        return (
            1 if wanted and node.get("province") in wanted else 0,
            weight.get(key, 0),
            int(node.get("observations") or 0),
            key == node.get("name_key"),
        )

    return max(nodes, key=rank).get("city_key")


def routes_from_home(
    rows: Iterable[Any],
    home_key: str,
    points: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> list[dict[str, Any]]:
    """Połączenia zapisane jako para A-B (alfabetycznie) -> „dokąd z domu".

    Z `points` (węzły po kluczu) każda trasa niesie też położenie celu, żeby
    telefon postawił kropkę w rozpoznanym miejscu, a nie w pierwszej
    miejscowości o tej nazwie z własnego atlasu."""
    out: list[dict[str, Any]] = []
    for row in rows:
        other_is_b = row["city_a_key"] == home_key
        key = row["city_b_key"] if other_is_b else row["city_a_key"]
        item: dict[str, Any] = {
            "key": key,
            "name": row["city_b_name"] if other_is_b else row["city_a_name"],
            "km": int(row["distance_km"]),
        }
        node = (points or {}).get(key)
        if node:
            item.update(
                latitude=node.get("latitude"),
                longitude=node.get("longitude"),
                province=node.get("province"),
                approximate=bool(node.get("approximate")),
                nameKey=node.get("name_key") or key,
            )
        out.append(item)
    return out

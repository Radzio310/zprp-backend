"""Audyt kilometrów rozliczeń okręgu - liść bez bazy i sieci.

Szuka dojazdów, które wyglądają na zmierzone do złej miejscowości (sprawa
Więcław, 26.10.2026: „Lipnik" ze Śląska zmierzony Google'em do Lipnika
świętokrzyskiego, 271,5 km zamiast 94 km). Powody (`reason`):

* ``imiennik_google``     - źródło Google, a nazwa miejscowości sędziego
                            istnieje też w innym województwie niż okręg,
* ``dom_poza_okregiem``   - w województwie okręgu nie ma miejscowości o takiej
                            nazwie, a gdzie indziej jest (profil sędziego?),
* ``google_vs_tabela``    - Google wyraźnie większy/mniejszy niż tabela okręgu,
* ``km_ponad_linia``      - km > 1,5 x 1,3 x linia prosta (najbliższe
                            kandydatki obu końców),
* ``km_ponizej_linii``    - km mniejsze niż linia prosta (pomyłka pary),
* ``skok_km``             - ta sama para, różne km w różnych meczach.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable, Iterable, Mapping, Optional

from app.national_place_rules import Gazetteer, haversine_km, province_slug

ROAD_FACTOR = 1.3
OVER_FACTOR = 1.5
TABLE_TOLERANCE = 0.25
TABLE_MIN_DELTA_KM = 15.0
JUMP_TOLERANCE = 0.2


def _km(value: Any) -> Optional[float]:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def audit_row(
    row: Mapping[str, Any],
    gaz: Gazetteer,
    *,
    province: str,
    table_km: Optional[float] = None,
    national_km: Optional[float] = None,
) -> list[dict]:
    """Powody podejrzeń dla jednego wiersza rozliczenia (pusta lista = czysto)."""
    km = _km(row.get("distance_km"))
    home, city = str(row.get("home_city") or ""), str(row.get("city") or "")
    if km is None or not home or not city:
        return []
    slug = province_slug(province)
    source = str(row.get("distance_source") or "")
    out: list[dict] = []

    homes = gaz.candidates(home)
    own_homes = [p for p in homes if p.province == slug]
    other_homes = [p for p in homes if p.province != slug]

    if source == "google" and own_homes and other_homes:
        out.append({"reason": "imiennik_google", "expected": table_km or national_km})
    if homes and not own_homes:
        out.append({"reason": "dom_poza_okregiem", "expected": table_km})

    if table_km is not None and source == "google":
        delta = abs(km - table_km)
        if delta >= TABLE_MIN_DELTA_KM and delta > table_km * TABLE_TOLERANCE:
            out.append({"reason": "google_vs_tabela", "expected": table_km})

    ends_a = own_homes or homes
    ends_b = gaz.candidates(city)
    if ends_a and ends_b and not (table_km is not None and abs(km - table_km) < 1):
        straight = min(haversine_km(a.point, b.point) for a in ends_a for b in ends_b)
        if straight > 0:
            limit = straight * ROAD_FACTOR * OVER_FACTOR + 10
            if km > limit:
                out.append({"reason": "km_ponad_linia", "expected": round(straight * ROAD_FACTOR, 1)})
            elif km < straight * 0.9 - 3:
                out.append({"reason": "km_ponizej_linii", "expected": round(straight * ROAD_FACTOR, 1)})
    return out


def pair_jumps(rows: Iterable[Mapping[str, Any]]) -> list[dict]:
    """Ta sama para (dom, miasto) z różnymi km w różnych meczach."""
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        km = _km(row.get("distance_km"))
        if km is None or km == 0:
            continue
        key = (str(row.get("home_city") or "").strip().lower(), str(row.get("city") or "").strip().lower())
        if all(key):
            groups[key].append(row)
    out: list[dict] = []
    for items in groups.values():
        values = [float(r["distance_km"]) for r in items]
        low, high = min(values), max(values)
        if low > 0 and (high - low) / low > JUMP_TOLERANCE and high - low >= 5:
            for r in items:
                out.append({
                    "row": r,
                    "reason": "skok_km",
                    "expected": low if float(r["distance_km"]) == high else high,
                })
    return out


def audit(
    rows: Iterable[Mapping[str, Any]],
    gaz: Gazetteer,
    *,
    province: str,
    table_lookup: Optional[Callable[[Any, Any, Any], Optional[float]]] = None,
    national_lookup: Optional[Callable[[Any, Any], Optional[float]]] = None,
) -> list[dict]:
    """Lista ustaleń: sędzia, mecz, para, km obecne/oczekiwane, źródło, powód."""
    rows = list(rows)
    found: list[dict] = []

    def put(row: Mapping[str, Any], reason: str, expected: Any) -> None:
        found.append({
            "judge_id": row.get("judge_id"),
            "name": row.get("full_name") or "",
            "match_key": row.get("match_key"),
            "match_at": str(row.get("match_at") or "")[:10],
            "match_code": row.get("match_code"),
            "home_city": row.get("home_city"),
            "city": row.get("city"),
            "km": row.get("distance_km"),
            "expected": expected,
            "source": row.get("distance_source"),
            "reason": reason,
        })

    for row in rows:
        home, city = row.get("home_city"), row.get("city")
        t = table_lookup(home, city, row.get("match_at")) if table_lookup and home and city else None
        n = national_lookup(home, city) if national_lookup and home and city else None
        for item in audit_row(row, gaz, province=province, table_km=t, national_km=n):
            put(row, item["reason"], item["expected"])
    for item in pair_jumps(rows):
        put(item["row"], item["reason"], item["expected"])
    found.sort(key=lambda f: (str(f["name"]), str(f["match_at"]), str(f["reason"])))
    return found

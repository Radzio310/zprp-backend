"""Statystyki sezonu sędziego dla Pod Ręką (czyste funkcje, bez bazy).

Wejście: wiersze meczów, w których sędzia stał w parze (kolumny kart +
`referee_1_*`/`referee_2_*`), oraz sumy z protokołów zawodników per mecz.
Wyjście: podział na rozgrywki i kategorie, partnerzy w parze, hale i miasta,
przybliżone kilometry, średnie bramek i kar 2 min, czerwone kartki, kluby.

Kilometry są PRZYBLIŻONE i mówią to wprost: nie znamy adresu sędziego, więc
punktem wyjścia jest miasto, w którym gwiżdże najczęściej. Odległość = linia
prosta (haversine) x współczynnik drogowy, w obie strony.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any, Callable, Optional

from app.zprp_public import referee_placeholder as RP

ROAD_FACTOR = 1.25  # linia prosta -> droga (średnio dla Polski)
ALL_SEASONS = "all"  # zakres „Wszystkie”: cała kariera sędziego


def is_all(season_id: Any) -> bool:
    return str(season_id or "").strip().lower() in (ALL_SEASONS, "wszystkie", "*")


def pick_season(requested: Any, counts: dict[str, int], current: Optional[str], order: list[str]) -> str:
    """Jeden zakres dla CAŁEGO profilu (liczby, mapa, kluby, rozgrywki, mecze, para).

    `all` = cała kariera; wskazany sezon = ten sezon; bez wskazania - bieżący,
    a gdy sędzia nie ma w nim meczów - ostatni sezon, w którym gwizdał."""
    if is_all(requested):
        return ALL_SEASONS
    req = str(requested or "").strip()
    if req:
        return req
    if current and counts.get(current):
        return current
    return order[0] if order else (current or ALL_SEASONS)


def career_totals(groups: list[dict]) -> dict[str, Any]:
    """Kariera bez limitów z wierszy (season_id, competition_id, n) - jedno GROUP BY w bazie.

    Ta sama definicja meczu co profil i wyszukiwarka: mecz, w którym sędzia stał
    na którejkolwiek pozycji pary, liczony raz."""
    by_season: Counter = Counter()
    comps: set = set()
    total = 0
    for g in groups:
        n = int(g.get("n") or 0)
        total += n
        by_season[g.get("season_id")] += n
        if g.get("competition_id"):
            comps.add(g["competition_id"])
    return {"matches": total, "seasons": len(by_season), "competitions": len(comps), "by_season": dict(by_season)}


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1 = map(math.radians, a)
    lat2, lon2 = map(math.radians, b)
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * 6371.0 * math.asin(min(1.0, math.sqrt(h)))


def partner_of(row: dict, referee_id: str) -> tuple[Optional[str], Optional[str]]:
    """Drugi sędzia z pary (id, nazwisko) albo (None, None), gdy sędziował sam.

    Placeholder ZPRP („--- ---", wspólny numer braku obsady) to BRAK partnera, nie osoba."""
    if row.get("referee_1_id") == referee_id:
        pid, pname = row.get("referee_2_id"), row.get("referee_2_name")
    elif row.get("referee_2_id") == referee_id:
        pid, pname = row.get("referee_1_id"), row.get("referee_1_name")
    else:
        return None, None
    return RP.clean_official(pid, pname)


def _finished(row: dict) -> bool:
    return row.get("score_home") is not None and row.get("score_away") is not None and not row.get("withdrawn")


def summarize(
    rows: list[dict],
    referee_id: str,
    protocol: dict[str, dict],
    *,
    venue_key: Callable[[Any, Any], str],
    display_city: Callable[[Any], str],
    clean_name: Callable[[str], str] = lambda s: s,
    kinds: Optional[dict[str, tuple[Any, Any]]] = None,
) -> dict[str, Any]:
    """`protocol[match_id]` = {"two_minutes", "disqualifications", "warnings"} (suma obu drużyn).
    `kinds[competition_id]` = (kategoria, płeć). Współrzędne miast dokłada `attach_geo`."""
    kinds = kinds or {}
    done = [r for r in rows if _finished(r)]
    # Walkower nie jest meczem na parkiecie: bez bramek do średniej.
    real = [r for r in done if not r.get("walkover_team_id")]

    comps: dict[str, dict] = {}
    cats: Counter = Counter()
    for r in rows:
        cid = r.get("competition_id") or r.get("competition_name") or "?"
        cat, gender = kinds.get(r.get("competition_id"), (None, None))
        e = comps.setdefault(cid, {"competition_id": r.get("competition_id"), "name": r.get("competition_name"),
                                   "category": cat, "gender": gender, "matches": 0})
        e["matches"] += 1
        cats[cat or "Inne"] += 1

    partners: dict[str, dict] = {}
    solo = 0  # mecze bez drugiego sędziego w obsadzie (pusto albo placeholder ZPRP)
    for r in rows:
        pid, pname = partner_of(r, referee_id)
        if not pid and not pname:
            solo += 1
            continue
        key = pid or f"name:{pname}"
        e = partners.setdefault(key, {"referee_id": pid, "name": clean_name(pname or ""), "matches": 0, "last_at": None})
        e["matches"] += 1
        at = r.get("scheduled_at")
        if at and (e["last_at"] is None or at > e["last_at"]):
            e["last_at"] = at

    venues: dict[str, dict] = {}
    cities: dict[str, dict] = {}
    for r in rows:
        name = (r.get("venue_name") or "").strip()
        city = display_city(r.get("venue_city")) if r.get("venue_city") else None
        if city:
            c = cities.setdefault(city, {"city": city, "matches": 0, "venues": set()})
            c["matches"] += 1
            if name:
                c["venues"].add(name)
        if name:
            k = venue_key(name, r.get("venue_city"))
            v = venues.setdefault(k, {"key": k, "name": name, "city": city, "matches": 0})
            v["matches"] += 1

    clubs: Counter = Counter()
    for r in rows:
        for side in ("home_club_id", "away_club_id"):
            if r.get(side):
                clubs[r[side]] += 1

    goals = sum(int(r["score_home"]) + int(r["score_away"]) for r in real)
    with_protocol = [r for r in real if r.get("match_id") in protocol]
    two = sum(int(protocol[r["match_id"]].get("two_minutes") or 0) for r in with_protocol)
    reds = sum(int(protocol[r["match_id"]].get("disqualifications") or 0) for r in with_protocol)
    warns = sum(int(protocol[r["match_id"]].get("warnings") or 0) for r in with_protocol)
    pm = len(with_protocol)

    return {
        "matches": len(rows),
        "finished": len(done),
        "upcoming": sum(1 for r in rows if not _finished(r) and not r.get("withdrawn")),
        "by_competition": sorted(comps.values(), key=lambda e: (-e["matches"], e["name"] or "")),
        "by_category": [{"category": k, "matches": n} for k, n in cats.most_common()],
        "partners": sorted(partners.values(), key=lambda e: (-e["matches"], e["name"]))[:5],
        # Tylko dla zgodności API (starsze klienty); portal tej liczby już nie pokazuje -
        # placeholder to puste pole, nie „mecz bez partnera".
        "no_partner_matches": solo,
        "venues": sorted(venues.values(), key=lambda v: (-v["matches"], v["name"]))[:30],
        "venues_count": len(venues),
        "no_city_matches": sum(1 for r in rows if not (r.get("venue_city") or "").strip()),
        "cities": [{**{k: v for k, v in c.items() if k != "venues"}, "venues": sorted(c["venues"])}
                   for c in sorted(cities.values(), key=lambda c: (-c["matches"], c["city"]))],
        "club_counts": clubs.most_common(8),
        "averages": {
            "matches": len(real),
            "goals": goals,
            "goals_per_match": round(goals / len(real), 1) if real else None,
            "protocol_matches": pm,
            "two_minutes": two,
            "two_minutes_per_match": round(two / pm, 1) if pm else None,
            "red_cards": reds,
            "warnings": warns,
        },
    }


def attach_geo(summary: dict, coords: dict[str, tuple[Optional[float], Optional[float]]]) -> None:
    """Dokłada lat/lon miastom, bazę (najczęstsze miasto) i przybliżone km w obie strony."""
    for c in summary["cities"]:
        lat, lon = coords.get(c["city"], (None, None))
        c["lat"], c["lon"] = lat, lon
    located = [c for c in summary["cities"] if c.get("lat") is not None]
    # Uczciwie: miasta bez współrzędnych (i mecze bez miasta) nie trafiają na mapę ani do km.
    missing = [c for c in summary["cities"] if c.get("lat") is None]
    summary["unlocated"] = {
        "cities": len(missing),
        "matches": sum(c["matches"] for c in missing) + int(summary.get("no_city_matches") or 0),
        "names": [c["city"] for c in missing][:12],
    }
    base = located[0] if located else None
    summary["base"] = {"city": base["city"], "lat": base["lat"], "lon": base["lon"], "source": "most_frequent_city"} if base else None
    if not base:
        summary["km"] = None
        return
    origin = (base["lat"], base["lon"])
    total = 0.0
    farthest: Optional[dict] = None
    counted = 0
    for c in located:
        one_way = haversine_km(origin, (c["lat"], c["lon"])) * ROAD_FACTOR
        c["km"] = round(one_way)
        total += 2 * one_way * c["matches"]
        counted += c["matches"]
        if farthest is None or one_way > farthest["km"]:
            farthest = {"city": c["city"], "km": round(one_way)}
    summary["km"] = {
        "total": round(total),
        "matches_counted": counted,
        "farthest": farthest if farthest and farthest["km"] > 0 else None,
        "road_factor": ROAD_FACTOR,
        "approximate": True,
    }

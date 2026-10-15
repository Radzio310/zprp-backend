"""Podgląd przeniesień miejscowości ogólnopolskiej tabeli odległości - TYLKO ODCZYT.

Liczy to samo co `POST /national-distances/admin/places/relocate` z
`apply=false`, ale bez serwera i bez zapisu:

* z pliku przeglądu (`GET /national-distances?routes=none` zapisany na dysk):

      python scripts/national_places_dry_run.py --overview ov.json

* z bazy produkcyjnej - sesja tylko do odczytu, `DATABASE_URL` z otoczenia
  (na Railway, z katalogu aplikacji):

      python scripts/national_places_dry_run.py --db

Wypisuje miejscowości, które się przesuną (z km i województwem przed/po),
rozdzielone nazwy i położenia przybliżone. Nic nie zapisuje.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import national_place_rules as P  # noqa: E402


def _from_overview(path: str):
    data = json.load(open(path, encoding="utf-8"))
    nodes = [
        P.NodeInfo(
            key=c["key"],
            name_key=c.get("nameKey") or P.name_key(c["name"]),
            name=c["name"],
            lat=c.get("latitude"),
            lon=c.get("longitude"),
            observations=int(c.get("observations") or 0),
            pinned=bool(c.get("pinned")),
            approximate=bool(c.get("approximate")),
            province=c.get("province") or "",
        )
        for c in data["cities"]
    ]
    edges = [
        P.EdgeInfo(
            a_key=e["fromKey"],
            b_key=e["toKey"],
            km=float(e["distanceKm"]),
            observations=int(e.get("observations") or 1),
        )
        for e in data["connections"]
    ]
    return nodes, edges


def _from_db():
    import psycopg2  # tylko na serwerze (psycopg2-binary w requirements)

    dsn = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://")
    conn = psycopg2.connect(dsn)
    conn.set_session(readonly=True)
    cur = conn.cursor()
    cur.execute(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'national_distance_cities'"
    )
    cols = {r[0] for r in cur.fetchall()}
    extra = [c for c in ("name_key", "province", "gid", "pinned", "approximate") if c in cols]
    cur.execute(
        "SELECT city_key, name, latitude, longitude, observations"
        + "".join(f", {c}" for c in extra)
        + " FROM national_distance_cities"
    )
    nodes = []
    for row in cur.fetchall():
        values = dict(zip(["key", "name", "lat", "lon", "obs", *extra], row))
        nodes.append(
            P.NodeInfo(
                key=values["key"],
                name_key=values.get("name_key") or P.name_key(values["name"]),
                name=values["name"],
                lat=values["lat"],
                lon=values["lon"],
                observations=int(values["obs"] or 0),
                pinned=bool(values.get("pinned")),
                approximate=bool(values.get("approximate")),
                province=values.get("province") or "",
                gid=values.get("gid") or "",
            )
        )
    cur.execute(
        "SELECT city_a_key, city_b_key, distance_km, observations FROM national_distance_connections"
    )
    edges = [P.EdgeInfo(a_key=a, b_key=b, km=float(km), observations=int(o or 1)) for a, b, km, o in cur.fetchall()]
    conn.close()
    return nodes, edges


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--overview")
    parser.add_argument("--db", action="store_true")
    parser.add_argument("--min-km", type=float, default=5.0)
    parser.add_argument("--json", action="store_true", help="pełny plan jako JSON")
    args = parser.parse_args()
    if not args.overview and not args.db:
        parser.error("podaj --overview PLIK albo --db")
    nodes, edges = _from_overview(args.overview) if args.overview else _from_db()
    gaz = P.default_gazetteer()
    result = P.resolve_network(nodes, edges, gaz.candidates, nearest=gaz.nearest)
    keys = P.assign_keys(result.nodes, nodes)
    plan = P.plan_relocation(nodes, edges, result, keys)

    if args.json:
        print(json.dumps({
            "nodes": plan.nodes,
            "drop": plan.drop_nodes,
            "moves": [[list(a), list(b)] for a, b in plan.edge_moves.items()],
            "reroute": len(plan.reroute),
        }, ensure_ascii=False, indent=1))
        return

    def where(point):
        if not point:
            return "brak współrzędnych"
        near = gaz.nearest(point[0], point[1], 40)
        prov = P.province_label(near.province) if near else "?"
        return f"{point[0]:.3f},{point[1]:.3f} ({prov}, przy: {near.name if near else '?'})"

    names: dict[str, list[str]] = {}
    for key, node in plan.nodes.items():
        names.setdefault(node["name_key"], []).append(key)

    print(f"Miejscowości przed: {len(nodes)}, po: {len(plan.nodes)}; trasy: {len(edges)}, "
          f"zmiana kluczy tras: {len(plan.edge_moves)}, trasy do przeliczenia OSRM: {len(plan.reroute)}")
    print()
    print("PRZENIESIENIA (> %.0f km):" % args.min_km)
    moved = sorted(
        ((k, n) for k, n in plan.nodes.items() if (n["moved_km"] or 0) > args.min_km),
        key=lambda kv: -(kv[1]["moved_km"] or 0),
    )
    for key, n in moved:
        flag = " [PRZYBLIŻONE]" if n["approximate"] else ""
        print(f"  {n['name']:<24} {key:<34} {n['moved_km']:>6.0f} km: {where(n['previous'])} -> "
              f"{n['latitude']:.3f},{n['longitude']:.3f} ({P.province_label(n['province'] or '')}){flag}"
              f" błąd={n['fit_error']}")
    print()
    print("ROZDZIELONE NAZWY:")
    for nk, keys_ in sorted(names.items()):
        if len(keys_) > 1:
            parts = ", ".join(
                f"{k} -> {P.province_label(plan.nodes[k]['province'] or '')} "
                f"({plan.nodes[k]['observations']} obs.)"
                for k in keys_
            )
            print(f"  {nk}: {parts}")
    print()
    print("PRZYBLIŻONE:")
    for key, n in sorted(plan.nodes.items()):
        if n["approximate"]:
            print(f"  {n['name']:<24} {key:<34} {P.province_label(n['province'] or '')} "
                  f"źródło={n['source']} błąd={n['fit_error']}")
    if plan.drop_nodes:
        print()
        print("DO USUNIĘCIA (bez tras):", ", ".join(plan.drop_nodes))


if __name__ == "__main__":
    main()

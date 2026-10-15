"""Węzły miejscowości ogólnopolskiej tabeli odległości - baza, geokoder, OSRM.

Reguły i algorytm: `app/national_place_rules.py` (liść bez bazy). Tu tylko
odczyt wierszy, zapis wyników i wywołania sieciowe:

* `resolve_document` - nowy ryczałt: który węzeł po każdej stronie
  (istniejący albo nowy, z kandydatów GeoNames, w ostateczności Nominatim),
* `reresolve` - po paczce dokumentów: rozpoznanie sieci od nowa dla nazw,
  których paczka dotknęła (przeniesienie, rozdzielenie, „przybliżone"),
* `relocate` - jednorazowe (i ręczne) rozpoznanie całej tabeli: podgląd
  albo zapis, z przeliczeniem geometrii OSRM przeniesionych tras w tle,
* `pin` - admin przypina położenie; automat go już nie rusza.

Kilometry nie zmieniają się nigdy: połączenie przechodzi do innego węzła
w całości (z sumą i liczbą dokumentów), więc wyszukiwanie po samej nazwie
(`load_national_pairs`, rozliczenia) zwraca po przeniesieniu te same km.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from sqlalchemy import String, and_, cast, delete, insert, null, or_, select, update

from app import national_place_rules as P

logger = logging.getLogger(__name__)

_relocate_lock = asyncio.Lock()
_reroute_tasks: set[asyncio.Task] = set()
_gazetteer_lock = asyncio.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def gazetteer() -> P.Gazetteer:
    """Skorowidz GeoNames - pierwsze wczytanie (kilka sekund) poza pętlą zdarzeń."""
    async with _gazetteer_lock:
        return await asyncio.to_thread(P.default_gazetteer)


def _node(row: Any) -> P.NodeInfo:
    data = dict(row)
    return P.NodeInfo(
        key=str(data["city_key"]),
        name_key=str(data.get("name_key") or P.name_key(data["name"]) or data["city_key"]),
        name=str(data["name"] or data["city_key"]),
        lat=data.get("latitude"),
        lon=data.get("longitude"),
        observations=int(data.get("observations") or 0),
        pinned=bool(data.get("pinned")),
        approximate=bool(data.get("approximate")),
        province=str(data.get("province") or ""),
        gid=str(data.get("gid") or ""),
    )


# ---------------------------------------------------------------------------
# Wskazówki dokumentów
# ---------------------------------------------------------------------------


async def _sources_with_hints() -> list[dict]:
    """Dokumenty z jakąkolwiek wskazówką + związek z publicznej bazy meczów."""
    from app.db import (
        database,
        national_distance_sources as S,
        zprp_public_competitions as C,
        zprp_public_matches as M,
    )

    query = (
        select(
            S.c.match_id,
            S.c.judge_node,
            S.c.venue_node,
            S.c.judge_city,
            S.c.venue_city,
            S.c.hint_judge_city,
            S.c.hint_venue_city,
            S.c.judge_province,
            S.c.judge_postal_code,
            S.c.match_province,
            M.c.venue_city.label("public_venue_city"),
            C.c.association_name.label("public_association"),
        )
        .select_from(
            S.outerjoin(M, M.c.match_id == S.c.match_id).outerjoin(
                C, C.c.competition_id == M.c.competition_id
            )
        )
        .where(S.c.status == "done")
    )
    try:
        return [dict(row) for row in await database.fetch_all(query)]
    except Exception as exc:  # brak tabel publicznych nie może zatrzymać rozpoznania
        logger.warning("Wskazówki dokumentów tabeli ZPRP niedostępne: %s", exc)
        return []


def _edge_hints(
    edges: list[P.EdgeInfo],
    nodes: dict[str, P.NodeInfo],
    sources: Iterable[dict],
) -> None:
    """Dokłada do krawędzi województwa ze wskazówek jej dokumentów.

    Dokument nowy zna swoje węzły (`judge_node`, `venue_node`). Stary (sprzed
    15.10.2026) - tylko nazwy z telefonu, więc łączymy go po kluczach nazw."""
    by_pair: dict[tuple[str, str], int] = {}
    by_names: dict[tuple[str, str], list[int]] = {}
    for i, edge in enumerate(edges):
        by_pair[P.canonical(edge.a_key, edge.b_key)] = i
        na = nodes[edge.a_key].name_key if edge.a_key in nodes else edge.a_key
        nb = nodes[edge.b_key].name_key if edge.b_key in nodes else edge.b_key
        by_names.setdefault(P.canonical(na, nb), []).append(i)

    collected: dict[int, tuple[set[str], set[str]]] = {}
    for src in sources:
        judge_hints = P.hint_provinces(src.get("judge_province"), postal=src.get("judge_postal_code"))
        venue_hints = P.hint_provinces(src.get("match_province"), src.get("public_association"))
        if not judge_hints and not venue_hints:
            continue
        targets: list[tuple[int, str]] = []
        if src.get("judge_node") and src.get("venue_node"):
            i = by_pair.get(P.canonical(src["judge_node"], src["venue_node"]))
            if i is not None:
                targets.append((i, src["judge_node"]))
        else:
            judge = P.name_key(src.get("judge_city") or src.get("hint_judge_city"))
            venue = P.name_key(
                src.get("venue_city") or src.get("hint_venue_city") or src.get("public_venue_city")
            )
            if judge and venue and judge != venue:
                for i in by_names.get(P.canonical(judge, venue), []):
                    edge = edges[i]
                    a_name = nodes[edge.a_key].name_key if edge.a_key in nodes else edge.a_key
                    targets.append((i, edge.a_key if a_name == judge else edge.b_key))
        for i, judge_key in targets:
            a_set, b_set = collected.setdefault(i, (set(), set()))
            if edges[i].a_key == judge_key:
                a_set.update(judge_hints)
                b_set.update(venue_hints)
            else:
                b_set.update(judge_hints)
                a_set.update(venue_hints)
    for i, (a_set, b_set) in collected.items():
        edges[i].hints_a = frozenset(a_set)
        edges[i].hints_b = frozenset(b_set)


async def load_network(with_hints: bool = True) -> tuple[list[P.NodeInfo], list[P.EdgeInfo]]:
    from app.db import database, national_distance_cities, national_distance_connections

    city_rows = await database.fetch_all(select(national_distance_cities))
    nodes = [_node(row) for row in city_rows]
    edge_rows = await database.fetch_all(
        select(
            national_distance_connections.c.city_a_key,
            national_distance_connections.c.city_b_key,
            national_distance_connections.c.distance_km,
            national_distance_connections.c.observations,
        )
    )
    edges = [
        P.EdgeInfo(
            a_key=str(r["city_a_key"]),
            b_key=str(r["city_b_key"]),
            km=float(r["distance_km"]),
            observations=int(r["observations"] or 1),
        )
        for r in edge_rows
    ]
    if with_hints:
        _edge_hints(edges, {n.key: n for n in nodes}, await _sources_with_hints())
    return nodes, edges


# ---------------------------------------------------------------------------
# Nowy dokument
# ---------------------------------------------------------------------------


async def _nodes_for_names(*keys: str) -> list[P.NodeInfo]:
    from app.db import database, national_distance_cities as T

    wanted = [k for k in keys if k]
    if not wanted:
        return []
    rows = await database.fetch_all(
        select(T).where(or_(T.c.name_key.in_(wanted), T.c.city_key.in_(wanted)))
    )
    return [_node(r) for r in rows]


async def _create_node(name: str, pick: P.SidePick, taken: set[str]) -> str:
    """Nowy węzeł z wybranego kandydata. Zwraca klucz."""
    from app.db import national_distance_cities as T

    place = pick.option.place
    nk = P.name_key(name)
    key = nk if nk not in taken else P.secondary_key(nk, place.province, place.gid, taken)
    now = _now()
    await _insert_once(
        T,
        city_key=key,
        name=name,
        name_key=nk,
        latitude=place.lat,
        longitude=place.lon,
        province=place.province or None,
        gid=place.gid,
        approximate=bool(pick.approximate),
        fit_error=round(pick.error, 4),
        observations=0,
        created_at=now,
        updated_at=now,
        resolved_at=now,
    )
    return key


async def _insert_once(table: Any, **values: Any) -> None:
    """Wstawienie, które przy wyścigu dwóch paczek (ten sam nowy węzeł)
    po cichu zostawia pierwszy wiersz - drugi i tak wskazuje ten sam klucz."""
    from app.db import database

    exists = await database.fetch_one(
        select(table.c.city_key).where(table.c.city_key == values["city_key"])
    )
    if exists:
        return
    try:
        await database.execute(insert(table).values(**values))
    except Exception as exc:  # unikalny klucz - ktoś był szybszy
        logger.info("Węzeł %s już istnieje: %s", values["city_key"], exc)


async def _geocode_place(name: str, hints: frozenset[str]) -> Optional[P.Place]:
    """Ostateczność: nazwa spoza skorowidza (literówka, przysiółek). Nominatim
    z województwem ze wskazówki, gdy jest jedno."""
    from app.national_distances import _geocode_city

    query = name
    if len(hints) == 1:
        query = f"{name}, województwo {P.province_label(next(iter(hints)))}"
    point = await _geocode_city(query)
    if not point and query != name:
        point = await _geocode_city(name)
    if not point:
        return None
    gaz = await gazetteer()
    near = gaz.nearest(point[0], point[1], 40)
    return P.Place(
        gid=f"geo:{point[0]:.4f},{point[1]:.4f}",
        name=name,
        lat=point[0],
        lon=point[1],
        province=near.province if near else "",
    )


async def resolve_document(
    judge_city: str,
    venue_city: str,
    km: float,
    judge_hints: frozenset[str] = frozenset(),
    venue_hints: frozenset[str] = frozenset(),
) -> tuple[str, str]:
    """Klucze węzłów (sędzia, hala) dla jednego ryczałtu - tworzy brakujące."""
    gaz = await gazetteer()
    jk, vk = P.name_key(judge_city), P.name_key(venue_city)
    existing = await _nodes_for_names(jk, vk)
    j_nodes = [n for n in existing if n.name_key == jk]
    v_nodes = [n for n in existing if n.name_key == vk]
    j_opts = P.side_options(j_nodes, gaz.candidates(judge_city))
    v_opts = P.side_options(v_nodes, gaz.candidates(venue_city))
    if not j_opts:
        place = await _geocode_place(judge_city, judge_hints)
        if place:
            j_opts = [P.Option(place=place)]
    if not v_opts:
        place = await _geocode_place(venue_city, venue_hints)
        if place:
            v_opts = [P.Option(place=place)]
    j_pick, v_pick = P.choose_document_nodes(km, j_opts, v_opts, judge_hints, venue_hints)

    taken = {n.key for n in existing}
    keys: list[str] = []
    for name, nodes, pick in ((judge_city, j_nodes, j_pick), (venue_city, v_nodes, v_pick)):
        if pick.option is not None and pick.option.node is not None:
            keys.append(pick.option.node.key)
        elif pick.option is not None:
            key = await _create_node(name, pick, taken)
            taken.add(key)
            keys.append(key)
        else:
            # Nic nie wiadomo o położeniu - węzeł bez współrzędnych pod gołą
            # nazwą (jak dawniej przy nieudanym geokodowaniu).
            key = nodes[0].key if nodes else P.name_key(name)
            if not nodes:
                await _create_bare(name, key)
            keys.append(key)
    return keys[0], keys[1]


async def _create_bare(name: str, key: str) -> None:
    from app.db import national_distance_cities as T

    now = _now()
    await _insert_once(
        T,
        city_key=key,
        name=name,
        name_key=P.name_key(name),
        approximate=True,
        observations=0,
        created_at=now,
        updated_at=now,
    )


async def bump_observations(key: str) -> None:
    from app.db import database, national_distance_cities as T

    await database.execute(
        update(T)
        .where(T.c.city_key == key)
        .values(observations=T.c.observations + 1, updated_at=_now())
    )


# ---------------------------------------------------------------------------
# Rozpoznanie sieci i zapis planu
# ---------------------------------------------------------------------------


async def compute_plan(only_names: Optional[set[str]] = None):
    nodes, edges = await load_network()
    gaz = await gazetteer()

    def run():
        result = P.resolve_network(nodes, edges, gaz.candidates, nearest=gaz.nearest)
        keys = P.assign_keys(result.nodes, nodes)
        return P.plan_relocation(nodes, edges, result, keys, only_names=only_names)

    plan = await asyncio.to_thread(run)
    return nodes, edges, plan


def plan_summary(nodes: list[P.NodeInfo], plan: P.PlacePlan, min_km: float = 5.0) -> dict:
    """Czytelny podgląd planu (endpoint admina, skrypt podglądu)."""
    old = {n.key: n for n in nodes}
    moved = []
    for key, value in plan.nodes.items():
        if (value.get("moved_km") or 0) > min_km or key not in old:
            moved.append(
                {
                    "key": key,
                    "name": value["name"],
                    "movedKm": value.get("moved_km"),
                    "from": value.get("previous"),
                    "to": [value["latitude"], value["longitude"]],
                    "province": value.get("province"),
                    "approximate": value["approximate"],
                    "fitError": value.get("fit_error"),
                    "new": key not in old,
                }
            )
    moved.sort(key=lambda m: -(m["movedKm"] or 0))
    groups: dict[str, list[str]] = {}
    for key, value in plan.nodes.items():
        groups.setdefault(value["name_key"], []).append(key)
    return {
        "nodesBefore": len(nodes),
        "nodesAfter": len(plan.nodes) + sum(1 for n in nodes if n.key not in plan.nodes and n.key not in plan.drop_nodes),
        "moved": moved,
        "split": {nk: keys for nk, keys in groups.items() if len(keys) > 1},
        "approximate": sorted(k for k, v in plan.nodes.items() if v["approximate"]),
        "edgeMoves": len(plan.edge_moves),
        "reroute": len(plan.reroute),
        "drop": plan.drop_nodes,
    }


async def apply_plan(plan: P.PlacePlan) -> None:
    """Zapis planu w jednej transakcji, potem geometria OSRM w tle."""
    from app.db import (
        database,
        national_distance_cities as T,
        national_distance_connections as E,
        national_distance_sources as S,
    )

    now = _now()
    async with database.transaction():
        # 1. Węzły (nowe i zmienione). Przypiętych automat nie dotyka.
        current = {
            r["city_key"]: dict(r)
            for r in await database.fetch_all(select(T).where(T.c.city_key.in_(list(plan.nodes) or [""])))
        }
        for key, value in plan.nodes.items():
            row = current.get(key)
            if row and row.get("pinned"):
                continue
            moved = value.get("moved_km") or 0
            values = {
                "name_key": value["name_key"],
                "latitude": value["latitude"],
                "longitude": value["longitude"],
                "province": value.get("province"),
                "gid": value.get("gid"),
                "approximate": bool(value["approximate"]),
                "fit_error": value.get("fit_error"),
                "candidates": value.get("candidates"),
                "observations": int(value.get("observations") or 0),
                "resolved_at": now,
                "updated_at": now,
            }
            if moved > P.MOVE_KM and value.get("previous"):
                values.update(
                    previous_latitude=value["previous"][0],
                    previous_longitude=value["previous"][1],
                    moved_km=moved,
                )
            if row:
                await database.execute(update(T).where(T.c.city_key == key).values(**values))
            else:
                await database.execute(
                    insert(T).values(city_key=key, name=value["name"], created_at=now, **values)
                )

        # 2. Trasy: przeniesienie całych połączeń (z sumą i liczbą dokumentów).
        if plan.edge_moves:
            old_rows = {
                P.canonical(r["city_a_key"], r["city_b_key"]): dict(r)
                for r in await database.fetch_all(select(E))
            }
            targets: dict[tuple[str, str], list[dict]] = {}
            for old_pair, row in old_rows.items():
                renamed = plan.edge_moves.get(old_pair)
                new_pair = P.canonical(*renamed) if renamed else old_pair
                targets.setdefault(new_pair, []).append(row)
            for old_pair, renamed in plan.edge_moves.items():
                if old_pair not in old_rows:
                    continue
                await database.execute(
                    delete(E).where(and_(E.c.city_a_key == old_pair[0], E.c.city_b_key == old_pair[1]))
                )
                # Dokumenty idą za połączeniem (obie strony naraz, w obu
                # kierunkach - sędzia mógł być po stronie A albo B).
                for j_old, v_old, j_new, v_new in (
                    (old_pair[0], old_pair[1], renamed[0], renamed[1]),
                    (old_pair[1], old_pair[0], renamed[1], renamed[0]),
                ):
                    await database.execute(
                        update(S)
                        .where(and_(S.c.judge_node == j_old, S.c.venue_node == v_old))
                        .values(judge_node=j_new, venue_node=v_new)
                    )
            for new_pair, rows in targets.items():
                if not any(plan.edge_moves.get(P.canonical(r["city_a_key"], r["city_b_key"])) for r in rows):
                    continue
                total = sum(int(r["distance_sum"] or r["distance_km"] or 0) for r in rows)
                obs = sum(int(r["observations"] or 0) for r in rows) or 1
                newest = max(rows, key=lambda r: r["updated_at"] or now)
                names = {}
                for r in rows:
                    names[r["city_a_key"]] = r["city_a_name"]
                    names[r["city_b_key"]] = r["city_b_name"]
                renamed_names: dict[str, str] = {}
                for r in rows:
                    pair = P.canonical(r["city_a_key"], r["city_b_key"])
                    mapped = plan.edge_moves.get(pair, pair)
                    renamed_names[mapped[0]] = names[pair[0]]
                    renamed_names[mapped[1]] = names[pair[1]]
                values = {
                    "city_a_name": renamed_names.get(new_pair[0], new_pair[0]),
                    "city_b_name": renamed_names.get(new_pair[1], new_pair[1]),
                    "distance_km": int(round(total / obs)),
                    "distance_sum": total,
                    "observations": obs,
                    # `null()` = prawdziwy NULL, nie JSON-owe „null" (kolumna JSON).
                    "route_geometry": null() if new_pair in plan.reroute else newest["route_geometry"],
                    "last_match_id": newest["last_match_id"],
                    "last_source_key": newest["last_source_key"],
                    "updated_at": now,
                }
                exists = await database.fetch_one(
                    select(E.c.city_a_key).where(and_(E.c.city_a_key == new_pair[0], E.c.city_b_key == new_pair[1]))
                )
                if exists:
                    await database.execute(
                        update(E)
                        .where(and_(E.c.city_a_key == new_pair[0], E.c.city_b_key == new_pair[1]))
                        .values(**values)
                    )
                else:
                    created = min((r["created_at"] for r in rows if r["created_at"]), default=now)
                    await database.execute(
                        insert(E).values(city_a_key=new_pair[0], city_b_key=new_pair[1], created_at=created, **values)
                    )

        # 3. Trasy z przesuniętym końcem: geometria do policzenia od nowa.
        for a, b in plan.reroute:
            await database.execute(
                update(E)
                .where(and_(E.c.city_a_key == a, E.c.city_b_key == b))
                .values(route_geometry=null(), updated_at=now)
            )

        # 4. Węzły, które zostały bez tras.
        if plan.drop_nodes:
            await database.execute(
                delete(T).where(and_(T.c.city_key.in_(plan.drop_nodes), T.c.pinned.is_(False)))
            )

    if plan.reroute:
        schedule_reroute(sorted(plan.reroute))


def schedule_reroute(pairs: list[tuple[str, str]]) -> None:
    task = asyncio.create_task(_reroute(pairs))
    _reroute_tasks.add(task)
    task.add_done_callback(_reroute_tasks.discard)


async def _reroute(pairs: list[tuple[str, str]]) -> None:
    """Geometria OSRM dla tras bez kształtu - po jednej, z przerwą (publiczny
    serwer OSRM nie lubi serii)."""
    from app.db import database, national_distance_cities as T, national_distance_connections as E
    from app.national_distances import _route_geometry

    for a, b in pairs:
        try:
            rows = {
                r["city_key"]: r
                for r in await database.fetch_all(select(T).where(T.c.city_key.in_([a, b])))
            }
            pa, pb = rows.get(a), rows.get(b)
            if not pa or not pb or pa["latitude"] is None or pb["latitude"] is None:
                continue
            geometry = await _route_geometry(
                (float(pa["latitude"]), float(pa["longitude"])),
                (float(pb["latitude"]), float(pb["longitude"])),
            )
            if geometry:
                await database.execute(
                    update(E)
                    .where(and_(E.c.city_a_key == a, E.c.city_b_key == b))
                    .values(route_geometry=geometry)
                )
        except Exception as exc:  # jedna trasa nie zatrzymuje reszty
            logger.info("Geometria trasy %s - %s: %s", a, b, exc)
        await asyncio.sleep(1.1)


async def missing_geometry_pairs(limit: int = 400) -> list[tuple[str, str]]:
    from app.db import database, national_distance_connections as E

    rows = await database.fetch_all(
        select(E.c.city_a_key, E.c.city_b_key)
        .where(or_(E.c.route_geometry.is_(None), cast(E.c.route_geometry, String) == "null"))
        .limit(limit)
    )
    return [(r["city_a_key"], r["city_b_key"]) for r in rows]


async def relocate(apply: bool, only_names: Optional[set[str]] = None) -> dict:
    """Rozpoznanie tabeli: podgląd (`apply=False`) albo zapis."""
    async with _relocate_lock:
        nodes, _edges, plan = await compute_plan(only_names)
        summary = plan_summary(nodes, plan)
        if apply:
            await apply_plan(plan)
            if only_names is None:
                # Pełny przebieg leczy też trasy, którym OSRM kiedyś nie odpowiedział.
                extra = [p for p in await missing_geometry_pairs() if p not in plan.reroute]
                if extra:
                    schedule_reroute(extra)
                summary["rerouteMissing"] = len(extra)
        summary["applied"] = bool(apply)
        return summary


async def reresolve(names: set[str]) -> None:
    """Po paczce dokumentów: tylko nazwy, których paczka dotknęła."""
    names = {n for n in names if n}
    if not names:
        return
    try:
        await relocate(True, only_names=names)
    except Exception as exc:
        logger.warning("Rozpoznanie miejscowości %s nie powiodło się: %s", sorted(names), exc)


# ---------------------------------------------------------------------------
# Admin: lista do przejrzenia i przypięcie
# ---------------------------------------------------------------------------


async def attention_list(days: int = 45, limit: int = 200) -> list[dict]:
    """Przybliżone, niedawno przeniesione i przypięte węzły z trasami do mini-mapy."""
    from datetime import timedelta

    from app.db import database, national_distance_cities as T, national_distance_connections as E

    since = _now() - timedelta(days=days)
    rows = await database.fetch_all(
        select(T)
        .where(
            or_(
                T.c.approximate.is_(True),
                T.c.pinned.is_(True),
                and_(T.c.moved_km > 15, T.c.resolved_at >= since),
                T.c.latitude.is_(None),
            )
        )
        .order_by(T.c.approximate.desc(), T.c.moved_km.desc().nullslast(), T.c.name.asc())
        .limit(limit)
    )
    keys = [r["city_key"] for r in rows]
    if not keys:
        return []
    links = await database.fetch_all(
        select(E.c.city_a_key, E.c.city_b_key, E.c.distance_km, E.c.observations).where(
            or_(E.c.city_a_key.in_(keys), E.c.city_b_key.in_(keys))
        )
    )
    others = {r["city_b_key"] if r["city_a_key"] in keys else r["city_a_key"] for r in links}
    other_rows = {
        r["city_key"]: dict(r)
        for r in await database.fetch_all(select(T).where(T.c.city_key.in_(list(others) or [""])))
    }
    out = []
    for r in rows:
        key = r["city_key"]
        routes = []
        for link in links:
            if key not in (link["city_a_key"], link["city_b_key"]):
                continue
            other_key = link["city_b_key"] if link["city_a_key"] == key else link["city_a_key"]
            other = other_rows.get(other_key) or {}
            if other.get("latitude") is None:
                continue
            routes.append(
                {
                    "key": other_key,
                    "name": other.get("name") or other_key,
                    "lat": other["latitude"],
                    "lon": other["longitude"],
                    "km": int(link["distance_km"]),
                    "observations": int(link["observations"] or 0),
                }
            )
        routes.sort(key=lambda x: -x["observations"])
        candidates = list(r["candidates"] or [])
        if not candidates:
            gaz = await gazetteer()
            candidates = [
                {"gid": p.gid, "name": p.name, "lat": p.lat, "lon": p.lon, "province": p.province,
                 "population": p.population, "error": None}
                for p in gaz.candidates(r["name"])[:8]
            ]
        # Błąd dopasowania liczony na bieżąco - trasy mogły przybyć.
        for cand in candidates:
            errs = [
                P.route_error(x["km"], P.haversine_km((cand["lat"], cand["lon"]), (x["lat"], x["lon"])))
                for x in routes
            ]
            cand["error"] = round(P._median(errs), 4) if errs else cand.get("error")
        candidates.sort(key=lambda c: (c["error"] if c.get("error") is not None else 9.0))
        out.append(
            {
                "key": key,
                "name": r["name"],
                "nameKey": r["name_key"],
                "latitude": r["latitude"],
                "longitude": r["longitude"],
                "province": r["province"],
                "provinceLabel": P.province_label(r["province"] or ""),
                "approximate": bool(r["approximate"]),
                "pinned": bool(r["pinned"]),
                "pinnedBy": r["pinned_by"],
                "fitError": r["fit_error"],
                "movedKm": r["moved_km"],
                "previous": (
                    [r["previous_latitude"], r["previous_longitude"]]
                    if r["previous_latitude"] is not None
                    else None
                ),
                "observations": int(r["observations"] or 0),
                "candidates": candidates[:8],
                "routes": routes[:40],
            }
        )
    return out


async def pin(key: str, *, lat: float, lon: float, province: str, gid: str, actor: str) -> dict:
    """Przypięcie położenia przez admina + przeliczenie geometrii jego tras."""
    from app.db import database, national_distance_cities as T, national_distance_connections as E

    row = await database.fetch_one(select(T).where(T.c.city_key == key))
    if not row:
        raise LookupError(key)
    now = _now()
    before = (row["latitude"], row["longitude"]) if row["latitude"] is not None else None
    moved = P.haversine_km(before, (lat, lon)) if before else None
    async with database.transaction():
        await database.execute(
            update(T)
            .where(T.c.city_key == key)
            .values(
                latitude=lat,
                longitude=lon,
                province=province or row["province"],
                gid=gid or row["gid"],
                approximate=False,
                pinned=True,
                pinned_by=actor,
                pinned_at=now,
                previous_latitude=before[0] if before else None,
                previous_longitude=before[1] if before else None,
                moved_km=round(moved, 1) if moved is not None else None,
                resolved_at=now,
                updated_at=now,
            )
        )
        pairs = []
        if moved is None or moved > P.MOVE_KM:
            links = await database.fetch_all(
                select(E.c.city_a_key, E.c.city_b_key).where(or_(E.c.city_a_key == key, E.c.city_b_key == key))
            )
            pairs = [(r["city_a_key"], r["city_b_key"]) for r in links]
            for a, b in pairs:
                await database.execute(
                    update(E)
                    .where(and_(E.c.city_a_key == a, E.c.city_b_key == b))
                    .values(route_geometry=null(), updated_at=now)
                )
    if pairs:
        schedule_reroute(pairs)
    return {"key": key, "movedKm": moved, "reroute": len(pairs)}


async def unpin(key: str) -> None:
    from app.db import database, national_distance_cities as T

    await database.execute(
        update(T)
        .where(T.c.city_key == key)
        .values(pinned=False, pinned_by=None, pinned_at=None, updated_at=_now())
    )


async def node_points(keys: Iterable[str]) -> dict[str, dict]:
    """Położenie węzłów do odpowiedzi (lat, lon, przybliżone, województwo)."""
    from app.db import database, national_distance_cities as T

    wanted = sorted({k for k in keys if k})
    if not wanted:
        return {}
    rows = await database.fetch_all(select(T).where(T.c.city_key.in_(wanted)))
    return {r["city_key"]: point_payload(r) for r in rows}


def point_payload(row: Any) -> dict:
    data = dict(row)
    return {
        "key": data["city_key"],
        "name": data["name"],
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "province": data.get("province"),
        "approximate": bool(data.get("approximate")),
    }

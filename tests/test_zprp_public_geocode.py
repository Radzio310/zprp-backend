"""Geokoder miast portalu: parser Nominatim, ogranicznik 1/s, ponowienie po 30 dniach,
kolejność kandydatów i pełny cykl na SQLite z udawanym HTTP (respx, bez sieci)."""

import asyncio
import importlib
import sys
import types
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import httpx
import pytest
import respx
import sqlalchemy
from databases import Database
from sqlalchemy import insert, select

from app.national_distance_tables import define_tables as define_national
from app.zprp_public import geocode_rules as G
from app.zprp_public import portal_rules as R
from app.zprp_public_geocode_tables import define_tables as define_geocode
from app.zprp_public_tables import define_tables as define_public

UTC = timezone.utc


def _hit(name="Wioska Nieznana", lat="50.1", lon="19.9", kind="village", **extra):
    return {"lat": lat, "lon": lon, "name": name, "display_name": f"{name}, gmina X, Polska", "addresstype": kind,
            "category": "place", "type": kind, **extra}


# ---------------------------------------------------------------------------
# Reguły
# ---------------------------------------------------------------------------


def test_parser_bierze_tylko_miejscowosc_w_polsce_o_tej_nazwie():
    assert G.parse_nominatim([_hit()], "Wioska Nieznana") == {
        "lat": 50.1, "lon": 19.9, "name": "Wioska Nieznana", "display_name": "Wioska Nieznana, gmina X, Polska",
        "place_type": "village"}
    assert G.parse_nominatim([], "X") is None
    assert G.parse_nominatim({"error": "x"}, "X") is None
    assert G.parse_nominatim([_hit(lat="52.5", lon="13.4")], "Wioska Nieznana") is None        # Berlin - poza Polską
    assert G.parse_nominatim([_hit(kind="county")], "Wioska Nieznana") is None                  # środek powiatu to nie miasto
    assert G.parse_nominatim([_hit(kind="state")], "Wioska Nieznana") is None
    assert G.parse_nominatim([_hit(name="Zupełnie Inna")], "Wioska Nieznana") is None           # rozmyte trafienie
    assert G.parse_nominatim([_hit(lat="abc")], "Wioska Nieznana") is None
    # Dzielnica miasta o złożonej nazwie i drugi wynik, gdy pierwszy odpada.
    assert G.parse_nominatim([_hit(name="Bemowo", kind="suburb")], "Warszawa-Bemowo")["lat"] == 50.1
    assert G.parse_nominatim([_hit(kind="county"), _hit(lat="50.2")], "Wioska Nieznana")["lat"] == 50.2
    # Bez polskich znaków i wielkości liter.
    assert G.parse_nominatim([_hit(name="Łódź", kind="city")], "lodz")["name"] == "Łódź"


def test_parametry_zapytania_i_nazwy():
    assert G.query_params("Kielce") == {"format": "jsonv2", "countrycodes": "pl", "city": "Kielce", "limit": 1}
    assert G.query_params("Kielce", "województwo świętokrzyskie")["state"] == "województwo świętokrzyskie"
    assert G.query_names("Warszawa-Bemowo") == ["Warszawa-Bemowo", "Warszawa"]
    assert G.query_names("Kielce") == ["Kielce"]
    assert "BAZA-pod-Reka" in G.USER_AGENT and "(" in G.USER_AGENT


def test_ponowienie_porazki_po_30_dniach_a_trafienie_na_zawsze():
    now = datetime(2026, 10, 22, tzinfo=UTC)
    assert G.due_for_lookup(None, now)
    assert not G.due_for_lookup({"failed": False, "lat": 50.0, "looked_up_at": now - timedelta(days=900)}, now)
    assert not G.due_for_lookup({"failed": True, "lat": None, "looked_up_at": now - timedelta(days=29)}, now)
    assert G.due_for_lookup({"failed": True, "lat": None, "looked_up_at": now - timedelta(days=30)}, now)
    # SQLite oddaje datę bez strefy - też działa.
    assert G.due_for_lookup({"failed": True, "looked_up_at": datetime(2026, 9, 1)}, now)
    assert not G.due_for_lookup({"failed": True, "looked_up_at": datetime(2026, 10, 20)}, now)


def test_kolejnosc_kandydatow_mecze_najblizsze_potem_kluby_potem_hale():
    now = datetime(2026, 10, 22, 12)
    matches = [
        {"city": "Daleko", "scheduled_at": now + timedelta(days=20)},
        {"city": "Jutro", "scheduled_at": now + timedelta(days=1)},
        {"city": "Wczoraj", "scheduled_at": now - timedelta(days=1)},
    ]
    clubs = [{"city": "Klubowo", "hint": "slaskie"}, {"city": "jutro"}]
    venues = [{"city": "Rzadko", "n": 1}, {"city": "Często", "n": 40}]
    order = [c["city"] for c in G.order_candidates(matches, clubs, venues, now)]
    assert order == ["Jutro", "Wczoraj", "Daleko", "Klubowo", "Często", "Rzadko"]


def test_ogranicznik_jedno_zapytanie_na_sekunde():
    t = {"now": 100.0}
    slept: list[float] = []

    async def fake_sleep(s):
        slept.append(round(s, 3))
        t["now"] += s

    limiter = G.RateLimiter(interval=1.0, clock=lambda: t["now"], sleep=fake_sleep)

    async def go():
        starts = []
        for _ in range(3):
            async with limiter.slot():
                starts.append(t["now"])
                t["now"] += 0.2  # samo zapytanie trwa 0,2 s
        t["now"] += 5  # długa przerwa - bez czekania
        async with limiter.slot():
            starts.append(t["now"])
        return starts

    starts = asyncio.run(go())
    assert slept == [0.8, 0.8]
    assert all(b - a >= 1.0 - 1e-9 for a, b in zip(starts, starts[1:]))


def test_ogranicznik_rownolegle_zadania_ida_po_kolei():
    t = {"now": 0.0}

    async def fake_sleep(s):
        t["now"] += s
        await asyncio.sleep(0)

    limiter = G.RateLimiter(interval=1.0, clock=lambda: t["now"], sleep=fake_sleep)
    starts: list[float] = []

    async def one():
        async with limiter.slot():
            starts.append(t["now"])
            await asyncio.sleep(0)

    async def go():
        await asyncio.gather(*(one() for _ in range(4)))

    asyncio.run(go())
    assert starts == [0.0, 1.0, 2.0, 3.0]


def test_resolve_city_ostatnia_deska_pamiec_geokodera():
    index = R.build_index([{"key": "k", "name": "Kielce", "name_key": "kielce", "lat": 50.87, "lon": 20.63, "province": "", "weight": 1}])
    cache = {"wioska nieznana": {"lat": 50.1, "lon": 19.9, "name": "Wioska Nieznana", "province": "malopolskie"}}.get
    assert R.resolve_city("Kielce", index, "", None, cache)["source"] == "national_places"
    hit = R.resolve_city("32-100 Wioska Nieznana", index, "", lambda key: [], cache)
    assert hit["source"] == "nominatim" and hit["lat"] == 50.1 and hit["key"] == "geo:wioska nieznana"
    assert R.resolve_city("Nigdzie", index, "", None, cache) is None
    # Stara sygnatura (bez pamięci) działa jak dawniej.
    assert R.resolve_city("Wioska Nieznana", index) is None


# ---------------------------------------------------------------------------
# Pełny cykl na SQLite + udawany Nominatim
# ---------------------------------------------------------------------------

_MODULES = ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.api", "app.zprp_public.portal",
            "app.zprp_public.extras", "app.zprp_public.geocode")


def _forget_modules():
    # Moduły z `from app.db import database` trzymają bazę z poprzedniego testu - czyścimy
    # wszystkie poza czystymi regułami (`*_rules`, bez bazy).
    # Atrybut pakietu też: `from app.zprp_public import portal` bierze go przed sys.modules.
    pkg = sys.modules.get("app.zprp_public")
    for name in [n for n in sys.modules if n in _MODULES or (n.startswith("app.zprp_public.") and not n.endswith("_rules"))]:
        sys.modules.pop(name, None)
        child = name.rsplit(".", 1)[1]
        if pkg is not None and name.startswith("app.zprp_public.") and hasattr(pkg, child):
            delattr(pkg, child)


@pytest.fixture
def env(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    tables = list(define_public(metadata)) + list(define_national(metadata)) + [define_geocode(metadata)]
    url = f"sqlite:///{tmp_path / 'geo.db'}"
    metadata.create_all(sqlalchemy.create_engine(url))
    fake = types.ModuleType("app.db")
    fake.database = Database(url.replace("sqlite://", "sqlite+aiosqlite://"))
    fake.DATABASE_URL = url
    for table in tables:
        setattr(fake, table.name, table)
    fake.__getattr__ = lambda name: MagicMock()
    monkeypatch.setitem(sys.modules, "app.db", fake)
    _forget_modules()
    portal = importlib.import_module("app.zprp_public.portal")
    geocode = importlib.import_module("app.zprp_public.geocode")
    extras = importlib.import_module("app.zprp_public.extras")
    portal._nodes_cache.update(at=0.0, index={})
    portal._map_cache.clear()
    geocode._mem.update(at=0.0, points={})

    async def no_gazetteer():
        return lambda key: []

    monkeypatch.setattr(portal, "_gazetteer_lookup", no_gazetteer)
    monkeypatch.setattr(extras, "_gazetteer_lookup", no_gazetteer)
    # Bez prawdziwego czekania 1 s w testach - liczymy tylko odstępy.
    slept: list[float] = []

    async def fake_sleep(s):
        slept.append(s)

    clock = {"t": 0.0}

    def tick():
        clock["t"] += 0.05
        return clock["t"]

    monkeypatch.setattr(G, "NOMINATIM_LIMITER", G.RateLimiter(interval=1.0, clock=tick, sleep=fake_sleep))
    yield types.SimpleNamespace(portal=portal, geocode=geocode, extras=extras, db=fake.database,
                                T={t.name: t for t in tables}, slept=slept)
    _forget_modules()


def _h(**extra):
    return {"source_hash": "h", "source_json": {}, **extra}


async def _seed(db, T):
    now = datetime.now().replace(microsecond=0)
    await db.execute(insert(T["zprp_public_seasons"]).values(season_id="S1", start_year=2026, name="2026/27", active=True, **_h()))
    await db.execute(insert(T["zprp_public_associations"]).values(association_id="A1", name="Małopolski ZPRP", **_h()))
    for cid, city in (("c1", "Kielce"), ("c2", "Wioska Nieznana"), ("c3", "Zadupie Wielkie")):
        await db.execute(insert(T["zprp_public_clubs"]).values(club_id=cid, association_id="A1", name=f"Klub {cid}", city=city,
                                                                archived=False, **_h()))
    base = dict(season_id="S1", competition_id="K1", home_team_id="t1", away_team_id="t2", home_club_id="c1",
                away_club_id="c2", home_team_name="A", away_team_name="B", **_h())
    # Hala bez klubu w mieście - jutrzejszy mecz, więc pierwsza w kolejce.
    await db.execute(insert(T["zprp_public_matches"]).values(match_id="m1", scheduled_at=now + timedelta(days=1),
                                                              venue_name="Hala", venue_city="Halowo", **base))
    await db.execute(insert(T["national_distance_cities"]).values(city_key="kielce", name="Kielce", name_key="kielce",
                                                                   latitude=50.87, longitude=20.63, province="swietokrzyskie",
                                                                   observations=40))


def _go(env, factory):
    async def run():
        await env.db.connect()
        try:
            await _seed(env.db, env.T)
            return await factory()
        finally:
            await env.db.disconnect()

    return asyncio.run(run())


def _nominatim(request: httpx.Request) -> httpx.Response:
    city = request.url.params.get("city")
    assert request.headers["User-Agent"] == G.USER_AGENT
    assert request.url.params.get("countrycodes") == "pl" and request.url.params.get("format") == "jsonv2"
    assert request.url.params.get("state") == "województwo małopolskie"
    if city == "Halowo":
        return httpx.Response(200, json=[_hit(name="Halowo", lat="50.30", lon="19.95")])
    if city == "Wioska Nieznana":
        return httpx.Response(200, json=[_hit()])
    return httpx.Response(200, json=[])


@respx.mock(assert_all_mocked=True)
def test_cykl_geokodera_zapisuje_trafienia_i_porazki_a_mapa_je_widzi(env, respx_mock):
    route = respx_mock.get(G.NOMINATIM_URL).mock(side_effect=_nominatim)

    async def flow():
        pending = await env.geocode.pending_candidates()
        first = await env.geocode.run_cycle(max_lookups=10)
        again = await env.geocode.run_cycle(max_lookups=10)     # nic nowego - porażka czeka 30 dni
        rows = {r["city_norm"]: dict(r) for r in await env.db.fetch_all(select(env.T["zprp_public_geocode_cache"]))}
        world = await env.portal.build_map("S1")
        lat_lon = await env.extras._geocode("Halowo")
        return pending, first, again, rows, world, lat_lon

    pending, first, again, rows, world, lat_lon = _go(env, flow)
    # Kielce zna tabela odległości - nie pytamy. Hala z jutrzejszego meczu idzie pierwsza.
    assert [c["display"] for c in pending] == ["Halowo", "Wioska Nieznana", "Zadupie Wielkie"]
    assert first == {"pending": 3, "found": 2, "failed": 1, "transient": 0}
    assert again["pending"] == 0 and route.call_count == 3
    assert rows["halowo"]["lat"] == 50.30 and not rows["halowo"]["failed"]
    assert rows["zadupie wielkie"]["failed"] and rows["zadupie wielkie"]["lat"] is None
    assert rows["zadupie wielkie"]["attempts"] == 1
    # Odstępy między zapytaniami pilnuje ogranicznik (bez prawdziwego czekania).
    assert len(env.slept) == 2 and all(s > 0.8 for s in env.slept)
    # Mapa: klub z „Wioski” ma pinezkę z Nominatim, hala bez klubu ląduje w `places`.
    cities = {c["city"]: c for c in world["cities"]}
    assert cities["Wioska Nieznana"]["source"] == "nominatim" and cities["Wioska Nieznana"]["lat"] == 50.1
    assert world["unmatched"]["count"] == 1 and world["unmatched"]["items"][0]["city"] == "Zadupie Wielkie"
    places = {p["city"]: p for p in world["places"]}
    assert places["Halowo"]["lat"] == 50.30 and places["Halowo"]["matches"] == 1
    assert world["stats"]["places"] == 1
    # Wspólna funkcja współrzędnych (hale, atlasy) widzi tę samą pamięć.
    assert lat_lon == (50.30, 19.95)


@respx.mock(assert_all_mocked=True)
def test_429_przerywa_cykl_bez_zapisu_porazki(env, respx_mock):
    respx_mock.get(G.NOMINATIM_URL).mock(return_value=httpx.Response(429))

    async def flow():
        stats = await env.geocode.run_cycle(max_lookups=10)
        rows = await env.db.fetch_all(select(env.T["zprp_public_geocode_cache"]))
        return stats, rows

    stats, rows = _go(env, flow)
    assert stats["transient"] == 1 and stats["found"] == 0 and stats["failed"] == 0
    assert rows == []


@respx.mock(assert_all_mocked=True)
def test_porazka_wraca_po_30_dniach(env, respx_mock):
    respx_mock.get(G.NOMINATIM_URL).mock(return_value=httpx.Response(200, json=[]))

    async def flow():
        await env.geocode.run_cycle(max_lookups=10)
        later = datetime.now(UTC) + timedelta(days=31)
        soon = datetime.now(UTC) + timedelta(days=5)
        return ([c["display"] for c in await env.geocode.pending_candidates(soon)],
                [c["display"] for c in await env.geocode.pending_candidates(later)])

    soon, later = _go(env, flow)
    assert soon == []
    assert sorted(later) == ["Halowo", "Wioska Nieznana", "Zadupie Wielkie"]


def test_wylacznik_srodowiskowy(monkeypatch):
    from app.zprp_public import geocode

    monkeypatch.setenv("GEOCODE_DISABLED", "1")
    called = []
    monkeypatch.setattr(geocode, "run_cycle", lambda **kw: called.append(kw))
    asyncio.run(geocode.run_geocode_scheduler())   # wraca od razu, bez cyklu
    assert called == []

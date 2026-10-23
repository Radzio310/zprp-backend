"""Pinezki hal na ulicy: geokoder adresów hal (Nominatim, zapytanie strukturalne
street= / city=), kontrola wyniku (klasa, odległość od miasta), pamięć w osobnej
tabeli, kolejność po miastach i `coords_precision: "address"` w /venues,
/venues/{key} i karcie meczu. SQLite + udawany HTTP (respx), bez sieci."""

import asyncio
import importlib
import sys
import types
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import httpx
import pytest
import respx
import sqlalchemy
from databases import Database
from sqlalchemy import insert, select

from app.national_distance_tables import define_tables as define_national
from app.zprp_public import geocode_rules as G
from app.zprp_public import match_rules as MR
from app.zprp_public_geocode_tables import define_tables as define_geocode, define_venue_table
from app.zprp_public_tables import define_tables as define_public

KIELCE = (50.87, 20.63)


def _item(lat, lon, category="leisure", kind="sports_centre", addresstype=None, name="Hala"):
    return {"lat": str(lat), "lon": str(lon), "category": category, "type": kind, "addresstype": addresstype or kind,
            "name": name, "display_name": f"{name}, Kielce, Polska"}


# ---------------------------------------------------------------------------
# Reguły
# ---------------------------------------------------------------------------


def test_klucz_i_zapytania_adresu():
    assert G.venue_addr_key("Kielce", "ul. Leszczyńska", "8") == "kielce|leszczynska 8"
    assert G.venue_addr_key("Kielce", "Leszczyńska 8", "8") == "kielce|leszczynska 8"   # numer już w ulicy
    assert G.venue_addr_key("Kielce", None, "8") == "" and G.venue_addr_key("", "Polna", "1") == ""
    assert G.address_queries("ul. Leszczyńska", "8") == ["Leszczyńska 8", "Leszczyńska"]
    assert G.address_queries("al. Pokoju 12a") == ["aleja Pokoju 12a", "aleja Pokoju"]
    assert G.address_queries("Sportowa") == ["Sportowa"]
    assert G.address_query_params("Sportowa 5", "Kielce") == {"format": "jsonv2", "countrycodes": "pl", "street": "Sportowa 5",
                                                             "city": "Kielce", "limit": 1}


def test_parser_adresu_bierze_obiekt_blisko_miasta():
    hit = G.parse_address([_item(50.879, 20.642)], *KIELCE)
    assert hit["lat"] == 50.879 and hit["place_class"] == "leisure" and hit["km"] < 2
    assert G.parse_address([_item(50.88, 20.64, "highway", "residential")], *KIELCE)["place_class"] == "highway"
    assert G.parse_address([_item(50.88, 20.64, "building", "yes")], *KIELCE) is not None
    assert G.parse_address([_item(50.88, 20.64, "amenity", "school")], *KIELCE) is not None
    # Za daleko od miasta (ulica o tej nazwie w innym mieście).
    assert G.parse_address([_item(51.40, 20.63)], *KIELCE) is None
    # Powiat / województwo / sama miejscowość - to nie hala.
    assert G.parse_address([_item(50.87, 20.63, "boundary", "administrative", "county")], *KIELCE) is None
    assert G.parse_address([_item(50.87, 20.63, "place", "state", "state")], *KIELCE) is None
    assert G.parse_address([_item(50.87, 20.63, "place", "city", "city")], *KIELCE) is None
    # Poza Polską, zła klasa, śmieci.
    assert G.parse_address([_item(52.5, 13.4)], 52.5, 13.4) is None
    assert G.parse_address([_item(50.88, 20.64, "shop", "bakery")], *KIELCE) is None
    assert G.parse_address({"error": "x"}, *KIELCE) is None and G.parse_address([{"lat": "x"}], *KIELCE) is None


def test_krok_harmonogramu_adresy_dopiero_po_miastach(monkeypatch):
    from app.zprp_public import geocode

    calls = []

    def fake_cities(stats):
        async def run_cycle(max_lookups=60, **_):
            calls.append(("cities", max_lookups))
            return stats
        return run_cycle

    async def run_venue_cycle(max_lookups=30, **_):
        calls.append(("venues", max_lookups))
        return {"pending": 5, "found": 5, "failed": 0, "transient": 0}

    monkeypatch.setattr(geocode, "run_venue_cycle", run_venue_cycle)
    # Kolejka miast dłuższa niż partia: adresy czekają.
    monkeypatch.setattr(geocode, "run_cycle", fake_cities({"pending": 80, "found": 60, "failed": 0, "transient": 0}))
    assert asyncio.run(geocode.scheduler_step(60, 30, 1800)) == 60
    assert calls == [("cities", 60)]
    # Miasta gotowe: adresy hal w tym samym obrocie.
    calls.clear()
    monkeypatch.setattr(geocode, "run_cycle", fake_cities({"pending": 0, "found": 0, "failed": 0, "transient": 0}))
    assert asyncio.run(geocode.scheduler_step(60, 30, 1800)) == 1800
    assert calls == [("cities", 60), ("venues", 30)]
    # Wyłącznik samych adresów.
    calls.clear()
    monkeypatch.setenv("GEOCODE_VENUES_DISABLED", "1")
    assert asyncio.run(geocode.scheduler_step(60, 30, 1800)) == 1800
    assert calls == [("cities", 60)]


# ---------------------------------------------------------------------------
# Pełny cykl na SQLite + udawany Nominatim
# ---------------------------------------------------------------------------

_MODULES = ("app.zprp_public.store", "app.zprp_public.sync", "app.zprp_public.api", "app.zprp_public.portal",
            "app.zprp_public.extras", "app.zprp_public.geocode")


def _forget_modules():
    pkg = sys.modules.get("app.zprp_public")
    for name in [n for n in sys.modules if n in _MODULES or (n.startswith("app.zprp_public.") and not n.endswith("_rules"))]:
        sys.modules.pop(name, None)
        child = name.rsplit(".", 1)[1]
        if pkg is not None and name.startswith("app.zprp_public.") and hasattr(pkg, child):
            delattr(pkg, child)


@pytest.fixture
def env(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    tables = list(define_public(metadata)) + list(define_national(metadata)) + [define_geocode(metadata), define_venue_table(metadata)]
    url = f"sqlite:///{tmp_path / 'venues.db'}"
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
    geocode._mem.update(at=0.0, points={})
    geocode._vmem.update(at=0.0, points={})
    extras._cache.clear()

    async def no_gazetteer():
        return lambda key: []

    monkeypatch.setattr(portal, "_gazetteer_lookup", no_gazetteer)
    monkeypatch.setattr(extras, "_gazetteer_lookup", no_gazetteer)
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


VENUES = [
    # (match_id, hala, miasto, ulica, numer)
    ("m1", "Hala Legionów", "25-001 Kielce", "ul. Leszczyńska", "8"),
    ("m2", "Hala Legionów", "Kielce", "ul. Leszczyńska", "8"),
    ("m3", "Hala Daleka", "Kielce", "Daleka", "1"),
    ("m4", "Hala Powiat", "Kielce", "Powiatowa", None),
    ("m5", "Hala Bez Ulicy", "Kielce", None, None),
    ("m6", "Hala Nigdzie", "Nigdzie", "Polna", "1"),
]


async def _seed(db, T):
    now = datetime.now().replace(microsecond=0)
    await db.execute(insert(T["zprp_public_seasons"]).values(season_id="S1", start_year=2026, name="2026/27", active=True, **_h()))
    await db.execute(insert(T["zprp_public_associations"]).values(association_id="A1", name="Świętokrzyski ZPRP", **_h()))
    await db.execute(insert(T["zprp_public_clubs"]).values(club_id="c1", association_id="A1", name="Klub", city="Kielce",
                                                            archived=False, **_h()))
    for i, (mid, name, city, street, number) in enumerate(VENUES):
        await db.execute(insert(T["zprp_public_matches"]).values(
            match_id=mid, season_id="S1", competition_id="K1", home_team_id="t1", away_team_id="t2", home_club_id="c1",
            away_club_id="c1", home_team_name="A", away_team_name="B", scheduled_at=now - timedelta(days=2 + i),
            venue_name=name, venue_city=city, venue_street=street, venue_number=number, **_h()))
    await db.execute(insert(T["national_distance_cities"]).values(city_key="kielce", name="Kielce", name_key="kielce",
                                                                   latitude=KIELCE[0], longitude=KIELCE[1],
                                                                   province="swietokrzyskie", observations=40))


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
    params = request.url.params
    assert request.headers["User-Agent"] == G.USER_AGENT
    assert params.get("countrycodes") == "pl" and params.get("format") == "jsonv2" and params.get("limit") == "1"
    assert params.get("city") == "Kielce" and "q" not in params
    street = params.get("street")
    if street == "Leszczyńska 8":
        return httpx.Response(200, json=[_item(50.8791, 20.6418, name="Hala Legionów")])
    if street in ("Daleka 1", "Daleka"):
        return httpx.Response(200, json=[_item(51.40, 20.60, "highway", "residential", name="Daleka")])  # ~59 km
    if street == "Powiatowa":
        return httpx.Response(200, json=[_item(50.87, 20.63, "boundary", "administrative", "county", name="powiat")])
    return httpx.Response(200, json=[])


@respx.mock(assert_all_mocked=True)
def test_cykl_adresow_hal_i_pinezka_na_hali(env, respx_mock):
    route = respx_mock.get(G.NOMINATIM_URL).mock(side_effect=_nominatim)

    async def flow():
        pending = await env.geocode.pending_venue_candidates()
        first = await env.geocode.run_venue_cycle(max_lookups=10)
        again = await env.geocode.run_venue_cycle(max_lookups=10)
        rows = {r["addr_norm"]: dict(r) for r in await env.db.fetch_all(select(env.T["zprp_public_venue_geocode_cache"]))}
        listing = await env.extras.venues(q="", limit=100, offset=0)
        legion = await env.extras.venue_details(MR.venue_key("Hala Legionów", "Kielce"))
        far = await env.extras.venue_details(MR.venue_key("Hala Daleka", "Kielce"))
        m = {"venue_name": "Hala Legionów", "venue_city": "25-001 Kielce", "venue_street": "ul. Leszczyńska", "venue_number": "8"}
        card = await env.portal._venue_payload(m)
        return pending, first, again, rows, listing, legion, far, card

    pending, first, again, rows, listing, legion, far, card = _go(env, flow)
    # Hala z dwoma meczami (dwa zapisy miasta) najpierw; bez ulicy i bez punktu miasta - poza kolejką.
    assert [c["addr_norm"] for c in pending] == ["kielce|leszczynska 8", "kielce|daleka 1", "kielce|powiatowa"]
    assert pending[0]["n"] == 2 and pending[0]["city_lat"] == KIELCE[0]
    assert first == {"pending": 3, "found": 1, "failed": 2, "transient": 0}
    # Leszczyńska: 1 zapytanie; Daleka: z numerem i bez (oba za daleko); Powiatowa: 1. Drugi cykl nic nie pyta.
    assert route.call_count == 4 and again["pending"] == 0
    assert len(env.slept) == 3 and all(s > 0.8 for s in env.slept)
    hit = rows["kielce|leszczynska 8"]
    assert not hit["failed"] and hit["lat"] == 50.8791 and hit["place_class"] == "leisure" and hit["km_from_city"] < 2
    assert rows["kielce|daleka 1"]["failed"] and rows["kielce|daleka 1"]["lat"] is None and rows["kielce|daleka 1"]["query"] == "Daleka"
    assert rows["kielce|powiatowa"]["failed"]
    # /venues: adres hali z precyzją „address”; reszta z punktem miasta i bez lat/lon.
    by_name = {v["name"]: v for v in listing["items"]}
    assert (by_name["Hala Legionów"]["lat"], by_name["Hala Legionów"]["coords_precision"]) == (50.8791, "address")
    assert by_name["Hala Legionów"]["city_lat"] == KIELCE[0]
    assert by_name["Hala Daleka"]["lat"] is None and by_name["Hala Daleka"]["coords_precision"] == "city"
    assert by_name["Hala Nigdzie"]["coords_precision"] is None
    # /venues/{key}: adres, a bez niego punkt miasta z precyzją „city”.
    assert (legion["lat"], legion["lon"], legion["coords_precision"]) == (50.8791, 20.6418, "address")
    assert (far["lat"], far["coords_precision"]) == (KIELCE[0], "city")
    # Karta meczu: ta sama pinezka (kod pocztowy i „ul.” nie psują klucza).
    assert (card["lat"], card["coords_precision"], card["name"]) == (50.8791, "address", "Hala Legionów")


@respx.mock(assert_all_mocked=True)
def test_429_w_adresach_przerywa_bez_zapisu(env, respx_mock):
    respx_mock.get(G.NOMINATIM_URL).mock(return_value=httpx.Response(429))

    async def flow():
        stats = await env.geocode.run_venue_cycle(max_lookups=10)
        rows = await env.db.fetch_all(select(env.T["zprp_public_venue_geocode_cache"]))
        return stats, rows

    stats, rows = _go(env, flow)
    assert stats["transient"] == 1 and stats["found"] == 0 and stats["failed"] == 0
    assert rows == []


def test_bez_tabeli_adresow_zostaje_punkt_miasta(env):
    async def flow():
        return await env.geocode.venue_point("Kielce", "Leszczyńska", "8")

    # Pusta pamięć adresów = brak punktu (endpointy wracają do punktu miasta).
    assert _go(env, flow) is None

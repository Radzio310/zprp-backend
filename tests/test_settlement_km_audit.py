import asyncio

from app import national_place_rules as P
from app import settlement_distances as SD
from app import settlement_km_audit_rules as A


def gaz():
    rows = [
        (P.Place("1", "Lipnik", 50.774, 19.432, "slaskie", 100), []),
        (P.Place("2", "Lipnik", 50.730, 21.494, "swietokrzyskie", 400), []),
        (P.Place("3", "Gliwice", 50.294, 18.666, "slaskie", 180000), []),
    ]
    return P.Gazetteer(rows)


def test_imiennik_google_wykryty():
    row = {"distance_km": 271.5, "home_city": "Lipnik", "city": "Gliwice", "distance_source": "google"}
    reasons = {i["reason"] for i in A.audit_row(row, gaz(), province="slaskie", table_km=94)}
    assert "imiennik_google" in reasons
    assert "google_vs_tabela" in reasons
    assert "km_ponad_linia" in reasons


def test_czysty_wiersz():
    row = {"distance_km": 94, "home_city": "Lipnik", "city": "Gliwice", "distance_source": "table"}
    assert A.audit_row(row, gaz(), province="slaskie", table_km=94) == []


def test_skok_km_tej_samej_pary_i_zrodla():
    rows = [
        {"distance_km": 94, "home_city": "Lipnik", "city": "Gliwice", "distance_source": "google"},
        {"distance_km": 271.5, "home_city": "Lipnik", "city": "Gliwice", "distance_source": "google"},
    ]
    assert len(A.pair_jumps(rows)) == 2


def test_tabela_okregu_vs_zprp_to_regula_nie_skok():
    rows = [
        {"distance_km": 94, "home_city": "Lipnik", "city": "Gliwice", "distance_source": "table"},
        {"distance_km": 120, "home_city": "Lipnik", "city": "Gliwice", "distance_source": "zprp-table"},
    ]
    assert A.pair_jumps(rows) == []


def test_imiennik_kandydat_nie_robi_falszywego_alarmu():
    g = P.Gazetteer([
        (P.Place("1", "Mikołów", 50.171, 18.904, "slaskie", 38000), []),
        (P.Place("2", "Kalisz", 51.761, 18.091, "wielkopolskie", 108000), []),
        (P.Place("3", "Kalisz", 50.258, 20.135, "malopolskie", 0), []),
    ])
    row = {"distance_km": 218, "home_city": "Mikołów", "city": "Kalisz", "distance_source": "zprp-table"}
    assert A.audit_row(row, g, province="slaskie", national_km=218) == []


def test_jaworzno_google_poprawne_km_bez_alarmu():
    g = P.Gazetteer([
        (P.Place("1", "Jaworzno", 50.205, 19.275, "slaskie", 96000), []),
        (P.Place("2", "Jaworzno", 51.026, 18.647, "opolskie", 0), []),
        (P.Place("3", "Gliwice", 50.294, 18.666, "slaskie", 180000), []),
    ])
    row = {"distance_km": 60, "home_city": "Jaworzno", "city": "Gliwice", "distance_source": "google"}
    assert A.audit_row(row, g, province="slaskie", table_km=58) == []


def test_google_najkrotsza_trasa_z_regionem_sedziego():
    seen = []

    class R:
        def __init__(self, km):
            self.km = km

        def json(self):
            return {"routes": [{"legs": [{"distance": {"value": int(self.km * 1000)}}]}]}

    class C:
        async def get(self, url, params):
            seen.append(params)
            return R(45.5 if params["avoid"] == "tolls" and "departure_time" not in params else 31.1)

    SD.GOOGLE_MAPS_API_KEY = "x"
    km = asyncio.run(SD.google_distance(C(), "Tychy", "Gliwice", "śląskie"))
    assert km == 31.1
    assert len(seen) == 4
    assert all(p["origin"] == "Tychy, śląskie, Polska" for p in seen)


def test_google_na_wspolrzednych_srodka_miejscowosci():
    seen = []

    class R:
        def json(self):
            return {"routes": [{"legs": [{"distance": {"value": 31100}}]}]}

    class C:
        async def get(self, url, params):
            seen.append(params)
            return R()

    SD.GOOGLE_MAPS_API_KEY = "x"
    km = asyncio.run(SD.google_distance(C(), "Tychy", "Gliwice", "śląskie", (50.12, 18.99), (50.29, 18.67)))
    assert km == 31.1
    assert seen[0]["origin"] == "50.12,18.99" and seen[0]["destination"] == "50.29,18.67"


def test_google_route_oddaje_geometrie_najkrotszego_wariantu():
    class R:
        def __init__(self, km, points):
            self.km, self.points = km, points

        def json(self):
            return {"routes": [{"overview_polyline": {"points": self.points},
                                "legs": [{"distance": {"value": int(self.km * 1000)}}]}]}

    class C:
        async def get(self, url, params):
            if params["avoid"] == "tolls|highways":
                return R(31.1, "krotka")
            return R(45.5, "domyslna")

    SD.GOOGLE_MAPS_API_KEY = "x"
    km, encoded = asyncio.run(SD.google_route(C(), "Tychy", "Gliwice", "śląskie"))
    assert (km, encoded) == (31.1, "krotka")


def test_resolve_distances_zbiera_geometrie():
    class R:
        def json(self):
            return {"routes": [{"overview_polyline": {"points": "abc"},
                                "legs": [{"distance": {"value": 20000}}]}]}

    class C:
        async def get(self, url, params):
            return R()

    SD.GOOGLE_MAPS_API_KEY = "x"
    shapes = {}
    out = asyncio.run(SD.resolve_distances([("Tychy", "Gliwice")], SD.DistanceIndex(None), client=C(), shapes=shapes))
    assert out[("Tychy", "Gliwice")] == (20.0, "google")
    assert shapes == {("tychy", "gliwice"): "abc"}


def test_dabrowa_pod_opolem_a_nie_gornicza():
    # IIM1/8 (Zawody=210953): hala w Dąbrowie pod Opolem. 12,4 km z Siemianowic i
    # 68,7 km z Bielska-Białej to Dąbrowa Górnicza - audyt ma to wytknąć.
    g = P.Gazetteer([
        (P.Place("1", "Dąbrowa", 53.65, 23.35, "podlaskie", 500), []),
        (P.Place("2", "Dąbrowa", 50.6835, 17.7496, "opolskie", 1100), []),
        (P.Place("3", "Dąbrowa Górnicza", 50.327, 19.203, "slaskie", 120000), []),
        (P.Place("4", "Siemianowice Śląskie", 50.327, 19.029, "slaskie", 66000), []),
        (P.Place("5", "Bielsko-Biała", 49.822, 19.047, "slaskie", 170000), []),
        (P.Place("6", "Opole", 50.671, 17.926, "opolskie", 127000), []),
    ])
    teams = "GTV BUS Gwardia II Opole - Sowie Żagiew Dzierżoniów"
    for home, km in (("Siemianowice Śląskie", 12.4), ("Bielsko-Biała", 68.7)):
        row = {"distance_km": km, "home_city": home, "city": "Dąbrowa", "distance_source": "google", "teams": teams}
        assert A.audit_row(row, g, province="slaskie")
    good = {"distance_km": 118.0, "home_city": "Siemianowice Śląskie", "city": "Dąbrowa",
            "distance_source": "google", "teams": teams}
    assert A.audit_row(good, g, province="slaskie") == []


def test_resolve_distances_rownolegle_i_raz_na_pare():
    calls = []
    inflight = {"now": 0, "max": 0}

    class R:
        def json(self):
            return {"routes": [{"overview_polyline": {"points": "p"},
                                "legs": [{"distance": {"value": 10000}}]}]}

    class C:
        async def get(self, url, params):
            calls.append(params["origin"])
            inflight["now"] += 1
            inflight["max"] = max(inflight["max"], inflight["now"])
            await asyncio.sleep(0.01)
            inflight["now"] -= 1
            return R()

    SD.GOOGLE_MAPS_API_KEY = "x"
    ticks = []
    pairs = [(f"Miasto{i}", "Gliwice") for i in range(10)] + [("Miasto0", "Gliwice")] * 3
    out = asyncio.run(
        SD.resolve_distances(pairs, SD.DistanceIndex(None), client=C(), on_progress=lambda d, t: ticks.append((d, t)))
    )
    assert len(out) == 10
    assert all(v == (10.0, "google") for v in out.values())
    assert len(calls) == 10 * 4  # cztery warianty na UNIKALNA pare, powtorki z pamieci
    assert inflight["max"] > 4  # kilka par naraz, nie jedna po drugiej
    assert ticks[-1] == (10, 10)

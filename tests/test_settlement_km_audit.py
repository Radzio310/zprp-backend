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


def test_czysty_wiersz():
    row = {"distance_km": 94, "home_city": "Lipnik", "city": "Gliwice", "distance_source": "table"}
    assert A.audit_row(row, gaz(), province="slaskie", table_km=94) == []


def test_skok_km_tej_samej_pary():
    rows = [
        {"distance_km": 94, "home_city": "Lipnik", "city": "Gliwice"},
        {"distance_km": 271.5, "home_city": "Lipnik", "city": "Gliwice"},
    ]
    assert len(A.pair_jumps(rows)) == 2


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

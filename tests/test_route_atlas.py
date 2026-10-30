"""Atlas tras: klucze, symetria, porazki, 6 miesiecy, dedup, endpoint (bez bazy i bez sieci)."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app import route_atlas as RA
from app import route_atlas_rules as R
from app.route_atlas_rules import Endpoint

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


class MemStore:
    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.fails: dict[str, dict] = {}
        self.touched: list[str] = []

    async def get_many(self, keys):
        return {k: dict(self.rows[k]) for k in keys if k in self.rows}

    async def failures_many(self, keys):
        return {k: dict(self.fails[k]) for k in keys if k in self.fails}

    async def upsert(self, row):
        self.rows[row["pair_key"]] = dict(row)

    async def touch(self, keys, now):
        self.touched.extend(keys)

    async def set_failure(self, key, kind, now):
        old = self.fails.get(key)
        attempts = (old["attempts"] + 1) if (old and kind == "transient" and old["kind"] == "transient") else 1
        self.fails[key] = {"kind": kind, "attempts": attempts, "retry_after": R.retry_after(kind, attempts, now)}

    async def clear_failure(self, key):
        self.fails.pop(key, None)


def counting(kind="ok", km=12.3, encoded="abc", delay=0.0):
    calls = []

    async def measure(pair, client):
        calls.append(pair)
        if delay:
            await asyncio.sleep(delay)
        return RA._Outcome(km if kind == "ok" else None, encoded if kind == "ok" else "", kind)

    return measure, calls


def pair(a="Gliwice", b="Zabrze", **kw):
    return RA.Pair(Endpoint(name=a, **kw), Endpoint(name=b))


# --- klucze ----------------------------------------------------------------

def test_klucz_bez_diakrytykow_i_wielkosci_liter():
    assert R.endpoint_key(Endpoint(name="Bielsko-Biała")) == R.endpoint_key(Endpoint(name="bielsko biala"))
    assert R.endpoint_key(Endpoint(name="Piekary Śl.")) == R.endpoint_key(Endpoint(name="piekary slaskie"))


def test_para_bez_adresu_jest_symetryczna():
    assert R.pair_key(Endpoint(name="Gliwice"), Endpoint(name="Zabrze")) == R.pair_key(
        Endpoint(name="zabrze"), Endpoint(name="GLIWICE")
    )


def test_para_z_adresem_albo_kierunkowa_nie_jest_symetryczna():
    hall = Endpoint(name="Zabrze", address="Wolności 1")
    home = Endpoint(name="Gliwice")
    assert R.pair_key(home, hall) != R.pair_key(hall, home)
    assert ">" in R.pair_key(home, hall)
    assert R.pair_key(Endpoint(name="A", directional=True), Endpoint(name="B")) == "a>b"


def test_wspolrzedne_zaokraglone_w_kluczu():
    a = Endpoint(name="x", lat=50.29441, lon=18.65512)
    b = Endpoint(name="inna nazwa", lat=50.29449, lon=18.65519)
    assert R.endpoint_key(a) == R.endpoint_key(b) == "@50.294,18.655"
    assert R.endpoint_key(Endpoint(name="Gliwice", lat=999, lon=1)) == "gliwice"  # zly punkt ignorowany


def test_region_rozroznia_imienniki():
    assert R.endpoint_key(Endpoint(name="Lipnik", region="śląskie")) == "lipnik|slaskie"
    assert R.endpoint_key(Endpoint(name="Lipnik", region="Śląskie")) != R.endpoint_key(
        Endpoint(name="Lipnik", region="małopolskie")
    )


def test_klucz_zgodny_z_dawnym_kluczem_rozliczen():
    # dom|wojewodztwo > cel obciety do pierwszego przecinka
    origin = Endpoint(name="Nakło Śląskie", region="Śląskie")
    dest = Endpoint(name="Szkolna 9, Dąbrowa, woj. opolskie", directional=True, key="szkolna 9")
    assert R.pair_key(origin, dest) == "naklo slaskie|slaskie>szkolna 9"


def test_pusty_koniec_to_brak_klucza():
    assert R.pair_key(Endpoint(name=""), Endpoint(name="Gliwice")) == ""


# --- terminy -----------------------------------------------------------------

def test_terminy_porazek():
    assert R.retry_after("transient", 1, NOW) == NOW + timedelta(hours=1)
    assert R.retry_after("transient", 3, NOW) == NOW + timedelta(hours=4)
    assert R.retry_after("transient", 20, NOW) == NOW + timedelta(hours=24)
    assert R.retry_after("no_route", 1, NOW) == NOW + timedelta(days=30)


def test_swiezosc_szesc_miesiecy():
    assert R.is_fresh(NOW - timedelta(days=180), NOW)
    assert not R.is_fresh(NOW - timedelta(days=200), NOW)
    assert not R.is_fresh(None, NOW)


# --- serwis ------------------------------------------------------------------

async def test_pomiar_zapisuje_i_drugie_pytanie_jest_za_darmo():
    store = MemStore()
    measure, calls = counting()
    first = await RA.resolve([pair()], store=store, measure=measure, now=NOW)
    assert first[0].status == "measured" and first[0].km == 12.3
    second = await RA.resolve([pair("zabrze", "GLIWICE")], store=store, measure=measure, now=NOW)  # odwrotnie
    assert second[0].status == "cached" and second[0].km == 12.3
    assert second[0].encoded == "abc"
    assert len(calls) == 1
    assert store.touched  # licznik uzyc


async def test_to_samo_miejsce_to_zero_bez_pomiaru():
    measure, calls = counting()
    res = await RA.resolve([pair("Gliwice", "gliwice")], store=MemStore(), measure=measure, now=NOW)
    assert res[0].km == 0.0 and res[0].status == "same" and not calls


async def test_pomiar_starszy_niz_6_miesiecy_jest_powtarzany():
    store = MemStore()
    key = R.pair_key(Endpoint(name="Gliwice"), Endpoint(name="Zabrze"))
    store.rows[key] = {"pair_key": key, "km": 10.0, "encoded": "old", "source": "x",
                       "measured_at": NOW - timedelta(days=200)}
    measure, calls = counting(km=11.0, encoded="new")
    res = await RA.resolve([pair()], store=store, measure=measure, now=NOW)
    assert len(calls) == 1 and res[0].km == 11.0 and res[0].status == "measured"
    assert store.rows[key]["measured_at"] == NOW


async def test_nieudany_ponowny_pomiar_oddaje_stary_wynik():
    store = MemStore()
    key = R.pair_key(Endpoint(name="Gliwice"), Endpoint(name="Zabrze"))
    store.rows[key] = {"pair_key": key, "km": 10.0, "encoded": "", "source": "x",
                       "measured_at": NOW - timedelta(days=200)}
    measure, _ = counting(kind="transient")
    res = await RA.resolve([pair()], store=store, measure=measure, now=NOW)
    assert res[0].km == 10.0 and res[0].status == "stale"
    assert store.fails[key]["kind"] == "transient"


async def test_blad_przejsciowy_blokuje_godzine_potem_ponawia():
    store = MemStore()
    bad, calls = counting(kind="transient")
    first = await RA.resolve([pair()], store=store, measure=bad, now=NOW)
    assert first[0].status == "missing" and first[0].reason == "error"
    again = await RA.resolve([pair()], store=store, measure=bad, now=NOW + timedelta(minutes=30))
    assert again[0].reason == "retry_later" and len(calls) == 1          # nie pytamy
    later = await RA.resolve([pair()], store=store, measure=bad, now=NOW + timedelta(hours=1, minutes=1))
    assert len(calls) == 2 and later[0].reason == "error"
    key = R.pair_key(Endpoint(name="Gliwice"), Endpoint(name="Zabrze"))
    assert store.fails[key]["attempts"] == 2                           # backoff rosnie


async def test_brak_trasy_pamietany_30_dni():
    store = MemStore()
    none, calls = counting(kind="no_route")
    await RA.resolve([pair()], store=store, measure=none, now=NOW)
    res = await RA.resolve([pair()], store=store, measure=none, now=NOW + timedelta(days=29))
    assert res[0].reason == "no_route" and len(calls) == 1
    await RA.resolve([pair()], store=store, measure=none, now=NOW + timedelta(days=31))
    assert len(calls) == 2


async def test_sukces_czysci_porazke():
    store = MemStore()
    bad, _ = counting(kind="transient")
    await RA.resolve([pair()], store=store, measure=bad, now=NOW)
    good, _ = counting()
    res = await RA.resolve([pair()], store=store, measure=good, now=NOW + timedelta(hours=2))
    assert res[0].status == "measured" and not store.fails


async def test_dedup_rownoleglych_pytan_jedno_zapytanie():
    store = MemStore()
    measure, calls = counting(delay=0.05)
    a, b = await asyncio.gather(
        RA.resolve([pair()], store=store, measure=measure, now=NOW),
        RA.resolve([pair("Zabrze", "Gliwice")], store=store, measure=measure, now=NOW),
    )
    assert len(calls) == 1
    assert a[0].km == b[0].km == 12.3


async def test_duplikaty_w_jednym_zadaniu_to_jeden_pomiar():
    measure, calls = counting()
    res = await RA.resolve([pair(), pair("zabrze", "gliwice"), pair()], store=MemStore(), measure=measure, now=NOW)
    assert len(calls) == 1 and [r.km for r in res] == [12.3] * 3


async def test_limit_nowych_pomiarow():
    measure, calls = counting()
    pairs = [pair("Gliwice", c) for c in ("Zabrze", "Bytom", "Opole", "Rybnik")]
    res = await RA.resolve(pairs, store=MemStore(), measure=measure, now=NOW, max_new=2)
    assert len(calls) == 2
    assert sum(1 for r in res if r.status == "measured") == 2
    assert [r.reason for r in res if r.status == "missing"] == ["budget", "budget"]


async def test_zero_limit_to_tylko_odczyt():
    measure, calls = counting()
    res = await RA.resolve([pair()], store=MemStore(), measure=measure, now=NOW, max_new=0)
    assert not calls and res[0].reason == "budget"


async def test_brak_geometrii_dociaga_raz_na_30_dni():
    store = MemStore()
    key = R.pair_key(Endpoint(name="Gliwice"), Endpoint(name="Zabrze"))
    store.rows[key] = {"pair_key": key, "km": 10.0, "encoded": "", "source": "x", "measured_at": NOW}
    measure, calls = counting(encoded="")           # Google znow bez geometrii
    await RA.resolve([pair()], store=store, measure=measure, now=NOW, need_shape=True)
    assert len(calls) == 1 and store.fails[key]["kind"] == "noshape"
    res = await RA.resolve([pair()], store=store, measure=measure, now=NOW + timedelta(days=1), need_shape=True)
    assert len(calls) == 1 and res[0].status == "cached"


# --- endpoint ----------------------------------------------------------------

async def test_endpoint_kontrakt_i_limity():
    from fastapi import HTTPException

    from app import atlas_routes as AR

    store = MemStore()
    measure, calls = counting()
    body = AR.RoutesIn.model_validate({
        "pairs": [
            {"from": {"name": "Gliwice", "region": "śląskie"}, "to": {"name": "Zabrze"}},
            {"from": {"name": "Gliwice"}, "to": {"lat": 50.3, "lon": 18.7}},
            {"from": {"name": ""}, "to": {"name": "Zabrze"}},
        ],
        "max_new": 1,
    })
    out = await AR.run(body, store=store, measure=measure)
    rows = out["routes"]
    assert [r["index"] for r in rows] == [0, 1, 2]
    assert rows[0]["status"] == "measured" and rows[0]["km"] == 12.3 and rows[0]["polyline"] == "abc"
    assert rows[0]["measured_at"] and rows[0]["source"] == R.SOURCE_MEASURED
    assert rows[1]["status"] == "missing" and rows[1]["reason"] == "budget" and rows[1]["km"] is None
    assert rows[2]["reason"] == "invalid"
    assert out["stats"]["max_new"] == 1 and len(calls) == 1

    too_many = AR.RoutesIn.model_validate({
        "pairs": [{"from": {"name": "A"}, "to": {"name": "B"}}] * (AR.MAX_PAIRS + 1)
    })
    with pytest.raises(HTTPException):
        await AR.run(too_many, store=store, measure=measure)

    only_read = AR.RoutesIn.model_validate({"pairs": [{"from": {"name": "X"}, "to": {"name": "Y"}}], "measure": False})
    out = await AR.run(only_read, store=store, measure=measure)
    assert out["routes"][0]["reason"] == "budget" and len(calls) == 1

"""
Pamięć policzonych rozliczeń (`app/settlement_cache.py`) - bez bazy.

Zgłoszenie z 24.09.2026: każde kliknięcie w zakładce Rozliczenia liczyło cały
okręg od zera. Serwer trzyma teraz wynik, ale NIGDY nie może oddać starego po
zapisie - to sprawdzają testy niżej.
"""

import asyncio
import gzip
import json

from sqlalchemy import Column, Integer, MetaData, String, Table, delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import settlement_cache as SC

META = MetaData()
ENTRIES = Table(
    "province_club_entries",
    META,
    Column("id", Integer),
    Column("province", String),
    Column("amount", Integer),
)
OTHER = Table("board_posts", META, Column("id", Integer), Column("province", String))


def run(coro):
    return asyncio.run(coro)


def setup_function():
    SC.clear()


def test_drugie_pytanie_nie_liczy_od_nowa():
    calls = []

    async def compute():
        calls.append(1)
        return {"suma": 704.6}

    async def scenario():
        first = await SC.remember("month", "SLASKIE", (2026, 9), compute)
        second = await SC.remember("month", "ŚLĄSKIE", (2026, 9), compute)
        return first, second

    first, second = run(scenario())
    assert first is second
    assert len(calls) == 1


def test_zapis_uniewaznia_tylko_swoj_okreg():
    calls = []

    async def compute():
        calls.append(1)
        return len(calls)

    async def scenario():
        await SC.remember("month", "SLASKIE", (), compute)
        await SC.remember("month", "MAZOWIECKIE", (), compute)
        SC.bump("ŚLĄSKIE")
        slaskie = await SC.remember("month", "SLASKIE", (), compute)
        mazowieckie = await SC.remember("month", "MAZOWIECKIE", (), compute)
        return slaskie, mazowieckie

    slaskie, mazowieckie = run(scenario())
    assert slaskie == 3  # policzone od nowa
    assert mazowieckie == 2  # z pamięci
    SC.bump()  # bez okręgu = wszystkie
    assert SC.peek("month", "MAZOWIECKIE") is None


def test_rownoczesne_pytania_licza_raz():
    calls = []

    async def compute():
        calls.append(1)
        await asyncio.sleep(0.01)
        return "wynik"

    async def scenario():
        return await asyncio.gather(
            *(SC.remember("summary", "SLASKIE", (1,), compute) for _ in range(5))
        )

    assert run(scenario()) == ["wynik"] * 5
    assert len(calls) == 1


def test_zapis_w_trakcie_liczenia_nie_zostaje_w_pamieci():
    async def compute():
        SC.bump("SLASKIE")  # ktoś zapisał, zanim skończyliśmy liczyć
        return "stare"

    async def scenario():
        value = await SC.remember("month", "SLASKIE", (), compute)
        return value, SC.peek("month", "SLASKIE")

    value, cached = run(scenario())
    assert value == "stare"
    assert cached is None


def test_siatka_bezpieczenstwa_ttl(monkeypatch):
    async def compute():
        return "x"

    run(SC.remember("month", "SLASKIE", (), compute))
    assert SC.peek("month", "SLASKIE") == "x"
    monkeypatch.setattr(SC, "TTL_SECONDS", -1.0)
    assert SC.peek("month", "SLASKIE") is None


def test_blad_liczenia_nie_zostaje_w_pamieci():
    async def boom():
        raise RuntimeError("baza")

    async def scenario():
        try:
            await SC.remember("month", "SLASKIE", (), boom)
        except RuntimeError:
            pass
        return SC.peek("month", "SLASKIE"), SC.stats()["inflight"]

    assert run(scenario()) == (None, 0)


# ---------------------------------------------------------------- haczyk zapisów

def test_rozpoznaje_zapisy_do_obserwowanych_tabel():
    insert = pg_insert(ENTRIES).values(province="ŚLĄSKIE", amount=1).on_conflict_do_nothing()
    assert SC.written_tables(insert) == {"province_club_entries"}
    assert SC.provinces_of(insert) == {"SLASKIE"}

    change = update(ENTRIES).where(ENTRIES.c.province.in_(["SLASKIE", "ŚLĄSKIE"])).values(amount=2)
    assert SC.provinces_of(change) == {"SLASKIE"}

    # Bez okręgu w zapytaniu = wszystkie okręgi.
    assert SC.provinces_of(delete(ENTRIES).where(ENTRIES.c.id == 3)) == set()

    assert SC.written_tables(select(ENTRIES)) == set()
    assert SC.written_tables(pg_insert(OTHER).values(province="SLASKIE")) == set()
    assert SC.written_tables("UPDATE province_clubs SET note = ''") == {"province_clubs"}
    assert SC.written_tables("SELECT * FROM province_clubs") == set()


class FakeTransaction:
    def __init__(self, log):
        self.log = log

    async def __aenter__(self):
        self.log.append("begin")
        return self

    async def __aexit__(self, *exc):
        self.log.append("commit")
        return False


class FakeDatabase:
    def __init__(self):
        self.log = []

    async def execute(self, query, values=None):
        self.log.append("execute")
        return 1

    async def execute_many(self, query, values):
        self.log.append("execute_many")

    async def fetch_one(self, query, values=None):
        return None

    async def fetch_val(self, query, values=None, column=0):
        return None

    def transaction(self):
        return FakeTransaction(self.log)


def test_zapis_przez_baze_uniewaznia_pamiec():
    db = FakeDatabase()
    SC.install_write_hook(db)
    SC.install_write_hook(db)  # drugi raz nic nie robi

    async def compute():
        return "saldo"

    async def scenario():
        await SC.remember("clubs", "SLASKIE", (), compute)
        await db.execute(select(ENTRIES))  # odczyt nie rusza pamięci
        kept = SC.peek("clubs", "SLASKIE")
        await db.execute(pg_insert(ENTRIES).values(province="SLASKIE", amount=5))
        dropped = SC.peek("clubs", "SLASKIE")
        return kept, dropped

    kept, dropped = run(scenario())
    assert kept == "saldo"
    assert dropped is None
    assert db.log == ["execute", "execute"]


def test_koniec_transakcji_podbija_jeszcze_raz():
    db = FakeDatabase()
    SC.install_write_hook(db)

    async def compute():
        return "sprzed zatwierdzenia"

    async def scenario():
        async with db.transaction():
            await db.execute_many(pg_insert(ENTRIES), [{"province": "SLASKIE", "amount": 1}])
            # Pytanie w trakcie transakcji liczy się ze starych danych...
            await SC.remember("clubs", "SLASKIE", (), compute)
            during = SC.peek("clubs", "SLASKIE")
        # ...i po zatwierdzeniu nie może już wyjść.
        return during, SC.peek("clubs", "SLASKIE")

    during, after = run(scenario())
    assert during == "sprzed zatwierdzenia"
    assert after is None


# ---------------------------------------------------------------- odpowiedzi HTTP

class FakeRequest:
    def __init__(self, headers):
        self.headers = headers


def test_etag_304_i_gzip():
    payload = {"clubs": [{"name": "KS Bystra", "balance": -704.6}] * 60}
    pack = SC.Packed(payload)
    assert json.loads(pack.body) == payload

    plain = SC.respond(FakeRequest({}), pack)
    assert plain.status_code == 200
    assert plain.headers["etag"] == pack.etag
    assert "no-cache" in plain.headers["cache-control"]

    zipped = SC.respond(FakeRequest({"accept-encoding": "gzip, br"}), pack)
    assert zipped.headers["content-encoding"] == "gzip"
    assert json.loads(gzip.decompress(zipped.body)) == payload

    same = SC.respond(FakeRequest({"if-none-match": f"W/{pack.etag}"}), pack)
    assert same.status_code == 304
    assert same.body == b""


def test_ten_sam_wynik_ten_sam_etag():
    assert SC.Packed({"a": 1}).etag == SC.Packed({"a": 1}).etag
    assert SC.Packed({"a": 1}).etag != SC.Packed({"a": 1.5}).etag


def test_wplata_nie_czyta_faktow_okregu_od_nowa():
    """Zapis do tabeli klubów przelicza wyniki, ale wspólna baza faktów zostaje."""
    db = FakeDatabase()
    SC.install_write_hook(db)

    async def compute():
        return "fakty"

    async def scenario():
        await SC.remember("base", "SLASKIE", (), compute)
        await SC.remember("clubs", "SLASKIE", (), compute)
        await db.execute(pg_insert(ENTRIES).values(province="SLASKIE", amount=5))
        return SC.peek("base", "SLASKIE"), SC.peek("clubs", "SLASKIE")

    base, clubs = run(scenario())
    assert base == "fakty"
    assert clubs is None
    SC.bump("SLASKIE")  # jawne podbicie bez zakresu rusza wszystko
    assert SC.peek("base", "SLASKIE") is None

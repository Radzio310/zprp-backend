"""Zgłoszenia błędów rysowania z przeglądarki - POST /api/v1/handball/client-errors i lista admina."""

import asyncio
import importlib
import json
import sys
import types
from unittest.mock import MagicMock

import httpx
import pytest
import sqlalchemy
from databases import Database
from fastapi import FastAPI

from app.client_error_tables import define_tables

URL = "/api/v1/handball/client-errors"
ADMIN_URL = "/api/v1/handball/admin/client-errors"


@pytest.fixture
def env(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    table = define_tables(metadata)
    url = f"sqlite:///{tmp_path / 'errors.db'}"
    metadata.create_all(sqlalchemy.create_engine(url))
    fake = types.ModuleType("app.db")
    fake.database = Database(url.replace("sqlite://", "sqlite+aiosqlite://"))
    fake.client_error_reports = table
    fake.__getattr__ = lambda name: MagicMock()
    monkeypatch.setitem(sys.modules, "app.db", fake)
    sys.modules.pop("app.client_errors", None)
    module = importlib.import_module("app.client_errors")
    monkeypatch.delenv("ADMIN_WRITE_STRICT", raising=False)
    app = FastAPI()
    app.include_router(module.router)
    app.include_router(module.admin_router)
    yield module, fake.database, app
    sys.modules.pop("app.client_errors", None)


def run(env, factory):
    module, db, app = env

    async def go():
        await db.connect()
        try:
            transport = httpx.ASGITransport(app=app, client=("203.0.113.7", 5555))
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await factory(module, db, client)
        finally:
            await db.disconnect()

    return asyncio.run(go())


def _report(**extra):
    body = {"kind": "stats", "route": "/statystyki?sezon=S26", "part": "wykres okładki",
            "message": "TypeError: Cannot read properties of undefined (reading 'length')",
            "stack": "MinuteStrip\nStageScope\nStatsGuard", "ua": "Mozilla/5.0 (Linux; Android 14) Chrome/141 Mobile",
            "build": "342503dabc12", "lite": True, "standalone": True, "width": 412}
    body.update(extra)
    return json.dumps(body)


def test_zgloszenie_zapisane_jako_text_plain_i_lista_admina(env):
    async def go(module, db, client):
        r1 = await client.post(URL, content=_report(), headers={"Content-Type": "text/plain;charset=UTF-8"})
        listed = await client.get(ADMIN_URL)
        return r1, listed

    r1, listed = run(env, go)
    assert r1.status_code == 202 and r1.json() == {"ok": True, "count": 1}
    assert listed.status_code == 200
    item = listed.json()["items"][0]
    assert item["route"] == "/statystyki" and item["part"] == "wykres okładki" and item["count"] == 1
    assert item["lite"] is True and item["standalone"] is True and item["width"] == 412 and item["build"] == "342503dabc12"
    assert item["message"].startswith("TypeError") and "MinuteStrip" in item["stack"]
    assert "203.0.113.7" not in json.dumps(item), "adres IP nie trafia do bazy"


def test_ten_sam_blad_zwieksza_licznik_zamiast_wierszy(env):
    async def go(module, db, client):
        for _ in range(3):
            await client.post(URL, content=_report())
        await client.post(URL, content=_report(route="/mecze/123456789"))
        await client.post(URL, content=_report(route="/mecze/987654321"))
        other = await client.post(URL, content=_report(part="rozdział season", message="Cannot read properties of undefined (reading 'filter')"))
        rows = await db.fetch_all(sqlalchemy.select(module.client_error_reports))
        return other, [dict(r) for r in rows]

    other, rows = run(env, go)
    assert other.json()["count"] == 1
    assert len(rows) == 3
    by = {(r["route"], r["part"]): r["count"] for r in rows}
    assert by[("/statystyki", "wykres okładki")] == 3
    # Identyfikatory w trasie są sklejane - błąd ekranu meczu to jeden wiersz, nie po wierszu na mecz.
    assert by[("/mecze/:id", "wykres okładki")] == 2


def test_limit_30_na_minute_z_jednego_adresu(env):
    async def go(module, db, client):
        codes = [(await client.post(URL, content=_report(message=f"Błąd {i}"))).status_code for i in range(32)]
        return codes

    codes = run(env, go)
    assert codes[:30] == [202] * 30
    assert codes[30:] == [429, 429]


def test_limit_rozmiaru_i_zle_zgloszenia(env):
    async def go(module, db, client):
        big = await client.post(URL, content=_report(stack="x" * 5000))
        bad = await client.post(URL, content="nie json")
        empty = await client.post(URL, content=json.dumps({"part": "x"}))
        arr = await client.post(URL, content="[1, 2]")
        count = await db.fetch_val(sqlalchemy.select(sqlalchemy.func.count()).select_from(module.client_error_reports))
        return big, bad, empty, arr, count

    big, bad, empty, arr, count = run(env, go)
    assert big.status_code == 413
    assert bad.status_code == 422 and empty.status_code == 422 and arr.status_code == 422
    assert count == 0


def test_czyszczenie_pol_bez_adresow_i_przyciete():
    from app import client_error_rules as CE  # czyste reguły - bez bazy

    row = CE.clean_report(_report(message="Failed https://x.example/a?token=1 " + "y" * 400, kind="hack", width=-5).encode())
    assert "<url>" in row["message"] and "token" not in row["message"] and len(row["message"]) == 300
    assert row["kind"] == "other" and row["width"] is None and row["route"] == "/statystyki"
    assert CE.fingerprint(row) == CE.fingerprint(dict(row, ua="inny telefon", width=360))
    with pytest.raises(CE.ReportError):
        CE.clean_report(b"x" * (CE.MAX_BODY + 1))


def test_lista_admina_w_trybie_twardym_wymaga_tokenu(env, monkeypatch):
    monkeypatch.setenv("ADMIN_WRITE_STRICT", "1")

    async def go(module, db, client):
        return await client.get(ADMIN_URL)

    r = run(env, go)
    assert r.status_code == 401

"""Panel: wgranie listy przejazdów i zapis zmiany miejsca zamieszkania (06.11.2026)."""
from datetime import date

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.test_settlement_home_rules import JUDGES, LIST_TEXT


@pytest.fixture
def client(monkeypatch):
    from app import province_panel_guard as G
    from app import province_settlement_homes as M

    async def allow(*args, **kwargs):
        return None

    async def judges(key):
        return JUDGES

    async def history(key, judge_id=None):
        return {"13": [(date(2026, 11, 1), "Bytom")]}

    saved, recomputed = [], []

    async def save(key, judge_id, city, until, **kw):
        saved.append((key, judge_id, city, until, kw.get("source"), kw.get("ref")))
        return len(saved)

    async def recompute(key, judge_id):
        recomputed.append(judge_id)
        return {"judge_id": judge_id, "matches": 4, "missing_km": 0}

    monkeypatch.setattr(G, "ensure_panel_write", allow)
    monkeypatch.setattr(M, "require_province", lambda province: province)
    monkeypatch.setattr(M, "_judges", judges)
    monkeypatch.setattr(M.HH, "load", history)
    monkeypatch.setattr(M.HH, "save", save)
    monkeypatch.setattr(M.HH, "recompute_judge", recompute)
    monkeypatch.setattr(M, "_pdf_text", lambda data: LIST_TEXT)
    app = FastAPI()
    app.include_router(M.router)
    c = TestClient(app)
    c.saved, c.recomputed = saved, recomputed
    return c


def test_scan_reports_who_moved(client):
    reply = client.post(
        "/province/settlements/homes/scan?province=SLASKIE",
        files={"file": ("lista.pdf", b"%PDF-1.7 test", "application/pdf")},
    )
    assert reply.status_code == 200, reply.text
    body = reply.json()
    assert (body["number"], body["from"], body["to"]) == ("SLP/2026_27/2", "2026-10-05", "2026-11-01")
    first = body["rows"][0]
    assert (first["name"], first["status"], first["list_city"], first["current"]) == (
        "Karol Wojtyczka", "changed", "Mikołów", "Orzesze")


def test_scan_refuses_non_pdf(client):
    reply = client.post(
        "/province/settlements/homes/scan?province=SLASKIE",
        files={"file": ("lista.txt", b"hello", "text/plain")},
    )
    assert reply.status_code == 400
    assert "PDF" in reply.json()["detail"]


def test_batch_saves_and_recomputes_each_judge_once(client):
    reply = client.post("/province/settlements/homes/batch", json={
        "province": "SLASKIE",
        "user": "admin",
        "entries": [
            {"province": "SLASKIE", "judge_id": "11", "city": "Mikołów", "until": "2026-11-01", "source": "list", "ref": "SLP/2026_27/2"},
            {"province": "SLASKIE", "judge_id": "11", "city": "Tychy", "until": "2026-06-30"},
        ],
    })
    assert reply.status_code == 200, reply.text
    assert reply.json()["matches"] == 4
    assert client.saved[0][2:] == ("Mikołów", date(2026, 11, 1), "list", "SLP/2026_27/2")
    assert client.recomputed == ["11"]


def test_entry_validation_messages(client):
    unknown = client.post("/province/settlements/homes", json={
        "province": "SLASKIE", "judge_id": "999", "city": "Mikołów", "until": "2026-11-01"})
    assert unknown.status_code == 400 and "999" in unknown.json()["detail"]
    empty = client.post("/province/settlements/homes", json={
        "province": "SLASKIE", "judge_id": "11", "city": "  ", "until": "2026-11-01"})
    assert empty.status_code == 400 and "poprzednie miejsce" in empty.json()["detail"]

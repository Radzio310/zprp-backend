"""Jednorazowy resync uwag portalu: kursor, znacznik końca, wznowienie, błędy."""
from __future__ import annotations

import pytest

import app.zprp_comment_resync as R

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


def _wire(monkeypatch, ids, state=None, failing=()):
    store = {"state": dict(state or {})}
    empty = set(ids)  # mecze z pustym comment; pobranie ich nie "naprawia" (puste uwagi)

    async def load():
        return dict(store["state"])

    async def save(s):
        store["state"] = dict(s)

    async def pick(after, limit=R.BATCH):
        return sorted(i for i in empty if i > after)[:2]

    fetched = []

    async def fetch(client, mid, counters):
        fetched.append(mid)
        if mid in failing:
            raise RuntimeError("boom")

    async def nosleep(_):
        return None

    monkeypatch.setattr(R, "load_state", load)
    monkeypatch.setattr(R, "save_state", save)
    monkeypatch.setattr(R, "pick_batch", pick)
    monkeypatch.setattr(R.asyncio, "sleep", nosleep)
    return store, fetched, fetch


async def test_przechodzi_wszystkie_i_ustawia_znacznik(monkeypatch):
    store, fetched, fetch = _wire(monkeypatch, ["1", "2", "3"])
    out = await R.run_resync(fetch=fetch)
    assert fetched == ["1", "2", "3"]  # pusty po pobraniu nie jest ponawiany
    assert out["done"] is True and store["state"]["done"] is True


async def test_wznawia_od_kursora(monkeypatch):
    store, fetched, fetch = _wire(monkeypatch, ["1", "2", "3"], {"last_id": "2", "seen": 2})
    await R.run_resync(fetch=fetch)
    assert fetched == ["3"]


async def test_gotowe_nie_rusza_sieci(monkeypatch):
    store, fetched, fetch = _wire(monkeypatch, ["1"], {"done": True})
    await R.run_resync(fetch=fetch)
    assert fetched == []


async def test_blad_pojedynczego_meczu_nie_przerywa(monkeypatch):
    store, fetched, fetch = _wire(monkeypatch, ["1", "2"], failing={"1"})
    out = await R.run_resync(fetch=fetch)
    assert out["errors"] == 1 and out["done"] is True and "2" in fetched

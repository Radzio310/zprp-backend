"""Przepływ meczu ręcznego (`M-<TULEJA>/<NUMER>`, bez IdZawody) przez serwer.

Incydent EHF/1 (06.11.2026): odcisk `local_key` liczony z pełnego klucza blokował
każdy zapis stolika jako `match.id_conflict`, a usunięcie meczu z panelu kasowało
migawki historii, więc przywrócenie z kosza oddawało pusty zapis.

Test przechodzi cały przepływ na żywej bazie: ensure -> lease -> kilka PUT ->
dosyłka migawek -> zakończenie -> PDF -> zatwierdzenie -> usunięcie ->
przywrócenie z historią. Drugi przebieg to klucz szkoleniowy `T-`.
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(
    not os.getenv("DATABASE_URL", "").startswith("postgres"),
    reason="Wymaga Postgresa (schemat używa ARRAY/JSONB/UUID). Ustaw DATABASE_URL=postgresql://…",
)

ADMIN = "999"
SECRET = "test-secret"
MANUAL = "M-5346E331/EHF/1"
TRAINING = "T-K3N8P2WQ/EHF/1"


def _blob(key: str, host_goals: int = 0, guest_goals: int = 0, events: int = 0):
    return {
        "scoreHost": host_goals,
        "scoreGuest": guest_goals,
        "date": "2026-11-06T18:00:00.000Z",
        "protocol": [{"type": "goal", "team": "host", "player": 7, "time": 1000 * (i + 1)} for i in range(events)],
        "matchConfig": {
            "matchNumber": "EHF/1",
            "proelKey": key,
            "hostTeamName": "Polska",
            "guestTeamName": "Słowenia",
            "referee1": {"name": "KOWALSKI Jan", "judgeId": ADMIN},
        },
    }


@pytest.fixture
async def client(monkeypatch):
    import httpx
    from fastapi import FastAPI

    import app.deps
    from app import proel, proel_admin_guard as guard, proel_archive, proel_auth, proel_snapshots
    from app.db import database

    async def is_admin(judge_id):
        return str(judge_id or "").strip() == ADMIN

    monkeypatch.setattr(app.deps, "get_settings", lambda: SimpleNamespace(SECRET_KEY=SECRET, ALGORITHM="HS256"))
    monkeypatch.setattr(guard, "claims_admin", is_admin)
    monkeypatch.delenv(guard.STRICT_ENV, raising=False)
    for module in (proel_auth, proel, proel_archive, proel_snapshots):
        if hasattr(module, "is_admin"):
            monkeypatch.setattr(module, "is_admin", is_admin)

    if not database.is_connected:
        await database.connect()
    keys = (MANUAL, TRAINING)
    await _wipe(database, keys)

    api = FastAPI()
    api.include_router(proel_archive.router)
    api.include_router(proel_snapshots.router)
    api.include_router(proel.router)
    transport = httpx.ASGITransport(app=api)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
        yield http
    await _wipe(database, keys)
    # Pula połączeń jest związana z pętlą zdarzeń testu - następny test ma własną.
    await database.disconnect()


async def _wipe(database, keys):
    for table, column in (
        ("proel_match_snapshots", "match_number"),
        ("proel_match_clock_trace", "match_number"),
        ("proel_match_state", "match_number"),
        ("proel_matches", "match_number"),
        ("proel_deleted_matches", "match_number"),
        ("proel_activity_log", "match_number"),
        ("shared_match_pdfs", "proel_key"),
    ):
        for key in keys:
            try:
                await database.execute(f"DELETE FROM {table} WHERE {column} = :k", {"k": key})
            except Exception as exc:  # noqa: BLE001
                print("wipe", table, exc)


def _headers():
    return {"X-Judge-Id": ADMIN, "X-Installation-Id": "tablet-1", "X-Actor-Name": "KOWALSKI Jan", "X-BAZA-Proel": "2"}


GUARD = {"hostTeamName": "Polska", "guestTeamName": "Słowenia"}


async def _run_flow(http, key: str):
    from app.db import database, proel_deleted_matches, proel_match_snapshots, saved_matches
    from sqlalchemy import func, select

    h = _headers()
    # ensure + lease: odcisk liczony z numeru, nie z klucza.
    r = await http.post("/proel/ensure", json={"match_number": key, "guard": GUARD}, headers=h)
    assert r.status_code == 200, r.text
    r = await http.post("/proel/lease", json={"match_number": key, "guard": GUARD}, headers=h)
    assert r.status_code == 200, r.text

    # założenie wiersza i kilka zapisów stolika (dawniej 409 match.id_conflict)
    r = await http.post("/proel/", json={"match_number": key, "data_json": _blob(key), "status": "in_progress"}, headers=h)
    assert r.status_code == 201, r.text
    rev = r.json()["doc_rev"]
    for goals in (1, 2, 3):
        r = await http.put(
            f"/proel/{key}",
            json={"data_json": _blob(key, goals, 0, goals), "status": "in_progress"},
            headers={**h, "X-Proel-Base-Rev": str(rev)},
        )
        assert r.status_code == 200, r.text
        rev = r.json()["doc_rev"]

    # dosyłka migawek z telefonu (klucz z przedrostkiem)
    r = await http.post(
        f"/proel/snapshots/{key}",
        json={"snapshots": [{"data_json": _blob(key, 3, 1, 4), "status": "in_progress", "phase": "live", "milestone": "live", "at": datetime.now(timezone.utc).isoformat()}]},
        headers=h,
    )
    assert r.status_code == 200, r.text

    # zakończenie
    r = await http.put(
        f"/proel/{key}",
        json={"data_json": _blob(key, 3, 1, 4), "status": "finished", "is_finished": True},
        headers={**h, "X-Proel-Base-Rev": str(rev)},
    )
    assert r.status_code == 200, r.text
    rev = r.json()["doc_rev"]

    # PDF protokołu (mecz ręczny: zostaje na serwerze)
    if key.startswith("M-"):
        from app.shared_match_pdf import pdf_meta, store_pdf

        assert await store_pdf(key, b"%PDF-1.4 test", filename="EHF-1", actor_name="K")
        assert (await pdf_meta(key))["exists"]

    # zatwierdzenie
    r = await http.put(
        f"/proel/{key}",
        json={"data_json": _blob(key, 3, 1, 4), "status": "approved", "is_finished": True},
        headers={**h, "X-Proel-Base-Rev": str(rev)},
    )
    assert r.status_code == 200, r.text

    # ani jedno id_conflict w dzienniku
    conflicts = await database.fetch_val(
        "SELECT count(*) FROM proel_activity_log WHERE match_number = :k AND event = 'match.id_conflict'", {"k": key}
    )
    assert int(conflicts or 0) == 0
    versions = await database.fetch_val(select(func.count()).select_from(proel_match_snapshots).where(proel_match_snapshots.c.match_number == key))
    assert int(versions) >= 3

    # usunięcie: migawki zostają (termin wydłużony do końca kosza)
    r = await http.delete(f"/proel/{key}", headers=h)
    assert r.status_code == 200, r.text
    after = await database.fetch_val(select(func.count()).select_from(proel_match_snapshots).where(proel_match_snapshots.c.match_number == key))
    assert int(after) == int(versions)
    soonest = await database.fetch_val(select(func.min(proel_match_snapshots.c.expires_at)).where(proel_match_snapshots.c.match_number == key))
    assert soonest is not None and soonest > datetime.now(timezone.utc) + timedelta(days=300)

    # kosz: wpis i przywrócenie
    r = await http.get("/proel/archive", headers=h)
    entry = next(i for i in r.json()["items"] if i["match_number"] == key)
    r = await http.post(f"/proel/archive/{entry['id']}/restore", headers=h)
    assert r.status_code == 200, r.text
    assert (await database.fetch_one(select(saved_matches.c.match_number).where(saved_matches.c.match_number == key))) is not None
    restored = await database.fetch_val(select(func.count()).select_from(proel_match_snapshots).where(proel_match_snapshots.c.match_number == key))
    assert int(restored) == int(versions)
    return entry


@pytest.mark.anyio
async def test_manual_key_full_flow(client):
    await _run_flow(client, MANUAL)


@pytest.mark.anyio
async def test_training_key_full_flow(client):
    await _run_flow(client, TRAINING)


@pytest.mark.anyio
async def test_empty_trash_entry_points_to_fuller_history(client):
    """Pusty zapis w koszu, pełna historia: kosz wskazuje najnowszą wersję z wynikiem."""
    from app.db import database, proel_deleted_matches, saved_matches
    from app.proel_snapshots import record_snapshot

    h = _headers()
    r = await client.post("/proel/", json={"match_number": MANUAL, "data_json": _blob(MANUAL, 0, 0, 0)}, headers=h)
    assert r.status_code == 201, r.text
    assert await record_snapshot(
        match_number=MANUAL, blob=_blob(MANUAL, 2, 1, 3), status="in_progress", phase="live", milestone="live",
        writer_judge=ADMIN, writer_name="K", writer_install="tablet-1",
    ) is None
    r = await client.delete(f"/proel/{MANUAL}", headers=h)
    assert r.status_code == 200, r.text
    items = (await client.get("/proel/archive", headers=h)).json()["items"]
    entry = next(i for i in items if i["match_number"] == MANUAL)

    detail = (await client.get(f"/proel/archive/{entry['id']}", headers=h)).json()
    fuller = detail["fuller_snapshot"]
    assert fuller and fuller["score_host"] == 2 and fuller["protocol_len"] == 3

    restored = (await client.post(f"/proel/archive/{entry['id']}/restore", headers=h)).json()
    assert restored["fuller_snapshot"]["snapshot_id"] == fuller["snapshot_id"]


@pytest.mark.anyio
async def test_trash_expiry_drops_history(client):
    """Dopiero wygaśnięcie kosza kasuje migawki i ślad zegara."""
    from app.db import database, proel_deleted_matches, proel_match_snapshots
    from app.proel_archive import _purge_expired
    from sqlalchemy import func, select, update

    h = _headers()
    await client.post("/proel/", json={"match_number": MANUAL, "data_json": _blob(MANUAL, 1, 0, 1)}, headers=h)
    await client.delete(f"/proel/{MANUAL}", headers=h)
    count = lambda: database.fetch_val(  # noqa: E731
        select(func.count()).select_from(proel_match_snapshots).where(proel_match_snapshots.c.match_number == MANUAL)
    )
    assert int(await count()) >= 1
    await _purge_expired()
    assert int(await count()) >= 1  # kosz jeszcze ważny
    await database.execute(
        update(proel_deleted_matches)
        .where(proel_deleted_matches.c.match_number == MANUAL)
        .values(expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    )
    await _purge_expired()
    assert int(await count()) == 0


@pytest.mark.anyio
async def test_id_conflict_details_name_the_fingerprints(client):
    """Odrzucenie przez odcisk lokalny mówi, który odcisk się nie zgodził."""
    from app.db import database

    h = _headers()
    await client.post("/proel/ensure", json={"match_number": MANUAL, "guard": GUARD}, headers=h)
    await client.post("/proel/lease", json={"match_number": MANUAL, "guard": GUARD}, headers=h)
    r = await client.post("/proel/", json={"match_number": MANUAL, "data_json": _blob(MANUAL)}, headers=h)
    assert r.status_code == 201, r.text
    other = _blob(MANUAL)
    other["matchConfig"]["guestTeamName"] = "Chorwacja"
    r = await client.put(f"/proel/{MANUAL}", json={"data_json": other, "status": "in_progress"}, headers=h)
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["code"] == "MATCH_ID_MISMATCH"
    row = await database.fetch_one(
        "SELECT details_json FROM proel_activity_log WHERE match_number = :k AND event = 'match.id_conflict' ORDER BY id DESC LIMIT 1",
        {"k": MANUAL},
    )
    details = row["details_json"]
    if isinstance(details, str):
        import json

        details = json.loads(details)
    assert details["layer"] == "local_key"
    assert details["known_local_key"] == "EHF1|POLSKA|SLOWENIA"
    assert details["incoming_local_key"] == "EHF1|POLSKA|CHORWACJA"
    assert details["known"] and details["incoming"]

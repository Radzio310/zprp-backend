"""Tryb prezentacji (`app/presentation*.py`) - middleware, nakładka giełdy, bramka admina.

Bez Postgresa: atrapa `app.db` z prawdziwymi tabelami w SQLite (stan, dziennik,
nakładka, ustawienia sędziów), reszta tabel to MagicMock. Trasy „prawdziwe" to
małe handlery z licznikiem wywołań - plus PRAWDZIWY router obsady ZPRP
(`app/zprp/assignments.py`) z podmienionym logowaniem i zapisem w ZPRP, które
rzucają wyjątkiem: test przechodzi tylko wtedy, gdy symulator ich nie dotknął.
"""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import sys
import types
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import httpx
import pytest
import sqlalchemy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from databases import Database
from fastapi import FastAPI, HTTPException
from jose import jwt
from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, Table

SECRET = "sekret-trybu-prezentacji"
ALGO = "HS256"
ADMIN = "5124"
OTHER = "9999"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PEM = _KEY.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
).decode()


def enc(text: str) -> str:
    return base64.b64encode(_KEY.public_key().encrypt(text.encode(), padding.PKCS1v15())).decode()


def token(judge_id: str = ADMIN, sub: str = "sedzia5124", **extra) -> str:
    claims = {"sub": sub, "judge_id": judge_id, "account_type": "judge" if judge_id else "org", **extra}
    return jwt.encode(claims, SECRET, algorithm=ALGO)


def auth(judge_id: str = ADMIN, sub: str = "sedzia5124", **extra) -> dict:
    return {"Authorization": f"Bearer {token(judge_id, sub, **extra)}"}


ENV = {
    "SECRET_KEY": SECRET,
    "ALGORITHM": ALGO,
    "ACCESS_TOKEN_EXPIRE_MINUTES": "60",
    "ZPRP_BASE_URL": "https://zprp.invalid",
    "ZPRP_BEACH_USERNAME": "u",
    "ZPRP_BEACH_PASSWORD": "p",
    "GOOGLE_CLIENT_ID": "id",
    "GOOGLE_CLIENT_SECRET": "secret",
    "BACKEND_URL": "https://example.test",
    "FRONTEND_DEEP_LINK": "baza://",
    "RSA_PRIVATE_KEY": _PEM,
}


class Calls:
    def __init__(self):
        self.items = []

    def hit(self, name):
        self.items.append(name)

    def count(self, name):
        return self.items.count(name)


@pytest.fixture
def env(monkeypatch, tmp_path):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    before = set(sys.modules)
    metadata = sqlalchemy.MetaData()
    from app.presentation_tables import define_tables

    state_t, ops_t, overlay_t = define_tables(metadata)
    settings_t = Table(
        "province_judge_settings", metadata,
        Column("province", String, primary_key=True), Column("judge_id", String, primary_key=True),
        Column("full_name", String), Column("needs_experienced", Boolean, nullable=False, default=False),
        Column("no_solo", Boolean, nullable=False, default=False), Column("preferred_days", JSON, nullable=False, default=list),
        Column("note", String), Column("assign_role", String), Column("updated_by", String),
        Column("updated_at", DateTime(timezone=True)),
    )
    judges_t = Table(
        "province_judges", metadata,
        Column("judge_id", String, primary_key=True), Column("full_name", String), Column("province", String),
        Column("badges", JSON), Column("photo_url", String), Column("updated_at", DateTime(timezone=True)),
    )
    homes_t = Table(
        "province_settlement_judges", metadata,
        Column("province", String, primary_key=True), Column("judge_id", String, primary_key=True),
        Column("full_name", String), Column("home_city", String), Column("updated_at", DateTime(timezone=True)),
    )
    url = f"sqlite:///{tmp_path / 'presentation.db'}"
    metadata.create_all(sqlalchemy.create_engine(url))
    fake = types.ModuleType("app.db")
    fake.database = Database(url.replace("sqlite://", "sqlite+aiosqlite://"))
    fake.presentation_state, fake.presentation_ops, fake.presentation_overlay = state_t, ops_t, overlay_t
    fake.province_judge_settings, fake.province_judges, fake.province_settlement_judges = settings_t, judges_t, homes_t
    fake.__getattr__ = lambda name: MagicMock()
    monkeypatch.setitem(sys.modules, "app.db", fake)
    for name in [n for n in sys.modules if n.startswith("app.presentation") or n in ("app.province_me", "app.zprp.assignments")]:
        sys.modules.pop(name, None)

    PS = importlib.import_module("app.presentation_state")
    sim = importlib.import_module("app.presentation_sim")
    mw = importlib.import_module("app.presentation_middleware")
    pres = importlib.import_module("app.presentation")
    me = importlib.import_module("app.province_me")
    zprp = importlib.import_module("app.zprp.assignments")
    mw._private_key = None

    import app.access_control as access_control

    async def admins():
        return [ADMIN]

    monkeypatch.setattr(access_control, "admin_judge_ids", admins)
    monkeypatch.setattr(me, "_is_app_admin", lambda jid: _true_if(jid == ADMIN))

    async def viewer(ctx):
        return {"judge_id": ctx.judge_id, "province": "SLASKIE", "full_name": f"Sędzia {ctx.judge_id}",
                "photo_url": "", "approver": False, "is_admin": False, "cfg": {"offer_deadline_hours": 48}}

    async def no_cards(ids):
        return {}

    async def match_row(province, match_id):
        return {"match_at": datetime.now(timezone.utc) + timedelta(days=7), "match_code": "S/MM/1",
                "state_json": {"RozgrywkiCode": "S/MM/1", "ID_zespoly_gosp_ZespolNazwa": "Gospodarz",
                               "ID_zespoly_gosc_ZespolNazwa": "Gość", "Hala_nazwa": "Hala", "Hala_miasto": "Katowice"}}

    monkeypatch.setattr(sim, "market_viewer", viewer)
    monkeypatch.setattr(sim, "judge_cards", no_cards)
    monkeypatch.setattr(sim, "_province_match", match_row)

    calls = Calls()

    async def zprp_login(*_a, **_k):
        calls.hit("zprp_login")
        raise HTTPException(418, "ZPRP nie może być wołane w teście")

    async def zprp_apply(*_a, **_k):
        calls.hit("zprp_apply")
        raise AssertionError("apply_referee_assignment nie może być wołane")

    monkeypatch.setattr(zprp, "_login_zprp", zprp_login)
    monkeypatch.setattr(zprp, "apply_referee_assignment", zprp_apply)

    inner = FastAPI()
    inner.include_router(pres.router)
    inner.include_router(me.router)
    inner.include_router(zprp.router)

    @inner.post("/match-market/offers", status_code=201)
    async def real_create_offer():
        calls.hit("create_offer")
        return {"id": 1, "status": "open"}

    @inner.get("/match-market/offers")
    async def real_list(scope: str = "market"):
        calls.hit("list_offers")
        return {"scope": scope, "offers": []}

    @inner.post("/province/assignment/candidates")
    async def real_candidates():
        calls.hit("candidates")
        return {"candidates": [{"judge_id": "1"}]}

    @inner.get("/match-market/crew-offers")
    async def real_crew_list():
        calls.hit("crew_list")
        return {"offers": [], "canManage": True}

    @inner.get("/province/assignment/draft")
    async def real_draft():
        calls.hit("draft")
        return {"rev": 3, "changes": [], "updated_by": None, "updated_at": None}

    @inner.post("/silesia/announcements/create", status_code=201)
    async def real_ann_create():
        calls.hit("ann_create")
        return {"id": 1}

    @inner.get("/silesia/announcements/")
    async def real_ann_list(province: str = ""):
        calls.hit("ann_list")
        return {"announcements": [{"id": 5, "title": "Stare", "content": "x", "priority": 1, "province": province,
                                   "updated_at": "2026-11-01T10:00:00+00:00", "likes": [], "comments": []}]}

    app = mw.PresentationMiddleware(inner)
    PS.reset_cache()
    yield types.SimpleNamespace(PS=PS, sim=sim, mw=mw, app=app, db=fake.database, calls=calls, fake=fake, pres=pres)
    # Moduły zaimportowane z atrapą bazy nie mogą zostać dla innych testów.
    for name in [n for n in sys.modules if n.startswith("app.") and (n not in before or n.startswith("app.presentation"))]:
        sys.modules.pop(name, None)


async def _true_if(value):
    return value


def run(env, factory):
    async def go():
        await env.db.connect()
        try:
            transport = httpx.ASGITransport(app=env.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await factory(client)
        finally:
            await env.db.disconnect()

    return asyncio.run(go())


async def enable(env, client, accounts=None, **extra):
    body = {"enabled": True, "accounts": accounts if accounts is not None else [], **extra}
    r = await client.put("/presentation/state", json=body, headers=auth())
    assert r.status_code == 200, r.text
    env.PS.reset_cache()
    return r.json()


# ───────────────────────────── bramka admina i stan ─────────────────────────────


def test_przelaczanie_tylko_admin(env):
    async def go(client):
        denied = await client.put("/presentation/state", json={"enabled": True}, headers=auth(OTHER, "inny"))
        read = await client.get("/presentation/state", headers=auth(OTHER, "inny"))
        state = await enable(env, client, accounts=[{"kind": "login", "value": "KS_SLZPR", "label": "Okręg"}])
        return denied, read, state

    denied, read, state = run(env, go)
    assert denied.status_code == 403 and read.status_code == 403
    assert state["enabled"] is True
    assert 170 <= state["minutes_left"] <= 180
    # admin, który włącza, dopisany automatycznie; login małymi literami
    values = {(a["kind"], a["value"]) for a in state["accounts"]}
    assert ("judge", ADMIN) in values and ("login", "ks_slzpr") in values
    assert state["areas"] == ["market", "obsada", "settlements", "offtimes", "announcements", "events"]


def test_wylaczony_tryb_przepuszcza_zapis(env):
    async def go(client):
        return await client.post("/match-market/offers", json={"match_id": "1", "slot": "sekretarz"}, headers=auth())

    r = run(env, go)
    assert r.status_code == 201 and r.json() == {"id": 1, "status": "open"}
    assert env.calls.count("create_offer") == 1


# ───────────────────────────── giełda z nakładką ─────────────────────────────


def test_gielda_udawana_i_widoczna_tylko_dla_konta_trybu(env):
    async def go(client):
        await enable(env, client)
        created = await client.post(
            "/match-market/offers", json={"match_id": "777", "slot": "sekretarz"}, headers=auth()
        )
        mine = await client.get("/match-market/offers", params={"scope": "mine"}, headers=auth())
        other_market = await client.get("/match-market/offers", params={"scope": "market"}, headers=auth(OTHER, "inny"))
        other_write = await client.post(
            "/match-market/offers", json={"match_id": "1", "slot": "sekretarz"}, headers=auth(OTHER, "inny")
        )
        detail = await client.get(f"/match-market/offers/{created.json()['id']}", headers=auth())
        claim = await client.post(f"/match-market/offers/{created.json()['id']}/claims", json={"note": "biorę"}, headers=auth("4321", "s4321"))
        ops = await client.get("/presentation/ops", headers=auth())
        return created, mine, other_market, other_write, detail, claim, ops

    created, mine, other_market, other_write, detail, claim, ops = run(env, go)
    assert created.status_code == 201
    body = created.json()
    assert body["status"] == "open" and body["id"] >= env.PS.SYNTH_BASE
    assert env.calls.count("create_offer") == 1  # tylko zapis konta spoza trybu
    assert other_write.json() == {"id": 1, "status": "open"}

    offers = mine.json()["offers"]
    assert [o["id"] for o in offers] == [body["id"]]
    assert offers[0]["matchId"] == "777" and offers[0]["isMine"] is True and offers[0]["status"] == "open"
    # inne konto: prawdziwa (pusta) lista, bez udawanej oferty
    assert other_market.json()["offers"] == []
    assert detail.status_code == 200 and detail.json()["slot"] == "sekretarz"
    # 4321 nie jest w trybie: zgłoszenie idzie do aplikacji (tu: brak trasy -> 404/405)
    assert claim.status_code in (404, 405)
    items = ops.json()["items"]
    assert len(items) == 1 and items[0]["area"] == "market" and items[0]["account"] == f"judge:{ADMIN}"


def test_odczyt_post_przechodzi(env):
    async def go(client):
        await enable(env, client)
        return await client.post("/province/assignment/candidates", json={"province": "ŚLĄSKIE"}, headers=auth())

    r = run(env, go)
    assert r.json() == {"candidates": [{"judge_id": "1"}]}
    assert env.calls.count("candidates") == 1


# ───────────────────────────── obsada ZPRP (RSA w treści) ─────────────────────────────


def _save_body(user="ks_slzpr"):
    return {
        "username": enc(user),
        "password": enc("tajne-haslo"),
        "IdZawody": "12345",
        "user": user,
        "NrSedzia_sekretarz": "881",
        "NrSedzia_sekretarz_name": "KOWALSKI Jan",
        "expect": {"sedzia1": "NOWAK Adam"},
        "province": "ŚLĄSKIE",
    }


def test_zapis_obsady_udawany_bez_zprp(env):
    async def go(client):
        await enable(env, client, accounts=[{"kind": "login", "value": "ks_slzpr", "label": "Okręg"}])
        saved = await client.post("/zprp/obsada/save", json=_save_body())  # bez JWT, jak aplikacja
        ops = await client.get("/presentation/ops", headers=auth())
        return saved, ops

    saved, ops = run(env, go)
    assert saved.status_code == 200, saved.text
    data = saved.json()
    assert data["success"] is True and data["code"] is None
    assert data["verified_slots"]["sekretarz"] == {"value": "881", "name": "KOWALSKI Jan"}
    assert data["verified_slots"]["sedzia1"]["name"] == "NOWAK Adam"
    assert env.calls.count("zprp_login") == 0 and env.calls.count("zprp_apply") == 0
    item = ops.json()["items"][0]
    assert item["area"] == "obsada" and item["account"] == "login:ks_slzpr"
    stored = asyncio.run(_payloads(env))
    assert "tajne" not in stored and "***" in stored


async def _payloads(env):
    await env.db.connect()
    try:
        rows = await env.db.fetch_all(env.fake.presentation_ops.select())
        return json.dumps([r["payload_json"] for r in rows])
    finally:
        await env.db.disconnect()


def test_zapis_obsady_innego_konta_idzie_do_zprp(env):
    async def go(client):
        await enable(env, client, accounts=[{"kind": "login", "value": "ks_slzpr", "label": "Okręg"}])
        return await client.post("/zprp/obsada/save", json=_save_body("ks_inny"))

    r = run(env, go)
    assert r.status_code == 418  # prawdziwy handler doszedł do logowania w ZPRP
    assert env.calls.count("zprp_login") == 1


def test_formularz_obsady_to_odczyt(env):
    async def go(client):
        await enable(env, client, accounts=[{"kind": "login", "value": "ks_slzpr", "label": "Okręg"}])
        return await client.post(
            "/zprp/obsada/match-form",
            json={"username": enc("ks_slzpr"), "password": enc("x"), "IdZawody": "1", "user": "ks_slzpr"},
        )

    r = run(env, go)
    assert r.status_code == 418 and env.calls.count("zprp_login") == 1


# ───────────────────────────── wygaśnięcie i czyszczenie ─────────────────────────────


def test_wygasniecie_wylacza_i_czysci_nakladke(env):
    async def go(client):
        await enable(env, client)
        await client.post("/match-market/offers", json={"match_id": "777", "slot": "czas"}, headers=auth())
        past = datetime.now(timezone.utc) - timedelta(minutes=1)
        await env.db.execute(env.fake.presentation_state.update().values(expires_at=past))
        env.PS.reset_cache()
        write = await client.post("/match-market/offers", json={"match_id": "1", "slot": "czas"}, headers=auth())
        state = await client.get("/presentation/state", headers=auth())
        left = await env.db.fetch_all(env.fake.presentation_overlay.select().where(env.fake.presentation_overlay.c.kind == "market_offer"))
        return write, state, left

    write, state, left = run(env, go)
    assert write.json() == {"id": 1, "status": "open"} and env.calls.count("create_offer") == 1
    assert state.json()["enabled"] is False and state.json()["expires_at"] is None
    assert left == []


def test_delete_ops_czysci_nakladke(env):
    async def go(client):
        await enable(env, client)
        await client.post("/match-market/offers", json={"match_id": "777", "slot": "czas"}, headers=auth())
        cleared = await client.delete("/presentation/ops", headers=auth())
        mine = await client.get("/match-market/offers", params={"scope": "mine"}, headers=auth())
        ops = await client.get("/presentation/ops", headers=auth())
        return cleared, mine, ops

    cleared, mine, ops = run(env, go)
    assert cleared.json() == {"cleared": 1}
    assert mine.json()["offers"] == [] and ops.json()["items"] == []


def test_wylaczenie_czysci_nakladke(env):
    async def go(client):
        await enable(env, client)
        await client.post("/match-market/offers", json={"match_id": "777", "slot": "czas"}, headers=auth())
        off = await client.put("/presentation/state", json={"enabled": False}, headers=auth())
        env.PS.reset_cache()
        left = await env.db.fetch_all(env.fake.presentation_overlay.select())
        return off, left

    off, left = run(env, go)
    assert off.json()["enabled"] is False and left == []


# ───────────────────────────── dyspozycyjność ─────────────────────────────


def test_dyspozycyjnosc_tylko_wlasny_wiersz(env):
    async def go(client):
        await env.db.execute(env.fake.province_judge_settings.insert().values(
            province="SLASKIE", judge_id="777", preferred_days=[1], note="cudzy", needs_experienced=True, no_solo=False,
        ))
        await env.db.execute(env.fake.province_judge_settings.insert().values(
            province="SLASKIE", judge_id=OTHER, preferred_days=[], needs_experienced=True, no_solo=True, assign_role=None,
        ))
        await env.db.execute(env.fake.province_settlement_judges.insert().values(province="SLASKIE", judge_id=OTHER, home_city="Gliwice"))
        put = await client.put(
            "/province/me/availability",
            json={"province": "ŚLĄSKIE", "preferred_days": [5, 6, 9, 5], "assign_role": "table", "note": "weekendy", "judge_id": "777"},
            headers=auth(OTHER, "inny"),
        )
        get = await client.get("/province/me/availability", params={"province": "ŚLĄSKIE"}, headers=auth(OTHER, "inny"))
        org = await client.get("/province/me/availability", params={"province": "ŚLĄSKIE"}, headers=auth("", "ks_slzpr"))
        rows = {r["judge_id"]: dict(r._mapping) for r in await env.db.fetch_all(env.fake.province_judge_settings.select())}
        return put, get, org, rows

    put, get, org, rows = run(env, go)
    assert put.status_code == 200, put.text
    assert put.json() == {"preferred_days": [5, 6], "assign_role": "table", "note": "weekendy", "home_city": "Gliwice"}
    assert get.json() == put.json()
    assert org.status_code == 403
    assert rows["777"]["note"] == "cudzy" and rows["777"]["preferred_days"] == [1]
    # pola obsadowego nietknięte
    assert rows[OTHER]["needs_experienced"] is True and rows[OTHER]["no_solo"] is True


# ───────────────────────────── reguły czyste ─────────────────────────────


def test_tabela_tras_rozroznia_odczyty(env):
    R = importlib.import_module("app.presentation_routes")
    assert R.match_write("POST", "/zprp/obsada/save")[0].area == "obsada"
    assert R.match_write("POST", "/zprp/obsada/match-form") is None
    assert R.match_write("POST", "/zprp/obsada/table-officials") is None
    assert R.match_write("POST", "/province/assignment/suggest") is None
    assert R.match_write("POST", "/province/assignment/candidates") is None
    assert R.match_write("POST", "/province/assignment")[0].sim == "obsada_auto_dry_run"
    assert R.match_write("POST", "/match-market/my-matches") is None
    assert R.match_write("POST", "/match-market/offers/12/approve")[1] == {"id": "12"}
    assert R.match_write("POST", "/province/settlements/me/forecast") is None
    assert R.match_write("DELETE", "/silesia/offtimes/assigned/abc")[0].sim == "ok_true"
    assert all(r.sim in env.sim.SIMS for r in R.WRITE_ROUTES)
    assert all(r.merge in env.sim.MERGES for r in R.READ_ROUTES)


def test_dopasowanie_kont(env):
    S = env.PS.State(enabled=True, accounts=[{"kind": "judge", "value": "5124", "label": ""}, {"kind": "login", "value": "ks_slzpr", "label": ""}])
    assert S.account_for(judge_id="5124") == "judge:5124"
    assert S.account_for(login="KS_SLZPR") == "login:ks_slzpr"
    assert S.account_for(judge_id="1", login="x") is None
    S.learned["sedzia5124"] = "5124"
    assert S.account_for(login="sedzia5124") == "judge:5124"


def test_preferencje_okregu():
    from app.push.preferences import notification_types_allowed

    prefs = {"notificationTypes": {"districtForms": False}}
    assert notification_types_allowed({}, "districtAnnouncements") is True
    assert notification_types_allowed(prefs, ("province_events", "districtForms")) is False
    assert notification_types_allowed(prefs, "districtEvents") is True


# ───────────────────────────── giełda obsadowego i scena demo ─────────────────────────────


def _crew_stubs(env, monkeypatch):
    C = importlib.import_module("app.match_market_crew")
    when = datetime.now(timezone.utc) + timedelta(days=5)

    async def match_context(key, match_id):
        return {"row": {"match_at": when}, "state": {"RozgrywkiCode": "S/JM/1"}, "code": "S/JM/1",
                "access": {"manual": True, "editable_slots": ["sekretarz", "czas"]}, "needs": {}, "crew": {}}

    async def viewer(actor, key):
        return {"hide_claimers": False, "approver_badges": ["Obsadowy"]}, True

    async def nothing(*_a, **_k):
        return None

    async def cards(ids):
        return {i: {"full_name": f"Sędzia {i}", "photo_url": ""} for i in ids if i}

    async def claims_view(offer, claims, cards_, quick=False):
        return {"_pending": False, "table": [{"claimId": c["id"]} for c in claims], "field": [], "packages": []}

    async def upcoming(key, limit=25):
        return [{"match_id": "4455", "match_at": when}]

    async def claimers(key, exclude, count=2):
        return [{"judge_id": "201", "name": "Anna", "photo_url": None}, {"judge_id": "202", "name": "Piotr", "photo_url": None}]

    monkeypatch.setattr(C, "_match_context", match_context)
    monkeypatch.setattr(C, "_viewer", viewer)
    monkeypatch.setattr(C, "_roster_for", nothing)
    monkeypatch.setattr(C, "_judge_cards", cards)
    monkeypatch.setattr(C, "_claims_view", claims_view)
    monkeypatch.setattr(C.R, "suggest_slots", lambda crew, editable, needs: {"slots": ["sekretarz", "czas"]})
    monkeypatch.setattr(env.pres, "_upcoming_matches", upcoming)
    monkeypatch.setattr(env.pres, "scene_claimers", claimers)
    return C


def test_scena_dwa_zgloszenia_tylko_w_nakladce(env, monkeypatch):
    _crew_stubs(env, monkeypatch)
    org = {"Authorization": f"Bearer {token('', 'ks_slzpr')}"}

    async def go(client):
        await enable(env, client, accounts=[{"kind": "login", "value": "ks_slzpr", "label": "Okręg"}])
        scene = await client.post("/presentation/scene", json={"scene": "market_offer_with_claims", "province": "ŚLĄSKIE"}, headers=auth())
        listed = await client.get("/match-market/crew-offers", params={"province": "ŚLĄSKIE"}, headers=org)
        other = await client.get("/match-market/crew-offers", params={"province": "ŚLĄSKIE"}, headers=auth(OTHER, "inny"))
        offer_id = scene.json()["created"]["crew_offer_id"]
        detail = await client.get(f"/match-market/crew-offers/{offer_id}", headers=org)
        claim_id = detail.json()["claims"]["table"][0]["claimId"]
        assigned = await client.post(f"/match-market/crew-offers/{offer_id}/assign", json={"claimId": claim_id}, headers=org)
        draft = await client.get("/province/assignment/draft", params={"province": "ŚLĄSKIE"}, headers=org)
        other_draft = await client.get("/province/assignment/draft", params={"province": "ŚLĄSKIE"}, headers=auth(OTHER, "inny"))
        return scene, listed, other, detail, assigned, draft, other_draft

    scene, listed, other, detail, assigned, draft, other_draft = run(env, go)
    assert scene.status_code == 200, scene.text
    created = scene.json()["created"]
    assert created["match_id"] == "4455" and len(created["claims"]) == 2
    offers = listed.json()["offers"]
    assert len(offers) == 1
    assert offers[0]["status"] == "open" and offers[0]["acceptingClaims"] is True and offers[0]["claimCount"] == 2
    assert other.json()["offers"] == []
    assert detail.status_code == 200 and len(detail.json()["claims"]["table"]) == 2
    assert assigned.status_code == 200, assigned.text
    changes = draft.json()["changes"]
    assert len(changes) == 1 and changes[0]["source"] == "market" and changes[0]["match_id"] == "4455"
    assert other_draft.json() == {"rev": 3, "changes": [], "updated_by": None, "updated_at": None}
    assert env.calls.count("draft") == 1  # tylko konto spoza trybu czytało prawdziwy szkic


def test_scena_wymaga_wlaczonego_trybu(env, monkeypatch):
    _crew_stubs(env, monkeypatch)

    async def go(client):
        return await client.post("/presentation/scene", json={"scene": "market_offer_with_claims", "province": "ŚLĄSKIE"}, headers=auth())

    assert run(env, go).status_code == 409


def enc_b64(text: str) -> str:
    """Pole ogłoszenia: RSA z base64 w środku (jak `silesia._decrypt_field`)."""
    return enc(base64.b64encode(text.encode("utf-8")).decode("ascii"))


def test_ogloszenie_multipart_bez_tokenu_udawane_i_w_liscie(env):
    form = {
        "username": enc("sedzia5124"), "password": enc("x"), "judge_id": enc_b64(ADMIN),
        "full_name": enc_b64("Jan Admin"), "title": enc_b64("Zbiórka przed sezonem"), "content": "Treść",
        "priority": "0", "province": "ŚLĄSKIE",
    }

    async def go(client):
        await enable(env, client)
        created = await client.post("/silesia/announcements/create", data=form, files={"image": ("a.png", b"PNG", "image/png")})
        mine = await client.get("/silesia/announcements/", params={"province": "ŚLĄSKIE"}, headers=auth())
        other = await client.get("/silesia/announcements/", params={"province": "ŚLĄSKIE"}, headers=auth(OTHER, "inny"))
        return created, mine, other

    created, mine, other = run(env, go)
    assert created.status_code == 201, created.text
    assert created.json()["title"] == "Zbiórka przed sezonem" and created.json()["judge_name"] == "Jan Admin"
    assert "image_url" not in created.json()
    assert env.calls.count("ann_create") == 0
    assert [a["title"] for a in mine.json()["announcements"]] == ["Zbiórka przed sezonem", "Stare"]
    assert [a["title"] for a in other.json()["announcements"]] == ["Stare"]


def test_profil_rol_z_odznak(env):
    async def go(client):
        await env.db.execute(env.fake.province_judges.insert().values(
            judge_id=ADMIN, full_name="Jan Admin", province="ŚLĄSKIE", badges={"Obsadowy": True, "Komisja sędziowska": True, "Stare": False}, photo_url="",
        ))
        return await client.get("/province/me/profile", headers=auth())

    data = run(env, go).json()
    assert data["judge_id"] == ADMIN and data["display_name"] == "Jan Admin" and data["province"] == "ŚLĄSKIE"
    assert data["roles"] == ["sedzia", "obsadowy", "komisja", "admin"]
    assert data["is_app_admin"] is True and len(data["provinces_available"]) == 16

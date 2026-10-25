"""Egzamin na żywo - trasy HTTP, strony i WebSocket (TestClient) na SQLite, bez Postgresa."""

import json
from contextlib import asynccontextmanager

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.exam_live_routes import LiveDeps, build_router
from exam_live_support import ADMIN, HOST, PLAIN, PLAYERS, SINGLES, make_store

WHO = {"admin": ADMIN, "host": HOST, "plain": PLAIN, **{f"p{i}": w for i, w in enumerate(PLAYERS, start=1)}}
TOKENS = {f"tok-{w.judge_id}": w.judge_id for w in [ADMIN, HOST, PLAIN, *PLAYERS]}


@pytest.fixture
def client(tmp_path):
    store = make_store(tmp_path / "routes.db")

    async def who(request: Request):
        key = request.headers.get("x-who")
        if key not in WHO:
            raise HTTPException(401, "Brak tokenu")
        return WHO[key]

    async def identify(token):
        return TOKENS.get(token)

    deps = LiveDeps(store=lambda: store, who=who, identify=identify)

    @asynccontextmanager
    async def lifespan(_app):
        await store.database.connect()
        yield
        await store.database.disconnect()

    app = FastAPI(lifespan=lifespan)
    app.include_router(build_router(deps))
    with TestClient(app) as c:
        yield c


def h(key):
    return {"x-who": key}


def create(client, key="host", **over):
    body = {"scope": "province", "province": "ŚLĄSKIE", "title": "Quiz", "question_ids": list(SINGLES)}
    body.update(over)
    res = client.post("/exam-live", json=body, headers=h(key))
    assert res.status_code == 200, res.text
    return res.json()


def err(res):
    return res.json()["detail"]["code"] if "detail" in res.json() else res.json()["code"]


def test_tworzenie_wymaga_tokenu_i_uprawnien(client):
    body = {"scope": "province", "province": "ŚLĄSKIE", "question_ids": list(SINGLES)}
    assert client.post("/exam-live", json=body).status_code == 401
    denied = client.post("/exam-live", json=body, headers=h("plain"))
    assert denied.status_code == 403 and err(denied) == "EXAM_FORBIDDEN"
    view = create(client)
    assert view["role"] == "host" and len(view["session"]["pin"]) == 6 and view["session"]["guests_allowed"] is False
    links = view["session"]["links"]
    assert links["projector_url"].startswith("https://www.bazapodreka.app/sala/ekran/")
    assert links["web_join"] == f"https://www.bazapodreka.app/sala/{view['session']['pin']}"


def test_dolaczanie_goscie_i_polling_since_rev(client):
    view = create(client)
    sid, pin = view["session"]["id"], view["session"]["pin"]
    joined = client.post("/exam-live/join", json={"pin": pin}, headers=h("p1"))
    assert joined.status_code == 200 and joined.json()["snapshot"]["role"] == "player"
    assert client.post("/exam-live/join", json={"pin": "999999"}, headers=h("p2")).status_code == 404
    off = client.post("/exam-live/guest/join", json={"pin": pin, "nick": "Gosc"})
    assert off.status_code == 403 and err(off) == "LIVE_GUESTS_OFF"
    assert client.patch(f"/exam-live/{sid}", json={"guests_allowed": True}, headers=h("p1")).status_code == 403
    assert client.patch(f"/exam-live/{sid}", json={"guests_allowed": True}, headers=h("host")).status_code == 200
    guest = client.post("/exam-live/guest/join", json={"pin": pin, "nick": "Gosc"})
    assert guest.status_code == 200 and guest.json()["guest_token"]
    gt = guest.json()["guest_token"]
    state = client.get(f"/exam-live/guest/{sid}/state", params={"gt": gt}).json()
    assert state["role"] == "player" and state["me"]["name"] == "Gosc" and state["session"]["joined"] == 2
    assert client.get(f"/exam-live/guest/{sid}/state", params={"gt": "zly"}).status_code == 403
    again = client.get(f"/exam-live/guest/{sid}/state", params={"gt": gt, "since_rev": state["rev"]}).json()
    assert again["unchanged"] is True and again["rev"] == state["rev"]
    # prowadzący, uczestnik i obcy
    assert client.get(f"/exam-live/{sid}/state", headers=h("host")).json()["role"] == "host"
    assert client.get(f"/exam-live/{sid}/state", headers=h("p1")).json()["role"] == "player"
    assert client.get(f"/exam-live/{sid}/state", headers=h("p3")).status_code == 403


def test_sterowanie_tylko_prowadzacy_i_odpowiedzi_bez_klucza(client):
    view = create(client)
    sid, pin = view["session"]["id"], view["session"]["pin"]
    client.post("/exam-live/join", json={"pin": pin}, headers=h("p1"))
    client.post("/exam-live/join", json={"pin": pin}, headers=h("p2"))
    assert client.post(f"/exam-live/{sid}/control", json={"action": "next"}, headers=h("p1")).status_code == 403
    q = client.post(f"/exam-live/{sid}/control", json={"action": "next", "from_phase": "lobby"}, headers=h("host")).json()
    assert q["session"]["phase"] == "question" and q["question"]["text"] and "correct_keys" not in json.dumps(q)
    stale = client.post(f"/exam-live/{sid}/control", json={"action": "next", "from_phase": "lobby"}, headers=h("host"))
    assert stale.status_code == 409 and err(stale) == "LIVE_STALE"
    ok = client.post(f"/exam-live/{sid}/answer", json={"selected": ["a"]}, headers=h("p1"))
    assert ok.status_code == 200 and ok.json()["accepted"] is True and "correct_keys" not in json.dumps(ok.json())
    assert err(client.post(f"/exam-live/{sid}/answer", json={"selected": ["b"]}, headers=h("p1"))) == "LIVE_ALREADY_ANSWERED"
    assert client.post(f"/exam-live/{sid}/answer", json={"selected": ["a"]}, headers=h("p4")).status_code == 403
    rev = client.post(f"/exam-live/{sid}/control", json={"action": "reveal"}, headers=h("host")).json()
    assert rev["reveal"]["correct_keys"] == ["a"] and rev["reveal"]["answered"] == 1 and rev["reveal"]["skipped"] == 1
    mine = client.get(f"/exam-live/{sid}/state", headers=h("p1")).json()
    assert mine["me"]["correct"] is True and mine["me"]["points"] > 900
    client.post(f"/exam-live/{sid}/control", json={"action": "end"}, headers=h("host"))
    results = client.get(f"/exam-live/{sid}/results", headers=h("host")).json()
    assert results["result"]["participants"] == 2 and client.get(f"/exam-live/{sid}/results", headers=h("plain")).status_code == 403
    listing = client.get("/exam-live/hosted", headers=h("host")).json()["sessions"]
    assert listing[0]["id"] == sid and listing[0]["active"] is False


def test_rzutnik_bez_logowania_qr_i_strony(client):
    view = create(client)
    token = view["session"]["links"]["projector_url"].rsplit("/", 1)[-1]
    state = client.get(f"/exam-live/projector/{token}/state")
    assert state.status_code == 200 and state.json()["role"] == "projector" and state.json()["session"]["pin"] == view["session"]["pin"]
    assert "me" in state.json() and state.json()["me"] is None
    assert client.get("/exam-live/projector/niezgadniete/state").status_code == 404
    qr = client.get(f"/exam-live/projector/{token}/qr.svg", headers={"host": "baza.example"})
    assert qr.status_code == 200 and qr.headers["content-type"].startswith("image/svg+xml") and b"<svg" in qr.content
    for url in (f"/exam-live/projector/{token}", "/exam-live/join"):
        moved = client.get(url, follow_redirects=False)
        assert moved.status_code == 302 and moved.headers["location"].startswith("https://www.bazapodreka.app/sala")
    proj = state.json()
    assert proj["brand"]["short"] == "bazapodreka.app/sala" and proj["brand"]["join_url"].endswith(proj["session"]["pin"])
    assert client.get("/exam-live/assets/sekret.txt").status_code == 404


def test_pin_zgadywanie_jest_ograniczone(client):
    codes = [client.post("/exam-live/guest/join", json={"pin": "999999", "nick": "Xx"}).status_code for _ in range(22)]
    assert codes[:20] == [404] * 20 and codes[20:] == [429, 429]


def recv(ws, kind="snapshot", limit=8):
    for _ in range(limit):
        msg = ws.receive_json()
        if msg["type"] == kind:
            return msg
    raise AssertionError(f"brak ramki {kind}")


def recv_phase(ws, phase, limit=12):
    for _ in range(limit):
        msg = recv(ws)
        if msg["snapshot"]["session"]["phase"] == phase:
            return msg["snapshot"]
    raise AssertionError(f"brak migawki w fazie {phase}")


def test_websocket_rozglaszanie_migawek_per_rola(client):
    view = create(client, guests_allowed=True)
    sid, pin = view["session"]["id"], view["session"]["pin"]
    token = view["session"]["links"]["projector_url"].rsplit("/", 1)[-1]
    client.post("/exam-live/join", json={"pin": pin}, headers=h("p1"))
    gt = client.post("/exam-live/guest/join", json={"pin": pin, "nick": "Gosc"}).json()["guest_token"]
    with client.websocket_connect(f"/exam-live/ws/{sid}?role=host&token=tok-2") as host, \
            client.websocket_connect(f"/exam-live/ws/{sid}?role=player&token=tok-101") as player, \
            client.websocket_connect(f"/exam-live/ws/{sid}?role=guest&gt={gt}") as guest, \
            client.websocket_connect(f"/exam-live/ws/{token}?role=projector") as proj:
        first = {n: recv(ws)["snapshot"] for n, ws in (("host", host), ("player", player), ("guest", guest), ("proj", proj))}
        assert first["host"]["role"] == "host" and first["player"]["me"]["name"] == "Sędzia 1" and first["guest"]["me"]["kind"] == "guest"
        assert first["proj"]["role"] == "projector" and first["proj"]["session"]["pin"] == pin and "pin" not in first["player"]["session"]

        player.send_json({"type": "ping"})
        assert recv(player, "pong")["type"] == "pong"

        # start z gniazda prowadzącego; wszyscy dostają pytanie, nikt nie dostaje klucza
        host.send_json({"type": "control", "action": "next", "from_phase": "lobby"})
        snaps = {n: recv_phase(ws, "question") for n, ws in (("host", host), ("player", player), ("guest", guest), ("proj", proj))}
        for name, snap in snaps.items():
            flat = json.dumps(snap)
            assert "correct_keys" not in flat and snap["reveal"] is None, name
            assert snap["question"]["deadline_at"] and snap["server_now"]
        assert snaps["player"]["me"]["answered"] is False

        # odpowiedź przez gniazdo: ack, a prowadzący widzi licznik odpowiedzi
        player.send_json({"type": "answer", "selected": ["a"]})
        assert recv(player, "ack")["ok"] is True
        host_view = recv(host)["snapshot"]
        while host_view["session"].get("answered") != 1:
            host_view = recv(host)["snapshot"]
        # drugi uczestnik (gość) odpowiada źle; wszyscy odpowiedzieli, więc serwer sam odsłania
        guest.send_json({"type": "answer", "selected": ["b"]})
        revealed = {n: recv_phase(ws, "reveal") for n, ws in (("host", host), ("player", player), ("guest", guest), ("proj", proj))}
        dist = revealed["proj"]["reveal"]["distribution"]
        assert revealed["proj"]["reveal"]["correct_keys"] == ["a"] and dist["a"] == 1 and dist["b"] == 1
        assert revealed["player"]["me"]["correct"] is True and revealed["guest"]["me"]["correct"] is False
        # błędna ramka nie zrywa gniazda
        player.send_json({"type": "nieznana"})
        assert recv(player, "error")["code"] == "LIVE_BAD_FRAME"
        # uczestnik nie steruje fazami
        player.send_json({"type": "control", "action": "next"})
        assert recv(player, "error")["code"] == "LIVE_NOT_HOST"


def test_websocket_odmowy_i_polling_awaryjny(client):
    view = create(client)
    sid, pin = view["session"]["id"], view["session"]["pin"]
    client.post("/exam-live/join", json={"pin": pin}, headers=h("p1"))

    def refused(url):
        with client.websocket_connect(url) as ws:
            msg = ws.receive_json()
            assert msg["type"] == "error"
            with pytest.raises(WebSocketDisconnect) as closed:
                ws.receive_json()
            return msg["code"], closed.value.code

    assert refused(f"/exam-live/ws/{sid}?role=host&token=zly") == ("UNAUTHORIZED", 4401)
    assert refused(f"/exam-live/ws/{sid}?role=host&token=tok-101") == ("LIVE_NOT_HOST", 4403)
    assert refused(f"/exam-live/ws/{sid}?role=player&token=tok-103") == ("LIVE_NOT_JOINED", 4403)
    assert refused(f"/exam-live/ws/{sid}?role=guest&gt=zly") == ("LIVE_NOT_JOINED", 4403)
    assert refused("/exam-live/ws/nieistnieje?role=projector")[0] == "LIVE_NOT_FOUND"
    # gniazdo nie odstawia GET-a: bez WebSocketu stan jest dostępny tak samo (polling)
    assert client.get(f"/exam-live/{sid}/state", headers=h("host")).json()["session"]["joined"] == 1

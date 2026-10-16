"""Egzamin na żywo - poprawki po krytyce: limit PIN-ów po adresie z proxy, osobny token rzutnika, sekrety poza URL-em."""

import pytest
from starlette.websockets import WebSocketDisconnect

from test_exam_live_routes import client, create, h  # noqa: F401 - fixture `client`


def proj_token(view):
    return view["session"]["links"]["projector_url"].rsplit("/", 1)[-1]


def join_token(view):
    return view["session"]["links"]["join_url"].rsplit("/", 1)[-1]


def test_sala_40_osob_za_proxy_nie_dzieli_limitu_blednych_pinow(client):
    for i in range(40):
        res = client.post("/exam-live/join", json={"pin": "000000"}, headers={**h("plain"), "x-forwarded-for": f"10.0.0.{i}, 10.9.9.9"})
        assert res.status_code == 404, (i, res.text)
    # jeden adres liczy swoje próby: po 20 błędnych dostaje 429
    codes = [client.post("/exam-live/join", json={"pin": "000000"}, headers={**h("plain"), "x-forwarded-for": "10.1.1.1"}).status_code
             for _ in range(22)]
    assert codes[:20] == [404] * 20 and codes[20:] == [429, 429]
    other = client.post("/exam-live/join", json={"pin": "000000"}, headers={**h("plain"), "x-forwarded-for": "10.1.1.2"})
    assert other.status_code == 404


def test_rzutnik_przyjmuje_tylko_token_rzutnika(client):
    view = create(client)
    ptoken, jtoken = proj_token(view), join_token(view)
    assert ptoken != jtoken
    assert client.get(f"/exam-live/projector/{ptoken}/state").status_code == 200
    assert client.get(f"/exam-live/projector/{ptoken}").status_code == 200
    qr = client.get(f"/exam-live/projector/{ptoken}/qr.svg")
    assert qr.status_code == 200 and b"<svg" in qr.content
    for url in (f"/exam-live/projector/{jtoken}/state", f"/exam-live/projector/{jtoken}", f"/exam-live/projector/{jtoken}/qr.svg"):
        assert client.get(url).status_code == 404
    # token z QR nadal służy do dołączania
    joined = client.post("/exam-live/join", json={"token": jtoken}, headers=h("p1"))
    assert joined.status_code == 200
    assert client.post("/exam-live/join", json={"token": ptoken}, headers=h("p2")).status_code == 404


def test_websocket_rzutnika_nie_przyjmuje_tokenu_dolaczania(client):
    view = create(client)
    sid = view["session"]["id"]
    with client.websocket_connect(f"/exam-live/ws/{proj_token(view)}?role=projector") as ws:
        assert ws.receive_json()["snapshot"]["role"] == "projector"
    with client.websocket_connect(f"/exam-live/ws/{join_token(view)}?role=projector") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error" and msg["code"] == "LIVE_NOT_FOUND"
    assert sid


def test_websocket_sekrety_w_pierwszej_ramce_i_naglowku(client):
    view = create(client, guests_allowed=True)
    sid, pin = view["session"]["id"], view["session"]["pin"]
    client.post("/exam-live/join", json={"pin": pin}, headers=h("p1"))
    gt = client.post("/exam-live/guest/join", json={"pin": pin, "nick": "Gosc"}).json()["guest_token"]
    with client.websocket_connect(f"/exam-live/ws/{sid}?role=host") as ws:
        ws.send_json({"type": "auth", "token": "tok-2"})
        assert ws.receive_json()["snapshot"]["role"] == "host"
    with client.websocket_connect(f"/exam-live/ws/{sid}?role=player", headers={"authorization": "Bearer tok-101"}) as ws:
        assert ws.receive_json()["snapshot"]["role"] == "player"
    with client.websocket_connect(f"/exam-live/ws/{sid}?role=guest") as ws:
        ws.send_json({"type": "auth", "gt": gt})
        assert ws.receive_json()["snapshot"]["me"]["kind"] == "guest"
    with client.websocket_connect(f"/exam-live/ws/{sid}?role=guest", headers={"x-guest-token": gt}) as ws:
        assert ws.receive_json()["snapshot"]["me"]["kind"] == "guest"
    with client.websocket_connect(f"/exam-live/ws/{sid}?role=host") as ws:
        ws.send_json({"type": "auth", "token": "zly"})
        assert ws.receive_json()["code"] == "UNAUTHORIZED"
    # zgodność: query nadal działa
    with client.websocket_connect(f"/exam-live/ws/{sid}?role=host&token=tok-2") as ws:
        assert ws.receive_json()["snapshot"]["role"] == "host"


def test_gosc_http_sekret_w_naglowku(client):
    view = create(client, guests_allowed=True)
    sid, pin = view["session"]["id"], view["session"]["pin"]
    gt = client.post("/exam-live/guest/join", json={"pin": pin, "nick": "Gosc"}).json()["guest_token"]
    ok = client.get(f"/exam-live/guest/{sid}/state", headers={"x-guest-token": gt})
    assert ok.status_code == 200 and ok.json()["role"] == "player"
    assert client.get(f"/exam-live/guest/{sid}/state").status_code == 403
    assert client.get(f"/exam-live/guest/{sid}/state?gt={gt}").status_code == 200

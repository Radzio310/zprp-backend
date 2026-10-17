"""Egzamin na żywo - pilot prowadzącego (17.10.2026): pauza z zamrożonym zegarem, dodatkowy czas,
pominięcie pytania, zamknięcie sali, usunięcie osoby, zapowiedź następnego pytania, linki zasobów."""

from datetime import datetime, timedelta, timezone

import pytest

from app import exam_live_rules as L
from test_exam_live_brand import create, err, h, make_client


class Clock:
    def __init__(self):
        self.t = datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.t

    def add(self, s):
        self.t += timedelta(seconds=s)


@pytest.fixture
def env(tmp_path):
    clock = Clock()
    with make_client(tmp_path, now=clock) as c:
        yield c, clock


def ctl(c, sid, action, **kw):
    return c.post(f"/exam-live/{sid}/control", json={"action": action, **kw}, headers=h("host"))


def started(c):
    v, ptok, jtok = create(c, config={"question_time_s": 30})
    sid = v["session"]["id"]
    for k in ("p1", "p2"):
        assert c.post("/exam-live/join", json={"pin": v["session"]["pin"]}, headers=h(k)).status_code == 200
    assert ctl(c, sid, "next").status_code == 200
    return v, sid, ptok


def test_host_ma_liste_polecen_i_zapowiedz_nastepnego(env):
    c, _clock = env
    v, sid, _p = started(c)
    assert v["session"]["controls"] == list(L.CONTROLS) and v["session"]["next"]["index"] == 0
    host = c.get(f"/exam-live/{sid}/state", headers=h("host")).json()["session"]
    assert host["next"]["index"] == 1 and host["next"]["text"] and host["paused"] is False and host["locked"] is False
    player = c.get(f"/exam-live/{sid}/state", headers=h("p1")).json()["session"]
    assert "next" not in player and "controls" not in player
    links = v["session"]["links"]
    assert links["qr_json_url"].endswith("/qr.json") and links["poster_url"].endswith("/poster.pdf") and links["story_url"].endswith("/story.png")
    assert c.get(links["qr_json_url"]).json()["matrix"][0].startswith("1111111")  # pełna macierz z oczkiem
    assert c.get(links["story_url"]).headers["content-type"] == "image/png"


def test_pauza_zamraza_zegar_odrzuca_odpowiedzi_a_wznowienie_przesuwa_termin(env):
    c, clock = env
    _v, sid, ptok = started(c)
    clock.add(10)
    paused = ctl(c, sid, "pause").json()
    assert paused["session"]["paused"] is True and paused["question"]["seconds_left"] == 20 and paused["question"]["deadline_at"] is None
    clock.add(100)  # pauza trwa dłużej niż czas pytania - nic się samo nie odsłania
    proj = c.get(f"/exam-live/projector/{ptok}/state").json()
    assert proj["session"]["phase"] == "question" and proj["question"]["seconds_left"] == 20 and proj["question"]["paused"] is True
    refused = c.post(f"/exam-live/{sid}/answer", json={"selected": ["a"]}, headers=h("p1"))
    assert refused.status_code == 409 and err(refused) == "LIVE_PAUSED"
    assert err(ctl(c, sid, "pause")) == "LIVE_PAUSED"
    resumed = ctl(c, sid, "resume").json()
    assert resumed["session"]["paused"] is False and resumed["question"]["seconds_left"] == 20
    assert err(ctl(c, sid, "resume")) == "LIVE_NOT_PAUSED"
    assert c.post(f"/exam-live/{sid}/answer", json={"selected": ["a"]}, headers=h("p1")).status_code == 200


def test_dodatkowy_czas_w_biegu_i_w_pauzie(env):
    c, clock = env
    _v, sid, _p = started(c)
    clock.add(25)
    assert ctl(c, sid, "extend").json()["question"]["seconds_left"] == 20  # 5 + 15 domyślnie
    assert ctl(c, sid, "extend", seconds=30).json()["question"]["seconds_left"] == 50
    assert err(ctl(c, sid, "extend", seconds=500)) == "BAD_CONFIG" or ctl(c, sid, "extend", seconds=500).status_code == 400
    ctl(c, sid, "pause")
    assert ctl(c, sid, "extend", seconds=10).json()["question"]["seconds_left"] == 60


def test_pominiete_pytanie_nie_liczy_sie_do_wyniku(env):
    c, _clock = env
    _v, sid, _p = started(c)
    c.post(f"/exam-live/{sid}/answer", json={"selected": ["a"]}, headers=h("p1"))
    skipped = ctl(c, sid, "skip").json()
    assert skipped["session"]["phase"] == "question" and skipped["session"]["q_index"] == 1 and skipped["session"]["answered"] == 0
    ctl(c, sid, "end")
    result = c.get(f"/exam-live/{sid}/results", headers=h("host")).json()["result"]
    assert result["question_count"] == 2 and all(r["score"] == 0 for r in result["ranking"])


def test_pilot_poza_pytaniem_mowi_czemu_nie(env):
    c, _clock = env
    v, _p, _j = create(c)
    sid = v["session"]["id"]
    for action in ("pause", "resume", "extend", "skip"):
        res = ctl(c, sid, action)
        assert res.status_code == 409 and err(res) == "LIVE_BAD_PHASE"
    assert c.post(f"/exam-live/{sid}/control", json={"action": "pause"}, headers=h("p1")).status_code == 403


def test_zamknieta_sala_nie_wpuszcza_nowych_ale_wpuszcza_powracajacych(env):
    c, _clock = env
    v, _p, jtok = create(c)
    sid, pin = v["session"]["id"], v["session"]["pin"]
    c.post("/exam-live/join", json={"pin": pin}, headers=h("p1"))
    assert ctl(c, sid, "lock").json()["session"]["locked"] is True
    assert c.get(f"/exam-live/peek?token={jtok}").json()["joinable"] is False
    late = c.post("/exam-live/join", json={"pin": pin}, headers=h("p2"))
    assert late.status_code == 409 and err(late) == "LIVE_LOCKED"
    guest = c.post("/exam-live/guest/join", json={"pin": pin, "nick": "Gosc"})
    assert err(guest) == "LIVE_LOCKED"
    assert c.post("/exam-live/join", json={"pin": pin}, headers=h("p1")).json()["rejoined"] is True
    assert ctl(c, sid, "unlock").json()["session"]["locked"] is False
    assert c.post("/exam-live/join", json={"pin": pin}, headers=h("p2")).status_code == 200


def test_usuniecie_z_sali(env):
    c, _clock = env
    v, _p, _j = create(c)
    sid, pin = v["session"]["id"], v["session"]["pin"]
    c.post("/exam-live/join", json={"pin": pin}, headers=h("p1"))
    gt = c.post("/exam-live/guest/join", json={"pin": pin, "nick": "Gosc"}).json()["guest_token"]
    host = c.get(f"/exam-live/{sid}/state", headers=h("host")).json()
    ids = {p["name"]: p["id"] for p in host["participants"]}
    assert c.delete(f"/exam-live/{sid}/participants/{ids['Gosc']}", headers=h("p1")).status_code == 403
    after = c.delete(f"/exam-live/{sid}/participants/{ids['Gosc']}", headers=h("host")).json()
    assert [p["name"] for p in after["participants"]] == [n for n in ids if n != "Gosc"]
    assert err(c.get(f"/exam-live/guest/{sid}/state", headers={"X-Guest-Token": gt})) == "LIVE_KICKED"
    c.delete(f"/exam-live/{sid}/participants/{ids[next(n for n in ids if n != 'Gosc')]}", headers=h("host"))
    assert err(c.get(f"/exam-live/{sid}/state", headers=h("p1"))) == "LIVE_KICKED"
    again = c.post("/exam-live/join", json={"pin": pin}, headers=h("p1"))
    assert again.status_code == 403 and err(again) == "LIVE_KICKED"
    assert c.delete(f"/exam-live/{sid}/participants/nikt", headers=h("host")).status_code == 404


def test_usuniety_dostaje_komunikat_przez_gniazdo(env):
    c, _clock = env
    v, _p, _j = create(c)
    sid, pin = v["session"]["id"], v["session"]["pin"]
    gt = c.post("/exam-live/guest/join", json={"pin": pin, "nick": "Gosc"}).json()["guest_token"]
    pid = c.get(f"/exam-live/{sid}/state", headers=h("host")).json()["participants"][0]["id"]
    with c.websocket_connect(f"/exam-live/ws/{sid}?role=guest", headers={"X-Guest-Token": gt}) as ws:
        assert ws.receive_json()["type"] == "snapshot"
        c.delete(f"/exam-live/{sid}/participants/{pid}", headers=h("host"))
        frame = ws.receive_json()
        while frame["type"] == "snapshot":
            frame = ws.receive_json()
        assert frame == {"type": "error", "code": "LIVE_KICKED", "message": "Prowadzący usunął Cię z tej sesji."}

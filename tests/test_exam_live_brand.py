"""Egzamin na żywo - oprawa marki (17.10.2026): markowy kod QR, karta linku, obraz 9:16, plakat A4,
strona uczestnika (podgląd sesji, logowanie kontem BAZY). SQLite + TestClient, bez Postgresa."""

import io
from contextlib import asynccontextmanager

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from app import exam_live_brand as BR
from app.exam_live_routes import LiveDeps, build_router
from app.exam_rules import ExamError
from exam_live_support import ADMIN, HOST, PLAIN, PLAYERS, SINGLES, make_store

WHO = {"admin": ADMIN, "host": HOST, "plain": PLAIN, **{f"p{i}": w for i, w in enumerate(PLAYERS, start=1)}}
TOKENS = {f"tok-{w.judge_id}": w for w in [ADMIN, HOST, PLAIN, *PLAYERS]}
URL = "https://zprp-backend-production.up.railway.app/exam-live/j/AbCdEfGhIjKlMnOpQrStUv"


def make_client(tmp_path, login="fake", now=None):
    store = make_store(tmp_path / "brand.db")

    async def who(request: Request):
        key = request.headers.get("x-who")
        if key in WHO:
            return WHO[key]
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer ") and auth[7:] in TOKENS:
            return TOKENS[auth[7:]]
        raise HTTPException(401, "Brak tokenu")

    async def identify(token):
        w = TOKENS.get(token)
        return w.judge_id if w else None

    async def fake_login(username, password):
        if password != "dobre":
            raise ExamError("LIVE_LOGIN_FAILED", "Login albo hasło się nie zgadza.", 401)
        return {"access_token": "tok-101", "expires_in": 43200, "judge_id": "101", "name": "Sędzia 1"}

    deps = LiveDeps(store=lambda: store, who=who, identify=identify, login=fake_login if login == "fake" else None)
    if now is not None:
        deps.now = now

    @asynccontextmanager
    async def lifespan(_app):
        await store.database.connect()
        yield
        await store.database.disconnect()

    app = FastAPI(lifespan=lifespan)
    app.include_router(build_router(deps))
    return TestClient(app)


@pytest.fixture
def client(tmp_path):
    with make_client(tmp_path) as c:
        yield c


def h(key):
    return {"x-who": key}


def create(client, **over):
    body = {"scope": "province", "province": "ŚLĄSKIE", "title": "Quiz <b>śląski</b>", "question_ids": list(SINGLES), "guests_allowed": True}
    body.update(over)
    res = client.post("/exam-live", json=body, headers=h("host"))
    assert res.status_code == 200, res.text
    v = res.json()
    links = v["session"]["links"]
    return v, links["projector_url"].rsplit("/", 1)[-1], links["join_url"].rsplit("/", 1)[-1]


def err(res):
    body = res.json()
    return body["detail"]["code"] if "detail" in body else body["code"]


# ---------------------------------------------------------------------------
# Barwy i macierz
# ---------------------------------------------------------------------------


def test_barwy_okregu_przyciemnione_do_druku_a_krajowy_w_barwach_zprp():
    for prov in BR.PROVINCE_COLORS:
        p = BR.palette_for("province", prov)
        assert p["kind"] == "province" and p["slug"] == prov
        assert BR.contrast(p["from"], "#FFFFFF") >= 4.5 and BR.contrast(p["to"], "#FFFFFF") >= 4.5, prov
        assert p["from"] != p["to"], "herb jednobarwny też ma widoczny gradient"
    assert BR.palette_for("province", "Dolnośląskie")["primary"] == "#F3C707"  # surowa barwa zostaje do świateł
    assert BR.palette_for("national", "ŚLĄSKIE")["kind"] == "zprp"
    assert BR.palette_for("province", "Atlantyda")["kind"] == "zprp"
    assert BR.province_slug("WARMIŃSKO-MAZURSKIE") == "WARMINSKO_MAZURSKIE"
    assert BR.crest_path(BR.palette_for("province", "ŚLĄSKIE")) is not None
    assert BR.crest_path(BR.palette_for("national", None)) is not None


def test_macierz_kodu_korekcja_h_wyciete_oczka_i_srodek():
    lay = BR.qr_layout(URL)
    n = lay["size"]
    assert lay["ecc"] == "H" and n == 17 + 4 * lay["version"]
    for e in lay["eyes"]:
        assert not any(lay["modules"][y][x] for y in range(e["y"], e["y"] + 7) for x in range(e["x"], e["x"] + 7))
    lg = lay["logo"]
    assert lg["size"] % 2 == 1 and lg["size"] * lg["size"] < 0.08 * n * n  # środek pod herb daleko w zapasie korekcji H
    assert not any(lay["modules"][y][x] for y in range(lg["y"], lg["y"] + lg["size"]) for x in range(lg["x"], lg["x"] + lg["size"]))
    data = BR.qr_json(URL, BR.palette_for("province", "OPOLSKIE"), "/exam-live/assets/img/okregi/opolskie.png")
    assert len(data["modules"]) == n and all(len(r) == n and set(r) <= {"0", "1"} for r in data["modules"])
    assert data["style"]["eye_outer"] == "square" and data["palette"]["slug"] == "OPOLSKIE"


@pytest.mark.parametrize("scope,prov", [("province", "ŚLĄSKIE"), ("province", "DOLNOŚLĄSKIE"), ("province", "WIELKOPOLSKIE"), ("national", None)])
@pytest.mark.parametrize("px", [330, 520, 760])
def test_markowy_kod_dekoduje_sie_czytnikiem(scope, prov, px):
    cv2 = pytest.importorskip("cv2")
    np = pytest.importorskip("numpy")
    from PIL import ImageOps

    img = ImageOps.expand(BR.qr_png(URL, BR.palette_for(scope, prov), px).convert("RGB"), 24, fill="white")
    value, _pts, _ = cv2.QRCodeDetector().detectAndDecode(cv2.cvtColor(np.array(img), cv2.COLOR_RGB2GRAY))
    assert value == URL


def test_svg_samodzielny_z_gradientem_i_herbem_w_data_uri():
    pal = BR.palette_for("province", "ŚLĄSKIE")
    body = BR.brand_svg(URL, pal, crest=BR.crest_data_uri(pal))
    assert body.startswith("<svg") and "linearGradient" in body and pal["from"] in body
    assert 'href="data:image/png;base64,' in body and "evenodd" in body


def test_karta_linku_i_obraz_relacji_maja_wlasciwe_wymiary():
    from PIL import Image

    pal = BR.palette_for("province", "ŚLĄSKIE")
    card = Image.open(io.BytesIO(BR.og_card_png(title="Sprawdzian okręgowy", pin="123456", character="quiz", palette=pal, url=URL)))
    assert card.size == (1200, 630)
    story = Image.open(io.BytesIO(BR.story_png(title="Sprawdzian", pin="123456", character="exam", palette=pal, url=URL, join_hint="albo adres")))
    assert story.size == (1080, 1920)


def test_plakat_html_ucieka_tytul_i_ma_pin_oraz_kod():
    html = BR.poster_html(title="<script>x</script>", pin="123456", character="quiz", palette=BR.palette_for("national", None),
                          url=URL, join_page="https://baza.example/exam-live/join", province_label="ZPRP", seal="<svg></svg>")
    assert "<script>x" not in html and "&lt;script&gt;" in html
    assert html.count('class="d"') == 6 and "<svg" in html and "@page" in html


def test_plakat_pdf_z_weasyprint():
    weasyprint = pytest.importorskip("weasyprint")
    html = BR.poster_html(title="Plakat", pin="123456", character="exam", palette=BR.palette_for("province", "OPOLSKIE"),
                          url=URL, join_page="https://baza.example/exam-live/join", province_label="Opolskie", seal="")
    assert weasyprint.HTML(string=html).write_pdf()[:4] == b"%PDF"


# ---------------------------------------------------------------------------
# Trasy
# ---------------------------------------------------------------------------


def test_kod_sesji_tylko_dla_prowadzacego_i_admina(client):
    v, _p, jtok = create(client)
    sid = v["session"]["id"]
    assert client.get(f"/exam-live/{sid}/qr.json").status_code == 401
    assert err(client.get(f"/exam-live/{sid}/qr.json", headers=h("p1"))) == "LIVE_NOT_HOST"
    data = client.get(f"/exam-live/{sid}/qr.json", headers={**h("host"), "host": "baza.example"}).json()
    assert data["url"] == f"https://www.bazapodreka.app/sala/{v['session']['pin']}" and data["pin"] == v["session"]["pin"]
    assert data["join_page"] == "https://www.bazapodreka.app/sala" and data["short"] == "bazapodreka.app/sala"
    assert data["crest_url"] == "/exam-live/assets/img/okregi/slaskie.png" and len(data["modules"]) == data["size"]
    assert client.get(f"/exam-live/{sid}/qr.json", headers=h("admin")).status_code == 200
    svg = client.get(f"/exam-live/{sid}/qr.svg?style=brand", headers=h("host"))
    assert svg.headers["content-type"].startswith("image/svg+xml") and b"linearGradient" in svg.content
    plain = client.get(f"/exam-live/{sid}/qr.svg?style=plain", headers=h("host"))
    assert plain.status_code == 200 and b"linearGradient" not in plain.content
    links = v["session"]["links"]
    assert links["join_short"] == f"/exam-live/j/{jtok}" and links["qr_json"].endswith("/qr.json")


def test_rzutnik_dostaje_macierz_kodu_tylko_swoim_tokenem(client):
    _v, ptok, jtok = create(client)
    assert client.get(f"/exam-live/projector/{ptok}/qr.json").json()["ecc"] == "H"
    assert b"linearGradient" in client.get(f"/exam-live/projector/{ptok}/qr.svg?style=brand").content
    assert client.get(f"/exam-live/projector/{jtok}/qr.json").status_code == 404


def test_obraz_relacji_i_plakat(client):
    from PIL import Image

    v, _p, _j = create(client)
    sid = v["session"]["id"]
    story = client.get(f"/exam-live/{sid}/story.png", headers=h("host"))
    assert story.status_code == 200 and Image.open(io.BytesIO(story.content)).size == (1080, 1920)
    assert client.get(f"/exam-live/{sid}/story.png", headers=h("p2")).status_code == 403
    poster = client.get(f"/exam-live/{sid}/poster.pdf", headers=h("host"))
    try:
        import weasyprint  # noqa: F401
    except Exception:  # noqa: BLE001
        assert poster.status_code == 503 and err(poster) == "LIVE_PDF_UNAVAILABLE"
    else:
        assert poster.status_code == 200 and poster.content[:4] == b"%PDF"


def test_stare_strony_przekierowuja_na_bazapodreka_a_karty_zostaja(client):
    from PIL import Image

    v, ptok, jtok = create(client)
    pin = v["session"]["pin"]
    for path in (f"/exam-live/join/{jtok}", f"/exam-live/j/{jtok}"):
        moved = client.get(path, follow_redirects=False)
        assert moved.status_code == 302 and moved.headers["location"] == f"https://www.bazapodreka.app/sala/{pin}"
    assert client.get("/exam-live/join", follow_redirects=False).headers["location"] == "https://www.bazapodreka.app/sala"
    assert client.get("/exam-live/join/nieznany", follow_redirects=False).headers["location"] == "https://www.bazapodreka.app/sala"
    screen = client.get(f"/exam-live/projector/{ptok}", follow_redirects=False)
    assert screen.status_code == 302 and screen.headers["location"] == f"https://www.bazapodreka.app/sala/ekran/{ptok}"
    card = client.get(f"/exam-live/join/{jtok}/card.png")
    assert card.status_code == 200 and Image.open(io.BytesIO(card.content)).size == (1200, 630)
    assert client.get("/exam-live/join/nieznany/card.png").status_code == 200  # ogólna karta, nie błąd


def test_podglad_sesji_przed_dolaczeniem(client):
    v, _p, jtok = create(client)
    pin = v["session"]["pin"]
    p = client.get(f"/exam-live/peek?pin={pin}").json()
    assert p["session_id"] == v["session"]["id"] and p["guests_allowed"] is True and p["joinable"] is True
    assert p["brand"]["palette"]["slug"] == "SLASKIE" and "pin" not in p
    assert client.get(f"/exam-live/peek?token={jtok}").json()["title"] == "Quiz <b>śląski</b>"
    assert err(client.get("/exam-live/peek?pin=000000")) == "LIVE_PIN_UNKNOWN"
    codes = [client.get("/exam-live/peek?pin=000001", headers={"x-forwarded-for": "10.7.7.7"}).status_code for _ in range(22)]
    assert codes[-1] == 429
    client.post(f"/exam-live/{v['session']['id']}/control", json={"action": "end"}, headers=h("host"))
    assert err(client.get(f"/exam-live/peek?token={jtok}")) == "LIVE_ENDED"


def test_logowanie_www_kontem_bazy_i_dolaczenie_jak_z_aplikacji(client):
    v, _p, jtok = create(client)
    sid = v["session"]["id"]
    bad = client.post("/exam-live/web-login", json={"username": "jan", "password": "zle"})
    assert bad.status_code == 401 and err(bad) == "LIVE_LOGIN_FAILED"
    assert err(client.post("/exam-live/web-login", json={"username": "", "password": ""})) == "LIVE_LOGIN_EMPTY"
    ok = client.post("/exam-live/web-login", json={"username": "jan", "password": "dobre"}).json()
    bearer = {"Authorization": f"Bearer {ok['access_token']}"}
    joined = client.post("/exam-live/join", json={"token": jtok}, headers=bearer).json()
    assert joined["session_id"] == sid and joined["snapshot"]["me"]["kind"] == "user"
    state = client.get(f"/exam-live/{sid}/state", headers=bearer).json()
    assert state["role"] == "player" and state["me"]["name"] == PLAYERS[0].name
    client.post(f"/exam-live/{sid}/control", json={"action": "end"}, headers=h("host"))
    result = client.get(f"/exam-live/{sid}/results", headers=h("host")).json()["result"]
    assert [r["judge_id"] for r in result["ranking"]] == ["101"]  # wynik konta, jak z aplikacji


def test_logowanie_www_ma_limit_prob(client):
    codes = [client.post("/exam-live/web-login", json={"username": "x", "password": "zle"}, headers={"x-forwarded-for": "10.8.8.8"}).status_code
             for _ in range(12)]
    assert codes[:10] == [401] * 10 and codes[-1] == 429


def test_logowanie_www_wylaczone_bez_zaleznosci(tmp_path):
    with make_client(tmp_path, login=None) as c:
        res = c.post("/exam-live/web-login", json={"username": "x", "password": "y"})
        assert res.status_code == 503 and err(res) == "LIVE_LOGIN_UNAVAILABLE"


def test_herby_tylko_z_listy(client):
    assert client.get("/exam-live/assets/img/okregi/slaskie.png").headers["content-type"] == "image/png"
    assert client.get("/exam-live/assets/img/zprp.png").status_code == 200
    for bad in ("okregi/../../exam_live.py", "okregi/nieistnieje.png", "zprp.svg"):
        assert client.get(f"/exam-live/assets/img/{bad}").status_code == 404

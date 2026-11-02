"""Poprawki z przeglądu „Wczytaj składy" (02.11.2026): limity PDF-a i obrazu, zwrot limitu AI, wiersze bez numeru,
duplikaty w jednym PDF-ie, clean_extra, zapis składu tylko w meczu ręcznym, modele serii o/gpt-5. Dane zmyślone."""

import asyncio
import io
import json

import fitz
import pytest

from app import lineup_pdf_parse as P
from app import lineup_read_rules as R
from app import lineup_vision as V
from app import shared_match_rules as SR
from tests import lineup_support as S
from tests.test_lineup_read_route import A, Upload, _actor_holder, denied, env, fake_model, make, used  # noqa: F401
from tests.test_lineup_read_rules import FakeClient, good_payload


# ─── 1. Znaczniki w PDF-ie: limity ──────────────────────────────────────────


def test_duzy_obraz_w_malym_prostokacie_nie_jest_dekodowany(monkeypatch):
    doc = fitz.open()
    page = doc.new_page(width=300, height=300)
    from PIL import Image

    big = io.BytesIO()
    Image.new("RGB", (900, 900), (30, 150, 40)).save(big, format="PNG")  # 810 000 px > limit znacznika
    page.insert_image(fitz.Rect(10, 10, 20, 20), stream=big.getvalue())
    page.insert_image(fitz.Rect(30, 10, 40, 20), stream=S.green_png())
    decoded = []
    real = fitz.Pixmap

    def spy(*a, **k):
        decoded.append(a)
        return real(*a, **k)

    monkeypatch.setattr(fitz, "Pixmap", spy)
    marks = P._badge_marks(page)
    assert len(decoded) == 1  # tylko mały obraz
    assert [m[1] for m in marks if m[1] is not None] == [True] and len(marks) == 2


def test_liczba_obrazow_i_rysunkow_jest_ograniczona(monkeypatch):
    monkeypatch.setattr(P, "MAX_BADGE_XREFS", 3)
    monkeypatch.setattr(P, "MAX_BADGE_DRAWINGS", 5)
    doc = fitz.open()
    page = doc.new_page(width=600, height=600)
    from PIL import Image

    for i in range(10):
        out = io.BytesIO()
        Image.new("RGB", (20 + i, 20), (30, 150, 40)).save(out, format="PNG")  # różne obrazy = różne xrefy
        page.insert_image(fitz.Rect(10 + 12 * i, 10, 20 + 12 * i, 20), stream=out.getvalue())
    for i in range(50):
        x = 10 + (11 * i) % 500
        page.draw_rect(fitz.Rect(x, 100, x + 10, 110), color=None, fill=(0.1, 0.6, 0.1))
    marks = P._badge_marks(page)
    assert sum(1 for m in marks if m[1] is True) <= 3 + 5


# ─── 2. Obraz: limit pikseli i draft ────────────────────────────────────────


def test_obraz_powyzej_25mp_odrzucony_a_duzy_jpeg_zmniejszony():
    assert V.MAX_PIXELS == 25_000_000
    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", (6000, 5000), (200, 200, 200)).save(out, format="JPEG")  # 30 MP
    with pytest.raises(R.LineupError) as exc:
        V.shrink_image(out.getvalue())
    assert exc.value.code == "IMAGE_TOO_LARGE"
    ok = io.BytesIO()
    Image.new("RGB", (5000, 4000), (200, 200, 200)).save(ok, format="JPEG")  # 20 MP
    small = Image.open(io.BytesIO(V.shrink_image(ok.getvalue())))
    assert max(small.size) <= V.MAX_SIDE


# ─── 3. Content-Length ──────────────────────────────────────────────────────


def test_naglowek_content_length_odrzuca_za_duze_zadanie(env):
    from fastapi import HTTPException

    L = env.read
    with pytest.raises(HTTPException) as exc:
        L.check_declared_size(str(L.MAX_REQUEST_BYTES + 1))
    assert exc.value.status_code == 413 and exc.value.detail["code"] == "REQUEST_TOO_LARGE"
    L.check_declared_size(str(L.MAX_REQUEST_BYTES))
    L.check_declared_size(None)
    L.check_declared_size("abc")


def test_trasa_odrzuca_za_duze_zadanie_przed_odczytem(env):
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    app = FastAPI()
    app.include_router(env.read.router)
    client = TestClient(app)
    resp = client.post("/matches/lineup/read", content=b"x", headers={"content-length": str(env.read.MAX_REQUEST_BYTES + 5),
                                                                       "content-type": "multipart/form-data; boundary=zz"})
    assert resp.status_code == 413 and resp.json()["detail"]["code"] == "REQUEST_TOO_LARGE"


# ─── 4. Zwrot limitu AI przy każdej awarii ──────────────────────────────────


@pytest.mark.parametrize("error", [IndexError("brak choices"), KeyError("x"), RuntimeError("boom")])
def test_dowolna_awaria_modelu_oddaje_limit(env, monkeypatch, error):
    fake_model(env, monkeypatch, error=error)

    async def go():
        try:
            await env.read.read_lineup([Upload(S.jpeg_bytes())], _actor_holder(env))
        except type(error):
            return await used(env)
        raise AssertionError("brak wyjątku")

    assert env.run(go) == 0


def test_wyjatek_w_vision_to_result_oddaje_limit(env, monkeypatch):
    fake_model(env, monkeypatch)

    def boom(payload, pages):
        raise ValueError("zły kształt")

    monkeypatch.setattr(env.read.V, "vision_to_result", boom)

    async def go():
        try:
            await env.read.read_lineup([Upload(S.jpeg_bytes())], _actor_holder(env))
        except ValueError:
            return await used(env)

    assert env.run(go) == 0


def test_anulowanie_oddaje_limit(env, monkeypatch):
    fake_model(env, monkeypatch, error=asyncio.CancelledError())

    async def go():
        try:
            await env.read.read_lineup([Upload(S.jpeg_bytes())], _actor_holder(env))
        except asyncio.CancelledError:
            return await used(env)

    assert env.run(go) == 0


def test_not_a_protocol_nie_oddaje_limitu(env, monkeypatch):
    fake_model(env, monkeypatch, payload={**good_payload(), "is_protocol": False})

    async def go():
        status, code, _ = await denied(env.read.read_lineup([Upload(S.jpeg_bytes())], _actor_holder(env)))
        return status, code, await used(env)

    assert env.run(go) == (422, "NOT_A_PROTOCOL", 1)


# ─── 5. Wiersz bez numeru w PDF-ie ──────────────────────────────────────────


def test_wiersz_bez_numeru_w_pdf_nie_znika():
    players = [(2, "ŻÓŁTEK Błażej"), (None, "BEZNUMEROWY Bogdan"), (9, "ŚWIT Ćwik")]
    out = P.parse_pdf(S.build_protocol(home_players=players))
    rows = out["home"]["players"]
    assert len(rows) == 3
    bare = next(r for r in rows if r["name"] == "BEZNUMEROWY Bogdan")
    assert bare["number"] is None and bare["confidence"] <= 0.4
    assert any(u["team"] == "home" and u["kind"] == "player" and u["field"] == "number" for u in out["unreadable"])


def test_zwykly_protokol_nie_dostaje_wierszy_widmo():
    out = P.parse_pdf(S.build_protocol())
    assert len(out["home"]["players"]) == len(S.HOME_PLAYERS) and len(out["away"]["players"]) == len(S.AWAY_PLAYERS)


# ─── 6. Powtórzony protokół, scalanie nieczytelnych ─────────────────────────


def test_powtorzony_protokol_w_jednym_pdf_nie_dubluje_wierszy():
    one = fitz.open(stream=S.build_protocol(), filetype="pdf")
    one.insert_pdf(fitz.open(stream=S.build_protocol(), filetype="pdf"))
    out = P.parse_pdf(one.tobytes())
    assert len(out["home"]["players"]) == len(S.HOME_PLAYERS)
    assert len(out["home"]["staff"]) == len(S.HOME_STAFF) and out["pages"] == 2
    assert not any(w["code"] == "DUPLICATE_NUMBER" for w in out["warnings"])


def test_merge_scala_nieczytelne_z_przeliczonymi_indeksami():
    def part(rows):
        return R.build_result(source="vision", pages=1, header={}, officials=[],
                              away={"players": [{"number": 1, "name": "ABRAMOWICZ Adam", "confidence": 0.9}]},
                              home={"name": "KS", "players": rows, "staff": []})

    p1 = part([{"number": 2, "name": "ŻÓŁTEK Błażej", "confidence": 0.9}])
    p2 = part([{"number": 5, "name": "NOWAK Jan", "confidence": 0.9}, {"number": None, "name": "ŁOBODA Łukasz", "confidence": 0.9}])
    merged = R.merge_results([p1, p2])
    assert [r["number"] for r in merged["home"]["players"]] == [2, 5, None]
    assert {"team": "home", "kind": "player", "index": 2, "field": "number"} in merged["unreadable"]


# ─── 7/8. clean_extra i clean_lineup ────────────────────────────────────────


def _lineup(**row):
    return {"home": {"name": "KS", "players": [{"number": None, "name": "ŻÓŁTEK Błażej", **row}], "staff": []},
            "away": {"name": "MKS", "players": [], "staff": []}}


def test_clean_extra_zapisuje_wynik_clean_lineup_a_nie_surowa_wartosc():
    raw = {"inne": 1, "lineup": _lineup(junk="x", hacked={"a": 1})}
    out = SR.clean_extra(raw)
    assert out["inne"] == 1 and out["lineup"]["v"] == 1
    assert "junk" not in out["lineup"]["home"]["players"][0] and "hacked" not in json.dumps(out["lineup"])


def test_clean_lineup_przyjmuje_clashed_number_tylko_przy_pustym_numerze():
    row = R.clean_lineup(_lineup(clashed_number=7))["home"]["players"][0]
    assert row["clashed_number"] == 7 and row["number"] is None
    row = R.clean_lineup(_lineup(number=3, clashed_number=7))["home"]["players"][0]
    assert "clashed_number" not in row


def test_put_lineup_odrzuca_mecz_z_numerycznym_zprp_id(env):
    lineup = _lineup(number=4)

    async def go():
        linked = await make(env, zprp_match_id="123456")
        manual = await make(env, code="EHF/2", home_name="KS Inny", away_name="KS Drugi")
        body = env.shared.LineupBody
        out = {"linked": (await denied(env.shared.put_lineup(linked["match"]["id"], body(base_rev=linked["rev"], lineup=lineup),
                                                              await env.actor(A))))[:2]}
        out["clear"] = (await env.shared.put_lineup(linked["match"]["id"], body(base_rev=linked["rev"], lineup=None), await env.actor(A)))["ok"]
        out["manual"] = (await env.shared.put_lineup(manual["match"]["id"], body(base_rev=manual["rev"], lineup=lineup), await env.actor(A)))["ok"]
        return out

    out = env.run(go)
    assert out["linked"] == (422, "LINEUP_NOT_ALLOWED") and out["clear"] is True and out["manual"] is True


# ─── 9. Modele serii o/gpt-5 ────────────────────────────────────────────────


@pytest.mark.parametrize("name,reasoning", [("gpt-4o", False), ("gpt-4.1", False), ("gpt-5", True), ("gpt-5-mini", True),
                                            ("o3", True), ("o4-mini", True), ("openai/gpt-5", True)])
def test_parametry_zaleza_od_serii_modelu(monkeypatch, name, reasoning):
    monkeypatch.setenv("OPENAI_LINEUP_MODEL", name)
    client = FakeClient(good_payload())
    asyncio.run(V.call_model([b"jpeg"], client=client))
    call = client.calls[0]
    if reasoning:
        assert "temperature" not in call and "max_tokens" not in call and call["max_completion_tokens"] >= V.MAX_TOKENS
    else:
        assert call["temperature"] == 0 and call["max_tokens"] == V.MAX_TOKENS and "max_completion_tokens" not in call

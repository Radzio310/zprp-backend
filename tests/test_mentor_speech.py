"""Dyktowanie w panelu (18.11.2026): podpowiedź słownictwa, typ nagrania, prawa i limity, wywołanie Whispera."""

import base64

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.mentor_panel_support import JUDGES, PAIR, Env


@pytest.fixture
def d(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    e.speech._calls.clear()
    return e


def test_podpowiedz_najpierw_nazwy_z_pokoju_bez_dubli_i_w_limicie(d):
    p = d.speech.speech_prompt(["Korona Handball Kielce", "Piłka Ręczna Koszalin", "korona handball kielce", "Faul w ataku"])
    assert p.startswith("Korona Handball Kielce, Piłka Ręczna Koszalin, Faul w ataku")
    assert p.lower().count("faul w ataku") == 1
    assert len(d.speech.speech_prompt(["x" * 50] * 0 + [f"Nazwa {i}" for i in range(200)], limit=120)) <= 120


def test_typ_nagrania_z_przegladarki(d):
    assert d.speech.audio_name("audio/webm;codecs=opus") == ("audio.webm", "audio/webm")
    assert d.speech.audio_name("audio/mp4") == ("audio.mp4", "audio/mp4")
    assert d.speech.audio_name(None) == ("audio.webm", "audio/webm")


def test_tekst_do_pola(d):
    assert d.speech.tidy("  próba   zwrócenia uwagi na pchanie. ") == "Próba zwrócenia uwagi na pchanie"
    assert d.speech.tidy("Pierwsze zdanie. Drugie zdanie.") == "Pierwsze zdanie. Drugie zdanie."
    assert d.speech.tidy("") == ""


def test_transkrypcja_idzie_z_podpowiedzia_i_wraca_do_pola(d, monkeypatch):
    seen = {}

    async def fake(audio, mime, language, prompt):
        seen.update(audio=audio, mime=mime, language=language, prompt=prompt)
        return "próba zwrócenia uwagi na pchanie."

    monkeypatch.setattr(d.speech, "_transcribe", fake)

    async def go():
        actor = await d.actor(JUDGES[0])
        body = d.speech.SpeechBody(audio_base64=base64.b64encode(b"\x1a\x45\xdf\xa3" * 20).decode(), mime="audio/webm", context=["Korona Handball Kielce"])
        return await d.speech.transcribe(PAIR, body, actor)

    out = d.run(go)
    assert out == {"text": "Próba zwrócenia uwagi na pchanie"}
    assert seen["mime"] == "audio/webm" and seen["language"] == "pl" and seen["prompt"].startswith("Korona Handball Kielce")


def test_limit_tempa_i_dlugosci(d, monkeypatch):
    async def fake(*a):
        return "ok"

    monkeypatch.setattr(d.speech, "_transcribe", fake)
    monkeypatch.setattr(d.speech, "MAX_AUDIO_BYTES", 10)

    async def go():
        actor = await d.actor(JUDGES[0])
        body = d.speech.SpeechBody(audio_base64=base64.b64encode(b"0" * 64).decode())
        try:
            await d.speech.transcribe(PAIR, body, actor)
        except Exception as e:  # noqa: BLE001
            return e

    err = d.run(go)
    assert getattr(err, "status_code", None) == 413
    assert all(d.speech._rate_ok("x", now=1000.0 + i) for i in range(d.speech.RATE_MAX))
    assert not d.speech._rate_ok("x", now=1100.0)
    assert d.speech._rate_ok("x", now=1000.0 + d.speech.RATE_WINDOW_S + 50)


def test_obcy_nie_dyktuje_w_parze(d, monkeypatch):
    async def fake(*a):
        return "ok"

    monkeypatch.setattr(d.speech, "_transcribe", fake)

    async def go():
        actor = await d.actor("999")
        try:
            await d.speech.transcribe(PAIR, d.speech.SpeechBody(audio_base64=base64.b64encode(b"0" * 64).decode()), actor)
        except Exception as e:  # noqa: BLE001
            return e

    err = d.run(go)
    assert getattr(err, "status_code", None) in (403, 404)


# ─── Ścieżka trasy (19.11.2026) ─────────────────────────────────────────────
# Router dyktowania nie miał `prefix="/mentor-panel"` i trasa wisiała pod `/pairs/{id}/speech`, a obaj klienci
# (panel web `MENTOR_API` i aplikacja `MENTOR_PANEL_URL`) wołają `/mentor-panel/pairs/{id}/speech` -> 404 na produkcji.


def _panel_app(env):
    app = FastAPI()
    app.include_router(env.panel.panel_router)

    @app.on_event("startup")
    async def start():
        await env.db.connect()
        await env.seed()

    @app.on_event("shutdown")
    async def stop():
        await env.db.disconnect()

    return app


def test_trasa_dyktowania_pod_prefiksem_panelu(d):
    paths = _panel_app(d).openapi()["paths"]
    assert "post" in paths.get("/mentor-panel/pairs/{pair_id}/speech", {})
    assert "/pairs/{pair_id}/speech" not in paths


def test_dyktowanie_wymaga_logowania_do_panelu(d, monkeypatch):
    async def fake_bearer(request, token):
        return {"sub": "x", "judge_id": token}

    async def fake(*a):
        return "próba"

    monkeypatch.setattr(d.auth, "_decode_bearer", fake_bearer)
    monkeypatch.setattr(d.speech, "_transcribe", fake)
    body = {"audio_base64": base64.b64encode(b"0" * 64).decode(), "mime": "audio/webm"}
    url = f"/mentor-panel/pairs/{PAIR}/speech"

    with TestClient(_panel_app(d)) as client:
        anon = client.post(url, json=body)
        # 401 z kodem panelu, nie goły 404 FastAPI („trasy nie ma”).
        assert anon.status_code == 401 and anon.json()["detail"]["code"] == "UNAUTHENTICATED"
        assert client.post(url, json=body, headers={"authorization": "Bearer 999"}).status_code in (403, 404)
        ok = client.post(url, json=body, headers={"authorization": f"Bearer {JUDGES[0]}"})
        assert ok.status_code == 200 and ok.json() == {"text": "Próba"}
        assert client.post(f"/pairs/{PAIR}/speech", json=body, headers={"authorization": f"Bearer {JUDGES[0]}"}).status_code == 404

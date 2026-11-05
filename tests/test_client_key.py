"""Bramka klucza klienta: reguły (`app/client_key_rules.py`) i middleware
(`app/client_key_guard.py`) na małej aplikacji z CORS - bez bazy."""

from __future__ import annotations

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-client-key")
os.environ.setdefault("ALGORITHM", "HS256")

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient
from jose import jwt

from app import client_key_guard as guard
from app.client_key_rules import decide, is_open_path, key_name, parse_settings

WEB = "w" * 24
APP = "a" * 24
WWW = "s" * 24
KEYS = f"web:{WEB},app:{APP},www:{WWW}@/public/baza-stats|/national-distances"


class TestUstawienia:
    def test_bez_kluczy_zawsze_off(self):
        assert parse_settings("enforce", "").mode == "off"
        assert parse_settings("enforce", None).mode == "off"

    def test_krotki_klucz_pomijany(self):
        s = parse_settings("enforce", "web:krotki")
        assert s.mode == "off" and s.keys == ()

    def test_nieznany_tryb_to_report(self):
        assert parse_settings("cokolwiek", KEYS).mode == "report"

    def test_zakres_klucza_strony(self):
        s = parse_settings("enforce", KEYS)
        assert key_name(s, WWW, "/public/baza-stats") == "www"
        assert key_name(s, WWW, "/national-distances/pairs") == "www"
        assert key_name(s, WWW, "/login_records/") is None
        assert key_name(s, WEB, "/login_records/") == "web"
        assert key_name(s, "zly" * 8, "/public/baza-stats") is None


class TestDecyzja:
    s = parse_settings("enforce", KEYS)

    def test_bez_klucza_i_tokenu_401(self):
        v = decide(self.s, "GET", "/province_judges/", None, False)
        assert not v.allow and v.would_block

    def test_klucz_albo_token_przepuszcza(self):
        assert decide(self.s, "GET", "/province_judges/", APP, False).allow
        assert decide(self.s, "GET", "/province_judges/", None, True).allow

    def test_preflight_i_otwarte(self):
        assert decide(self.s, "OPTIONS", "/cokolwiek", None, False).allow
        for p in (
            "/health",
            "/.well-known/assetlinks.json",
            "/static/abc.png",
            "/auth/login",
            "/public_key",
            "/admin/versions",
            "/admin/forced_logout/next",
            "/province/settlements/pdf/download/TOKEN123",
            "/zprp/statystyki/okreg/export/table-officials-pdf-download/TOK",
            "/api/v1/handball/teams/12/calendar.ics",
            "/e/5/tok",
            "/exam-live/ws/abc",
            "/calendar/oauth2callback",
        ):
            assert decide(self.s, "GET", p, None, False).allow, p

    def test_dane_nie_sa_otwarte(self):
        for p in ("/login_records/", "/province_judges/", "/admin/json_files/kontakty", "/api/v1/handball/matches", "/docs", "/openapi.json", "/eksport", "/beach/users/"):
            assert not is_open_path(p), p

    def test_rejestracja_tylko_post(self):
        assert decide(self.s, "POST", "/beach/users/", None, False).allow
        assert not decide(self.s, "GET", "/beach/users/", None, False).allow

    def test_report_przepuszcza_ale_liczy(self):
        s = parse_settings("report", KEYS)
        v = decide(s, "GET", "/province_judges/", None, False)
        assert v.allow and v.would_block


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(guard.ClientKeyMiddleware)
    app.add_middleware(CORSMiddleware, allow_origins=["https://bazapodreka.app"], allow_methods=["*"], allow_headers=["*"])

    @app.get("/dane")
    async def dane():
        return {"ok": True}

    @app.get("/health")
    async def health():
        return {"ok": True}

    return app


@pytest.fixture
def client(monkeypatch):
    def make(mode: str):
        monkeypatch.setattr(guard, "_settings", parse_settings(mode, KEYS))
        return TestClient(_app())

    yield make
    guard._settings = None


class TestMiddleware:
    def test_enforce(self, client):
        c = client("enforce")
        r = c.get("/dane")
        assert r.status_code == 401 and r.json()["error"] == "CLIENT_KEY_REQUIRED"
        assert c.get("/dane", headers={"X-Baza-Key": WEB}).status_code == 200
        assert c.get(f"/dane?baza_key={APP}").status_code == 200
        assert c.get("/health").status_code == 200

    def test_token_podpisany_przez_serwer_nawet_wygasly(self, client):
        c = client("enforce")
        good = jwt.encode({"sub": "1", "exp": 1}, os.environ["SECRET_KEY"], algorithm=os.environ["ALGORITHM"])
        bad = jwt.encode({"sub": "1"}, "inny-sekret", algorithm="HS256")
        assert c.get("/dane", headers={"Authorization": f"Bearer {good}"}).status_code == 200
        assert c.get("/dane", headers={"Authorization": f"Bearer {bad}"}).status_code == 401
        assert c.get("/dane", headers={"Authorization": "Bearer x"}).status_code == 401

    def test_401_ma_naglowki_cors_i_preflight_przechodzi(self, client):
        c = client("enforce")
        r = c.get("/dane", headers={"Origin": "https://bazapodreka.app"})
        assert r.status_code == 401
        assert r.headers.get("access-control-allow-origin") == "https://bazapodreka.app"
        pre = c.options(
            "/dane",
            headers={"Origin": "https://bazapodreka.app", "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "x-baza-key"},
        )
        assert pre.status_code == 200

    def test_report_nie_blokuje(self, client):
        c = client("report")
        assert c.get("/dane").status_code == 200

    def test_off_bez_konfiguracji(self, monkeypatch):
        monkeypatch.setattr(guard, "_settings", parse_settings(None, None))
        assert TestClient(_app()).get("/dane").status_code == 200
        guard._settings = None

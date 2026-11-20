"""Panel okręgowy: logowanie komputera kodem QR i pieczęć hasła (`app/panel_web_auth.py`, `app/panel_web_seal.py`)."""

import base64
import importlib
import sys
import types
from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from databases import Database
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app import panel_web_seal as S
from app.panel_web_tables import define_tables

SECRET = "sekret-testowy"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUB = KEY.public_key()
NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


def enc(text: str) -> str:
    """Jak JSEncrypt w aplikacji i na stronie."""
    return base64.b64encode(PUB.encrypt(text.encode("utf-8"), padding.PKCS1v15())).decode("ascii")


# ─── Pieczęć ────────────────────────────────────────────────────────────────


def test_pieczec_otwiera_tylko_ten_serwer_i_tylko_do_wygasniecia():
    sealed, expires = S.seal("Tajne-Haslo1", SECRET, now=NOW)
    assert sealed.startswith(S.SEAL_PREFIX) and b"Tajne" not in sealed
    assert expires == NOW + S.SEAL_TTL
    assert S.unseal(sealed, SECRET, now=NOW)["p"] == "Tajne-Haslo1"
    with pytest.raises(S.SealError) as other:
        S.unseal(sealed, "inny-sekret", now=NOW)
    assert other.value.reason == "invalid"
    with pytest.raises(S.SealError) as late:
        S.unseal(sealed, SECRET, now=expires + timedelta(seconds=1))
    assert late.value.reason == "expired"
    with pytest.raises(S.SealError):
        S.unseal(sealed[:-4] + b"AAAA", SECRET, now=NOW)


def test_klucz_otwiera_pieczec_a_zwykle_szyfrogramy_zostawia():
    key = S.SealAwareKey(KEY, lambda: SECRET)
    sealed, _ = S.seal("Haslo z ąę", SECRET)
    wrapped = S.rsa_wrap(PUB, sealed)
    # Trasy /zprp/* odszyfrowują dokładnie tak:
    assert key.decrypt(base64.b64decode(wrapped), padding.PKCS1v15()).decode("utf-8") == "Haslo z ąę"
    assert key.decrypt(base64.b64decode(enc("zwykle")), padding.PKCS1v15()) == b"zwykle"
    # Reszta klucza (podpis protokołu, klucz publiczny) bez zmian.
    assert key.public_key().public_numbers() == PUB.public_numbers()
    assert key.key_size == 2048


def test_za_dlugie_haslo_nie_miesci_sie_w_pieczeci():
    with pytest.raises(S.SealError):
        S.seal("x" * 300, SECRET)


# ─── Trasy ──────────────────────────────────────────────────────────────────


@pytest.fixture
def web(monkeypatch, tmp_path):
    metadata = sqlalchemy.MetaData()
    (table,) = define_tables(metadata)
    url = f"sqlite:///{tmp_path / 'panel.db'}"
    metadata.create_all(sqlalchemy.create_engine(url))
    fake_db = types.ModuleType("app.db")
    fake_db.database = Database(url)
    fake_db.panel_web_qr_logins = table
    monkeypatch.setitem(sys.modules, "app.db", fake_db)
    sys.modules.pop("app.panel_web_auth", None)
    A = importlib.import_module("app.panel_web_auth")
    monkeypatch.setattr(A, "_keys", lambda: (KEY, PUB))
    monkeypatch.setattr(A, "_secret", lambda: SECRET)
    for limiter in (A._QR_LIMITER, A._APPROVE_LIMITER, A._TOKEN_LIMITER):
        monkeypatch.setattr(limiter, "blocked", lambda *keys: False)

    tokens = {"app-anna": {"sub": "anna.nowak", "judge_id": "101"}, "app-form": {"sub": "anna.nowak", "scope": "form-web"},
              # Panel w przeglądarce telefonu, konto okręgu (komisja) - bez numeru sędziego.
              "web-okreg": {"sub": "ks_slzpr", "judge_id": "", "account_type": "org"}}

    async def fake_bearer(request, token):
        if token not in tokens:
            raise HTTPException(401, "zły token")
        return tokens[token]

    calls = []

    async def fake_panel_login(username, password):
        calls.append(("panel", username, password))
        if username == "ks_slzpr" and password == "Okreg-1":
            return {"success": True, "judge_id": None, "account_type": "org", "display_name": "Śląski ZPR",
                    "available_tabs": ["Terminarz", "Rozgrywki"], "vip": {"record": {"username": "ks_slzpr", "permissions_json": {"admin": True}}},
                    "tab_access": {"terminarz": True}}
        if password != "Haslo-ZPRP":
            return {"success": False, "error": "Niepoprawny użytkownik lub hasło"}
        return {"success": True, "judge_id": "101", "account_type": "judge", "display_name": "Anna NOWAK | Śląski ZPR",
                "available_tabs": ["Zawody"], "vip": None, "tab_access": {"terminarz": False}}

    async def fake_jwt_login(username, password):
        calls.append(("jwt", username, password))
        return {"access_token": "jwt-" + username, "expires_in": 3600, "judge_id": "101"}

    monkeypatch.setattr(A, "_decode_bearer", fake_bearer)
    monkeypatch.setattr(A, "_panel_login", fake_panel_login)
    monkeypatch.setattr(A, "_jwt_login", fake_jwt_login)

    async def fake_profile(username, password, judge_id):
        calls.append(("profile", username, password))
        return {"firstName": "Anna", "lastName": "NOWAK", "voivodeship": "ŚLĄSKIE"}

    monkeypatch.setattr(A, "_panel_profile", fake_profile)
    app = FastAPI()
    app.include_router(A.router)

    @app.on_event("startup")
    async def start():
        await fake_db.database.connect()

    @app.on_event("shutdown")
    async def stop():
        await fake_db.database.disconnect()

    with TestClient(app) as client:
        yield client, calls
    # Moduł zbudowany na atrapie bazy nie może zostać dla kolejnych testów.
    sys.modules.pop("app.panel_web_auth", None)


def _approve(client, code, token="app-anna", username="anna.nowak", password="Haslo-ZPRP"):
    return client.post(f"/panel-web/auth/qr/{code}/approve", json={"username": enc(username), "password": enc(password)},
                       headers={"authorization": f"Bearer {token}"} if token else {})


def test_kod_zatwierdzony_w_aplikacji_loguje_komputer_bez_hasla(web):
    client, calls = web
    qr = client.post("/panel-web/auth/qr", headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"}).json()
    code, poll = qr["code"], qr["poll_token"]
    assert qr["approve_url"] == f"https://www.bazapodreka.app/okreg/zaloguj/{code}"
    assert qr["app_url"] == f"refhandballapp://panel/login/{code}"
    assert client.get(f"/panel-web/auth/qr/{code}", params={"poll_token": poll, "wait": 0}).json() == {"status": "waiting"}
    assert client.get(f"/panel-web/auth/qr/{code}", params={"poll_token": "zly", "wait": 0}).status_code == 404

    ok = _approve(client, code)
    assert ok.status_code == 200, ok.text
    assert ok.json()["device_hint"] == "Chrome na Windows" and ok.json()["display_name"] == "Anna NOWAK"
    assert ("panel", "anna.nowak", "Haslo-ZPRP") in calls
    # Drugie zatwierdzenie tego samego kodu - odmowa.
    assert _approve(client, code).status_code == 409

    done = client.get(f"/panel-web/auth/qr/{code}", params={"poll_token": poll, "wait": 0}).json()
    assert done["status"] == "approved" and done["username"] == "anna.nowak"
    assert done["login"]["judge_id"] == "101" and done["login"]["success"] is True
    assert done["login"]["profile"]["lastName"] == "NOWAK"
    assert "Haslo-ZPRP" not in str(done)
    # W polu `password` leży szyfrogram pieczęci, nie hasło.
    assert S.is_sealed(KEY.decrypt(base64.b64decode(done["password"]), padding.PKCS1v15()))
    # Odbiór jest jednorazowy.
    assert client.get(f"/panel-web/auth/qr/{code}", params={"poll_token": poll, "wait": 0}).json() == {"status": "expired"}

    token = client.post("/panel-web/auth/token", json={"username": "anna.nowak", "password": done["password"]})
    assert token.status_code == 200 and token.json()["access_token"] == "jwt-anna.nowak"
    assert ("jwt", "anna.nowak", "Haslo-ZPRP") in calls
    # Trasa tokenu nie przyjmuje zwykłego hasła.
    assert client.post("/panel-web/auth/token", json={"username": "anna.nowak", "password": enc("Haslo-ZPRP")}).status_code == 400


def test_zatwierdza_tylko_konto_zalogowane_w_aplikacji(web):
    client, _ = web
    code = client.post("/panel-web/auth/qr").json()["code"]
    assert _approve(client, code, token=None).status_code == 401
    assert _approve(client, code, token="obcy").status_code == 401
    assert _approve(client, code, token="app-form").status_code == 403
    mismatch = _approve(client, code, username="ktos.inny")
    assert mismatch.status_code == 403 and mismatch.json()["detail"]["code"] == "ACCOUNT_MISMATCH"
    bad = _approve(client, code, password="zle")
    assert bad.status_code == 401 and bad.json()["detail"]["code"] == "BAD_CREDENTIALS"
    # Pieczęć nie zatwierdza kolejnego komputera (tylko prawdziwe dane z aplikacji).
    sealed, _ = S.seal("Haslo-ZPRP", SECRET)
    replay = client.post(f"/panel-web/auth/qr/{code}/approve", json={"username": enc("anna.nowak"), "password": S.rsa_wrap(PUB, sealed)},
                         headers={"authorization": "Bearer app-anna"})
    assert replay.status_code == 400
    assert _approve(client, "ZZZZZZZZ").status_code == 404


def test_wygasla_pieczec_nie_daje_tokenu(web, monkeypatch):
    client, _ = web
    old, _ = S.seal("Haslo-ZPRP", SECRET, now=datetime.now(timezone.utc) - S.SEAL_TTL - timedelta(minutes=1))
    res = client.post("/panel-web/auth/token", json={"username": "anna.nowak", "password": S.rsa_wrap(PUB, old)})
    assert res.status_code == 401 and res.json()["detail"]["code"] == "SESSION_EXPIRED"


def test_konto_okregu_z_panelu_na_telefonie_loguje_komputer(web):
    client, calls = web
    qr = client.post("/panel-web/auth/qr").json()
    ok = _approve(client, qr["code"], token="web-okreg", username="ks_slzpr", password="Okreg-1")
    assert ok.status_code == 200, ok.text
    done = client.get(f"/panel-web/auth/qr/{qr['code']}", params={"poll_token": qr["poll_token"], "wait": 0}).json()
    assert done["status"] == "approved" and done["username"] == "ks_slzpr"
    assert done["login"]["account_type"] == "org" and done["login"]["vip"]["record"]["permissions_json"]["admin"] is True
    # Konto okręgu nie ma profilu sędziego - serwer go nie pobiera.
    assert not any(c[0] == "profile" for c in calls)

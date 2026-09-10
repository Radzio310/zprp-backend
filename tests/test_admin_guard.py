"""Bramka zapisów panelu administratora: okres przejściowy i twarda odmowa.

`app.admin_guard` sięga do bazy i ustawień dopiero w środku funkcji, więc
test podmienia listę adminów i ustawienia JWT - bez Postgresa i bez kompletu
zmiennych Railway.
"""

from __future__ import annotations

import ast
import pathlib
import time
from types import SimpleNamespace

import pytest
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from jose import jwt

from app import admin_guard

SECRET = "test-secret"
ALG = "HS256"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    """Admin aplikacji to 999, zwykły sędzia to 7."""
    import app.deps

    monkeypatch.setattr(
        app.deps, "get_settings", lambda: SimpleNamespace(SECRET_KEY=SECRET, ALGORITHM=ALG)
    )

    async def admins():
        return {"999"}

    monkeypatch.setattr(admin_guard, "read_admin_ids", admins)
    monkeypatch.delenv(admin_guard.STRICT_ENV, raising=False)


def bearer(judge_id="999", *, exp_in=3600, secret=SECRET):
    claims = {"sub": "login", "judge_id": judge_id, "exp": int(time.time()) + exp_in}
    return "Bearer " + jwt.encode(claims, secret, algorithm=ALG)


async def check(method="PUT", path="/admin/json_files/kontakty", authorization=None):
    return await admin_guard.check_admin_write(
        method=method, path=path, authorization=authorization
    )


# ── rozstrzygnięcia ──────────────────────────────────────────────────────


async def test_admin_z_tokenem_przechodzi_i_jest_rozpoznany():
    assert await check(authorization=bearer("999")) == "999"


@pytest.mark.parametrize("strict", ["", "1"])
async def test_odczyty_zostaja_otwarte_w_obu_trybach(monkeypatch, caplog, strict):
    # Manifesty i pliki JSON aplikacja pobiera przed zalogowaniem i w tle.
    monkeypatch.setenv(admin_guard.STRICT_ENV, strict)
    with caplog.at_level("WARNING"):
        for path in ("/admin/json_files/manifest", "/admin/central_rates/versions"):
            assert await check("GET", path) is None
    assert not caplog.records


@pytest.mark.parametrize(
    "authorization, reason",
    [
        (None, admin_guard.REASON_NO_TOKEN),
        ("Bearer smieci", admin_guard.REASON_BAD_TOKEN),
        (bearer(secret="cudzy-sekret"), admin_guard.REASON_BAD_TOKEN),
        (bearer(exp_in=-10), admin_guard.REASON_EXPIRED),
        (bearer(""), admin_guard.REASON_NO_JUDGE),
        (bearer("7"), admin_guard.REASON_NOT_ADMIN),
    ],
)
async def test_okres_przejsciowy_przepuszcza_ale_zostawia_slad(caplog, authorization, reason):
    # Stare wersje w sklepie nie wysyłają nagłówka - nie wolno ich odciąć,
    # ale log musi powiedzieć, DLACZEGO zapis nie był dowiedziony.
    with caplog.at_level("WARNING"):
        assert await check(authorization=authorization) is None
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "[admin_guard]" in text
    assert f"powod={reason}" in text
    assert "tryb=przejsciowy" in text


@pytest.mark.parametrize(
    "authorization, status, fragment",
    [
        (None, 401, "Zaktualizuj"),
        ("Bearer smieci", 401, "zaloguj"),
        (bearer(exp_in=-10), 401, "Sesja wygasła"),
        (bearer("7"), 403, "administrator"),
    ],
)
async def test_po_zamknieciu_furtki_odmowa_z_powodem(monkeypatch, authorization, status, fragment):
    monkeypatch.setenv(admin_guard.STRICT_ENV, "1")
    with pytest.raises(HTTPException) as err:
        await check(authorization=authorization)
    assert err.value.status_code == status
    assert fragment in err.value.detail


async def test_po_zamknieciu_furtki_admin_dalej_zapisuje(monkeypatch):
    monkeypatch.setenv(admin_guard.STRICT_ENV, "1")
    assert await check("DELETE", "/admin/central_rates/versions/3", bearer("999")) == "999"


@pytest.mark.parametrize(
    "path", ["/admin/validate_pin", "/admin/reports", "/admin/halls/reports", "/admin/reports/"]
)
async def test_zapisy_zwyklego_uzytkownika_zostaja_otwarte(monkeypatch, path):
    # Zgłoszenie błędu czy nowej hali nie może wymagać uprawnień admina.
    monkeypatch.setenv(admin_guard.STRICT_ENV, "1")
    assert await check("POST", path) is None


async def test_otwarty_jest_tylko_konkretny_zapis_nie_cala_sciezka(monkeypatch):
    # POST /admin/reports jest otwarty, ale kasowanie zgłoszeń już nie.
    monkeypatch.setenv(admin_guard.STRICT_ENV, "1")
    with pytest.raises(HTTPException):
        await check("DELETE", "/admin/reports/5")
    with pytest.raises(HTTPException):
        await check("PUT", "/admin/reports/5/read")


async def test_awaria_listy_adminow_w_trybie_twardym_to_odmowa(monkeypatch):
    async def broken():
        raise RuntimeError("baza lezy")

    monkeypatch.setattr(admin_guard, "read_admin_ids", broken)
    monkeypatch.setenv(admin_guard.STRICT_ENV, "1")
    with pytest.raises(HTTPException) as err:
        await check(authorization=bearer("999"))
    assert err.value.status_code == 403


# ── zależność na routerze + koperta błędu ────────────────────────────────


def _app() -> FastAPI:
    app = FastAPI()

    @app.exception_handler(HTTPException)
    async def envelope(request: Request, exc: HTTPException):  # jak w main.py
        return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})

    router = APIRouter(prefix="/admin", dependencies=[Depends(admin_guard.admin_write_guard)])

    @router.get("/json_files/manifest")
    async def manifest():
        return {"files": []}

    @router.put("/json_files/{key}")
    async def save(key: str):
        return {"saved": key}

    app.include_router(router)
    return app


def test_router_twardy_odbija_zapis_w_kopercie_error(monkeypatch):
    monkeypatch.setenv(admin_guard.STRICT_ENV, "1")
    client = TestClient(_app())

    assert client.get("/admin/json_files/manifest").status_code == 200

    res = client.put("/admin/json_files/kontakty")
    assert res.status_code == 401
    body = res.json()
    # Zasada projektu: błąd wraca jako {"error": ...}, nie {"detail": ...}.
    assert "error" in body and "detail" not in body

    ok = client.put("/admin/json_files/kontakty", headers={"Authorization": bearer("999")})
    assert ok.status_code == 200 and ok.json() == {"saved": "kontakty"}


def test_router_przejsciowy_nie_zmienia_zachowania_starych_aplikacji():
    client = TestClient(_app())
    assert client.put("/admin/json_files/kontakty").json() == {"saved": "kontakty"}


# ── okablowanie - czytane ze źródła, bo `app.admin` żąda żywej bazy ──────

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"


def _router_dependencies(filename: str) -> str:
    tree = ast.parse((APP_DIR / filename).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "router" for t in node.targets)
            and isinstance(node.value, ast.Call)
        ):
            for kw in node.value.keywords:
                if kw.arg == "dependencies":
                    return ast.unparse(kw.value)
    return ""


@pytest.mark.parametrize("filename", ["admin.py", "central_rates.py"])
def test_bramka_wisi_na_calym_routerze(filename):
    # Na routerze, nie na pojedynczych trasach: nowa trasa zapisu jest
    # chroniona bez pamiętania o tym.
    assert "admin_write_guard" in _router_dependencies(filename)


def test_otwarte_zapisy_istnieja_w_admin_py():
    # Wpis w PUBLIC_WRITES bez trasy to martwa furtka - albo literówka, przez
    # którą prawdziwa trasa użytkownika dostanie 401 po zamknięciu furtki.
    source = (APP_DIR / "admin.py").read_text(encoding="utf-8")
    for method, path in admin_guard.PUBLIC_WRITES:
        route = path.removeprefix("/admin")
        assert f'@router.{method.lower()}("{route}"' in source, (method, path)

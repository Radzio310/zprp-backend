"""Bramka zapisów pod `/admin`: poziomy, okres przejściowy i twarda odmowa.

`app.admin_guard` sięga do bazy i ustawień dopiero w środku funkcji, więc
test podmienia listy uprawnień i ustawienia JWT - bez Postgresa i bez
kompletu zmiennych Railway.
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
    """Admin aplikacji to 999, Match Master Śląska to 7, zwykły sędzia to 8."""
    import app.deps

    monkeypatch.setattr(
        app.deps, "get_settings", lambda: SimpleNamespace(SECRET_KEY=SECRET, ALGORITHM=ALG)
    )

    async def admins():
        return {"999"}

    calls = []

    async def province_lists(kind, province):
        calls.append((kind, province))
        masters = {"SLASKIE": ["7"]}.get(admin_guard_norm(province), [])
        return masters, ["999"]

    monkeypatch.setattr(admin_guard, "read_admin_ids", admins)
    monkeypatch.setattr(admin_guard, "read_province_lists", province_lists)
    monkeypatch.delenv(admin_guard.STRICT_ENV, raising=False)
    return calls


def admin_guard_norm(province):
    from app.province_access import normalize_province

    return normalize_province(province)


def bearer(judge_id="999", *, exp_in=3600, secret=SECRET, account_type="judge"):
    claims = {
        "sub": "login",
        "judge_id": judge_id,
        "account_type": account_type,
        "exp": int(time.time()) + exp_in,
    }
    return "Bearer " + jwt.encode(claims, secret, algorithm=ALG)


async def check(method="PUT", path="/admin/json_files/kontakty", authorization=None, province=None):
    return await admin_guard.check_admin_write(
        method=method, path=path, authorization=authorization, province=province
    )


@pytest.fixture
def strict(monkeypatch):
    monkeypatch.setenv(admin_guard.STRICT_ENV, "1")


# ── poziomy ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "method, path, tier",
    [
        ("GET", "/admin/json_files/manifest", admin_guard.TIER_READ),
        ("GET", "/admin/central_rates/versions", admin_guard.TIER_READ),
        ("POST", "/admin/validate_pin", admin_guard.TIER_PUBLIC),
        ("POST", "/admin/halls/reports/", admin_guard.TIER_PUBLIC),
        ("POST", "/admin/contacts/judges/upsert", admin_guard.TIER_USER),
        ("POST", "/admin/okreg_rates/ŚLĄSKIE/versions", admin_guard.TIER_PROVINCE),
        ("PUT", "/admin/okreg_distances/ŚLĄSKIE", admin_guard.TIER_PROVINCE),
        ("PUT", "/admin/json_files/przepisy", admin_guard.TIER_ADMIN),
        ("DELETE", "/admin/central_rates/versions/3", admin_guard.TIER_ADMIN),
        ("PUT", "/admin/admins", admin_guard.TIER_ADMIN),
        ("PUT", "/admin/update_pin", admin_guard.TIER_ADMIN),
        # otwarty jest konkretny zapis, nie cała ścieżka
        ("DELETE", "/admin/reports/5", admin_guard.TIER_ADMIN),
        ("DELETE", "/admin/halls/reports/5", admin_guard.TIER_ADMIN),
        ("PUT", "/admin/okreg/active/SLASKIE", admin_guard.TIER_ADMIN),
    ],
)
def test_klasyfikacja(method, path, tier):
    assert admin_guard.classify(method, path)[0] == tier


# ── rozstrzygnięcia ──────────────────────────────────────────────────────


async def test_admin_z_tokenem_przechodzi_i_jest_rozpoznany():
    assert await check(authorization=bearer("999")) == "999"


@pytest.mark.parametrize("strict_value", ["", "1"])
async def test_odczyty_zostaja_otwarte_w_obu_trybach(monkeypatch, caplog, strict_value):
    # Manifesty i pliki JSON aplikacja pobiera przed zalogowaniem i w tle.
    monkeypatch.setenv(admin_guard.STRICT_ENV, strict_value)
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
        (bearer("", account_type="org"), admin_guard.REASON_ORG),
        (bearer("8"), admin_guard.REASON_NOT_ADMIN),
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
        (bearer("8"), 403, "administrator"),
    ],
)
async def test_po_zamknieciu_furtki_odmowa_z_powodem(strict, authorization, status, fragment):
    with pytest.raises(HTTPException) as err:
        await check(authorization=authorization)
    assert err.value.status_code == status
    assert fragment in err.value.detail


async def test_po_zamknieciu_furtki_admin_dalej_zapisuje(strict):
    assert await check("DELETE", "/admin/central_rates/versions/3", bearer("999")) == "999"


@pytest.mark.parametrize("path", ["/admin/validate_pin", "/admin/reports", "/admin/halls/reports"])
async def test_zapisy_publiczne_zostaja_otwarte(strict, path):
    # Zgłoszenie błędu czy nowej hali nie może wymagać nawet zalogowania.
    assert await check("POST", path) is None


async def test_kontakty_przy_logowaniu_pisze_kazdy_zalogowany(strict):
    # Aplikacja aktualizuje kontakty przy KAŻDYM logowaniu - zwykły sędzia
    # i konto organizacji muszą przejść, anonim już nie.
    path = "/admin/contacts/judges/upsert"
    assert await check("POST", path, bearer("8")) == "8"
    assert await check("POST", "/admin/contacts/clubs/upsert", bearer("", account_type="org")) is None
    with pytest.raises(HTTPException) as err:
        await check("POST", path)
    assert err.value.status_code == 401


async def test_stawki_okregu_zapisuje_master_tego_okregu(strict, env):
    path = "/admin/okreg_rates/ŚLĄSKIE/versions"
    assert await check("POST", path, bearer("7"), province="ŚLĄSKIE") == "7"
    assert env == [("match", "ŚLĄSKIE")]


async def test_master_nie_zapisuje_w_cudzym_okregu(strict):
    with pytest.raises(HTTPException) as err:
        await check("PUT", "/admin/okreg_distances/MAZOWIECKIE", bearer("7"), province="MAZOWIECKIE")
    assert err.value.status_code == 403
    assert "Match Master" in err.value.detail
    assert "MAZOWIECKIE" in err.value.detail


async def test_admin_zapisuje_stawki_kazdego_okregu(strict):
    path = "/admin/okreg_rates/MAZOWIECKIE/versions/4"
    assert await check("PUT", path, bearer("999"), province="MAZOWIECKIE") == "999"


async def test_awaria_list_w_trybie_twardym_to_odmowa(monkeypatch, strict):
    async def broken():
        raise RuntimeError("baza lezy")

    monkeypatch.setattr(admin_guard, "read_admin_ids", broken)
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

    @router.put("/okreg_distances/{province}")
    async def distances(province: str):
        return {"saved": province}

    app.include_router(router)
    return app


def test_router_twardy_odbija_zapis_w_kopercie_error(strict):
    client = TestClient(_app())

    assert client.get("/admin/json_files/manifest").status_code == 200

    res = client.put("/admin/json_files/kontakty")
    assert res.status_code == 401
    body = res.json()
    # Zasada projektu: błąd wraca jako {"error": ...}, nie {"detail": ...}.
    assert "error" in body and "detail" not in body

    ok = client.put("/admin/json_files/kontakty", headers={"Authorization": bearer("999")})
    assert ok.status_code == 200 and ok.json() == {"saved": "kontakty"}


def test_router_bierze_okreg_z_adresu(strict):
    # Polskie znaki w adresie przychodzą zakodowane - bramka ma dostać
    # województwo już zdekodowane, z parametru trasy.
    client = TestClient(_app())
    ok = client.put("/admin/okreg_distances/%C5%9AL%C4%84SKIE", headers={"Authorization": bearer("7")})
    assert ok.status_code == 200
    denied = client.put("/admin/okreg_distances/MAZOWIECKIE", headers={"Authorization": bearer("7")})
    assert denied.status_code == 403


def test_router_przejsciowy_nie_zmienia_zachowania_starych_aplikacji():
    client = TestClient(_app())
    assert client.put("/admin/json_files/kontakty").json() == {"saved": "kontakty"}


def test_awaria_bramki_w_okresie_przejsciowym_nie_psuje_zapisu(monkeypatch):
    # Priorytet wdrożenia: nic, co działało, nie może przestać działać. Nawet
    # wyjątek z wnętrza bramki ma zostawić ślad w logu, a nie 500.
    async def boom(**kwargs):
        raise RuntimeError("bramka pekla")

    monkeypatch.setattr(admin_guard, "check_admin_write", boom)
    client = TestClient(_app())
    res = client.put("/admin/json_files/kontakty", headers={"Authorization": bearer("999")})
    assert res.status_code == 200 and res.json() == {"saved": "kontakty"}


# ── okablowanie - czytane ze źródła, bo `app.admin` żąda żywej bazy ──────

APP_DIR = pathlib.Path(__file__).resolve().parents[1] / "app"
ADMIN_SOURCE = (APP_DIR / "admin.py").read_text(encoding="utf-8")


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


@pytest.mark.parametrize("method, path", sorted(admin_guard.PUBLIC_WRITES | admin_guard.USER_WRITES))
def test_luzniejsze_zapisy_istnieja_w_admin_py(method, path):
    # Wpis bez trasy to martwa furtka - albo literówka, przez którą prawdziwa
    # trasa użytkownika dostanie 401 po zamknięciu furtki.
    route = path.removeprefix("/admin")
    assert f'@router.{method.lower()}(\n    "{route}"' in ADMIN_SOURCE or (
        f'@router.{method.lower()}("{route}"' in ADMIN_SOURCE
    ), (method, path)


@pytest.mark.parametrize("prefix", sorted(admin_guard.PROVINCE_WRITE_PREFIXES))
def test_trasy_okregowe_maja_parametr_province(prefix):
    # Bramka czyta okręg z `path_params["province"]` - inna nazwa parametru
    # oznaczałaby pytanie o okręg `None`, czyli odmowę każdemu Masterowi.
    route = prefix.removeprefix("/admin")
    assert f'"{route}{{province}}' in ADMIN_SOURCE

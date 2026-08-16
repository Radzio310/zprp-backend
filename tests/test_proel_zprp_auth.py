"""
Proxy autoryzacji ProEl → baza.zprp.pl/api/proel/v1/.

Sedno tych testów: `app_key` zna wyłącznie serwer, a mapowanie błędów musi
odróżniać trzy zupełnie różne sytuacje, które upstream zgłasza podobnie:
  • złe dane UŻYTKOWNIKA (401 INVALID_CREDENTIALS) — jego problem,
  • zły app_key (403 INVALID_APP_IDENTIFIER) — NASZ problem konfiguracyjny,
  • upstream leży (timeout/sieć) — problem chwilowy.
Pomylenie ich oznacza, że użytkownik widzi „zły token" przy awarii serwera —
i przestaje ufać tokenowi, który ma na kartce.

Sieć jest zastąpiona monkeypatchem `_post_upstream` (jedyny punkt sieciowy),
limiter DB — no-opem; limiter ma osobne testy z prawdziwym Postgresem.
"""
from __future__ import annotations

import httpx
import pytest
from fastapi import HTTPException

import app.proel_zprp as z
from app.proel_zprp import ZprpAuthRequest, authorize, close_session

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _env_and_quiet_limiter(monkeypatch):
    monkeypatch.setenv("PROEL_APP_KEY", "test-app-key")

    async def _noop(*_a, **_kw):
        return None

    monkeypatch.setattr(z.rate_limit, "enforce", _noop)
    monkeypatch.setattr(z.rate_limit, "record", _noop)


def _upstream(status: int, data: dict):
    async def fake(endpoint: str, payload: dict):
        fake.calls.append((endpoint, payload))
        return status, data

    fake.calls = []
    return fake


SUCCESS = {
    "status": "success",
    "message": "Autoryzacja udana.",
    "hash_sesji": "b5c68b72e12176ee64f7bfa6d9124a9a",
    "mecz_info": {"IdZawody": 12345},
}


# ─────────────────────── wariant A: token meczu ───────────────────────

async def test_token_variant_builds_upstream_payload(monkeypatch):
    fake = _upstream(200, SUCCESS)
    monkeypatch.setattr(z, "_post_upstream", fake)

    out = await authorize(ZprpAuthRequest(token="x8r2k"), "1.2.3.4")

    assert out["hash_sesji"] == SUCCESS["hash_sesji"]
    assert out["id_zawody"] == 12345
    endpoint, payload = fake.calls[0]
    assert endpoint == "auth.php"
    # Token jest normalizowany do wersalików, id_zawody=0, nr_sedzia pusty —
    # dokładnie kształt z dokumentacji v1.8.
    assert payload == {
        "app_key": "test-app-key",
        "token_proel": "X8R2K",
        "id_zawody": 0,
        "nr_sedzia": "",
    }


async def test_judge_variant_builds_upstream_payload(monkeypatch):
    fake = _upstream(200, SUCCESS)
    monkeypatch.setattr(z, "_post_upstream", fake)

    out = await authorize(
        ZprpAuthRequest(id_zawody=12345, nr_sedzia=" 5102138 "), "1.2.3.4"
    )

    assert out["status"] == "success"
    _, payload = fake.calls[0]
    assert payload == {
        "app_key": "test-app-key",
        "token_proel": "",
        "id_zawody": 12345,
        "nr_sedzia": "5102138",
    }


async def test_missing_id_zawody_in_response_falls_back_to_request(monkeypatch):
    """Wariant B zna IdZawody z góry — brak `mecz_info` nie może go zgubić."""
    monkeypatch.setattr(z, "_post_upstream", _upstream(200, {**SUCCESS, "mecz_info": {}}))
    out = await authorize(ZprpAuthRequest(id_zawody=777, nr_sedzia="1"), "ip")
    assert out["id_zawody"] == 777


# ─────────────────────── walidacja wejścia ───────────────────────

async def test_empty_request_is_400_without_touching_upstream(monkeypatch):
    fake = _upstream(200, SUCCESS)
    monkeypatch.setattr(z, "_post_upstream", fake)
    with pytest.raises(HTTPException) as e:
        await authorize(ZprpAuthRequest(), "ip")
    assert e.value.status_code == 400
    assert fake.calls == []


async def test_malformed_token_is_rejected_locally(monkeypatch):
    """Literówka nie może kosztować wywołania upstreamu ani wpisu limitera."""
    fake = _upstream(200, SUCCESS)
    monkeypatch.setattr(z, "_post_upstream", fake)
    for bad in ("X8R2", "X8R2KK", "X8R!K", "ĄĆĘŁŃ"):
        with pytest.raises(HTTPException) as e:
            await authorize(ZprpAuthRequest(token=bad), "ip")
        assert e.value.status_code == 400
        assert e.value.detail["code"] == "BAD_TOKEN"
    assert fake.calls == []


# ─────────────────────── mapowanie błędów upstreamu ───────────────────────

async def test_upstream_401_maps_to_invalid_credentials(monkeypatch):
    monkeypatch.setattr(z, "_post_upstream", _upstream(401, {"error": "INVALID_CREDENTIALS"}))
    with pytest.raises(HTTPException) as e:
        await authorize(ZprpAuthRequest(token="X8R2K"), "ip")
    assert e.value.status_code == 401
    assert e.value.detail["code"] == "INVALID_CREDENTIALS"


async def test_upstream_403_is_our_config_problem_not_users(monkeypatch):
    """INVALID_APP_IDENTIFIER = zły app_key. Użytkownik dostaje 502 PROEL_CONFIG,
    a nie 403 — bo z jego tokenem może być wszystko w porządku."""
    monkeypatch.setattr(z, "_post_upstream", _upstream(403, {"error": "INVALID_APP_IDENTIFIER"}))
    with pytest.raises(HTTPException) as e:
        await authorize(ZprpAuthRequest(token="X8R2K"), "ip")
    assert e.value.status_code == 502
    assert e.value.detail["code"] == "PROEL_CONFIG"


async def test_upstream_timeout_maps_to_504(monkeypatch):
    async def boom(endpoint, payload):
        raise httpx.ReadTimeout("slow")

    monkeypatch.setattr(z, "_post_upstream", boom)
    with pytest.raises(HTTPException) as e:
        await authorize(ZprpAuthRequest(token="X8R2K"), "ip")
    assert e.value.status_code == 504
    assert e.value.detail["code"] == "UPSTREAM_TIMEOUT"


async def test_upstream_network_error_maps_to_502(monkeypatch):
    async def boom(endpoint, payload):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(z, "_post_upstream", boom)
    with pytest.raises(HTTPException) as e:
        await authorize(ZprpAuthRequest(token="X8R2K"), "ip")
    assert e.value.status_code == 502
    assert e.value.detail["code"] == "UPSTREAM_ERROR"


async def test_missing_app_key_is_503(monkeypatch):
    monkeypatch.delenv("PROEL_APP_KEY", raising=False)
    with pytest.raises(HTTPException) as e:
        await authorize(ZprpAuthRequest(token="X8R2K"), "ip")
    assert e.value.status_code == 503
    assert e.value.detail["code"] == "PROEL_CONFIG"


async def test_200_without_success_status_is_upstream_error(monkeypatch):
    """200 z body błędu (API bywa kreatywne) nie może udawać sukcesu."""
    monkeypatch.setattr(z, "_post_upstream", _upstream(200, {"status": "error"}))
    with pytest.raises(HTTPException) as e:
        await authorize(ZprpAuthRequest(token="X8R2K"), "ip")
    assert e.value.status_code == 502


# ─────────────────────── limiter jest wołany ───────────────────────

async def test_rate_limit_blocks_before_upstream(monkeypatch):
    fake = _upstream(200, SUCCESS)
    monkeypatch.setattr(z, "_post_upstream", fake)

    async def deny(scope, ref, limit, window):
        raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "retry_after_s": 30})

    monkeypatch.setattr(z.rate_limit, "enforce", deny)
    with pytest.raises(HTTPException) as e:
        await authorize(ZprpAuthRequest(token="X8R2K"), "ip")
    assert e.value.status_code == 429
    assert fake.calls == []  # upstream nietknięty


async def test_attempt_is_recorded_even_on_upstream_failure(monkeypatch):
    """Brute force liczy się PRÓBAMI — nieudana autoryzacja też idzie do licznika."""
    recorded: list = []

    async def rec(scope, ref):
        recorded.append(scope)

    monkeypatch.setattr(z.rate_limit, "record", rec)
    monkeypatch.setattr(z, "_post_upstream", _upstream(401, {}))
    with pytest.raises(HTTPException):
        await authorize(ZprpAuthRequest(token="X8R2K"), "ip")
    assert "proel_auth_token_ip" in recorded


# ─────────────────────── logout ───────────────────────

async def test_logout_success(monkeypatch):
    monkeypatch.setattr(z, "_post_upstream", _upstream(200, {"status": "success"}))
    out = await close_session("abc123")
    assert out == {"status": "success", "already_expired": False}


async def test_logout_expired_session_is_still_success(monkeypatch):
    """404 = sesja już nie żyje — dokładnie to chcieliśmy osiągnąć."""
    monkeypatch.setattr(z, "_post_upstream", _upstream(404, {}))
    out = await close_session("abc123")
    assert out == {"status": "success", "already_expired": True}


async def test_logout_empty_hash_is_400(monkeypatch):
    with pytest.raises(HTTPException) as e:
        await close_session("   ")
    assert e.value.status_code == 400

"""Proxy statystyk zawodnika: /proel/zprp/player-stats → player_stats.php.

Sedno tych testów to trzy rozróżnienia, których pomylenie kosztuje protokół:

  • „nie ma takiego zawodnika w kadrze" (404) to NIE jest awaria. Wysyłamy
    kilkunastu zawodników po kolei i jeden nierozpoznany nie może przerwać
    całości ani udawać błędu sieci - aplikacja ma go pominąć i powiedzieć,
    kogo nie zapisała.
  • wygasła sesja (401) MUSI dojść do aplikacji z własnym kodem, bo tylko ona
    umie się przelogować z zapamiętanego materiału i ponowić.
  • zamknięty protokół (403 PROTOCOL_LOCKED) to stan meczu, nie błąd sędziego.

Do tego biała lista pól: literówka w nazwie klucza jest po stronie ZPRP
ignorowana po cichu, więc sędzia zobaczyłby „zapisano" przy niezapisanej karze.

Sieć zastąpiona monkeypatchem `_post_upstream` - jedynego punktu sieciowego.
"""
from __future__ import annotations

import httpx
import pytest
from fastapi import HTTPException

import app.proel_zprp as z
from app.proel_zprp import ZprpPlayerStatsRequest, submit_player_stats

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _app_key(monkeypatch):
    monkeypatch.setenv("PROEL_APP_KEY", "test-app-key")


def _upstream(status: int, data: dict):
    async def fake(endpoint: str, payload: dict):
        fake.calls.append((endpoint, payload))
        return status, data

    fake.calls = []
    return fake


def _req(**over):
    base = dict(
        hash_sesji="abc123",
        id_zawody=208136,
        id_zespol=17889,
        id_zawodnik=48990,
        fields={"bramki": "5", "wyjscie": "1"},
    )
    base.update(over)
    return ZprpPlayerStatsRequest(**base)


async def test_sukces_przekazuje_trojke_adresujaca(monkeypatch):
    fake = _upstream(200, {"status": "success", "message": "Statystyki zawodnika zostaly zaktualizowane."})
    monkeypatch.setattr(z, "_post_upstream", fake)

    out = await submit_player_stats(_req())

    assert out["status"] == "success"
    endpoint, payload = fake.calls[0]
    assert endpoint == "player_stats.php"
    # Zawodnika wskazuje TRÓJKA, nie numer koszulki.
    assert payload["id_zawody"] == 208136
    assert payload["id_zespol"] == 17889
    assert payload["id_zawodnik"] == 48990
    assert payload["hash_sesji"] == "abc123"


async def test_wysylamy_tylko_przyslane_pola(monkeypatch):
    """Aktualizacja częściowa: czego nie ma w żądaniu, to zostaje nietknięte."""
    fake = _upstream(200, {"status": "success"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    await submit_player_stats(_req(fields={"2minuty": "2"}))

    _, payload = fake.calls[0]
    assert payload["2minuty"] == "2"
    assert "bramki" not in payload
    assert "dyskwalifikacja" not in payload


async def test_numer_koszulki_jest_polem_a_nie_adresem(monkeypatch):
    fake = _upstream(200, {"status": "success"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    await submit_player_stats(_req(fields={"NrKoszulki2": "13"}))

    _, payload = fake.calls[0]
    assert payload["NrKoszulki2"] == "13"


async def test_nieznane_pole_odrzucone_przed_wyslaniem(monkeypatch):
    fake = _upstream(200, {"status": "success"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as err:
        await submit_player_stats(_req(fields={"bramki": "3", "czerwona": "1"}))

    assert err.value.status_code == 400
    assert err.value.detail["code"] == "BAD_FIELDS"
    assert "czerwona" in err.value.detail["message"]
    assert fake.calls == []  # nic nie poleciało


async def test_pusty_zestaw_pol_odrzucony(monkeypatch):
    fake = _upstream(200, {"status": "success"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as err:
        await submit_player_stats(_req(fields={}))

    assert err.value.status_code == 400
    assert fake.calls == []


async def test_brak_zawodnika_w_kadrze_ma_wlasny_kod(monkeypatch):
    monkeypatch.setattr(
        z,
        "_post_upstream",
        _upstream(404, {"status": "error", "message": "Nie znaleziono takiego zawodnika."}),
    )

    with pytest.raises(HTTPException) as err:
        await submit_player_stats(_req())

    assert err.value.status_code == 404
    assert err.value.detail["code"] == "PLAYER_NOT_IN_SQUAD"


async def test_wygasla_sesja_zachowuje_kod(monkeypatch):
    monkeypatch.setattr(
        z,
        "_post_upstream",
        _upstream(401, {"status": "error", "code": "SESSION_EXPIRED", "message": "Sesja wygasla."}),
    )

    with pytest.raises(HTTPException) as err:
        await submit_player_stats(_req())

    assert err.value.status_code == 401
    assert err.value.detail["code"] == "SESSION_EXPIRED"


async def test_zatwierdzony_protokol_to_konflikt(monkeypatch):
    monkeypatch.setattr(
        z,
        "_post_upstream",
        _upstream(403, {"status": "error", "code": "PROTOCOL_LOCKED"}),
    )

    with pytest.raises(HTTPException) as err:
        await submit_player_stats(_req())

    assert err.value.status_code == 409
    assert err.value.detail["code"] == "PROTOCOL_LOCKED"


async def test_zly_app_key_to_nasz_problem(monkeypatch):
    monkeypatch.setattr(
        z,
        "_post_upstream",
        _upstream(403, {"status": "error", "code": "INVALID_APP_IDENTIFIER"}),
    )

    with pytest.raises(HTTPException) as err:
        await submit_player_stats(_req())

    assert err.value.status_code == 502
    assert err.value.detail["code"] == "PROEL_CONFIG"


async def test_brak_app_key_to_503(monkeypatch):
    monkeypatch.delenv("PROEL_APP_KEY", raising=False)
    fake = _upstream(200, {"status": "success"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as err:
        await submit_player_stats(_req())

    assert err.value.status_code == 503
    assert fake.calls == []


async def test_timeout_upstreamu(monkeypatch):
    async def boom(endpoint: str, payload: dict):
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(z, "_post_upstream", boom)

    with pytest.raises(HTTPException) as err:
        await submit_player_stats(_req())

    assert err.value.status_code == 504
    assert err.value.detail["code"] == "UPSTREAM_TIMEOUT"

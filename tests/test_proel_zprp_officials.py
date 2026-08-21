"""Proxy kar osób towarzyszących: /proel/zprp/officials-stats → officials_stats.php.

Ten endpoint ma semantykę INNĄ niż wynik skrócony i statystyki zawodnika, i to
jest sedno tych testów. Tam pominięty klucz znaczy „nie ruszaj", a "" znaczy
„wyczyść". Tutaj każde pole jest binarne: 1 dopisuje karę, 0 ją KASUJE z
centralnego systemu. Nie ma stanu „nie wiem", bo API nie pozwala odczytać
obecnych kar osoby towarzyszącej - w danych meczu są tylko nazwisko, rola,
licencja i funkcja.

Konsekwencja, którą trzeba mieć na oku przy każdej zmianie tego kodu:
wysłanie zera naprawdę usuwa wpis, także taki, którego nie my dodaliśmy.

Poza tym te same trzy rozróżnienia co przy zawodniku:
  • 404 („nie ma takiej osoby w składzie") to NIE jest awaria - jedna pozycja
    odpada, reszta osób ma się zapisać,
  • 401 musi dojść do aplikacji z własnym kodem, bo tylko ona umie odnowić sesję,
  • 403 PROTOCOL_LOCKED to stan meczu, nie błąd sędziego.

Sieć zastąpiona monkeypatchem `_post_upstream` - jedynego punktu sieciowego.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

import app.proel_zprp as z
from app.proel_zprp import ZprpOfficialsStatsRequest, submit_officials_stats

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
        id_zespol=17890,
        id_osoba=196,
        fields={"upomnienie_U": "1", "wykluczenie_2min": "0", "dyskwalifikacja_D": "0"},
    )
    base.update(over)
    return ZprpOfficialsStatsRequest(**base)


async def test_sukces_przekazuje_trojke_adresujaca(monkeypatch):
    fake = _upstream(200, {"status": "success", "message": "Kary osoby towarzyszacej zsynchronizowane."})
    monkeypatch.setattr(z, "_post_upstream", fake)

    out = await submit_officials_stats(_req())

    assert out["status"] == "success"
    endpoint, payload = fake.calls[0]
    assert endpoint == "officials_stats.php"
    # Osobę wskazuje TRÓJKA (mecz, drużyna, osoba) - litera A-E służy tylko
    # aplikacji do dopasowania i nie ma prawa pojawić się w żądaniu.
    assert payload["id_zawody"] == 208136
    assert payload["id_zespol"] == 17890
    assert payload["id_osoba"] == 196
    assert payload["hash_sesji"] == "abc123"


async def test_zero_dociera_jako_zero(monkeypatch):
    """Zero to polecenie „skasuj tę karę", a nie brak danych do pominięcia."""
    fake = _upstream(200, {"status": "success"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    await submit_officials_stats(
        _req(fields={"upomnienie_U": "0", "dyskwalifikacja_D": "0"})
    )

    _, payload = fake.calls[0]
    assert payload["upomnienie_U"] == "0"
    assert payload["dyskwalifikacja_D"] == "0"


async def test_brak_osoby_w_skladzie_ma_wlasny_kod(monkeypatch):
    """404 nie może udawać awarii - reszta osób ma się zapisać."""
    fake = _upstream(
        404,
        {"status": "error", "message": "Ta osoba towarzyszaca nie jest wpisana do skladu."},
    )
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_officials_stats(_req())

    assert ei.value.status_code == 404
    assert ei.value.detail["code"] == "OFFICIAL_NOT_IN_SQUAD"


async def test_druzyna_spoza_meczu_tez_jest_pominieciem(monkeypatch):
    """Upstream ma dwa różne 404; dla aplikacji znaczą to samo."""
    fake = _upstream(
        404,
        {"status": "error", "message": "Podana druzyna nie bierze udzialu w tym meczu."},
    )
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_officials_stats(_req())

    assert ei.value.status_code == 404
    assert ei.value.detail["code"] == "OFFICIAL_NOT_IN_SQUAD"


async def test_wygasla_sesja_zachowuje_kod(monkeypatch):
    fake = _upstream(401, {"status": "error", "code": "SESSION_EXPIRED"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_officials_stats(_req())

    assert ei.value.status_code == 401
    assert ei.value.detail["code"] == "SESSION_EXPIRED"


async def test_zamkniety_protokol_to_konflikt(monkeypatch):
    fake = _upstream(403, {"status": "error", "code": "PROTOCOL_LOCKED"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_officials_stats(_req())

    assert ei.value.status_code == 409
    assert ei.value.detail["code"] == "PROTOCOL_LOCKED"


async def test_403_z_innym_kodem_to_nasza_konfiguracja(monkeypatch):
    fake = _upstream(403, {"status": "error", "code": "INVALID_APP_IDENTIFIER"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_officials_stats(_req())

    assert ei.value.status_code == 502
    assert ei.value.detail["code"] == "PROEL_CONFIG"


async def test_nieznane_pole_odrzucone_przed_siecia(monkeypatch):
    """Literówkę upstream zignorowałby po cichu - sędzia zobaczyłby „zapisano"."""
    fake = _upstream(200, {"status": "success"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_officials_stats(_req(fields={"upomnienie": "1"}))

    assert ei.value.status_code == 400
    assert ei.value.detail["code"] == "BAD_FIELDS"
    assert fake.calls == []


async def test_pusty_zestaw_pol_odrzucony(monkeypatch):
    fake = _upstream(200, {"status": "success"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_officials_stats(_req(fields={}))

    assert ei.value.status_code == 400
    assert ei.value.detail["code"] == "BAD_REQUEST"
    assert fake.calls == []


async def test_brak_hash_sesji_odrzucony(monkeypatch):
    fake = _upstream(200, {"status": "success"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_officials_stats(_req(hash_sesji="   "))

    assert ei.value.status_code == 400
    assert fake.calls == []


async def test_brak_klucza_aplikacji_to_503(monkeypatch):
    monkeypatch.delenv("PROEL_APP_KEY", raising=False)
    fake = _upstream(200, {"status": "success"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_officials_stats(_req())

    assert ei.value.status_code == 503
    assert ei.value.detail["code"] == "PROEL_CONFIG"
    assert fake.calls == []

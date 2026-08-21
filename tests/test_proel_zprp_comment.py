"""Proxy uwag sędziów (verte): /proel/zprp/match-comment → match_comment.php.

Sedno: PUSTY TEKST to polecenie, nie brak danych. Sędzia, który skasował opis
z odwrotnej strony protokołu, chce go skasować także w bazie ZPRP - dlatego ""
musi dojechać do upstreamu nietknięte, a nie zniknąć po drodze w jakimś
`or ""`, `strip()` czy odsiewie pustych wartości. To samo rozróżnienie, które
respektuje już wynik skrócony.

Drugie rozróżnienie: upstream odpowiada 400, gdy `id_zawody` nie pasuje do
sesji. To błąd adresowania po NASZEJ stronie, nie wygaśnięcie sesji - dostaje
własny kod, żeby aplikacja mogła się przelogować pod właściwy mecz zamiast
pokazywać sędziemu „serwer odrzucił dane".

Sieć zastąpiona monkeypatchem `_post_upstream` - jedynego punktu sieciowego.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

import app.proel_zprp as z
from app.proel_zprp import ZprpMatchCommentRequest, submit_match_comment

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
        komentarz="Zawodnik nr 7 opuścił boisko bez zgody sędziego.",
    )
    base.update(over)
    return ZprpMatchCommentRequest(**base)


async def test_sukces_przekazuje_mecz_i_tekst(monkeypatch):
    fake = _upstream(200, {"status": "success", "message": "Komentarz zaktualizowany."})
    monkeypatch.setattr(z, "_post_upstream", fake)

    out = await submit_match_comment(_req())

    assert out["status"] == "success"
    endpoint, payload = fake.calls[0]
    assert endpoint == "match_comment.php"
    assert payload["id_zawody"] == 208136
    assert payload["hash_sesji"] == "abc123"
    assert payload["komentarz"].startswith("Zawodnik nr 7")


async def test_pusty_tekst_dociera_jako_pusty_string(monkeypatch):
    """Wyczyszczenie uwag to świadoma decyzja sędziego, nie brak danych."""
    fake = _upstream(200, {"status": "success"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    await submit_match_comment(_req(komentarz=""))

    _, payload = fake.calls[0]
    assert "komentarz" in payload
    assert payload["komentarz"] == ""


async def test_diakrytyki_i_lamanie_wierszy_bez_zmian(monkeypatch):
    """Tekst idzie dosłownie - żadnego strip(), żadnej normalizacji."""
    tekst = "  Kara dla trenera gospodarzy.\n\nŻółta kartka w 12. minucie.  "
    fake = _upstream(200, {"status": "success"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    await submit_match_comment(_req(komentarz=tekst))

    _, payload = fake.calls[0]
    assert payload["komentarz"] == tekst


async def test_wygasla_sesja_zachowuje_kod(monkeypatch):
    fake = _upstream(401, {"status": "error", "code": "SESSION_EXPIRED"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_match_comment(_req())

    assert ei.value.status_code == 401
    assert ei.value.detail["code"] == "SESSION_EXPIRED"


async def test_niezgodny_mecz_ma_wlasny_kod(monkeypatch):
    """400 od upstreamu znaczy „sesja dotyczy innego meczu" - to nie jest
    odrzucenie treści uwag."""
    fake = _upstream(
        400,
        {"status": "error", "message": "Przeslane id_zawody nie zgadza sie z aktywna sesja meczu."},
    )
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_match_comment(_req(id_zawody=999999))

    assert ei.value.status_code == 400
    assert ei.value.detail["code"] == "MATCH_MISMATCH"


async def test_zamkniety_protokol_to_konflikt(monkeypatch):
    fake = _upstream(403, {"status": "error", "code": "PROTOCOL_LOCKED"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_match_comment(_req())

    assert ei.value.status_code == 409
    assert ei.value.detail["code"] == "PROTOCOL_LOCKED"


async def test_403_z_innym_kodem_to_nasza_konfiguracja(monkeypatch):
    fake = _upstream(403, {"status": "error", "code": "INVALID_APP_IDENTIFIER"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_match_comment(_req())

    assert ei.value.status_code == 502
    assert ei.value.detail["code"] == "PROEL_CONFIG"


async def test_brak_hash_sesji_odrzucony(monkeypatch):
    fake = _upstream(200, {"status": "success"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_match_comment(_req(hash_sesji=""))

    assert ei.value.status_code == 400
    assert fake.calls == []


async def test_brak_klucza_aplikacji_to_503(monkeypatch):
    monkeypatch.delenv("PROEL_APP_KEY", raising=False)
    fake = _upstream(200, {"status": "success"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_match_comment(_req())

    assert ei.value.status_code == 503
    assert ei.value.detail["code"] == "PROEL_CONFIG"
    assert fake.calls == []


async def test_nieoczekiwany_status_to_502(monkeypatch):
    fake = _upstream(500, {"status": "error"})
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as ei:
        await submit_match_comment(_req())

    assert ei.value.status_code == 502
    assert ei.value.detail["code"] == "UPSTREAM_ERROR"

"""Proxy załącznika: /proel/zprp/attachment → upload_attachment.php.

Jedyny endpoint ZPRP, który nie jest JSON-em. Testy pilnują trzech rzeczy:

  • zły plik odbijamy U SIEBIE, zanim pójdzie w świat - sędzia w hali wysyła
    przez komórkę i kilka megabajtów w obie strony po to, żeby usłyszeć „zły
    format", to kilkanaście sekund jego czasu i jego transferu,
  • typ pliku bierzemy z ROZSZERZENIA, nie z tego, co przysłała aplikacja -
    React Native potrafi oznaczyć wszystko jako octet-stream, a ZPRP odrzuca
    po typie,
  • komunikat upstreamu o pliku przechodzi do aplikacji, bo serwer wie o nim
    więcej niż my (np. że PDF jest uszkodzony).
"""
from __future__ import annotations

import httpx
import pytest
from fastapi import HTTPException

import app.proel_zprp as z
from app.proel_zprp import ATTACHMENT_MAX_BYTES, upload_attachment

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _app_key(monkeypatch):
    monkeypatch.setenv("PROEL_APP_KEY", "test-app-key")


def _upstream(status: int, data: dict):
    async def fake(endpoint, form, *, filename, content, content_type):
        fake.calls.append((endpoint, form, filename, content, content_type))
        return status, data

    fake.calls = []
    return fake


PDF = b"%PDF-1.4 fake protocol"


async def _send(monkeypatch, fake, **over):
    monkeypatch.setattr(z, "_post_upstream_file", fake)
    args = dict(
        hash_sesji="abc123",
        nazwa="Protokół TEST/2",
        filename="protokol_TEST-2.pdf",
        content=PDF,
    )
    args.update(over)
    return await upload_attachment(**args)


async def test_sukces_wysyla_plik_i_nazwe(monkeypatch):
    fake = _upstream(200, {"status": "success", "message": "Zapisano jako zalacznik nr 1"})
    out = await _send(monkeypatch, fake)

    assert out["status"] == "success"
    endpoint, form, filename, content, content_type = fake.calls[0]
    assert endpoint == "upload_attachment.php"
    assert form == {"hash_sesji": "abc123", "nazwa": "Protokół TEST/2"}
    assert filename == "protokol_TEST-2.pdf"
    assert content == PDF
    assert content_type == "application/pdf"


async def test_typ_bierzemy_z_rozszerzenia(monkeypatch):
    fake = _upstream(200, {"status": "success"})
    await _send(monkeypatch, fake, filename="skan.JPG", content=b"\xff\xd8\xff fake jpg")

    assert fake.calls[0][4] == "image/jpeg"


async def test_pusta_nazwa_dostaje_domyslna(monkeypatch):
    fake = _upstream(200, {"status": "success"})
    await _send(monkeypatch, fake, nazwa="   ")

    assert fake.calls[0][1]["nazwa"] == "Protokół zawodów"


async def test_zly_format_odbijamy_u_siebie(monkeypatch):
    fake = _upstream(200, {"status": "success"})

    with pytest.raises(HTTPException) as err:
        await _send(monkeypatch, fake, filename="protokol.png", content=b"\x89PNG")

    assert err.value.status_code == 400
    assert err.value.detail["code"] == "BAD_FILE"
    assert fake.calls == []  # nic nie poleciało do ZPRP


async def test_plik_bez_rozszerzenia_odrzucony(monkeypatch):
    fake = _upstream(200, {"status": "success"})

    with pytest.raises(HTTPException) as err:
        await _send(monkeypatch, fake, filename="protokol")

    assert err.value.status_code == 400
    assert fake.calls == []


async def test_pusty_plik_odrzucony(monkeypatch):
    fake = _upstream(200, {"status": "success"})

    with pytest.raises(HTTPException) as err:
        await _send(monkeypatch, fake, content=b"")

    assert err.value.status_code == 400
    assert fake.calls == []


async def test_za_duzy_plik_odrzucony(monkeypatch):
    fake = _upstream(200, {"status": "success"})

    with pytest.raises(HTTPException) as err:
        await _send(monkeypatch, fake, content=b"x" * (ATTACHMENT_MAX_BYTES + 1))

    assert err.value.status_code == 413
    assert err.value.detail["code"] == "FILE_TOO_LARGE"
    assert fake.calls == []


async def test_brak_sesji_odrzucony(monkeypatch):
    fake = _upstream(200, {"status": "success"})

    with pytest.raises(HTTPException) as err:
        await _send(monkeypatch, fake, hash_sesji="")

    assert err.value.status_code == 400
    assert fake.calls == []


async def test_komunikat_upstreamu_o_pliku_przechodzi(monkeypatch):
    fake = _upstream(400, {"status": "error", "message": "Nieprawidlowy format pliku."})

    with pytest.raises(HTTPException) as err:
        await _send(monkeypatch, fake)

    assert err.value.status_code == 400
    assert err.value.detail["code"] == "BAD_FILE"
    assert "Nieprawidlowy format" in err.value.detail["message"]


async def test_wygasla_sesja_zachowuje_kod(monkeypatch):
    fake = _upstream(401, {"status": "error", "code": "SESSION_EXPIRED"})

    with pytest.raises(HTTPException) as err:
        await _send(monkeypatch, fake)

    assert err.value.status_code == 401
    assert err.value.detail["code"] == "SESSION_EXPIRED"


async def test_zatwierdzony_protokol_to_konflikt(monkeypatch):
    fake = _upstream(403, {"status": "error", "code": "PROTOCOL_LOCKED"})

    with pytest.raises(HTTPException) as err:
        await _send(monkeypatch, fake)

    assert err.value.status_code == 409
    assert err.value.detail["code"] == "PROTOCOL_LOCKED"


async def test_timeout_wysylki(monkeypatch):
    async def boom(endpoint, form, *, filename, content, content_type):
        raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(z, "_post_upstream_file", boom)

    with pytest.raises(HTTPException) as err:
        await upload_attachment(
            hash_sesji="abc123",
            nazwa="Protokół",
            filename="p.pdf",
            content=PDF,
        )

    assert err.value.status_code == 504
    assert err.value.detail["code"] == "UPSTREAM_TIMEOUT"

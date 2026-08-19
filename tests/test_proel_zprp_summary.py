"""
Wysyłka wyniku skróconego przez oficjalne API ZPRP (`summary.php`).

Sedno tych testów to semantyka aktualizacji częściowej. `summary.php` zapisuje
wyłącznie klucze, które faktycznie przyszły, a pusty string kasuje wartość
(NULL). Proxy nie ma prawa tego wygładzać: pominięcie klucza i klucz z ""
to dwie różne decyzje sędziego, a pomyłka w którąkolwiek stronę kasuje dane
w bazie ZPRP albo zostawia stare. Stąd testy pilnują, że payload upstreamu
jest ZNAKOWO tym, co przyszło z aplikacji, plus hash sesji.

Druga rzecz to mapowanie 403. Upstream używa go i na „protokół zamknięty"
(stan meczu, komunikat dla sędziego), i na zły app_key (nasza awaria) - te
dwa muszą wyjść z proxy jako zupełnie różne kody.

Sieć zastąpiona monkeypatchem `_post_upstream`, jak w teście autoryzacji.
"""
from __future__ import annotations

import httpx
import pytest
from fastapi import HTTPException

import app.proel_zprp as z
from app.proel_zprp import SUMMARY_FIELDS, ZprpSummaryRequest, submit_summary

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


HASH = "b5c68b72e12176ee64f7bfa6d9124a9a"
OK = {"status": "success", "message": "Zapisano."}

# Typowy komplet z toru meczowego: 24:22 (12:10), gospodarze wzięli dwa czasy,
# goście trzy, widzów sędzia nie policzył (klucza nie ma wcale).
FIELDS = {
    "wynik_gosp_pol": "12",
    "wynik_gosc_pol": "10",
    "wynik_gosp_full": "24",
    "wynik_gosc_full": "22",
    "wynik_bramki_gosp": "24",
    "wynik_bramki_gosc": "22",
    "timeout1_gosp_ii": "08",
    "timeout1_gosp_ss": "12",
    "timeout2_gosp_ii": "24",
    "timeout2_gosp_ss": "50",
    "timeout3_gosp_ii": "",
    "timeout3_gosp_ss": "",
}


def _req(fields=None, hash_sesji=HASH):
    return ZprpSummaryRequest(hash_sesji=hash_sesji, fields=FIELDS if fields is None else fields)


# ───────────────────────────── droga szczęśliwa ─────────────────────────────

async def test_wysyla_dokladnie_te_pola_ktore_dostal(monkeypatch):
    fake = _upstream(200, OK)
    monkeypatch.setattr(z, "_post_upstream", fake)

    out = await submit_summary(_req())

    assert out["status"] == "success"
    endpoint, payload = fake.calls[0]
    assert endpoint == "summary.php"
    assert payload.pop("hash_sesji") == HASH
    # Ani jednego pola więcej, ani jednego mniej - zwłaszcza brakującego
    # `widzowie`, którego dorzucenie jako "" skasowałoby liczbę w bazie.
    assert payload == FIELDS


async def test_pusty_string_jedzie_dalej_jako_pusty(monkeypatch):
    """Trzeci czas, którego drużyna nie wzięła, MA wyczyścić pole w ZPRP."""
    fake = _upstream(200, OK)
    monkeypatch.setattr(z, "_post_upstream", fake)

    await submit_summary(_req())

    _endpoint, payload = fake.calls[0]
    assert payload["timeout3_gosp_ii"] == ""
    assert payload["timeout3_gosp_ss"] == ""


async def test_liczby_ida_jako_stringi(monkeypatch):
    fake = _upstream(200, OK)
    monkeypatch.setattr(z, "_post_upstream", fake)

    await submit_summary(ZprpSummaryRequest(hash_sesji=HASH, fields={"widzowie": "350"}))

    _endpoint, payload = fake.calls[0]
    assert payload["widzowie"] == "350"


async def test_status_inny_niz_success_to_blad(monkeypatch):
    monkeypatch.setattr(z, "_post_upstream", _upstream(200, {"status": "error"}))

    with pytest.raises(HTTPException) as exc:
        await submit_summary(_req())
    assert exc.value.status_code == 502


# ───────────────────────────── walidacja wejścia ─────────────────────────────

async def test_nieznane_pole_odrzucone_przed_siecia(monkeypatch):
    """Literówka w nazwie klucza musi boleć TU, nie zostać po cichu zjedzona
    przez upstream i pokazana sędziemu jako udany zapis."""
    fake = _upstream(200, OK)
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as exc:
        await submit_summary(ZprpSummaryRequest(hash_sesji=HASH, fields={"wynik_gosp_ful": "24"}))

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "BAD_FIELDS"
    assert "wynik_gosp_ful" in exc.value.detail["message"]
    assert fake.calls == []


async def test_pusty_zestaw_pol_odrzucony(monkeypatch):
    fake = _upstream(200, OK)
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as exc:
        await submit_summary(ZprpSummaryRequest(hash_sesji=HASH, fields={}))
    assert exc.value.status_code == 400
    assert fake.calls == []


async def test_brak_hash_sesji_odrzucony(monkeypatch):
    fake = _upstream(200, OK)
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as exc:
        await submit_summary(_req(hash_sesji="   "))
    assert exc.value.status_code == 400
    assert fake.calls == []


async def test_biala_lista_zna_wszystkie_pola_z_dokumentacji():
    """Kanarek na rozjazd z dokumentacją v2.0 - komplet 34 kluczy (36 z dokumentacji minus hash_sesji, ktory nie jest polem)."""
    assert len(SUMMARY_FIELDS) == 34
    for key in ("data_fakt", "widzowie", "dogrywka_2_full_gosc", "karne_bramki_gosc"):
        assert key in SUMMARY_FIELDS


# ───────────────────────────── mapowanie błędów ─────────────────────────────

async def test_sesja_wygasla_przechodzi_kodem_do_aplikacji(monkeypatch):
    """401 musi zachować SESSION_EXPIRED - po tym kodzie aplikacja robi
    ponowną autoryzację i ponawia wysyłkę."""
    monkeypatch.setattr(
        z, "_post_upstream", _upstream(401, {"status": "error", "code": "SESSION_EXPIRED"})
    )

    with pytest.raises(HTTPException) as exc:
        await submit_summary(_req())

    assert exc.value.status_code == 401
    assert exc.value.detail["code"] == "SESSION_EXPIRED"


async def test_protokol_zatwierdzony_to_409(monkeypatch):
    monkeypatch.setattr(
        z, "_post_upstream", _upstream(403, {"status": "error", "code": "PROTOCOL_LOCKED"})
    )

    with pytest.raises(HTTPException) as exc:
        await submit_summary(_req())

    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "PROTOCOL_LOCKED"


async def test_zly_app_key_to_nasza_awaria_nie_stan_meczu(monkeypatch):
    monkeypatch.setattr(
        z, "_post_upstream", _upstream(403, {"status": "error", "code": "INVALID_APP_IDENTIFIER"})
    )

    with pytest.raises(HTTPException) as exc:
        await submit_summary(_req())

    assert exc.value.status_code == 502
    assert exc.value.detail["code"] == "PROEL_CONFIG"


async def test_zla_struktura_to_400(monkeypatch):
    monkeypatch.setattr(z, "_post_upstream", _upstream(400, {"status": "error"}))

    with pytest.raises(HTTPException) as exc:
        await submit_summary(_req())
    assert exc.value.status_code == 400


async def test_timeout_upstreamu(monkeypatch):
    async def boom(_endpoint, _payload):
        raise httpx.ReadTimeout("timeout")

    monkeypatch.setattr(z, "_post_upstream", boom)

    with pytest.raises(HTTPException) as exc:
        await submit_summary(_req())
    assert exc.value.status_code == 504
    assert exc.value.detail["code"] == "UPSTREAM_TIMEOUT"


async def test_brak_app_key_to_503(monkeypatch):
    monkeypatch.delenv("PROEL_APP_KEY", raising=False)
    fake = _upstream(200, OK)
    monkeypatch.setattr(z, "_post_upstream", fake)

    with pytest.raises(HTTPException) as exc:
        await submit_summary(_req())
    assert exc.value.status_code == 503
    assert fake.calls == []

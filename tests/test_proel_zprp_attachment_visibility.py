"""Proxy widoczności załącznika: /proel/zprp/attachment-visibility -> hide_attachment.php.

Sedno: ZPRP nie sprawdza ani ról, ani zatwierdzenia protokołu - sprawdza tylko
parę (mecz, załącznik). Dlatego serwer przed wywołaniem pyta publiczne API
meczu: zatwierdzony protokół odmawia (409 MATCH_APPROVED), ukrywany plik musi
stać w `Zalczniki`, a przywracany w naszej księdze ukrytych.

Sieć i baza zastąpione monkeypatchem: `_post_upstream`, `_fetch_match_details`
i funkcje księgi w `app/zprp_hidden_attachments.py`.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import pytest
from fastapi import HTTPException

import app.proel_zprp as z
import app.zprp_hidden_attachments as ledger
from app.proel_zprp import ZprpAttachmentVisibilityRequest, set_attachment_visibility

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _app_key(monkeypatch):
    monkeypatch.setenv("PROEL_APP_KEY", "test-app-key")


def _match(approved: bool = False, attachments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "Id": "205603",
        "protokol_zatwierdz": "1" if approved else "0",
    }
    if attachments is not None:
        out["Zalczniki"] = attachments
    return out


ONE = {
    "1": {
        "protokol_zalcznik_plik": "zawody_zalaczniki/205603_3.jpg",
        "protokol_zalcznik_plik_typ": "jpg",
        "protokol_zalcznik_nazwa": "IMG_20260504_230650.jpg",
        "protokol_id": "86914",
    }
}


class FakeLedger:
    def __init__(self, open_ids=()):
        self.open = {str(i) for i in open_ids}
        self.hidden: List[Tuple[int, str, Dict[str, Any], Optional[str]]] = []
        self.restored: List[Tuple[int, str]] = []

    def install(self, monkeypatch):
        async def open_entry(match_id, attachment_id):
            return {"attachment_id": attachment_id} if attachment_id in self.open else None

        async def mark_hidden(match_id, attachment_id, *, values, by_name, by_judge_id):
            self.hidden.append((match_id, attachment_id, values, by_name))

        async def mark_restored(match_id, attachment_id, *, by_name):
            self.restored.append((match_id, attachment_id))

        monkeypatch.setattr(ledger, "ledger_open_entry", open_entry)
        monkeypatch.setattr(ledger, "ledger_mark_hidden", mark_hidden)
        monkeypatch.setattr(ledger, "ledger_mark_restored", mark_restored)
        return self


def _setup(monkeypatch, *, match, status=200, data=None, open_ids=()):
    calls: List[Tuple[str, Dict[str, Any]]] = []

    async def fake_post(endpoint, payload):
        calls.append((endpoint, payload))
        return status, data if data is not None else {
            "status": "success",
            "message": "Zalacznik zostal pomyslnie ukryty na stronie WWW.",
        }

    async def fake_details(match_id):
        return match

    monkeypatch.setattr(z, "_post_upstream", fake_post)
    monkeypatch.setattr(z, "_fetch_match_details", fake_details)
    return calls, FakeLedger(open_ids).install(monkeypatch)


def _req(**over):
    base = dict(
        hash_sesji="abc123",
        zprp_match_id="205603",
        attachment_id="86914",
        hidden=True,
        label="Zdjęcie z galerii",
    )
    base.update(over)
    return ZprpAttachmentVisibilityRequest(**base)


async def test_ukrycie_wysyla_pare_mecz_zalacznik_i_zapisuje_ksiege(monkeypatch):
    calls, book = _setup(monkeypatch, match=_match(attachments=ONE))

    out = await set_attachment_visibility(_req(), by_name="Jan KOWALSKI", by_judge_id="465")

    assert out == {"ok": True, "hidden": True, "already": False}
    endpoint, payload = calls[0]
    assert endpoint == "hide_attachment.php"
    assert payload == {
        "hash_sesji": "abc123",
        "id_zawody": 205603,
        "id_zalacznik": 86914,
        "ukryty_www": 1,
    }
    (match_id, attachment_id, values, by_name) = book.hidden[0]
    assert (match_id, attachment_id, by_name) == (205603, "86914", "Jan KOWALSKI")
    # Opis pliku z publicznego API wygrywa z tym, co przysłał telefon.
    assert values["label"] == "IMG_20260504_230650.jpg"
    assert values["file_url"] == "https://baza.zprp.pl/zawody_zalaczniki/205603_3.jpg"
    assert values["is_pdf"] is False


async def test_status_juz_aktualny_to_already(monkeypatch):
    calls, _ = _setup(
        monkeypatch,
        match=_match(attachments=ONE),
        data={"status": "success", "message": "Status zalacznika jest juz aktualny (brak potrzeb zmian)."},
    )

    out = await set_attachment_visibility(_req())

    assert out == {"ok": True, "hidden": True, "already": True}
    assert len(calls) == 1


async def test_ponowne_ukrycie_pliku_ktory_juz_zniknal_z_api(monkeypatch):
    """Ukryty plik znika z publicznej listy - księga mówi, że to my go schowaliśmy."""
    calls, _ = _setup(monkeypatch, match=_match(attachments={}), open_ids=["86914"])

    out = await set_attachment_visibility(_req())

    assert out == {"ok": True, "hidden": True, "already": True}
    assert calls == []


async def test_zatwierdzony_protokol_odmawia_bez_wywolania_zprp(monkeypatch):
    calls, book = _setup(monkeypatch, match=_match(approved=True, attachments=ONE))

    with pytest.raises(HTTPException) as err:
        await set_attachment_visibility(_req())

    assert err.value.status_code == 409
    assert err.value.detail["code"] == "MATCH_APPROVED"
    assert calls == []
    assert book.hidden == []


async def test_cudzy_zalacznik_to_404_bez_wywolania(monkeypatch):
    calls, _ = _setup(monkeypatch, match=_match(attachments=ONE))

    with pytest.raises(HTTPException) as err:
        await set_attachment_visibility(_req(attachment_id="99999"))

    assert err.value.status_code == 404
    assert err.value.detail["code"] == "ATTACHMENT_NOT_FOUND"
    assert calls == []


async def test_404_z_zprp_mapowane_na_attachment_not_found(monkeypatch):
    _setup(
        monkeypatch,
        match=_match(attachments=ONE),
        status=404,
        data={"status": "error", "message": "Nie znaleziono takiego zalacznika dla podanego meczu."},
    )

    with pytest.raises(HTTPException) as err:
        await set_attachment_visibility(_req())

    assert err.value.status_code == 404
    assert err.value.detail["code"] == "ATTACHMENT_NOT_FOUND"


async def test_przywrocenie_z_ksiegi(monkeypatch):
    calls, book = _setup(
        monkeypatch,
        match=_match(attachments={}),
        open_ids=["86914"],
        data={"status": "success", "message": "Zalacznik zostal przywrocony."},
    )

    out = await set_attachment_visibility(_req(hidden=False))

    assert out == {"ok": True, "hidden": False, "already": False}
    assert calls[0][1]["ukryty_www"] == 0
    assert book.restored == [(205603, "86914")]


async def test_przywrocenie_spoza_ksiegi_to_404(monkeypatch):
    calls, _ = _setup(monkeypatch, match=_match(attachments={}))

    with pytest.raises(HTTPException) as err:
        await set_attachment_visibility(_req(hidden=False))

    assert err.value.status_code == 404
    assert err.value.detail["code"] == "ATTACHMENT_NOT_FOUND"
    assert calls == []


async def test_przywrocenie_widocznego_to_already_bez_wywolania(monkeypatch):
    calls, _ = _setup(monkeypatch, match=_match(attachments=ONE))

    out = await set_attachment_visibility(_req(hidden=False))

    assert out == {"ok": True, "hidden": False, "already": True}
    assert calls == []


async def test_wygasla_sesja_to_401(monkeypatch):
    _setup(monkeypatch, match=_match(attachments=ONE), status=401, data={"code": "SESSION_EXPIRED"})

    with pytest.raises(HTTPException) as err:
        await set_attachment_visibility(_req())

    assert err.value.status_code == 401
    assert err.value.detail["code"] == "SESSION_EXPIRED"


async def test_proel_wylaczony_to_403(monkeypatch):
    _setup(
        monkeypatch,
        match=_match(attachments=ONE),
        status=403,
        data={"status": "error", "code": "PROEL_INACTIVE", "message": "x"},
    )

    with pytest.raises(HTTPException) as err:
        await set_attachment_visibility(_req())

    assert err.value.status_code == 403
    assert err.value.detail["code"] == "PROEL_INACTIVE"


async def test_brak_szczegolow_meczu_odmawia(monkeypatch):
    calls, _ = _setup(monkeypatch, match=None)

    with pytest.raises(HTTPException) as err:
        await set_attachment_visibility(_req())

    assert err.value.status_code == 502
    assert err.value.detail["code"] == "UPSTREAM_ERROR"
    assert calls == []


async def test_zly_identyfikator_odbijamy_u_siebie(monkeypatch):
    calls, _ = _setup(monkeypatch, match=_match(attachments=ONE))

    with pytest.raises(HTTPException) as err:
        await set_attachment_visibility(_req(attachment_id="../1"))

    assert err.value.status_code == 400
    assert calls == []


async def test_blad_ksiegi_nie_wywraca_udanej_zmiany(monkeypatch):
    _setup(monkeypatch, match=_match(attachments=ONE))

    async def boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(ledger, "ledger_mark_hidden", boom)

    out = await set_attachment_visibility(_req())

    assert out["ok"] is True


def test_reguly_api_meczu():
    assert ledger.match_from_details([[_match(attachments=ONE)]])["Id"] == "205603"
    assert ledger.match_from_details({"0": [_match()]})["Id"] == "205603"
    assert ledger.is_approved(_match(approved=True))
    assert not ledger.is_approved(_match())
    assert set(ledger.visible_attachments(_match(attachments=ONE))) == {"86914"}
    assert ledger.normalize_attachment_id("0086914") == "86914"
    assert ledger.normalize_attachment_id("abc") is None
    assert ledger.is_already_current("Status zalacznika jest juz aktualny")


def test_pozycja_kosza_ma_ksztalt_kontraktu():
    from datetime import datetime, timezone

    item = ledger.row_to_item(
        {
            "attachment_id": "86914",
            "filename": "205603_3.jpg",
            "label": "",
            "file_url": "https://baza.zprp.pl/zawody_zalaczniki/205603_3.jpg",
            "is_pdf": False,
            "hidden_at": datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc),
            "hidden_by_name": "Jan KOWALSKI",
        }
    )
    assert item == {
        "attachment_id": "86914",
        "filename": "205603_3.jpg",
        "label": "205603_3.jpg",
        "file_url": "https://baza.zprp.pl/zawody_zalaczniki/205603_3.jpg",
        "is_pdf": False,
        "hidden_at": "2026-10-15T12:00:00+00:00",
        "hidden_by_name": "Jan KOWALSKI",
    }

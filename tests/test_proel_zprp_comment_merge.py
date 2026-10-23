"""Scalanie uwag po stronie serwera dla starego buildu (bez `baseline_seen`)."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

import app.proel_zprp as z
from app.proel_zprp import ZprpMatchCommentRequest, submit_match_comment
from app.zprp_comment_rules import (
    EXTRA_REPORT_FOOTER,
    EXTRA_REPORT_HEADER,
    merge_comment_additive,
)

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _app_key(monkeypatch):
    monkeypatch.setenv("PROEL_APP_KEY", "test-app-key")


def _block(body: str) -> str:
    return f"{EXTRA_REPORT_HEADER}\n{body}\n{EXTRA_REPORT_FOOTER}"


def _wire(monkeypatch, current):
    calls = []

    async def upstream(endpoint, payload):
        calls.append(payload)
        return 200, {"status": "success"}

    async def details(_mid):
        return None if current is None else {"Id": "1", "komentarz": current}

    monkeypatch.setattr(z, "_call_upstream", upstream)
    monkeypatch.setattr(z, "_fetch_match_details", details)
    return calls


def _req(text):
    return ZprpMatchCommentRequest(hash_sesji="h", id_zawody=1, komentarz=text)


async def test_pusty_przychodzacy_nie_czysci_verte(monkeypatch):
    calls = _wire(monkeypatch, "Uwaga sędziego")
    out = await submit_match_comment(_req(""))
    assert out["status"] == "success" and out["unchanged"] is True
    assert calls == []


async def test_verte_zostaje_a_blok_jest_podmieniony(monkeypatch):
    calls = _wire(monkeypatch, "Uwaga A\n\n" + _block("stary"))
    await submit_match_comment(_req(_block("nowy")))
    sent = calls[0]["komentarz"]
    assert sent.startswith("Uwaga A") and "nowy" in sent and "stary" not in sent


async def test_nowy_tekst_dopisany_gdy_go_nie_ma(monkeypatch):
    calls = _wire(monkeypatch, "Uwaga A")
    await submit_match_comment(_req("Uwaga B"))
    assert calls[0]["komentarz"] == "Uwaga A\n\nUwaga B"


async def test_blad_odczytu_nie_zapisuje_na_slepo(monkeypatch):
    calls = _wire(monkeypatch, None)
    with pytest.raises(HTTPException) as e:
        await submit_match_comment(_req("cokolwiek"))
    assert e.value.status_code == 502 and calls == []


async def test_baseline_seen_bez_zmian(monkeypatch):
    calls = _wire(monkeypatch, "Uwaga A")
    await submit_match_comment(
        ZprpMatchCommentRequest(hash_sesji="h", id_zawody=1, komentarz="", baseline_seen=True)
    )
    assert calls[0]["komentarz"] == ""


def test_scalanie_czyste():
    assert merge_comment_additive("A", "A") == "A"
    assert merge_comment_additive("A", "A plus B") == "A plus B"
    assert merge_comment_additive("", "B") == "B"

"""Logi logowania Beach do baza.zprp.pl nie mogą zawierać hasła (ani w całości, ani w formie urlencoded)."""
from __future__ import annotations

import importlib
import logging
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock
from urllib.parse import quote_plus

import httpx
import pytest
from fastapi import HTTPException



def _load_teams():
    # Wzorzec z innych testów: app.db przy imporcie tworzy schemat w bazie, więc go mockujemy.
    before = set(sys.modules)
    sys.modules["app.db"] = MagicMock()
    try:
        return importlib.import_module("app.beach.teams")
    finally:
        for name in set(sys.modules) - before:
            if name.startswith("app."):
                sys.modules.pop(name, None)
        if isinstance(sys.modules.get("app.db"), MagicMock):
            sys.modules.pop("app.db", None)


teams = _load_teams()

FAKE_PASSWORD = "Fikcyjne!Haslo#2026"
FAKE_LOGIN = "beach_test_user"


def _settings():
    return SimpleNamespace(
        ZPRP_BASE_URL="https://baza.zprp.pl",
        ZPRP_BEACH_USERNAME=FAKE_LOGIN,
        ZPRP_BEACH_PASSWORD=f" {FAKE_PASSWORD} ",
    )


def _fake_client_cls(html: str):
    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.cookies = httpx.Cookies()

        async def request(self, method, url, **kwargs):
            req = httpx.Request(method, "https://baza.zprp.pl" + url)
            return httpx.Response(200, content=html.encode("iso-8859-2"), request=req)

        async def aclose(self):
            pass

    return FakeClient


def _assert_no_password(text: str):
    for variant in (FAKE_PASSWORD, quote_plus(FAKE_PASSWORD)):
        assert variant not in text


async def test_login_success_logs_have_no_password(monkeypatch, caplog):
    monkeypatch.setattr(teams, "AsyncClient", _fake_client_cls("<html>Zalogowany: test | Wyloguj</html>"))
    with caplog.at_level(logging.DEBUG):
        await teams._login_beach_client(_settings())
    assert "BEACH login request payload" in caplog.text
    _assert_no_password(caplog.text)


async def test_login_rejected_logs_have_no_password(monkeypatch, caplog):
    monkeypatch.setattr(teams, "AsyncClient", _fake_client_cls("<html>Nieznany użytkownik lub hasło</html>"))
    with caplog.at_level(logging.DEBUG), pytest.raises(HTTPException) as exc:
        await teams._login_beach_client(_settings())
    assert "BEACH login rejected by ZPRP" in caplog.text
    _assert_no_password(caplog.text)
    _assert_no_password(str(exc.value.detail))


def test_mask_secret_reveals_nothing():
    assert teams._mask_secret(FAKE_PASSWORD) == "***"
    assert teams._mask_secret("") == ""

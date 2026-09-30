from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException

from app.zprp import assignments as A


def date_form(value: str) -> str:
    return f"""
    <form name="zawody_data" method="POST">
      <input type="hidden" name="IdZawody" value="209640">
      <input type="hidden" name="akcja" value="UstawDate">
      <input type="hidden" name="token" value="fresh-token">
      <input name="data_fakt" type="text" value="{value}">
      <input name="akcja_edycja" type="submit" value="ZAPISZ ZMIANY">
    </form>
    """


class DummyClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class FakeHttp:
    def __init__(self, *pages: str):
        self.pages = list(pages)
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, client, path, method="GET", data=None, cookies=None, **kwargs):
        self.calls.append({"path": path, "data": dict(data or {})})
        index = min(len(self.calls) - 1, len(self.pages) - 1)
        return None, self.pages[index]


@pytest.fixture
def date_http(monkeypatch):
    def install(*pages: str) -> FakeHttp:
        fake = FakeHttp(*pages)
        monkeypatch.setattr(A, "fetch_with_correct_encoding", fake)
        monkeypatch.setattr(A, "AsyncClient", DummyClient)
        monkeypatch.setattr(A, "_decrypt_field", lambda _key, value: value)

        async def login(*args, **kwargs):
            return {"session": "ok"}

        monkeypatch.setattr(A, "_login_zprp", login)
        return fake

    return install


async def save(value: str, *, expect: str | None = None):
    payload = A.ObsadaSaveDateRequest(
        username="user",
        password="pass",
        IdZawody="209640",
        user="ks_dolzpr",
        date_value=value,
        expect={"date": expect} if expect is not None else None,
    )
    return await A.obsada_save_date(
        payload,
        settings=SimpleNamespace(ZPRP_BASE_URL="https://zprp.invalid"),
        keys=("private", "public"),
    )


@pytest.mark.asyncio
async def test_date_save_preserves_form_fields_and_exact_minute(date_http):
    fake = date_http(date_form("2026-09-30 15:00"), date_form("2026-10-03 18:37"))

    out = await save("2026-10-03 18:37", expect="2026-09-30 15:00")

    assert out["success"] is True
    assert fake.calls[1]["data"]["data_fakt"] == "2026-10-03 18:37"
    assert fake.calls[1]["data"]["token"] == "fresh-token"
    assert fake.calls[1]["data"]["akcja_edycja"] == "ZAPISZ ZMIANY"


@pytest.mark.asyncio
async def test_date_save_stops_on_concurrent_zprp_change(date_http):
    fake = date_http(date_form("2026-09-30 16:00"))

    with pytest.raises(HTTPException) as caught:
        await save("2026-10-03 18:37", expect="2026-09-30 15:00")

    assert caught.value.status_code == 409
    assert caught.value.detail["code"] == "ZPRP_CHANGED"
    assert len(fake.calls) == 1


@pytest.mark.asyncio
async def test_date_save_reports_unverified_response(date_http):
    old = date_form("2026-09-30 15:00")
    date_http(old, old, old)

    out = await save("2026-10-03 18:37")

    assert out["success"] is False
    assert out["date_value"] == "2026-09-30 15:00"
    assert "verification failed" in out["error"].lower()

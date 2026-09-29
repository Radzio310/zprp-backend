from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import app.judge_documents as documents


class _Response:
    def __init__(self, data: bytes, status_code: int = 200):
        self.status_code = status_code
        self._data = data

    async def aread(self) -> bytes:
        return self._data


class _Client:
    def __init__(self, data: bytes):
        self.response = _Response(data)
        self.closed = False
        self.calls = []

    async def get(self, path: str, *, params: dict):
        self.calls.append((path, params))
        return self.response

    async def aclose(self):
        self.closed = True


def _request():
    return SimpleNamespace(
        url_for=lambda _name, token: f"https://backend.test/temp/document/{token}.pdf",
    )


async def test_raw_protocol_is_downloaded_in_server_side_judge_session(
    monkeypatch, tmp_path: Path,
):
    client = _Client(b"%PDF-1.7\nraw protocol")

    async def login(_user, _password, _settings):
        return client

    monkeypatch.setattr(documents, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(documents, "_login_and_client", login)
    monkeypatch.setattr(documents, "_decrypt_field", lambda value, _key: value)

    result = await documents.raw_protocol_download(
        documents.RawProtocolDownloadRequest(
            username="judge",
            password="secret",
            judge_id="84",
            match_id=208146,
            filename="Protokół surowy IIM4-10.pdf",
        ),
        _request(),
        settings=object(),
        keys=(object(), object()),
    )

    assert client.calls == [
        ("/zawody_protokol_1.php", {"IdZawody": 208146}),
    ]
    assert client.closed is True
    assert "Protok%C3%B3%C5%82%20surowy%20IIM4-10.pdf" in result["download_url"]
    saved = list(tmp_path.glob("doc_*.pdf"))
    assert len(saved) == 1
    assert saved[0].read_bytes().startswith(b"%PDF-")


async def test_raw_protocol_rejects_login_html_disguised_as_pdf(
    monkeypatch, tmp_path: Path,
):
    client = _Client(b"<!DOCTYPE html><title>Logowanie</title>")

    async def login(_user, _password, _settings):
        return client

    monkeypatch.setattr(documents, "TMP_DIR", str(tmp_path))
    monkeypatch.setattr(documents, "_login_and_client", login)
    monkeypatch.setattr(documents, "_decrypt_field", lambda value, _key: value)

    with pytest.raises(HTTPException) as error:
        await documents.raw_protocol_download(
            documents.RawProtocolDownloadRequest(
                username="judge",
                password="secret",
                judge_id="84",
                match_id=208146,
            ),
            _request(),
            settings=object(),
            keys=(object(), object()),
        )

    assert error.value.status_code == 502
    assert "nie udostępnił" in str(error.value.detail)
    assert client.closed is True
    assert list(tmp_path.iterdir()) == []

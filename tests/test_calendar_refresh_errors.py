import ast
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from app.calendar_refresh_errors import (
    RECONNECT_CODE,
    UNAVAILABLE_CODE,
    refresh_error_handler,
    transport_error_handler,
)

REQUEST = SimpleNamespace(url=SimpleNamespace(path="/calendar/events"))


def _body(response):
    return json.loads(response.body)


def test_cofnieta_zgoda_to_403_z_kodem_i_komunikatem():
    exc = Exception("invalid_grant: Token has been expired or revoked.")
    response = asyncio.run(refresh_error_handler(REQUEST, exc))
    assert response.status_code == 403
    body = _body(response)
    assert body["code"] == RECONNECT_CODE
    assert body["error"]["code"] == RECONNECT_CODE
    assert "Połącz kalendarz ponownie" in body["message"]
    assert body["detail"] == body["message"]


def test_chwilowy_blad_google_nie_kaze_laczyc_ponownie():
    exc = Exception("server_error")
    exc.retryable = True
    response = asyncio.run(refresh_error_handler(REQUEST, exc))
    assert response.status_code == 503
    assert _body(response)["code"] == UNAVAILABLE_CODE


def test_brak_lacznosci_z_google_to_503():
    response = asyncio.run(transport_error_handler(REQUEST, Exception("timeout")))
    assert response.status_code == 503
    assert _body(response)["code"] == UNAVAILABLE_CODE


def test_main_instaluje_handlery():
    tree = ast.parse(Path(__file__).resolve().parents[1].joinpath("main.py").read_text(encoding="utf-8"))
    calls = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert "install_google_refresh_handlers" in calls

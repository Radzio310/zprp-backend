# app/calendar_refresh_errors.py
"""Nieudane odświeżenie tokenu Google jako odpowiedź, a nie goły 500.

`creds.refresh()` stoi w wielu trasach kalendarza i żadna go nie łapie. Gdy
Google odmawia (`invalid_grant`: cofnięta zgoda, zmiana hasła, pół roku
bezczynności), aplikacja widziała tylko „Internal Server Error", po jednym na
każdy mecz. Status 403 jest celowy: zainstalowane aplikacje traktują go jako
błąd całego konta Google i przerywają serię, a nie kojarzą go z wylogowaniem.
"""
import logging

from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

RECONNECT_CODE = "calendar_reconnect_required"
RECONNECT_MESSAGE = (
    "Google nie przyjmuje już zgody tego konta. "
    "Połącz kalendarz ponownie w Ustawieniach > Kalendarz."
)
UNAVAILABLE_CODE = "calendar_google_unavailable"
UNAVAILABLE_MESSAGE = "Google chwilowo nie odpowiada. Spróbujemy ponownie później."


def _envelope(status_code: int, code: str, message: str) -> JSONResponse:
    # Koperta jak w main.py, a `detail` dla starszych klientów pisanych „po FastAPI".
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {"code": code, "message": message},
            "code": code,
            "message": message,
            "detail": message,
        },
    )


async def refresh_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Treść błędu Google nie zawiera tokenu, a mówi, dlaczego konto odpadło.
    logger.warning("Odświeżenie tokenu Google nieudane (%s): %s", request.url.path, exc)
    if getattr(exc, "retryable", False):
        return _envelope(503, UNAVAILABLE_CODE, UNAVAILABLE_MESSAGE)
    return _envelope(403, RECONNECT_CODE, RECONNECT_MESSAGE)


async def transport_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.warning("Brak łączności z Google (%s): %s", request.url.path, exc)
    return _envelope(503, UNAVAILABLE_CODE, UNAVAILABLE_MESSAGE)


def install_google_refresh_handlers(app) -> None:
    from google.auth.exceptions import RefreshError, TransportError

    app.add_exception_handler(RefreshError, refresh_error_handler)
    app.add_exception_handler(TransportError, transport_error_handler)

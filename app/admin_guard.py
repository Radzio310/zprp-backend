# app/admin_guard.py
#
# Bramka zapisów panelu administratora (`/admin/*` z `app/admin.py`
# i `app/central_rates.py`).
#
# Do 10.09.2026 te trasy nie sprawdzały NIC: kto znał adres backendu, mógł bez
# logowania nadpisać stawki ryczałtów, przepisy, kontakty, listę adminów, a
# nawet PIN dowolnego admina. Odczyty zostają otwarte - aplikacja pobiera
# manifesty, stawki i pliki JSON przed zalogowaniem i w tle.
#
# Tożsamość = token JWT z logowania do BAZY (`Authorization: Bearer ...`),
# ten sam, który już wpuszcza do pokazów wersji (`require_release_admin`).
# Numer sędziego w tokenie pochodzi z logowania do baza.zprp.pl, więc nie da
# się go podać samemu. Admin = numer na liście `admin_settings.allowed_admins`,
# tej samej, po której aplikacja pokazuje panel. PIN zostaje zamkiem ekranu
# w aplikacji - na serwer się nie nadaje (nowi admini dostają "0000").
#
# OKRES PRZEJŚCIOWY, tak samo jak w `app/province_guard.py`. Wersje aplikacji
# w sklepie wysyłają zapisy admina bez nagłówka. Twarda odmowa od razu
# zamknęłaby panel każdemu, kto nie zaktualizował aplikacji. Dlatego:
#
#   * dopóki `ADMIN_WRITE_STRICT` nie jest ustawione, bramka NICZEGO nie
#     odrzuca - każdy zapis bez ważnego tokenu admina zostawia ostrzeżenie
#     `[admin_guard]` w logu z powodem (brak / nieważny / nie-admin),
#   * `ADMIN_WRITE_STRICT=1` na Railway zamyka furtkę. Wystarczy restart,
#     bez wydania backendu - gdy w logu przestaną się pojawiać wpisy
#     `powod=brak_tokenu` od prawdziwych adminów.
#
# Odrzucanie tokenu nie-admina już w okresie przejściowym nic by nie dało
# (napastnik po prostu nie wyśle nagłówka), a mogłoby zamknąć panel komuś, kto
# wchodzi PIN-em głównym spoza listy. Log pokaże, czy taki ktoś istnieje.

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import Header, HTTPException, Request, status

log = logging.getLogger(__name__)

#: Nazwa zmiennej środowiskowej zamykającej okres przejściowy.
STRICT_ENV = "ADMIN_WRITE_STRICT"

_TRUE = {"1", "true", "tak", "yes", "on"}

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

#: Zapisy pod `/admin`, które wykonuje ZWYKŁY użytkownik, nie admin. Muszą
#: zostać otwarte także po zamknięciu furtki - inaczej zgłoszenie błędu czy
#: nowej hali wymagałoby uprawnień administratora.
PUBLIC_WRITES = frozenset(
    {
        # sprawdzenie PIN-u przy wejściu do panelu - odbywa się PRZED byciem adminem
        ("POST", "/admin/validate_pin"),
        # zgłoszenie od użytkownika (formularz "Zgłoś problem")
        ("POST", "/admin/reports"),
        # zgłoszenie nowej hali przez sędziego
        ("POST", "/admin/halls/reports"),
    }
)

# Powody zapisywane w logu - stałe, żeby dało się je grepować na Railway.
REASON_OK = "ok"
REASON_NO_TOKEN = "brak_tokenu"
REASON_BAD_TOKEN = "niewazny_token"
REASON_EXPIRED = "wygasly_token"
REASON_NO_JUDGE = "token_bez_numeru"
REASON_NOT_ADMIN = "nie_admin"


def strict_mode() -> bool:
    """Czy zapis bez ważnego tokenu admina ma być odrzucany."""
    return os.getenv(STRICT_ENV, "").strip().lower() in _TRUE


def is_public_write(method: str, path: str) -> bool:
    return (method.upper(), (path or "").rstrip("/") or "/") in PUBLIC_WRITES


def bearer_token(authorization: Optional[str]) -> str:
    """Sam token z `Authorization: Bearer ...`, albo pusty napis."""
    parts = str(authorization or "").strip().split(" ", 1)
    if len(parts) != 2 or parts[0].strip().lower() != "bearer":
        return ""
    return parts[1].strip()


def decode_token(token: str) -> tuple[Optional[dict], str]:
    """(payload, powód). Payload tylko wtedy, gdy token jest ważny i ma numer."""
    if not token:
        return None, REASON_NO_TOKEN

    # Import w środku: `app.deps` czyta ustawienia z env, a moduł ma dać się
    # testować bez kompletu zmiennych Railway (testy podmieniają tę funkcję).
    from jose import ExpiredSignatureError, JWTError, jwt

    from app.deps import get_settings

    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except ExpiredSignatureError:
        return None, REASON_EXPIRED
    except JWTError:
        return None, REASON_BAD_TOKEN
    if not str(payload.get("judge_id") or "").strip():
        return None, REASON_NO_JUDGE
    return payload, REASON_OK


async def read_admin_ids() -> set[str]:
    """Lista adminów aplikacji - ta sama, którą pokazuje `GET /admin/admins`."""
    from sqlalchemy import select

    from app.db import admin_settings, database

    row = await database.fetch_one(select(admin_settings).limit(1))
    allowed = (row["allowed_admins"] if row else []) or []
    return {str(a).strip() for a in allowed if str(a).strip()}


def _refusal(reason: str) -> HTTPException:
    """Odmowa, która mówi, co się stało i co z tym zrobić."""
    if reason == REASON_NOT_ADMIN:
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Tę zmianę może zapisać tylko administrator aplikacji. "
                "O nadanie uprawnień poproś innego administratora."
            ),
        )
    if reason == REASON_EXPIRED:
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesja wygasła. Wyloguj się i zaloguj ponownie, a potem powtórz zapis.",
        )
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=(
            "Zapis w panelu administratora wymaga zalogowania. "
            "Zaktualizuj aplikację, zaloguj się ponownie i powtórz zapis."
        ),
    )


async def check_admin_write(
    *,
    method: str,
    path: str,
    authorization: Optional[str],
    client: str = "",
    user_agent: str = "",
    app_version: str = "",
) -> Optional[str]:
    """Wpuszcza albo odmawia. Zwraca numer admina, gdy token go dowiódł.

    Czysta od FastAPI, żeby testy nie potrzebowały ani serwera, ani bazy.
    """
    if method.upper() in READ_METHODS or is_public_write(method, path):
        return None

    payload, reason = decode_token(bearer_token(authorization))
    judge_id = str((payload or {}).get("judge_id") or "").strip()

    if payload is not None:
        try:
            admins = await read_admin_ids()
        except Exception:  # noqa: BLE001
            # Bez listy nie rozstrzygniemy - w trybie twardym to odmowa (lepiej
            # powtórzyć zapis niż wpuścić każdego), w przejściowym ślad i dalej.
            log.warning("[admin_guard] odczyt listy adminow nieudany", exc_info=True)
            admins = set()
        if judge_id in admins:
            return judge_id
        reason = REASON_NOT_ADMIN

    strict = strict_mode()
    # Ślad w obu trybach: przed zamknięciem furtki pokazuje, kto jeszcze pisze
    # bez nagłówka, po zamknięciu - kogo odbiliśmy.
    log.warning(
        "[admin_guard] zapis bez uprawnien: %s %s powod=%s judge_id=%s tryb=%s "
        "klient=%s wersja=%s ua=%s",
        method.upper(),
        path,
        reason,
        judge_id or "-",
        "twardy" if strict else "przejsciowy",
        client or "-",
        app_version or "-",
        (user_agent or "-")[:120],
    )
    if strict:
        raise _refusal(reason)
    return None


async def admin_write_guard(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_app_version: Optional[str] = Header(None, alias="X-App-Version"),
) -> Optional[str]:
    """Zależność routera: `APIRouter(..., dependencies=[Depends(admin_write_guard)])`.

    Wisi na CAŁYM routerze, więc nowa trasa zapisu dopisana do `app/admin.py`
    jest chroniona od pierwszego dnia - otwarcie jej wymaga świadomego wpisu
    w `PUBLIC_WRITES`.
    """
    return await check_admin_write(
        method=request.method,
        path=request.url.path,
        authorization=authorization,
        client=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
        app_version=x_app_version or "",
    )

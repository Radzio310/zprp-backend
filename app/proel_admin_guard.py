# app/proel_admin_guard.py
#
# Bramka tras administratora, które przedstawiają się nagłówkami aktora ProEl:
#
#   * `/admin/extra-report/*`     (app/extra_reports.py, `admin_router`),
#   * `/admin/training/spk/*`     (app/training_spk.py, `admin_router`),
#   * `/proel/users/admin/*`      (app/proel_users/users.py).
#
# DZIURA, KTÓRĄ ZAMYKA. Te trasy sprawdzały `is_admin(actor.judge_id)`, a
# `proel_actor` oddaje aktora także wtedy, gdy pary `X-Judge-Id` +
# `X-Installation-Id` nie ma w rejestrze urządzeń (`verified=False` - tak musi
# być, bo sędzia bez zgody na powiadomienia nigdy do rejestru nie trafia).
# Wystarczyło więc wysłać numer sędziego admina - a numery są półjawne - z
# dowolnym identyfikatorem instalacji, żeby przepisać adresatów raportów
# dodatkowych albo zablokować i zanonimizować konto ProEl.
#
# DOWÓD TOŻSAMOŚCI. Numer z nagłówka jest deklaracją. Admina uznajemy, gdy
# jego numer potwierdza coś podpisanego przez serwer:
#
#   * `X-Admin-Token` - token JWT z logowania do BAZY (numer w nim pochodzi z
#     baza.zprp.pl), ten sam, który wpuszcza do `/admin/*` (`app/admin_guard.py`).
#     Osobny nagłówek, bo `Authorization` na trasach ProEla oznacza token KONTA
#     ProEl i `proel_actor` odbija JWT BAZY jako 401 ACTOR_REQUIRED,
#   * sesja podniesiona (`X-Elevation`, `actor.elevated`),
#   * token konta ProEl z potwierdzonym numerem sędziego (`Authorization` +
#     `actor.verified`).
#
# Sam rejestr urządzeń (`verified` bez tokenu) dowodem NIE jest: identyfikator
# instalacji ląduje w overlayu i dzienniku meczu (`Actor.as_by`), więc bywa
# czytelny dla innych. Log mówi jednak, czy urządzenie było w rejestrze -
# `urzadzenie=niepotwierdzone` przy numerze admina to dokładnie ten atak.
#
# OKRES PRZEJŚCIOWY, jak w `app/admin_guard.py` i `app/province_guard.py`.
# Wersje w sklepie nie wysyłają `X-Admin-Token`, więc:
#
#   * dopóki `PROEL_ADMIN_STRICT` nie jest ustawione, bramka NICZEGO nie
#     odrzuca - niedowiedziony admin zostawia wpis `[proel_admin_guard]`
#     z powodem (brak_tokenu / niewazny_token / wygasly_token / inny_sedzia),
#   * `PROEL_ADMIN_STRICT=1` na Railway zamyka furtkę (restart, bez wydania),
#     gdy w logu przestaną się pojawiać `powod=brak_tokenu` od prawdziwych
#     adminów.
#
# Aktor, który NIE jest na liście adminów, przechodzi przez bramkę bez słowa:
# odmowę 403 daje mu sama trasa, dokładnie taką jak dotąd.

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status

from app.admin_guard import (
    REASON_BAD_TOKEN,
    REASON_EXPIRED,
    REASON_NO_TOKEN,
    REASON_OK,
    bearer_token,
    decode_token,
)
from app.proel_auth import Actor, proel_actor

log = logging.getLogger(__name__)

#: Nazwa zmiennej środowiskowej zamykającej okres przejściowy.
STRICT_ENV = "PROEL_ADMIN_STRICT"

#: Nagłówek z tokenem JWT BAZY. NIE `Authorization` - patrz nagłówek pliku.
ADMIN_TOKEN_HEADER = "X-Admin-Token"

_TRUE = {"1", "true", "tak", "yes", "on"}

# Powody w logu - stałe, żeby dało się je grepować na Railway.
REASON_OTHER_JUDGE = "inny_sedzia"

PROOF_TOKEN = "token"
PROOF_ELEVATION = "podniesienie"
PROOF_ACCOUNT = "konto"


def strict_mode() -> bool:
    """Czy niedowiedziony admin ma być odrzucany."""
    return os.getenv(STRICT_ENV, "").strip().lower() in _TRUE


def _clean(v: object) -> str:
    return str(v or "").strip()


def admin_token_value(raw: Optional[str]) -> str:
    """Token z `X-Admin-Token` - przyjmujemy go goły albo z przedrostkiem `Bearer`."""
    value = _clean(raw)
    if not value:
        return ""
    return bearer_token(value) or value


async def claims_admin(judge_id: str) -> bool:
    """Czy numer z nagłówka jest na liście adminów. Osobno, żeby test go podmienił."""
    from app.proel_auth import is_admin

    return await is_admin(judge_id)


def identity_proof(
    actor: Actor, *, admin_token: Optional[str], account_header: bool
) -> tuple[Optional[str], str]:
    """(czym dowiedziono numer aktora, powód braku dowodu).

    Czysta od bazy i FastAPI - rozstrzyga wyłącznie na tym, co przyszło.
    """
    if actor.elevated:
        return PROOF_ELEVATION, REASON_OK
    if account_header and actor.verified:
        # `Authorization` na trasie ProEla, a `proel_actor` nie rzucił - więc
        # aktora złożył podpisany token konta, nie para nagłówków.
        return PROOF_ACCOUNT, REASON_OK

    payload, reason = decode_token(admin_token_value(admin_token))
    if payload is None:
        return None, reason
    if _clean(payload.get("judge_id")) != _clean(actor.judge_id):
        # Token dowodzi, kim jest ktoś INNY niż numer z nagłówka. Nie
        # wybieramy, któremu wierzyć - to ma się zgadzać.
        return None, REASON_OTHER_JUDGE
    return PROOF_TOKEN, REASON_OK


def _refusal(reason: str) -> HTTPException:
    """Odmowa, która mówi, co się stało i co z tym zrobić."""
    if reason == REASON_EXPIRED:
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Sesja administratora wygasła. Wyloguj się i zaloguj ponownie, "
                "a potem powtórz."
            ),
        )
    if reason == REASON_OTHER_JUDGE:
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Konto zalogowane w aplikacji nie zgadza się z tożsamością w ProElu. "
                "Wyloguj się, zaloguj na swoje konto administratora i powtórz."
            ),
        )
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=(
            "Ta operacja wymaga potwierdzenia, że jesteś administratorem. "
            "Zaktualizuj aplikację, zaloguj się ponownie i powtórz."
        ),
    )


async def check_proel_admin(
    actor: Actor,
    *,
    method: str,
    path: str,
    admin_token: Optional[str],
    account_header: bool,
    client: str = "",
    user_agent: str = "",
    app_version: str = "",
) -> Optional[str]:
    """Przepuszcza albo odmawia. Zwraca rodzaj dowodu, gdy admin go przedstawił.

    Czysta od FastAPI, żeby testy nie potrzebowały ani serwera, ani bazy.
    """
    try:
        admin = await claims_admin(actor.judge_id)
    except Exception:  # noqa: BLE001
        # Bez listy nie wiemy, czy to admin. Trasa i tak zapyta o nią sama i
        # odmówi - bramka nie ma tu nic do dodania.
        log.warning("[proel_admin_guard] odczyt listy adminow nieudany", exc_info=True)
        return None
    if not admin:
        return None

    proof, reason = identity_proof(
        actor, admin_token=admin_token, account_header=account_header
    )
    if proof is not None:
        return proof

    strict = strict_mode()
    # Ślad w obu trybach: przed zamknięciem furtki pokazuje, kto jeszcze
    # przychodzi bez tokenu, po zamknięciu - kogo odbiliśmy.
    log.warning(
        "[proel_admin_guard] admin niedowiedziony: %s %s powod=%s judge_id=%s "
        "urzadzenie=%s tryb=%s klient=%s wersja=%s ua=%s",
        (method or "").upper(),
        path,
        reason,
        actor.judge_id or "-",
        "potwierdzone" if actor.verified else "niepotwierdzone",
        "twardy" if strict else "przejsciowy",
        client or "-",
        app_version or "-",
        (user_agent or "-")[:120],
    )
    if strict:
        raise _refusal(reason)
    return None


async def proel_admin_guard(
    request: Request,
    actor: Actor = Depends(proel_actor),
    x_admin_token: Optional[str] = Header(None, alias=ADMIN_TOKEN_HEADER),
    authorization: Optional[str] = Header(None),
    x_app_version: Optional[str] = Header(None, alias="X-App-Version"),
) -> Optional[str]:
    """Zależność: na całym routerze admina albo na pojedynczej trasie.

    `proel_actor` jest tu tą samą zależnością co w trasie, więc FastAPI liczy
    go raz na żądanie. Obejmuje też odczyty: listy adresatów, kont ProEl czy
    wyników szkolenia to dane osobowe, a nie manifesty pobierane przed
    zalogowaniem.
    """
    kwargs = dict(
        method=request.method,
        path=request.url.path,
        admin_token=x_admin_token,
        account_header=bool(_clean(authorization)),
        client=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
        app_version=x_app_version or "",
    )
    if not strict_mode():
        # Okres przejściowy: bramka ma WYŁĄCZNIE patrzeć. Cokolwiek w niej
        # pęknie, żądanie idzie dalej tak jak przed jej wdrożeniem.
        try:
            return await check_proel_admin(actor, **kwargs)
        except HTTPException:
            raise
        except Exception:  # noqa: BLE001
            log.warning("[proel_admin_guard] awaria bramki - przepuszczam", exc_info=True)
            return None
    return await check_proel_admin(actor, **kwargs)

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
import time
from dataclasses import dataclass, field
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


# ─────────────── uprawnienie admina W MECZU (miękka odmiana) ───────────────
#
# Nie każde `is_admin(actor.judge_id)` jest bramką trasy. W `app/proel.py`
# administrator bywa DODATKIEM do tego, co aktor i tak może w tym meczu:
#
#   * `_may_approve`     - zatwierdzenie należy do delegata (a gdy go nie ma,
#     do sędziów prowadzących); admin jest tu drugą drogą,
#   * `POST /proel/patch`- admin pisze pole mimo braku roli i wygrywa scalanie,
#   * `POST /proel/lease` z `force` - przejęcie prowadzenia komuś innemu.
#
# Twarda odmowa byłaby w tych miejscach GORSZA od dziury, którą zamykamy:
# delegat, który przy okazji jest administratorem, przestałby zatwierdzać
# własny mecz, a sędzia z obsady - zapisywać pola, do których ma rolę. Odmowa
# przyszłaby przy tym w hali, w trakcie meczu, za coś, o co nikt nie prosił.
#
# Dlatego niedowiedziony numer admina nie odbija żądania - traci sam DODATEK:
# aktor zostaje ze swoimi rolami z obsady i idzie dalej tą samą drogą, co
# każdy sędzia. Gdy ról nie ma, odmowę wystawia jak dotąd sama trasa, swoim
# komunikatem („Nie masz roli uprawniającej do tej zmiany", „Mecz prowadzi już
# inna osoba"), więc nikt nie dostaje komunikatu o administratorze w miejscu,
# w którym administratorem być nie musi.
#
# Okres przejściowy działa tu tak samo: dopóki `PROEL_ADMIN_STRICT` nie jest
# ustawione, uprawnienie ZOSTAJE (zmienia się tylko wpis w logu), po zamknięciu
# furtki - znika.

#: Jak często ten sam niedowiedziony admin trafia do logu (sekundy).
#:
#: `GET /proel/state` odpytuje prowadzące urządzenie co kilka sekund, a
#: `_may_approve` siedzi w jego odpowiedzi. Wpis przy każdym odpytaniu
#: zasypałby log Railway dokładnie tym jednym zdaniem i schował pod nim resztę
#: - a do zamknięcia furtki wystarczy wiedzieć, ŻE taki admin przychodzi.
SOFT_LOG_EVERY_SECONDS = 600

#: (numer, ścieżka, powód) -> kiedy ostatnio poszło do logu.
_soft_log_seen: dict[tuple[str, str, str], float] = {}


def _soft_log_due(key: tuple[str, str, str], now: Optional[float] = None) -> bool:
    """Czy ten sam wpis wolno powtórzyć. Pamięć jest procesu, nie bazy."""
    stamp = time.monotonic() if now is None else now
    last = _soft_log_seen.get(key)
    if last is not None and stamp - last < SOFT_LOG_EVERY_SECONDS:
        return False
    if len(_soft_log_seen) > 500:
        # Restart Railway czyści to i tak; chodzi tylko o to, żeby słownik nie
        # rósł w nieskończoność przy tysiącu różnych numerów.
        _soft_log_seen.clear()
    _soft_log_seen[key] = stamp
    return True


@dataclass
class AdminRights:
    """Pytanie „czy TEN aktor ma tu uprawnienia administratora" z dowodem.

    Liczone LENIWIE i zapamiętywane na czas żądania: `POST /proel/patch`
    przechodzi kilkanaście operacji w pętli i żadna z nich nie ma powodu
    czytać listy adminów po raz drugi. Aktor, który adminem nie jest, kosztuje
    jeden odczyt listy i ani jednego wpisu w logu.
    """

    admin_token: Optional[str] = None
    account_header: bool = False
    method: str = ""
    path: str = ""
    client: str = ""
    user_agent: str = ""
    app_version: str = ""
    _decided: dict[str, bool] = field(default_factory=dict, repr=False)

    async def granted(self, actor: Actor) -> bool:
        key = _clean(actor.judge_id)
        if key not in self._decided:
            self._decided[key] = await self._decide(actor)
        return self._decided[key]

    async def _decide(self, actor: Actor) -> bool:
        try:
            if not await claims_admin(actor.judge_id):
                return False
        except Exception:  # noqa: BLE001
            # Bez listy nie wiemy, czy to admin. Uprawnienia DODATKOWEGO nie
            # przyznajemy w ciemno - aktor zostaje ze swoimi rolami z obsady.
            log.warning("[proel_admin_guard] odczyt listy adminow nieudany", exc_info=True)
            return False

        proof, reason = identity_proof(
            actor, admin_token=self.admin_token, account_header=self.account_header
        )
        if proof is not None:
            return True

        strict = strict_mode()
        if _soft_log_due((_clean(actor.judge_id), self.path, reason)):
            log.warning(
                "[proel_admin_guard] uprawnienie admina w meczu niedowiedzione: "
                "%s %s powod=%s judge_id=%s urzadzenie=%s tryb=%s skutek=%s "
                "klient=%s wersja=%s ua=%s",
                (self.method or "").upper(),
                self.path or "-",
                reason,
                actor.judge_id or "-",
                "potwierdzone" if actor.verified else "niepotwierdzone",
                "twardy" if strict else "przejsciowy",
                "role_z_obsady" if strict else "uprawnienie_zostaje",
                self.client or "-",
                self.app_version or "-",
                (self.user_agent or "-")[:120],
            )
        # Okres przejściowy: uprawnienie zostaje, zmienia się tylko log.
        return not strict


def admin_rights(
    *,
    request: Optional[Request] = None,
    admin_token: Optional[str] = None,
    authorization: Optional[str] = None,
    app_version: Optional[str] = None,
) -> AdminRights:
    """`AdminRights` z tego, co przyszło - także tam, gdzie nagłówki bierze
    sama trasa (`PUT /proel/{numer}` czyta je po nazwach)."""
    return AdminRights(
        admin_token=admin_token,
        account_header=bool(_clean(authorization)),
        method=(request.method if request is not None else ""),
        path=(request.url.path if request is not None else ""),
        client=(request.client.host if request is not None and request.client else ""),
        user_agent=(request.headers.get("user-agent", "") if request is not None else ""),
        app_version=app_version or "",
    )


async def proel_admin_rights(
    request: Request,
    x_admin_token: Optional[str] = Header(None, alias=ADMIN_TOKEN_HEADER),
    authorization: Optional[str] = Header(None),
    x_app_version: Optional[str] = Header(None, alias="X-App-Version"),
) -> AdminRights:
    """Zależność dla tras, w których admin tylko ROZSZERZA swoje uprawnienia.

    Sama niczego nie odrzuca i nie czyta bazy - decyzja zapada dopiero przy
    `await rights.granted(actor)`, czyli w miejscu, w którym uprawnienie
    administratora naprawdę byłoby użyte.
    """
    return admin_rights(
        request=request,
        admin_token=x_admin_token,
        authorization=authorization,
        app_version=x_app_version,
    )

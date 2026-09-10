# app/admin_guard.py
#
# Bramka zapisów pod `/admin/*` (routery z `app/admin.py` i `app/central_rates.py`).
#
# Do 10.09.2026 te trasy nie sprawdzały NIC: kto znał adres backendu, mógł bez
# logowania nadpisać stawki ryczałtów, przepisy, kontakty, listę adminów, a
# nawet PIN dowolnego admina. Odczyty zostają otwarte - aplikacja pobiera
# manifesty, stawki i pliki JSON przed zalogowaniem i w tle.
#
# Tożsamość = token JWT z logowania do BAZY (`Authorization: Bearer ...`),
# ten sam, który już wpuszcza do pokazów wersji (`require_release_admin`).
# Numer sędziego w tokenie pochodzi z logowania do baza.zprp.pl, więc nie da
# się go podać samemu. PIN zostaje zamkiem ekranu w aplikacji - na serwer się
# nie nadaje (nowi admini dostają "0000", a sprawdzenie nie wydaje niczego).
#
# Nie każdy zapis pod `/admin` robi admin. Poziomy, od najluźniejszego:
#
#   * PUBLIC_WRITES  - otwarte zawsze (PIN przed wejściem do panelu, zgłoszenia),
#   * USER_WRITES    - każdy zalogowany (kontakty aktualizowane przy logowaniu),
#   * PROVINCE_WRITES- admin albo Match Master okręgu z adresu (stawki, odległości),
#   * cała reszta    - admin z listy `admin_settings.allowed_admins`.
#
# OKRES PRZEJŚCIOWY, tak samo jak w `app/province_guard.py`. Wersje aplikacji
# w sklepie wysyłają zapisy admina bez nagłówka. Twarda odmowa od razu
# zamknęłaby panel każdemu, kto nie zaktualizował aplikacji. Dlatego:
#
#   * dopóki `ADMIN_WRITE_STRICT` nie jest ustawione, bramka NICZEGO nie
#     odrzuca - każdy niedowiedziony zapis zostawia ostrzeżenie `[admin_guard]`
#     z powodem (brak_tokenu / niewazny_token / nie_admin ...),
#   * `ADMIN_WRITE_STRICT=1` na Railway zamyka furtkę. Wystarczy restart,
#     bez wydania backendu - gdy w logu przestaną się pojawiać wpisy
#     `powod=brak_tokenu` od prawdziwych adminów.
#
# Odrzucanie tokenu bez uprawnień już w okresie przejściowym nic by nie dało
# (napastnik po prostu nie wyśle nagłówka), a mogłoby zamknąć panel komuś, kto
# wchodzi PIN-em głównym spoza listy. Log pokaże, czy taki ktoś istnieje.

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from fastapi import Header, HTTPException, Request, status

log = logging.getLogger(__name__)

#: Nazwa zmiennej środowiskowej zamykającej okres przejściowy.
STRICT_ENV = "ADMIN_WRITE_STRICT"

_TRUE = {"1", "true", "tak", "yes", "on"}

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

#: Zapisy pod `/admin` otwarte zawsze - także po zamknięciu furtki.
PUBLIC_WRITES = frozenset(
    {
        # sprawdzenie PIN-u przy wejściu do panelu - odbywa się PRZED byciem adminem
        ("POST", "/admin/validate_pin"),
        # zgłoszenie od użytkownika (starsze wersje; nowe piszą do /reports/)
        ("POST", "/admin/reports"),
        # zgłoszenie nowej hali - ręczne i automatyczne w tle (`utils/halls.ts`)
        ("POST", "/admin/halls/reports"),
    }
)

#: Zapisy każdego zalogowanego. Aplikacja wysyła je przy KAŻDYM logowaniu
#: (`LoginForm.tsx`) i przy zapisie własnego profilu, już z tokenem.
USER_WRITES = frozenset(
    {
        ("POST", "/admin/contacts/judges/upsert"),
        ("POST", "/admin/contacts/clubs/upsert"),
    }
)

#: Zapisy okręgowe: admin albo Master danego rodzaju w okręgu z adresu.
#: Rodzaj jak w aplikacji - stawki i odległości edytuje Match Master
#: (`OkregRatesModal.tsx`, `DistanceTable.tsx`).
PROVINCE_WRITE_PREFIXES = {
    "/admin/okreg_rates/": "match",
    "/admin/okreg_distances/": "match",
}

TIER_READ = "odczyt"
TIER_PUBLIC = "publiczny"
TIER_USER = "zalogowany"
TIER_PROVINCE = "okregowy"
TIER_ADMIN = "admin"

# Powody zapisywane w logu - stałe, żeby dało się je grepować na Railway.
REASON_OK = "ok"
REASON_NO_TOKEN = "brak_tokenu"
REASON_BAD_TOKEN = "niewazny_token"
REASON_EXPIRED = "wygasly_token"
REASON_NO_JUDGE = "token_bez_numeru"
REASON_ORG = "konto_organizacji"
REASON_NOT_ADMIN = "nie_admin"
REASON_NOT_MASTER = "nie_master"


def strict_mode() -> bool:
    """Czy niedowiedziony zapis ma być odrzucany."""
    return os.getenv(STRICT_ENV, "").strip().lower() in _TRUE


def _norm_path(path: str) -> str:
    return (path or "").rstrip("/") or "/"


def classify(method: str, path: str) -> tuple[str, str]:
    """(poziom, rodzaj Mastera). Rodzaj ma sens tylko dla poziomu okręgowego."""
    m = (method or "").upper()
    if m in READ_METHODS:
        return TIER_READ, ""
    key = (m, _norm_path(path))
    if key in PUBLIC_WRITES:
        return TIER_PUBLIC, ""
    if key in USER_WRITES:
        return TIER_USER, ""
    for prefix, kind in PROVINCE_WRITE_PREFIXES.items():
        if (path or "").startswith(prefix):
            return TIER_PROVINCE, kind
    return TIER_ADMIN, ""


def bearer_token(authorization: Optional[str]) -> str:
    """Sam token z `Authorization: Bearer ...`, albo pusty napis."""
    parts = str(authorization or "").strip().split(" ", 1)
    if len(parts) != 2 or parts[0].strip().lower() != "bearer":
        return ""
    return parts[1].strip()


def decode_token(token: str) -> tuple[Optional[dict], str]:
    """(payload, powód). Payload tylko dla ważnego tokenu BAZY (z `sub`)."""
    if not token:
        return None, REASON_NO_TOKEN

    # Import w środku: `app.deps` czyta ustawienia z env, a moduł ma dać się
    # testować bez kompletu zmiennych Railway (testy podmieniają ustawienia).
    from jose import ExpiredSignatureError, JWTError, jwt

    from app.deps import get_settings

    try:
        settings = get_settings()
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except ExpiredSignatureError:
        return None, REASON_EXPIRED
    except JWTError:
        return None, REASON_BAD_TOKEN
    except Exception:  # noqa: BLE001
        # Awaria samej bramki (ustawienia, biblioteka) nie może wywrócić
        # zapisu w okresie przejściowym - traktujemy to jak token niedowiedziony.
        log.warning("[admin_guard] dekodowanie tokenu nieudane", exc_info=True)
        return None, REASON_BAD_TOKEN
    if not isinstance(payload, dict) or payload.get("sub") is None:
        return None, REASON_BAD_TOKEN
    return payload, REASON_OK


async def read_admin_ids() -> set[str]:
    """Lista adminów aplikacji - ta sama, którą pokazuje `GET /admin/admins`."""
    from sqlalchemy import select

    from app.db import admin_settings, database

    row = await database.fetch_one(select(admin_settings).limit(1))
    allowed = (row["allowed_admins"] if row else []) or []
    return {str(a).strip() for a in allowed if str(a).strip()}


async def read_province_lists(kind: str, province: Any) -> tuple[list, list]:
    """Masterzy rodzaju `kind` w okręgu + admini - wspólny odczyt z bramką okręgową."""
    from app.province_guard import _read_access_lists

    return await _read_access_lists(kind, province)


async def _authorize(tier: str, kind: str, province: Any, payload: dict) -> tuple[bool, str]:
    """Czy WAŻNY token wystarcza na ten poziom. (wpuścić, powód odmowy)."""
    if tier == TIER_USER:
        return True, REASON_OK

    judge_id = str(payload.get("judge_id") or "").strip()
    if str(payload.get("account_type") or "").strip().lower() == "org":
        # Konto klubu czy związku nie ma numeru sędziego, więc nie może być na
        # żadnej liście - tak samo jak w `app/province_guard.py`.
        return False, REASON_ORG
    if not judge_id:
        return False, REASON_NO_JUDGE

    if tier == TIER_PROVINCE:
        from app.province_access import may_write_province

        masters, admins = await read_province_lists(kind, province)
        allowed = may_write_province(
            judge_id=judge_id, master_judge_ids=masters, admin_ids=admins
        )
        return allowed, (REASON_OK if allowed else REASON_NOT_MASTER)

    allowed = judge_id in await read_admin_ids()
    return allowed, (REASON_OK if allowed else REASON_NOT_ADMIN)


def _refusal(tier: str, reason: str, province: Any) -> HTTPException:
    """Odmowa, która mówi, co się stało i co z tym zrobić."""
    if reason == REASON_EXPIRED:
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesja wygasła. Wyloguj się i zaloguj ponownie, a potem powtórz zapis.",
        )
    if reason in (REASON_NO_TOKEN, REASON_BAD_TOKEN):
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Ten zapis wymaga zalogowania. "
                "Zaktualizuj aplikację, zaloguj się ponownie i powtórz zapis."
            ),
        )
    if tier == TIER_PROVINCE:
        from app.province_access import normalize_province

        prov = normalize_province(province)
        where = f" w okręgu {prov}" if prov else ""
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Tę zmianę może zapisać Match Master{where} albo administrator "
                "aplikacji. O nadanie uprawnień poproś administratora."
            ),
        )
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            "Tę zmianę może zapisać tylko administrator aplikacji. "
            "O nadanie uprawnień poproś innego administratora."
        ),
    )


async def check_admin_write(
    *,
    method: str,
    path: str,
    authorization: Optional[str],
    province: Any = None,
    client: str = "",
    user_agent: str = "",
    app_version: str = "",
) -> Optional[str]:
    """Wpuszcza albo odmawia. Zwraca numer sędziego, gdy token dowiódł uprawnień.

    Czysta od FastAPI, żeby testy nie potrzebowały ani serwera, ani bazy.
    """
    tier, kind = classify(method, path)
    if tier in (TIER_READ, TIER_PUBLIC):
        return None

    payload, reason = decode_token(bearer_token(authorization))
    judge_id = str((payload or {}).get("judge_id") or "").strip()

    if payload is not None:
        try:
            allowed, reason = await _authorize(tier, kind, province, payload)
        except Exception:  # noqa: BLE001
            # Bez list nie rozstrzygniemy - w trybie twardym to odmowa (lepiej
            # powtórzyć zapis niż wpuścić każdego), w przejściowym ślad i dalej.
            log.warning("[admin_guard] odczyt list uprawnien nieudany", exc_info=True)
            allowed, reason = False, (REASON_NOT_MASTER if tier == TIER_PROVINCE else REASON_NOT_ADMIN)
        if allowed:
            return judge_id or None

    strict = strict_mode()
    # Ślad w obu trybach: przed zamknięciem furtki pokazuje, kto jeszcze pisze
    # bez nagłówka, po zamknięciu - kogo odbiliśmy.
    log.warning(
        "[admin_guard] zapis niedowiedziony: %s %s poziom=%s powod=%s judge_id=%s "
        "okreg=%s tryb=%s klient=%s wersja=%s ua=%s",
        method.upper(),
        path,
        tier,
        reason,
        judge_id or "-",
        province or "-",
        "twardy" if strict else "przejsciowy",
        client or "-",
        app_version or "-",
        (user_agent or "-")[:120],
    )
    if strict:
        raise _refusal(tier, reason, province)
    return None


async def admin_write_guard(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_app_version: Optional[str] = Header(None, alias="X-App-Version"),
) -> Optional[str]:
    """Zależność routera: `APIRouter(..., dependencies=[Depends(admin_write_guard)])`.

    Wisi na CAŁYM routerze, więc nowa trasa zapisu dopisana do `app/admin.py`
    jest od pierwszego dnia trasą admina - luźniejszy poziom wymaga
    świadomego wpisu w `PUBLIC_WRITES` / `USER_WRITES` / `PROVINCE_WRITE_PREFIXES`.
    """
    if request.method.upper() in READ_METHODS:
        # Odczyty nie dotykają nawet klasyfikacji - manifesty odpytywane w tle
        # co kilkanaście minut mają iść tą samą drogą co przed bramką.
        return None
    if not strict_mode():
        # Okres przejściowy: bramka ma WYŁĄCZNIE patrzeć. Cokolwiek w niej
        # pęknie, zapis idzie dalej tak jak przed jej wdrożeniem.
        try:
            return await _check_request(request, authorization, x_app_version)
        except HTTPException:
            raise
        except Exception:  # noqa: BLE001
            log.warning("[admin_guard] awaria bramki - przepuszczam", exc_info=True)
            return None
    return await _check_request(request, authorization, x_app_version)


async def _check_request(
    request: Request, authorization: Optional[str], x_app_version: Optional[str]
) -> Optional[str]:
    return await check_admin_write(
        method=request.method,
        path=request.url.path,
        authorization=authorization,
        # Województwo z parametru trasy, nie z treści - bramka pyta o okręg,
        # którego dotyczy adres.
        province=request.path_params.get("province"),
        client=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent", ""),
        app_version=x_app_version or "",
    )

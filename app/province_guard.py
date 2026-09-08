# app/province_guard.py
#
# Bramka przy zapisach okręgowych: czyta bazę, pyta liścia `province_access`
# i albo przepuszcza, albo odmawia z powodem.
#
# OKRES PRZEJŚCIOWY. Aplikacje, które ludzie mają dziś w telefonach, wysyłają
# część żądań okręgowych BEZ tokenu (ekran dodawania ogłoszenia nie dokładał
# nagłówka). Gdyby bramka od razu odcinała takie żądania, dodawanie ogłoszeń
# przestałoby działać wszystkim, którzy nie zaktualizowali aplikacji. Dlatego:
#
#   * żądanie Z tokenem jest sprawdzane zawsze i bez ulgi,
#   * żądanie BEZ tokenu przechodzi i zostawia ostrzeżenie w logu,
#   * zmienna `PROVINCE_WRITE_STRICT=1` na Railway zamyka tę furtkę na głucho,
#     gdy stare wersje wygasną. Nie wymaga to wydania backendu - tylko restartu.
#
# Konta organizacji (`account_type == "org"`) NIE przechodzą, i tu świadomie
# różnimy się od `app/board.py`. Konto klubu czy związku nie ma numeru sędziego,
# więc nie może być na żadnej liście Masterów - a skoro aplikacja i tak nie
# pokazuje mu przycisków, to serwer nie ma powodu przyjmować od niego zapisu.

from __future__ import annotations

import logging
import os
from typing import Any, Optional, Tuple

from fastapi import HTTPException, status

from app.province_access import (
    MASTER_CALENDAR,
    MASTER_KINDS,
    MASTER_NEWS,
    master_ids_for_province,
    may_write_offtimes,
    may_write_province,
    normalize_province,
)

log = logging.getLogger(__name__)

#: Nazwa zmiennej środowiskowej zamykającej okres przejściowy.
STRICT_ENV = "PROVINCE_WRITE_STRICT"

_TRUE = {"1", "true", "tak", "yes", "on"}

#: Jak nazwać uprawnienie w komunikacie dla człowieka.
MASTER_LABELS = {
    "news": "News Mastera",
    "calendar": "Calendar Mastera",
    "match": "Match Mastera",
    "teach": "Teach Mastera",
}


def strict_mode() -> bool:
    """Czy żądanie bez tokenu ma być odrzucane."""
    return os.getenv(STRICT_ENV, "").strip().lower() in _TRUE


def actor_judge_id(payload: Optional[dict]) -> str:
    """Numer sędziego z tokenu - jedyne źródło tożsamości, jakie tu uznajemy.

    Numer w tokenie pochodzi z logowania w bazie ZPRP (`app/auth.py` wyciąga go
    z `NrSedzia`), więc nie da się go podać samemu. Numer przysłany w treści
    żądania celowo NIE jest brany pod uwagę.
    """
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("judge_id") or "").strip()


def _account_type(payload: Optional[dict]) -> str:
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("account_type") or "").strip().lower()


async def _read_access_lists(kind: str, province: Any) -> Tuple[list, list]:
    """Lista Masterów danego rodzaju w okręgu oraz lista adminów aplikacji."""
    # Import w środku: `app.db` żąda żywej bazy już przy imporcie, a ten moduł
    # ma dać się czytać testom bez Postgresa.
    from sqlalchemy import select

    from app.db import (
        admin_settings,
        calendar_masters,
        database,
        match_masters,
        news_masters,
        teach_masters,
    )

    tables = {
        "news": news_masters,
        "calendar": calendar_masters,
        "match": match_masters,
        "teach": teach_masters,
    }
    table = tables[kind]

    rows = await database.fetch_all(select(table))
    masters = master_ids_for_province(rows, province)

    admin_row = await database.fetch_one(select(admin_settings).limit(1))
    admins = (admin_row["allowed_admins"] if admin_row else []) or []
    return masters, list(admins)


def _denied(action: str, kind: str, province: Any) -> HTTPException:
    """Odmowa, która tłumaczy się sama i mówi, co z tym zrobić."""
    label = MASTER_LABELS.get(kind, "Mastera")
    prov = normalize_province(province)
    where = f" w okręgu {prov}" if prov else ""
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            f"{action} wymaga uprawnień {label}{where}. "
            "O nadanie poproś administratora aplikacji."
        ),
    )


async def ensure_province_write(
    payload: Optional[dict],
    *,
    province: Any,
    kind: str = MASTER_NEWS,
    action: str = "Ta operacja",
    target_judge_id: Any = None,
) -> None:
    """Wpuszcza albo odmawia. Nic nie zwraca - liczy się to, czy rzuci.

    `target_judge_id` podany oznacza zapis pod konkretnego sędziego: po swoich
    pisze każdy zalogowany, po cudzych tylko Master okręgu albo admin.
    """
    if kind not in MASTER_KINDS:
        raise ValueError(f"nieznany rodzaj uprawnienia: {kind!r}")

    if payload is None:
        if strict_mode():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=(
                    f"{action} wymaga zalogowania. "
                    "Zaloguj się w aplikacji i spróbuj ponownie."
                ),
            )
        # Okres przejściowy: przepuszczamy, ale zostawiamy ślad. Po tych wpisach
        # widać, kiedy stare wersje przestaną się odzywać i można domknąć bramkę.
        log.warning(
            "[province_guard] zapis bez tokenu: action=%s kind=%s province=%s",
            action,
            kind,
            normalize_province(province),
        )
        return

    if _account_type(payload) == "org":
        raise _denied(action, kind, province)

    judge_id = actor_judge_id(payload)
    if not judge_id:
        raise _denied(action, kind, province)

    masters, admins = await _read_access_lists(kind, province)

    if target_judge_id is None:
        allowed = may_write_province(
            judge_id=judge_id, master_judge_ids=masters, admin_ids=admins
        )
    else:
        allowed = may_write_offtimes(
            judge_id=judge_id,
            target_judge_id=target_judge_id,
            master_judge_ids=masters,
            admin_ids=admins,
        )

    if not allowed:
        raise _denied(action, kind, province)


async def ensure_announcement_write(
    payload: Optional[dict],
    *,
    province: Any,
    action: str,
    extra_province: Any = None,
) -> None:
    """Bramka ogłoszeń. `extra_province` to okręg, DO którego wpis ma trafić.

    Przeniesienie ogłoszenia do innego województwa musi przejść przez OBIE
    listy - inaczej Master jednego okręgu wrzucałby wpisy do cudzego, mając
    uprawnienia wyłącznie u siebie.
    """
    await ensure_province_write(
        payload, province=province, kind=MASTER_NEWS, action=action
    )
    if extra_province is None:
        return
    if normalize_province(extra_province) == normalize_province(province):
        return
    await ensure_province_write(
        payload, province=extra_province, kind=MASTER_NEWS, action=action
    )


async def ensure_offtimes_write(
    payload: Optional[dict],
    *,
    province: Any,
    target_judge_id: Any,
    action: str,
) -> None:
    """Bramka niedyspozycji: swoje zawsze, cudze tylko Calendar Master."""
    await ensure_province_write(
        payload,
        province=province,
        kind=MASTER_CALENDAR,
        action=action,
        target_judge_id=target_judge_id,
    )

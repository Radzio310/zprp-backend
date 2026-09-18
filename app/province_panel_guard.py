"""
Bramka zapisów w panelach okręgu z BAZA_web: panel klubów i Obsada.

Do 18.09.2026 trasy zapisu pod `/province/clubs` i `/province/assignment` nie
sprawdzały NIC - kto znał adres API, zmieniał wpłaty i salda klubów, rozliczanie
przez okręg i deklaracje obsadowe. Reguła (kto może) siedzi w liściu
`province_panel_access`; tutaj tylko czytamy bazę i pilnujemy tras.

OKRES PRZEJŚCIOWY - ten sam, co w `province_guard`:
  - żądanie Z tokenem jest sprawdzane zawsze i bez ulgi,
  - żądanie BEZ tokenu przechodzi i zostawia ostrzeżenie w logu,
  - `PROVINCE_WRITE_STRICT=1` na Railway zamyka tę furtkę (wystarczy restart).
BAZA_web wysyła od tej wersji token przy każdym zapisie, więc po jej wdrożeniu
w logu nie powinno zostać żadne ostrzeżenie - to znak, że można domknąć.

BRAMKA NA CAŁYM ROUTERZE, nie przy każdej trasie: `panel_write_gate` przepuszcza
odczyty (GET, HEAD, OPTIONS), a każdą inną metodę sprawdza. Dzięki temu nowa
trasa zapisu nie może o bramce zapomnieć. Okręg bierze z parametru `province`
w adresie albo z pola `province` w treści JSON - tak samo, jak trasy przekazują
go do `require_province`. Formularzy z plikiem nie rozbieramy: import Excela
ma okręg w adresie.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional, Tuple

from fastapi import Depends, HTTPException, Request, status

from app.deps import get_optional_jwt_payload
from app.province_access import normalize_province
from app.province_guard import strict_mode
from app.province_panel_access import VipRecord, panel_write_refusal, vip_permissions

log = logging.getLogger(__name__)

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


async def _lookup(payload: dict) -> Tuple[bool, Optional[VipRecord]]:
    """(czy sędzia z tokenu jest adminem, rekord VIP konta z tokenu)."""
    # Import w środku: `app.db` łączy się z bazą przy imporcie, a testy
    # podmieniają tę funkcję, żeby sprawdzić samą bramkę.
    from sqlalchemy import func, select

    from app.admin_alerts import admin_judge_ids
    from app.db import baza_vips, database

    judge_id = _s(payload.get("judge_id"))
    if judge_id:
        admins = {_s(item) for item in await admin_judge_ids()}
        return judge_id in admins, None

    login = _s(payload.get("sub"))
    if not login:
        return False, None
    rows = await database.fetch_all(
        select(baza_vips.c.username, baza_vips.c.province, baza_vips.c.permissions_json).where(
            func.lower(baza_vips.c.username) == login.lower()
        )
    )
    if not rows:
        return False, None
    # Login bywa wpisany raz małymi, raz wielkimi literami - dokładne trafienie
    # wygrywa, a gdy go nie ma, bierzemy jedyny rekord tej samej nazwy.
    row = next((item for item in rows if _s(item["username"]) == login), rows[0])
    return False, VipRecord(
        username=_s(row["username"]),
        province=_s(row["province"]),
        permissions=vip_permissions(row["permissions_json"]),
    )


async def ensure_panel_write(
    payload: Optional[dict],
    *,
    province: Any,
    panel: str,
    action: str,
) -> None:
    """Wpuszcza albo odmawia z powodem. Nic nie zwraca - liczy się to, czy rzuci."""
    if payload is None:
        if strict_mode():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"{action} wymaga zalogowania. Zaloguj się ponownie i spróbuj jeszcze raz.",
            )
        # Okres przejściowy: przepuszczamy, ale zostawiamy ślad. Po tych wpisach
        # widać, czy ktoś jeszcze pisze bez tokenu i czy można domknąć bramkę.
        log.warning(
            "[province_panel_guard] zapis bez tokenu: action=%s panel=%s province=%s",
            action,
            panel,
            normalize_province(province),
        )
        return

    is_admin, vip = await _lookup(payload)
    reason = panel_write_refusal(
        panel=panel,
        province=province,
        account_type=_s(payload.get("account_type")),
        judge_id=_s(payload.get("judge_id")),
        login=_s(payload.get("sub")),
        is_admin=is_admin,
        vip=vip,
    )
    if reason:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"{action}: {reason}")


async def _request_province(request: Request) -> str:
    """Okręg z adresu, a gdy go tam nie ma - z pola `province` w treści JSON."""
    province = _s(request.query_params.get("province"))
    if province:
        return province
    if "application/json" not in (request.headers.get("content-type") or "").lower():
        return ""
    try:
        # FastAPI czyta treść PRZED zależnościami, więc to odczyt z pamięci,
        # a trasa i tak dostanie swój model bez ponownego czytania strumienia.
        body = await request.json()
    except Exception:  # noqa: BLE001 - zła treść odrzuci już sama trasa
        return ""
    return _s(body.get("province")) if isinstance(body, dict) else ""


def panel_write_gate(panel: str, action: str) -> Callable:
    """Zależność dla CAŁEGO routera panelu: odczyty wolne, zapisy przez bramkę."""

    async def gate(
        request: Request,
        payload: Optional[dict] = Depends(get_optional_jwt_payload),
    ) -> None:
        if request.method.upper() in READ_METHODS:
            return
        await ensure_panel_write(
            payload,
            province=await _request_province(request),
            panel=panel,
            action=action,
        )

    return gate

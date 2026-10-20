"""Server-side authorization gates for BAZA_web district panels."""

from __future__ import annotations

from typing import Any, Callable, Optional, Tuple

from fastapi import Depends, HTTPException, Request, status

from app.deps import get_jwt_payload, get_optional_jwt_payload
from app.province_panel_access import (
    VipRecord,
    choose_vip_row,
    panel_write_refusal,
    vip_permissions,
)

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


async def _lookup(payload: dict) -> Tuple[bool, Optional[VipRecord]]:
    """Return (is application admin, matching organization VIP record)."""
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
    row = choose_vip_row(rows, login)
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
    """Authorize one panel operation or raise a clear 401/403 response."""
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"{action} wymaga zalogowania. Zaloguj sie ponownie i sprobuj jeszcze raz.",
        )

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
    """Read province from query/path parameters or a JSON request body."""
    province = _s(request.query_params.get("province"))
    if province:
        return province
    province = _s(request.path_params.get("province"))
    if province:
        return province
    if "application/json" not in (request.headers.get("content-type") or "").lower():
        return ""
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return ""
    return _s(body.get("province")) if isinstance(body, dict) else ""


def panel_write_gate(panel: str, action: str) -> Callable:
    """Router dependency: public reads, authenticated and authorized writes."""

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


def panel_read_gate(panel: str, action: str) -> Callable:
    """Dependency for reads of private, district-wide data."""

    async def gate(
        request: Request,
        payload: dict = Depends(get_jwt_payload),
    ) -> None:
        await ensure_panel_write(
            payload,
            province=await _request_province(request),
            panel=panel,
            action=action,
        )

    return gate

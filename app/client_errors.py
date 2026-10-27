"""Zgłoszenia błędów rysowania z przeglądarki portalu BAZA pod RĘKĄ.

27.10.2026: ekran Statystyk pokazywał na telefonie właściciela karty „nie udało się
narysować”, których nie dało się odtworzyć poza tym telefonem (stare dane z pamięci
urządzenia). Granice błędów w przeglądarce (`StatsGuard`, `ScreenGuard`) wysyłają teraz
krótki raport, a admin widzi listę ostatnich awarii.

* `POST /api/v1/handball/client-errors` - publiczne (przeglądarka bez logowania), treść
  JSON jako `text/plain` (navigator.sendBeacon bez zapytania wstępnego CORS), najwyżej
  4 kB, 30 zgłoszeń na minutę z jednego adresu. Ten sam błąd (odcisk: rodzaj, trasa,
  część, komunikat, build) zwiększa licznik zamiast dokładać wiersz. Bez danych
  osobowych: adres IP służy tylko limitowi w pamięci procesu, do bazy nie trafia.
* `GET /api/v1/handball/admin/client-errors` - ostatnie zgłoszenia (admin).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import delete, func, insert, select, update

from app.admin_guard import admin_write_guard
from app.client_error_rules import MAX_BODY, MAX_ROWS, RATE_LIMIT, ReportError, clean_report, fingerprint
from app.db import client_error_reports, database
from app.pod_reka_login_rules import AttemptLimiter, client_key

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/handball", tags=["handball_client_errors"])
admin_router = APIRouter(
    prefix="/api/v1/handball/admin",
    tags=["handball_client_errors_admin"],
    dependencies=[Depends(admin_write_guard)],
)

limiter = AttemptLimiter(limit=RATE_LIMIT, window=timedelta(minutes=1), max_keys=20_000)


async def store_report(row: Dict[str, Any], now: Optional[datetime] = None) -> int:
    """Zapis albo +1 do licznika. Zwraca licznik po zapisie."""
    now = now or datetime.now(timezone.utc)
    fp = fingerprint(row)
    T = client_error_reports
    found = await database.fetch_one(select(T.c.id, T.c.count).where(T.c.fingerprint == fp))
    if found:
        count = int(found["count"] or 0) + 1
        await database.execute(update(T).where(T.c.id == found["id"]).values(
            count=count, last_at=now, ua=row.get("ua"), lite=row.get("lite"), standalone=row.get("standalone"), width=row.get("width")))
        return count
    await database.execute(insert(T).values(fingerprint=fp, count=1, created_at=now, last_at=now, **row))
    total = await database.fetch_val(select(func.count()).select_from(T))
    if total and total > MAX_ROWS:
        cutoff = await database.fetch_val(select(T.c.last_at).order_by(T.c.last_at.desc()).offset(MAX_ROWS - 1).limit(1))
        if cutoff is not None:
            await database.execute(delete(T).where(T.c.last_at < cutoff))
    return 1


@router.post("/client-errors", status_code=202)
async def report_client_error(request: Request) -> JSONResponse:
    address = client_key(request.headers.get("x-forwarded-for", ""), request.client.host if request.client else "")
    if limiter.blocked(address):
        return JSONResponse({"detail": "Zbyt wiele zgłoszeń. Spróbuj za chwilę."}, status_code=429,
                            headers={"Retry-After": str(limiter.retry_after(address))})
    limiter.fail(address)
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY:
        return JSONResponse({"detail": "Zgłoszenie jest za duże."}, status_code=413)
    raw = b""
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > MAX_BODY:
            return JSONResponse({"detail": "Zgłoszenie jest za duże."}, status_code=413)
    try:
        row = clean_report(raw)
    except ReportError as exc:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status)
    try:
        count = await store_report(row)
    except Exception:  # noqa: BLE001 - zgłoszenie jest dodatkiem, nie może wywrócić niczego
        log.warning("[client-error] zapis zgłoszenia nieudany", exc_info=True)
        count = None
    log.warning("[client-error] %s %s | %s | %s | build=%s lite=%s x%s", row["kind"], row["route"], row["part"],
                row["message"], row.get("build") or "-", row.get("lite"), count or "?")
    return JSONResponse({"ok": True, "count": count}, status_code=202)


async def client_errors_read_guard(authorization: Optional[str] = Header(default=None)) -> None:
    """Odczyt listy: jak w całej bramce admina - do `ADMIN_WRITE_STRICT` tylko ślad, potem token admina."""
    from app import admin_guard as guard

    payload, reason = guard.decode_token(guard.bearer_token(authorization))
    allowed = False
    if payload is not None:
        allowed, reason = await guard._authorize(guard.TIER_ADMIN, "", None, payload)
    if allowed:
        return
    if guard.strict_mode():
        raise guard._refusal(guard.TIER_ADMIN, reason, None)
    log.warning("[client-error] odczyt listy bez tokenu admina (okres przejściowy): %s", reason)


@admin_router.get("/client-errors", dependencies=[Depends(client_errors_read_guard)])
async def list_client_errors(limit: int = Query(default=100, ge=1, le=500), days: int = Query(default=7, ge=1, le=90),
                             kind: Optional[str] = None) -> Dict[str, Any]:
    T = client_error_reports
    since = datetime.now(timezone.utc) - timedelta(days=days)
    statement = select(T).where(T.c.last_at >= since).order_by(T.c.last_at.desc()).limit(limit)
    if kind:
        statement = statement.where(T.c.kind == kind)
    rows = [dict(r) for r in await database.fetch_all(statement)]
    items = [{
        "id": r["id"], "kind": r["kind"], "route": r["route"], "part": r["part"], "message": r["message"],
        "stack": r.get("stack"), "ua": r.get("ua"), "build": r.get("build"), "lite": r.get("lite"),
        "standalone": r.get("standalone"), "width": r.get("width"), "count": r["count"],
        "created_at": _iso(r.get("created_at")), "last_at": _iso(r.get("last_at")),
    } for r in rows]
    return {"items": items, "count": len(items), "total_reports": sum(i["count"] for i in items), "days": days}


def _iso(value: Any) -> Optional[str]:
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()
    return str(value) if value else None

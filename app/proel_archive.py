"""Archiwum usuniętych zapisów meczów ProEl.

Usunięcie zapisu przestało być nieodwracalne (patrz `delete_proel_match` w
`app/proel.py`): komplet przenosi się do `proel_deleted_matches` na rok. Ten
moduł daje administratorowi to, po co ta tabela w ogóle powstała - możliwość
zobaczenia, co zniknęło, i cofnięcia pomyłki.

⚠ Router MUSI być zarejestrowany PRZED `proel_router` w `main.py`. `app/proel.py`
ma catch-all `GET /proel/{match_number:path}`, więc `/proel/archive/...`
wpadłoby w `match_number="archive/..."` i zamiast listy archiwum wróciłoby
404 „nie znaleziono meczu".
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import delete, func, or_, select

from app.db import (
    database,
    proel_deleted_matches,
    proel_match_state,
    saved_matches,
)
from app.proel_auth import Actor, is_admin, proel_actor
from app.proel_journal import log_match_event

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/proel/archive", tags=["ProEl: archiwum"])

#: Ile trzymamy usunięty zapis. Ta sama wartość, którą wpisuje `delete`.
RETENTION_DAYS = 365


async def _require_admin(actor: Actor) -> None:
    if not await is_admin(actor.judge_id):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={
                "code": "ADMIN_REQUIRED",
                "message": "Archiwum usuniętych meczów jest dostępne tylko dla administratora.",
            },
        )


def _json_value(raw: Any) -> Any:
    """Kolumna JSON w ksztalcie, w jakim ja zapisano - niezaleznie od sterownika.

    asyncpg pod `databases` bez kodeka jsonb oddaje JSONB surowym NAPISEM.
    W archiwum leza i obiekty, i listy, wiec parsujemy do dowolnego ksztaltu;
    napis nie do sparsowania wraca bez zmian - lepszy surowy wpis niz zaden.
    """
    if isinstance(raw, (dict, list)) or raw is None:
        return raw
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw
    if isinstance(raw, str) and raw.strip():
        try:
            return json.loads(raw)
        except ValueError:
            return raw
    return raw


def _summary(row) -> Dict[str, Any]:
    """Wiersz archiwum BEZ ciężkich blobów - do listy.

    `data_json` potrafi mieć setki kilobajtów (pełny protokół z przebiegiem
    meczu). Lista pokazuje kilkadziesiąt pozycji, więc gdyby niosła blob,
    jedno wejście w zakładkę ściągałoby kilkanaście megabajtów.
    """
    data = row["data_json"] or {}
    cfg = (data.get("matchConfig") or {}) if isinstance(data, dict) else {}
    return {
        "id": row["id"],
        "match_number": row["match_number"],
        "zprp_match_id": row["zprp_match_id"],
        "status": row["status"],
        "host_team_name": cfg.get("hostTeamName"),
        "guest_team_name": cfg.get("guestTeamName"),
        "match_date": data.get("date") if isinstance(data, dict) else None,
        "is_test": bool(cfg.get("isTest")),
        "deleted_at": row["deleted_at"],
        "deleted_by_judge_id": row["deleted_by_judge_id"],
        "deleted_by_name": row["deleted_by_name"],
        "deleted_by_verified": bool(row["deleted_by_verified"]),
        "expires_at": row["expires_at"],
        "restored_at": row["restored_at"],
        "restored_by_judge_id": row["restored_by_judge_id"],
    }


async def _purge_expired() -> int:
    """Leniwe czyszczenie: kasuje wpisy starsze niż rok.

    Bez zadania cyklicznego - odpalane przy każdym wejściu do archiwum. To
    jedyne miejsce, które tę tabelę czyta, więc jest też jedynym, w którym
    warto po niej posprzątać, a rok to termin, nie sekunda.
    """
    try:
        return await database.execute(
            delete(proel_deleted_matches).where(
                proel_deleted_matches.c.expires_at.is_not(None),
                proel_deleted_matches.c.expires_at < datetime.now(timezone.utc),
            )
        )
    except Exception:
        # Sprzątanie nie ma prawa uniemożliwić odczytu archiwum.
        logger.warning("ProEl archiwum: czyszczenie przeterminowanych nie powiodło się", exc_info=True)
        return 0


@router.get("", summary="Lista usuniętych zapisów meczów (administrator)")
@router.get("/", include_in_schema=False)
async def list_deleted(
    actor: Actor = Depends(proel_actor),
    q: Optional[str] = Query(None, description="Numer meczu, drużyna lub kto usunął"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    await _require_admin(actor)
    await _purge_expired()

    where = []
    if q and q.strip():
        needle = f"%{q.strip().lower()}%"
        where.append(
            or_(
                func.lower(proel_deleted_matches.c.match_number).like(needle),
                func.lower(func.coalesce(proel_deleted_matches.c.deleted_by_name, "")).like(needle),
                func.lower(func.coalesce(proel_deleted_matches.c.zprp_match_id, "")).like(needle),
            )
        )

    total_q = select(func.count()).select_from(proel_deleted_matches)
    rows_q = select(proel_deleted_matches).order_by(
        proel_deleted_matches.c.deleted_at.desc()
    )
    for clause in where:
        total_q = total_q.where(clause)
        rows_q = rows_q.where(clause)

    total = await database.fetch_val(total_q)
    rows = await database.fetch_all(rows_q.limit(limit).offset(offset))

    return {
        "total": int(total or 0),
        "items": [_summary(r) for r in rows],
        "retention_days": RETENTION_DAYS,
    }


@router.get("/{entry_id}", summary="Usunięty zapis meczu w całości (administrator)")
async def get_deleted(
    entry_id: int,
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    await _require_admin(actor)

    row = await database.fetch_one(
        select(proel_deleted_matches).where(proel_deleted_matches.c.id == entry_id)
    )
    if row is None:
        raise HTTPException(
            404,
            detail={"code": "NOT_FOUND", "message": "Nie ma takiego wpisu w archiwum."},
        )

    out = _summary(row)
    # Przez parser, nie wprost: kolumna JSON potrafi wrocic z bazy surowym
    # napisem (asyncpg bez kodeka jsonb), a panel oczekuje obiektu.
    out["data_json"] = _json_value(row["data_json"])
    out["state_json"] = _json_value(row["state_json"])
    return out


@router.post("/{entry_id}/restore", summary="Przywróć usunięty zapis meczu (administrator)")
async def restore_deleted(
    entry_id: int,
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    """Wraca zapisem tam, skąd go usunięto.

    Świadomie NIE nadpisuje istniejącego meczu. Numer meczu bywa użyty ponownie
    (mecz założono jeszcze raz po skasowaniu), a wtedy przywrócenie zniszczyłoby
    świeży protokół, żeby oddać stary - czyli dokładnie ten sam błąd, przed
    którym to archiwum ma chronić. W takim wypadku admin dostaje 409 i decyduje
    sam, co zrobić z bieżącym zapisem.

    Overlay pól przywracamy tylko wtedy, gdy mecz go miał - starsze zapisy nie
    mają wiersza stanu i nie ma czego odtwarzać.
    """
    await _require_admin(actor)

    row = await database.fetch_one(
        select(proel_deleted_matches).where(proel_deleted_matches.c.id == entry_id)
    )
    if row is None:
        raise HTTPException(
            404,
            detail={"code": "NOT_FOUND", "message": "Nie ma takiego wpisu w archiwum."},
        )
    if row["restored_at"] is not None:
        raise HTTPException(
            409,
            detail={
                "code": "ALREADY_RESTORED",
                "message": "Ten zapis został już przywrócony.",
            },
        )

    match_number = row["match_number"]

    async with database.transaction():
        clash = await database.fetch_one(
            select(saved_matches.c.match_number).where(
                saved_matches.c.match_number == match_number
            )
        )
        if clash is not None:
            raise HTTPException(
                409,
                detail={
                    "code": "MATCH_EXISTS",
                    "message": (
                        f"Mecz {match_number} istnieje już w ProEl'u. "
                        "Usuń albo zmień bieżący zapis, zanim przywrócisz archiwalny."
                    ),
                },
            )

        restored_status = row["status"] or "finished"
        await database.execute(
            saved_matches.insert().values(
                match_number=match_number,
                # Sparsowane, nie surowe: napis wstawiony w kolumne JSON
                # zakodowalby sie DRUGI raz i przywrocony mecz bylby dla
                # aplikacji nieczytelny.
                data_json=_json_value(row["data_json"]),
                status=restored_status,
                is_finished=restored_status in ("finished", "approved"),
                zprp_match_id=row["zprp_match_id"],
            )
        )

        # Napisowy stan wygladal jak "nie-slownik" i przywracanie PO CICHU
        # gubilo stan wspolpracy nad meczem - te sama chorobe mial monitor
        # okregu, patrz nota przy `state_dict` w province_match_monitor.
        state = _json_value(row["state_json"])
        if isinstance(state, dict) and state.get("match_number"):
            # Kolumny czasowe wróciły z archiwum jako ISO; wstawiamy tylko te
            # pola, które faktycznie odtwarzają współpracę nad meczem. Leasing
            # celowo pomijamy - był ważny w chwili meczu i dawno wygasł.
            await database.execute(
                proel_match_state.insert().values(
                    match_number=match_number,
                    zprp_match_id=state.get("zprp_match_id"),
                    guard_json=state.get("guard_json"),
                    rev=int(state.get("rev") or 0),
                    fields_json=state.get("fields_json") or {},
                    audit_json=state.get("audit_json") or [],
                    status_cache=restored_status,
                )
            )

        await database.execute(
            proel_deleted_matches.update()
            .where(proel_deleted_matches.c.id == entry_id)
            .values(
                restored_at=datetime.now(timezone.utc),
                restored_by_judge_id=actor.judge_id,
            )
        )

    await log_match_event(
        match_number=match_number,
        event="match.restored",
        actor=actor,
        zprp_match_id=str(row["zprp_match_id"] or ""),
        details={"archive_id": entry_id, "status": restored_status},
    )

    return {"success": True, "match_number": match_number}

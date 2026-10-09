"""Mecz jako materiał dowodowy - oznaczenie, ochrona historii i teczki.

Reguły i format teczki: `app/proel_evidence_rules.py` (liść z testami).
Tu zostaje to, co dotyka bazy, i trasy panelu (Dziennik meczu).

⚠ Router MUSI stać PRZED `proel_router` w `main.py` - catch-all
`/proel/{match_number:path}` połknąłby `/proel/evidence/...`. Wewnątrz pliku
trasa zachłanna (`/status/{match_number:path}`) stoi NA KOŃCU.

Pomocniki dla reszty systemu (`active_holds_select`, `is_held`) NIGDY nie
rzucają w miejscach, gdzie ich błąd mógłby wywrócić zapis meczu - patrz
`record_snapshot`. Odmowa usunięcia czyta oznaczenie sama, w transakcji.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select

from app.proel_admin_guard import proel_admin_guard
from app.proel_auth import Actor, is_admin, proel_actor
from app.proel_bulk_delete_rules import PinThrottle, lock_message
from app.proel_evidence_rules import (
    NOT_HELD_MESSAGE,
    RELEASE_ARCHIVE_DAYS,
    UNKNOWN_MATCH_MESSAGE,
    build_package,
    has_any_trace,
    hold_view,
    normalize_reason,
    package_doc,
    package_filename,
    package_view,
)

logger = logging.getLogger(__name__)

#: Ile żyje podpisany adres teczki. Pobranie startuje od razu po prośbie.
LINK_TTL_SECONDS = 5 * 60


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ─────────────────────── pomocniki dla reszty systemu ───────────────────────


def active_holds_select():
    """`SELECT match_number` aktywnych oznaczeń - do `NOT IN` w sprzątaniu."""
    from app.db import proel_evidence_holds as H

    return select(H.c.match_number).where(H.c.released_at.is_(None))


async def is_held(match_number: str) -> bool:
    """Czy mecz jest chroniony. Błąd bazy = `False` (zwykła retencja).

    Wołane z `record_snapshot`, który nie ma prawa rzucić. Prawdziwą
    gwarancją jest i tak sprzątanie, które pomija chronione mecze osobnym
    warunkiem - ta funkcja tylko oszczędza im daty wygaśnięcia.
    """
    key = str(match_number or "").strip()
    if not key:
        return False
    try:
        from app.db import database, proel_evidence_holds as H

        row = await database.fetch_one(
            select(H.c.match_number).where(
                and_(H.c.match_number == key, H.c.released_at.is_(None))
            )
        )
        return row is not None
    except Exception:  # noqa: BLE001
        logger.warning("materiał dowodowy: nie sprawdzono oznaczenia %s", key, exc_info=True)
        return False


async def carry_evidence(old_key: str, new_key: str) -> None:
    """Awans szkoleniowego na oficjalny przenosi oznaczenie i teczki.

    Bez tego chroniony mecz po awansie przestałby być chroniony, bo jego
    migawki (`carry_snapshots`) przeszłyby pod klucz, którego oznaczenie
    nie zna. Gdy nowy klucz ma już własne oznaczenie, zostaje ono.
    """
    try:
        from app.db import database, proel_evidence_holds as H, proel_evidence_packages as P

        old = str(old_key or "").strip()
        new = str(new_key or "").strip()
        if not old or not new or old == new:
            return
        taken = await database.fetch_one(select(H.c.match_number).where(H.c.match_number == new))
        if taken is None:
            await database.execute(H.update().where(H.c.match_number == old).values(match_number=new))
        await database.execute(P.update().where(P.c.match_number == old).values(match_number=new))
    except Exception:  # noqa: BLE001
        logger.warning("materiał dowodowy: nie przeniesiono %s -> %s", old_key, new_key, exc_info=True)


# ─────────────────────────── teczka ───────────────────────────


async def _zbierz(key: str) -> Dict[str, Any]:
    """Komplet wierszy meczu ze wszystkich tabel - wejście dla `build_package`."""
    from app.db import (
        database,
        proel_activity_log,
        proel_deleted_matches,
        proel_doc_history,
        proel_match_snapshots,
        proel_match_state,
        protocol_audit,
        saved_matches,
    )

    async def all_rows(query) -> List[Dict[str, Any]]:
        return [dict(r) for r in await database.fetch_all(query)]

    mecz = await database.fetch_one(select(saved_matches).where(saved_matches.c.match_number == key))
    stan = await database.fetch_one(select(proel_match_state).where(proel_match_state.c.match_number == key))
    zprp_id = (dict(mecz).get("zprp_match_id") if mecz is not None else None) or (
        dict(stan).get("zprp_match_id") if stan is not None else None
    )
    pdf_where = protocol_audit.c.match_number == key
    if zprp_id:
        pdf_where = or_(pdf_where, protocol_audit.c.match_id == str(zprp_id))
    return {
        "mecz": dict(mecz) if mecz is not None else None,
        "stan": dict(stan) if stan is not None else None,
        "migawki": await all_rows(
            select(proel_match_snapshots)
            .where(proel_match_snapshots.c.match_number == key)
            .order_by(proel_match_snapshots.c.created_at, proel_match_snapshots.c.id)
        ),
        "dziennik": await all_rows(
            select(proel_activity_log)
            .where(proel_activity_log.c.match_number == key)
            .order_by(proel_activity_log.c.created_at, proel_activity_log.c.id)
        ),
        "historia_sporow": await all_rows(
            select(proel_doc_history)
            .where(proel_doc_history.c.match_number == key)
            .order_by(proel_doc_history.c.archived_at, proel_doc_history.c.id)
        ),
        "usuniete": await all_rows(
            select(proel_deleted_matches)
            .where(proel_deleted_matches.c.match_number == key)
            .order_by(proel_deleted_matches.c.deleted_at, proel_deleted_matches.c.id)
        ),
        "protokoly_pdf": await all_rows(
            select(protocol_audit).where(pdf_where).order_by(protocol_audit.c.created_at)
        ),
    }


async def create_package(key: str, actor: Actor, reason: str) -> Dict[str, Any]:
    """Zamroź komplet zapisu meczu jako nową teczkę. Zwraca jej opis (bez treści)."""
    from app.db import database, proel_evidence_packages as P

    zebrane = await _zbierz(key)
    now = _now()
    teczka = {
        "powod": reason,
        "utworzyl": actor.name or actor.judge_id or "",
        "utworzyl_numer": actor.judge_id or "",
        "utworzono": now,
    }
    # Pakowanie kilku megabajtów JSON-a nie może zatrzymać pętli zdarzeń -
    # w tym samym procesie lecą autozapisy meczów w toku.
    paczka, sha, counts = await asyncio.to_thread(
        lambda: build_package(match_number=key, teczka=teczka, now=now, **zebrane)
    )
    if not has_any_trace(counts):
        raise HTTPException(404, detail={"code": "UNKNOWN_MATCH", "message": UNKNOWN_MATCH_MESSAGE})
    package_id = await database.execute(
        P.insert().values(
            match_number=key,
            created_at=now,
            created_by_judge=actor.judge_id or None,
            created_by_name=actor.name or None,
            reason=reason or None,
            payload=paczka,
            sha256=sha,
            payload_bytes=len(paczka),
            counts_json=counts,
        )
    )
    row = await database.fetch_one(
        select(*[c for c in P.c if c.name != "payload"]).where(P.c.id == package_id)
    )
    return package_view(dict(row))


async def _packages(key: str) -> List[Dict[str, Any]]:
    from app.db import database, proel_evidence_packages as P

    rows = await database.fetch_all(
        select(*[c for c in P.c if c.name != "payload"])
        .where(P.c.match_number == key)
        .order_by(P.c.created_at.desc(), P.c.id.desc())
    )
    return [package_view(dict(r)) for r in rows]


async def _hold(key: str) -> Optional[Dict[str, Any]]:
    from app.db import database, proel_evidence_holds as H

    row = await database.fetch_one(select(H).where(H.c.match_number == key))
    return dict(row) if row is not None else None


async def _status(key: str) -> Dict[str, Any]:
    hold = await _hold(key)
    view = hold_view(hold)
    return {
        "match_number": key,
        "held": bool(view and view["active"]),
        "hold": view,
        "packages": await _packages(key),
    }


# ─────────────────────────── trasy ───────────────────────────

router = APIRouter(prefix="/proel/evidence", tags=["ProEl: materiał dowodowy"])
_ADMIN_GUARD = [Depends(proel_admin_guard)]
_pin_throttle = PinThrottle()


async def _require_admin(actor: Actor) -> None:
    if not await is_admin(actor.judge_id):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={
                "code": "ADMIN_REQUIRED",
                "message": "Materiał dowodowy jest dostępny tylko dla administratora.",
            },
        )


def _key(raw: Any) -> str:
    key = str(raw or "").strip()
    if not key:
        raise HTTPException(400, detail={"code": "NO_MATCH", "message": "Podaj numer meczu."})
    return key


class MarkIn(BaseModel):
    match_number: str
    reason: str = ""


class ReleaseIn(BaseModel):
    match_number: str
    reason: str = ""
    pin: str = ""


class PackageIn(BaseModel):
    match_number: str
    reason: str = ""


class PackageLink(BaseModel):
    ok: bool = True
    #: Ścieżka z podpisem - adres publiczny składa aplikacja (zna backend na pewno).
    path: str
    expiresAt: int
    filename: str
    sha256: str


@router.get("/list", summary="Mecze oznaczone jako materiał dowodowy", dependencies=_ADMIN_GUARD)
async def list_holds(
    actor: Actor = Depends(proel_actor),
    released: bool = Query(False, description="Także te, z których oznaczenie zdjęto"),
):
    await _require_admin(actor)
    from app.db import database, proel_evidence_holds as H, proel_evidence_packages as P

    query = select(H).order_by(H.c.marked_at.desc())
    if not released:
        query = query.where(H.c.released_at.is_(None))
    holds = [dict(r) for r in await database.fetch_all(query)]
    counts = {
        r["match_number"]: (int(r["n"] or 0), r["last"])
        for r in await database.fetch_all(
            select(P.c.match_number, func.count().label("n"), func.max(P.c.created_at).label("last"))
            .group_by(P.c.match_number)
        )
    }
    out = []
    for h in holds:
        n, last = counts.get(h["match_number"], (0, None))
        out.append({**hold_view(h), "packages": n, "last_package_at": last.isoformat() if last else None})
    return {"holds": out}


@router.post("/mark", summary="Oznacz mecz jako materiał dowodowy", dependencies=_ADMIN_GUARD)
async def mark(req: MarkIn, actor: Actor = Depends(proel_actor)):
    """Oznaczenie + zdjęcie dat wygaśnięcia + pierwsza teczka + wpis w dzienniku.

    Ponowne oznaczenie meczu już chronionego niczego nie psuje: zmienia
    uzasadnienie i dokłada świeżą teczkę.
    """
    await _require_admin(actor)
    key = _key(req.match_number)
    reason = normalize_reason(req.reason)
    from app.db import (
        database,
        proel_deleted_matches,
        proel_doc_history,
        proel_evidence_holds as H,
        proel_match_snapshots,
        proel_match_state,
        saved_matches,
    )

    zprp = await database.fetch_one(
        select(saved_matches.c.zprp_match_id).where(saved_matches.c.match_number == key)
    ) or await database.fetch_one(
        select(proel_match_state.c.zprp_match_id).where(proel_match_state.c.match_number == key)
    )
    values = {
        "zprp_match_id": (dict(zprp).get("zprp_match_id") if zprp is not None else None),
        "reason": reason or None,
        "marked_at": _now(),
        "marked_by_judge": actor.judge_id or None,
        "marked_by_name": actor.name or None,
        "marked_by_install": actor.installation_id or None,
        "released_at": None,
        "released_by_judge": None,
        "released_by_name": None,
        "release_reason": None,
    }

    # Teczka PRZED oznaczeniem: gdy meczu nie ma nigdzie, `create_package`
    # odmówi i nie zostanie po nim osierocone oznaczenie.
    package = await create_package(key, actor, f"Oznaczenie jako materiał dowodowy. {reason}".strip())

    async with database.transaction():
        if await _hold(key) is None:
            await database.execute(H.insert().values(match_number=key, **values))
        else:
            await database.execute(H.update().where(H.c.match_number == key).values(**values))
        # Nic z historii tego meczu nie ma już daty ważności.
        for table in (proel_match_snapshots, proel_doc_history, proel_deleted_matches):
            await database.execute(
                table.update().where(table.c.match_number == key).values(expires_at=None)
            )

    from app.proel_journal import log_match_event

    await log_match_event(
        match_number=key,
        event="evidence.marked",
        actor=actor,
        details={"reason": reason, "package_id": package["id"], "sha256": package["sha256"]},
    )
    return await _status(key)


@router.post("/release", summary="Zdejmij oznaczenie (PIN administratora)", dependencies=_ADMIN_GUARD)
async def release(req: ReleaseIn, actor: Actor = Depends(proel_actor)):
    """Zwykła retencja wraca - liczona od TERAZ, a teczki zostają na zawsze.

    PIN sprawdzamy tutaj, w tym samym żądaniu (jak przy grupowym usuwaniu):
    zdjęcie ochrony to pierwszy krok do utraty historii, więc ma być świadome.
    """
    await _require_admin(actor)
    key = _key(req.match_number)
    hold = await _hold(key)
    if hold is None or hold.get("released_at") is not None:
        raise HTTPException(409, detail={"code": "NOT_HELD", "message": NOT_HELD_MESSAGE})

    who = actor.judge_id
    if _pin_throttle.blocked(who):
        raise HTTPException(
            429, detail={"code": "PIN_LOCKED", "message": lock_message(_pin_throttle.seconds_left(who))}
        )
    from app.admin import pin_is_valid  # leniwie - ciągnie pół aplikacji

    if not await pin_is_valid(who, req.pin):
        _pin_throttle.fail(who)
        raise HTTPException(
            403, detail={"code": "PIN_INVALID", "message": "Nieprawidłowy PIN - oznaczenie zostaje."}
        )
    _pin_throttle.reset(who)

    from app.db import (
        database,
        proel_deleted_matches,
        proel_doc_history,
        proel_evidence_holds as H,
        proel_match_snapshots as S,
    )
    from app.snapshot_rules import expires_at

    now = _now()
    reason = normalize_reason(req.reason)
    async with database.transaction():
        await database.execute(
            H.update().where(H.c.match_number == key).values(
                released_at=now,
                released_by_judge=actor.judge_id or None,
                released_by_name=actor.name or None,
                release_reason=reason or None,
            )
        )
        # Retencja od chwili zdjęcia: zwykła wersja tydzień, kamień milowy 90 dni.
        await database.execute(
            S.update().where(and_(S.c.match_number == key, S.c.milestone.is_(None)))
            .values(expires_at=expires_at(now, None))
        )
        await database.execute(
            S.update().where(and_(S.c.match_number == key, S.c.milestone.is_not(None)))
            .values(expires_at=expires_at(now, "end"))
        )
        for table in (proel_doc_history, proel_deleted_matches):
            await database.execute(
                table.update().where(table.c.match_number == key)
                .values(expires_at=now + timedelta(days=RELEASE_ARCHIVE_DAYS))
            )

    from app.proel_journal import log_match_event

    await log_match_event(
        match_number=key, event="evidence.released", actor=actor, details={"reason": reason}
    )
    return await _status(key)


@router.post("/package", summary="Dołóż nową teczkę (stan na teraz)", dependencies=_ADMIN_GUARD)
async def new_package(req: PackageIn, actor: Actor = Depends(proel_actor)):
    await _require_admin(actor)
    key = _key(req.match_number)
    reason = normalize_reason(req.reason)
    package = await create_package(key, actor, reason or "Teczka na żądanie administratora.")
    from app.proel_journal import log_match_event

    await log_match_event(
        match_number=key,
        event="evidence.package",
        actor=actor,
        details={"reason": reason, "package_id": package["id"], "sha256": package["sha256"]},
    )
    return await _status(key)


@router.post(
    "/package/{package_id}/link",
    response_model=PackageLink,
    summary="Podpisany adres pobrania teczki",
    dependencies=_ADMIN_GUARD,
)
async def package_link(package_id: int = Path(..., ge=1), actor: Actor = Depends(proel_actor)):
    """Osobny adres, bo systemowy menedżer pobierania nie niesie nagłówków admina.

    Ten sam podpis co materiał SPK (`app/spk_pdf_link.py`), ale `doc` wskazuje
    JEDNĄ teczkę - token do teczki nr 3 nie otworzy teczki nr 4 ani prezentacji.
    """
    await _require_admin(actor)
    from app.db import database, proel_evidence_packages as P
    from app.spk_pdf_link import create_pdf_token, token_expires_at

    row = await database.fetch_one(
        select(P.c.id, P.c.match_number, P.c.sha256).where(P.c.id == package_id)
    )
    if row is None:
        raise HTTPException(404, detail={"code": "NO_PACKAGE", "message": "Nie ma takiej teczki."})
    token = create_pdf_token(
        str(actor.judge_id or ""), ttl_seconds=LINK_TTL_SECONDS, doc=package_doc(package_id)
    )
    return PackageLink(
        path=f"/proel/evidence/package/{package_id}/file?t={token}",
        expiresAt=token_expires_at(token),
        filename=package_filename(row["match_number"], package_id),
        sha256=row["sha256"],
    )


@router.get("/package/{package_id}/file", summary="Teczka (adres podpisany)")
async def package_file(package_id: int = Path(..., ge=1), t: str = Query("")):
    """Trasa dla menedżera pobierania - całe uprawnienie siedzi w tokenie."""
    from app.spk_pdf_link import verify_pdf_token

    payload = verify_pdf_token(t)
    if payload is None or payload.get("doc") != package_doc(package_id):
        raise HTTPException(403, "Adres teczki wygasł. Poproś o nowy w Dzienniku meczu.")
    from app.db import database, proel_evidence_packages as P

    row = await database.fetch_one(select(P).where(P.c.id == package_id))
    if row is None:
        raise HTTPException(404, "Nie ma takiej teczki.")
    return Response(
        content=bytes(row["payload"]),
        media_type="application/gzip",
        headers={
            "Content-Disposition": f'attachment; filename="{package_filename(row["match_number"], package_id)}"',
            "X-Content-SHA256": row["sha256"],
        },
    )


# TRASA ZACHŁANNA - zawsze ostatnia w pliku (patrz nagłówek i `proel_snapshots.py`).
@router.get(
    "/status/{match_number:path}",
    summary="Oznaczenie i teczki jednego meczu",
    dependencies=_ADMIN_GUARD,
)
async def match_status(match_number: str, actor: Actor = Depends(proel_actor)):
    await _require_admin(actor)
    return await _status(_key(match_number))

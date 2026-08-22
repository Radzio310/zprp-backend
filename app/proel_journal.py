"""Dziennik zdarzeń meczu ProEl: kto, kiedy i co zrobił.

Po co: do tej pory system zbierał tożsamość przy każdym wywołaniu ProEla
(`X-Judge-Id`, `X-Installation-Id`, `X-Actor-Name`) i wyrzucał ją na dwóch
najważniejszych ścieżkach - `POST /proel/` i `PUT /proel/{nr}` nie czytały
aktora, więc założenie, zakończenie i zatwierdzenie meczu były anonimowe.
Na pytanie „kto zamknął ten protokół" nie było odpowiedzi i nie było jej skąd
wziąć, bo dane nie były zapisywane.

Dwie zasady, obie twarde:

1. **Zapis do dziennika nigdy nie może wywrócić operacji, którą opisuje.**
   `log_match_event` łyka wszystko. Protokół jest ważniejszy od swojej
   historii, a dziennik, który potrafi zablokować zakończenie meczu, jest
   gorszy niż brak dziennika.

2. **Aktora czytamy MIĘKKO.** Twarda zależność (`Depends(proel_actor)`)
   zwraca 401 przy braku nagłówków - a stara wersja aplikacji ich nie wysyła.
   Wymuszenie tożsamości na zapisie bloba oznaczałoby ciche gubienie meczów
   prowadzonych ze starszych telefonów.

Odczyt jest wyłącznie dla administratora i stronicuje się KURSOREM po `id`,
nie `OFFSET`-em: dziennik rośnie w trakcie przeglądania, a offset przy
dopisywanym logu gubi i dubluje wiersze.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy import func, select

from app.proel_auth import Actor, header_text, is_admin, proel_actor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/proel/journal", tags=["ProEl: dziennik"])


# ─────────────────────────── nazwy zdarzeń ───────────────────────────
#
# JEDNA tablica na cały system - i backend, i panel biorą etykiety stąd.
# W panelu Beacha te same nazwy żyją w dwóch plikach i dawno się rozjechały.

EVENT_LABELS: Dict[str, str] = {
    "match.created": "Założenie meczu",
    "match.live_started": "Start prowadzenia",
    "table.taken_over": "Przejęcie stolika",
    "match.finished": "Zakończenie meczu",
    "match.approved": "Zatwierdzenie protokołu",
    "match.unapproved": "Cofnięcie zatwierdzenia",
    "match.deleted": "Usunięcie zapisu",
    "match.restored": "Przywrócenie zapisu",
    "match.id_conflict": "Odrzucony zapis (inny mecz)",
    "field.changed": "Zmiana pól",
    "protocol.pdf_generated": "Wygenerowanie protokołu PDF",
    "zprp.summary_sent": "Wynik skrócony do ZPRP",
    "zprp.players_sent": "Statystyki zawodników do ZPRP",
    "zprp.officials_sent": "Kary osób towarzyszących do ZPRP",
    "zprp.comment_sent": "Uwagi verte do ZPRP",
    "zprp.attachment_sent": "Załącznik do ZPRP",
}


def client_ip(request: Optional[Request], forwarded: Optional[str] = None) -> str:
    """Adres klienta zza proxy Railway - ten sam odczyt co w `proel_zprp`."""
    if forwarded:
        first = str(forwarded).split(",")[0].strip()
        if first:
            return first[:64]
    try:
        return (request.client.host if request and request.client else "")[:64]
    except Exception:
        return ""


async def soft_actor(
    x_judge_id: Optional[str] = None,
    x_installation_id: Optional[str] = None,
    x_actor_name: Optional[str] = None,
) -> Optional[Actor]:
    """Aktor bez rzucania 401.

    Wzorzec `_soft_verify_actor` z generatora protokołów: brak nagłówków to
    normalna sytuacja (stara aplikacja, gość bez powiadomień), a nie błąd.
    Zwraca `None`, gdy nie ma czego zapisać.
    """
    judge_id = str(x_judge_id or "").strip()
    install = str(x_installation_id or "").strip()
    if not judge_id and not install:
        return None

    actor = Actor(
        judge_id=judge_id,
        installation_id=install,
        name=header_text(x_actor_name),
    )
    if not judge_id or not install:
        return actor

    try:
        from app.db import database, push_tokens

        row = await database.fetch_one(
            select(push_tokens).where(push_tokens.c.installation_id == install)
        )
        if row is not None:
            known = str(row["judge_id"] or "").strip()
            actor.verified = bool(known) and known == judge_id
    except Exception:
        # Brak potwierdzenia to nie to samo co oszustwo - zapisujemy jako
        # niezweryfikowanego i idziemy dalej.
        pass
    return actor


async def log_match_event(
    *,
    match_number: str,
    event: str,
    actor: Optional[Actor] = None,
    zprp_match_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    event_key: Optional[str] = None,
    app_version: Optional[str] = None,
    ip: Optional[str] = None,
) -> None:
    """Dopisuje zdarzenie. NIGDY nie rzuca.

    `event_key` jest unikalny w tabeli - dzięki temu bicie serca leasingu co
    25 s daje jeden wpis, a ponowienie z outboxa nie dopisuje drugiego.
    Kolizja klucza jest normalnym wynikiem, nie błędem.
    """
    number = str(match_number or "").strip()
    if not number or not event:
        return

    try:
        from app.db import database, proel_activity_log

        if event_key:
            exists = await database.fetch_one(
                select(proel_activity_log.c.id).where(
                    proel_activity_log.c.event_key == event_key
                )
            )
            if exists is not None:
                return

        await database.execute(
            proel_activity_log.insert().values(
                match_number=number,
                zprp_match_id=(str(zprp_match_id).strip() or None)
                if zprp_match_id
                else None,
                event=str(event),
                actor_judge_id=(actor.judge_id or None) if actor else None,
                actor_name=(actor.name or None) if actor else None,
                actor_install=(actor.installation_id or None) if actor else None,
                actor_verified=bool(actor.verified) if actor else False,
                details_json=details or None,
                app_version=(str(app_version).strip()[:32] or None)
                if app_version
                else None,
                client_ip=(str(ip).strip()[:64] or None) if ip else None,
                event_key=event_key,
            )
        )
    except Exception:
        # Wpis do dziennika nie ma prawa wywrócić operacji, którą opisuje.
        logger.debug("proel journal: nie zapisano %s dla %s", event, number, exc_info=True)


# ─────────────────────────── odczyt (admin) ───────────────────────────


async def _require_admin(actor: Actor) -> None:
    if not await is_admin(actor.judge_id):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={
                "code": "FORBIDDEN",
                "message": "Dziennik meczów jest dostępny tylko dla administratora.",
            },
        )


def _row_out(row: Any) -> Dict[str, Any]:
    d = dict(row)
    created = d.get("created_at")
    return {
        "id": int(d["id"]),
        "match_number": d.get("match_number") or "",
        "zprp_match_id": d.get("zprp_match_id"),
        "event": d.get("event") or "",
        "label": EVENT_LABELS.get(str(d.get("event") or ""), str(d.get("event") or "")),
        "actor": {
            "judge_id": d.get("actor_judge_id"),
            "name": d.get("actor_name"),
            "install": d.get("actor_install"),
            "verified": bool(d.get("actor_verified")),
        },
        "details": d.get("details_json"),
        "app_version": d.get("app_version"),
        "client_ip": d.get("client_ip"),
        "created_at": created.isoformat() if created is not None else None,
    }


@router.get(
    "/matches",
    summary="Mecze widziane od strony dziennika - jeden wiersz na mecz",
)
async def journal_matches(
    q: Optional[str] = Query(None, description="Fragment numeru meczu"),
    limit: int = Query(40, ge=1, le=200),
    offset: int = Query(0, ge=0),
    actor: Actor = Depends(proel_actor),
):
    """Poziom pierwszy panelu: co w ogóle się działo i przy którym meczu.

    Grupujemy w bazie, a nie w aplikacji: przy tysiącu meczów ściągnięcie
    całego dziennika po to, żeby go policzyć na telefonie, jest tym samym
    błędem co `GET /proel/` z pełnymi blobami.
    """
    await _require_admin(actor)

    from app.db import database, proel_activity_log, saved_matches

    log = proel_activity_log
    grouped = (
        select(
            log.c.match_number.label("match_number"),
            func.count().label("events"),
            func.max(log.c.created_at).label("last_at"),
            func.max(log.c.id).label("last_id"),
        )
        .group_by(log.c.match_number)
        .order_by(func.max(log.c.id).desc())
    )
    if q:
        grouped = grouped.where(log.c.match_number.ilike(f"%{str(q).strip()}%"))

    rows = await database.fetch_all(grouped.limit(limit).offset(offset))

    out: List[Dict[str, Any]] = []
    for row in rows:
        number = row["match_number"]

        last = await database.fetch_one(
            select(log).where(log.c.id == row["last_id"])
        )
        # Kto brał udział - do inicjałów na kaflu meczu.
        people = await database.fetch_all(
            select(log.c.actor_name)
            .where(log.c.match_number == number, log.c.actor_name.isnot(None))
            .group_by(log.c.actor_name)
            .limit(8)
        )
        doc = await database.fetch_one(
            select(saved_matches.c.status).where(
                saved_matches.c.match_number == number
            )
        )

        last_at = row["last_at"]
        out.append(
            {
                "match_number": number,
                "events": int(row["events"] or 0),
                "last_at": last_at.isoformat() if last_at is not None else None,
                "last_event": _row_out(last) if last is not None else None,
                "people": [str(p["actor_name"]) for p in people if p["actor_name"]],
                # Brak wiersza w `proel_matches` znaczy „zapis usunięty" -
                # dziennik zostaje i to jest jego sens.
                "status": (doc["status"] if doc is not None else "deleted"),
            }
        )
    return {"matches": out, "has_more": len(rows) == limit}


@router.get(
    "",
    summary="Zdarzenia dziennika - stronicowanie kursorem po id",
)
async def journal_events(
    match: Optional[str] = Query(None, description="Numer meczu"),
    event: Optional[str] = Query(None, description="Nazwa zdarzenia"),
    actor_id: Optional[str] = Query(None, description="Numer sędziego"),
    before_id: Optional[int] = Query(
        None, description="Kursor: zwróć zdarzenia starsze niż to id"
    ),
    limit: int = Query(50, ge=1, le=200),
    actor: Actor = Depends(proel_actor),
):
    await _require_admin(actor)

    from app.db import database, proel_activity_log

    log = proel_activity_log
    stmt = select(log).order_by(log.c.id.desc())
    if match:
        stmt = stmt.where(log.c.match_number == str(match).strip())
    if event:
        stmt = stmt.where(log.c.event == str(event).strip())
    if actor_id:
        stmt = stmt.where(log.c.actor_judge_id == str(actor_id).strip())
    if before_id:
        stmt = stmt.where(log.c.id < int(before_id))

    rows = await database.fetch_all(stmt.limit(limit))
    items = [_row_out(r) for r in rows]
    return {
        "events": items,
        "next_cursor": items[-1]["id"] if len(items) == limit else None,
        "labels": EVENT_LABELS,
    }

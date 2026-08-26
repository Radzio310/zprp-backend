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
from sqlalchemy import exists, func, literal, select

from app.proel_auth import (
    Actor,
    header_text,
    is_admin,
    is_synthetic_judge_id,
    proel_actor,
)

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
    "zprp.full_data_sent": "Pełne dane meczu do ZPRP",
    "zprp.players_sent": "Statystyki zawodników do ZPRP",
    "zprp.officials_sent": "Kary osób towarzyszących do ZPRP",
    "zprp.comment_sent": "Uwagi verte do ZPRP",
    "zprp.attachment_sent": "Protokół PDF wysłany do ZPRP",
    "match.reopened": "Wznowienie meczu",
}


# ─────────────────────── pola po ludzku ───────────────────────
#
# Dziennik czyta CZŁOWIEK, nie serwer. `post.protocolSent` mówi coś tylko temu,
# kto zna rejestr pól z `proel_fields`; administrator sprawdzający, co się działo
# przy meczu, ma prawo zobaczyć „protokół PDF trafił do załączników".
#
# Tłumaczenie żyje po stronie serwera razem z nazwami zdarzeń - z tego samego
# powodu, dla którego `EVENT_LABELS` nie mieszka w panelu: żeby nie było dwóch
# list, które się rozjadą.

_ROLE_NAMES: Dict[str, str] = {
    "referee1": "sędzia 1",
    "referee2": "sędzia 2",
    "secretary": "sekretarz",
    "timekeeper": "mierzący czas",
    "delegate": "delegat",
}

_LEAF_NAMES: Dict[str, str] = {
    "fullName": "nazwisko",
    "city": "miejscowość",
    "signature": "podpis",
    "function": "funkcja",
    "license": "licencja",
}

_TEAM_NAMES: Dict[str, str] = {"host": "gospodarzy", "guest": "gości"}

#: Pola „po meczu" - klucze z `_POST_EXTRAS` w `app/proel_fields.py`.
_POST_NAMES: Dict[str, str] = {
    "spectatorsCount": "liczba widzów",
    "venueCapacity": "pojemność hali",
    "eventRegistration": "rejestracja zawodów",
    "detailedRefereeNotes": "uwagi verte (zaznaczenie)",
    "extraReport": "dodatkowy raport",
    "notesText": "treść uwag sędziów",
    "shortResultSent": "znacznik: wynik skrócony w bazie ZPRP",
    "fullDataSent": "znacznik: pełne dane w bazie ZPRP",
    "protocolSent": "znacznik: protokół PDF w załącznikach",
}

_CFG_NAMES: Dict[str, str] = {
    "referee1": "sędzia 1",
    "referee2": "sędzia 2",
    "delegate": "delegat",
    "timekeeper": "mierzący czas",
    "secretary": "sekretarz",
    "venueAddress": "adres hali",
}

_EXTRAS_NAMES: Dict[str, str] = {
    "matchDate": "data meczu",
    "matchTime": "godzina meczu",
}

#: Znaczniki wysyłki opisujemy zdaniem, nie nazwą pola - bo to jedyne „pola",
#: których zmiana jest sama w sobie zdarzeniem, a nie poprawką w rubryce.
_MARK_SENTENCES: Dict[str, str] = {
    "post.shortResultSent": "wynik skrócony trafił do bazy ZPRP",
    "post.fullDataSent": "pełne dane meczu trafiły do bazy ZPRP",
    "post.protocolSent": "protokół PDF trafił do załączników meczu",
}

# Znacznik zadania pomeczowego nie jest zwykłą zmianą rubryki. Powstaje dopiero
# po potwierdzonym sukcesie wysyłki, więc w dzienniku ma być samodzielnym
# zdarzeniem, na które administrator może odpowiedzieć „kto i kiedy".
_SENT_EVENT_BY_PATH: Dict[str, str] = {
    "post.shortResultSent": "zprp.summary_sent",
    "post.fullDataSent": "zprp.full_data_sent",
    "post.protocolSent": "zprp.attachment_sent",
}


def describe_field(path: str) -> str:
    """Ścieżka pola z `proel_fields` jako kawałek polskiego zdania."""
    raw = str(path or "").strip()
    if not raw:
        return ""

    parts = raw.split(".")
    head = parts[0]

    if raw in _MARK_SENTENCES:
        return _MARK_SENTENCES[raw]

    if head == "post" and len(parts) == 2:
        return _POST_NAMES.get(parts[1], parts[1])

    if head == "cfg" and len(parts) == 2:
        return _CFG_NAMES.get(parts[1], parts[1])

    if head == "extras" and len(parts) == 2:
        return _EXTRAS_NAMES.get(parts[1], parts[1])

    if head == "sig" and len(parts) == 3 and parts[1] == "team":
        return f"podpis {_TEAM_NAMES.get(parts[2], parts[2])}"

    if head == "official" and len(parts) == 3:
        role = _ROLE_NAMES.get(parts[1], parts[1])
        return f"{role} - {_LEAF_NAMES.get(parts[2], parts[2])}"

    if head == "companion" and len(parts) == 4:
        team = _TEAM_NAMES.get(parts[1], parts[1])
        leaf = _LEAF_NAMES.get(parts[3], parts[3])
        return f"osoba towarzysząca {parts[2]} {team} - {leaf}"

    if head == "exam" and len(parts) == 3:
        team = _TEAM_NAMES.get(parts[1], parts[1])
        number = parts[2].lstrip("#")
        return f"badania zawodnika nr {number} ({team})"

    # Nieznana ścieżka wraca taka, jaka jest - lepiej techniczna prawda niż
    # ładne kłamstwo. To także sygnał, że doszło pole bez nazwy.
    return raw


def _join_fields(paths: List[str], limit: int = 3) -> str:
    named = [describe_field(p) for p in paths if str(p or "").strip()]
    if not named:
        return ""
    if len(named) <= limit:
        return ", ".join(named)
    rest = len(named) - limit
    tail = "pole" if rest == 1 else ("pola" if 2 <= rest <= 4 else "pól")
    return f"{', '.join(named[:limit])} i {rest} {tail} więcej"


_STATUS_NAMES: Dict[str, str] = {
    "in_progress": "w toku",
    "finished": "zakończony",
    "approved": "zatwierdzony",
    "deleted": "usunięty",
}


def event_summary(event: str, details: Optional[Dict[str, Any]]) -> str:
    """Jedno zdanie o tym, co się właściwie stało.

    Podtytuł wiersza w dzienniku. Wcześniej stała tu surowa treść `details_json`
    - administrator oglądał `{"paths":["post.protocolSent"],"rev":313}` i musiał
    sam zgadnąć, co to znaczy.
    """
    d = details or {}
    ev = str(event or "")

    if ev == "field.changed":
        paths = [str(x) for x in (d.get("paths") or []) if str(x or "").strip()]
        if len(paths) == 1 and paths[0] in _MARK_SENTENCES:
            # Znacznik wysyłki niesie całą treść sam - „zmieniono" brzmiałoby
            # tu jak poprawka w rubryce, a to jest fakt z przebiegu meczu.
            sentence = _MARK_SENTENCES[paths[0]]
            # Wielka litera TYLKO pierwsza - `capitalize()` zjadałoby skróty
            # w środku zdania („PDF" na „pdf").
            return sentence[:1].upper() + sentence[1:]
        joined = _join_fields(paths)
        return f"Zmieniono: {joined}" if joined else ""

    if ev == "table.taken_over":
        who = str(d.get("from") or "").strip()
        return f"Prowadzenie odebrane urządzeniu: {who}" if who else "Prowadzenie przeszło na inne urządzenie"

    if ev == "match.id_conflict":
        return (
            f"W bazie leży mecz {d.get('known') or '?'}, "
            f"a przyszedł zapis meczu {d.get('incoming') or '?'}"
        )

    if ev == "protocol.pdf_generated":
        code = str(d.get("audit_code") or "").strip()
        return f"Kod dziennika protokołów: {code}" if code else ""

    if ev in _SENT_EVENT_BY_PATH.values():
        paths = [str(x) for x in (d.get("paths") or []) if str(x or "").strip()]
        sentence = _MARK_SENTENCES.get(paths[0], "") if len(paths) == 1 else ""
        return sentence[:1].upper() + sentence[1:] if sentence else ""

    frm = _STATUS_NAMES.get(str(d.get("from") or ""), "")
    to = _STATUS_NAMES.get(str(d.get("to") or ""), "")
    if frm and to:
        return f"Stan meczu: {frm} → {to}"
    if to:
        return f"Stan meczu: {to}"
    return ""


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
    # `proel:` / `inst:` to nie numer sędziego - rejestr urządzeń nie ma go z
    # czym zestawić, a zapytanie i tak skończyłoby się na `verified = False`.
    if not judge_id or not install or is_synthetic_judge_id(judge_id):
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

_protocol_pdf_backfill_done = False


async def _backfill_protocol_pdf_events() -> None:
    """Przenosi wcześniejsze generowania PDF na wspólną oś czasu meczu.

    Generator od dawna zapisuje dokładny `protocol_audit`, więc utrata tej
    historii tylko dlatego, że wspólny dziennik powstał później, byłaby
    sztuczna. Klucz `protocol-pdf:<kod>` zapewnia idempotencję także przy
    restarcie procesu. Funkcja jest best-effort tak samo jak sam dziennik.
    """
    global _protocol_pdf_backfill_done
    if _protocol_pdf_backfill_done:
        return

    try:
        from app.db import database, proel_activity_log, protocol_audit

        event_key = literal("protocol-pdf:") + protocol_audit.c.code
        rows = await database.fetch_all(
            select(protocol_audit).where(
                protocol_audit.c.match_number.isnot(None),
                protocol_audit.c.match_number != "",
                ~exists(
                    select(proel_activity_log.c.id).where(
                        proel_activity_log.c.event_key == event_key
                    )
                ),
            )
        )
        had_failure = False
        for row in rows:
            try:
                await database.execute(
                    proel_activity_log.insert().values(
                        match_number=str(row["match_number"] or "").strip(),
                        zprp_match_id=row["match_id"],
                        event="protocol.pdf_generated",
                        actor_judge_id=row["judge_id"],
                        actor_name=row["actor_name"],
                        actor_install=row["installation_id"],
                        actor_verified=bool(row["verified"]),
                        details_json={"audit_code": row["code"]},
                        app_version=row["app_version"],
                        client_ip=row["client_ip"],
                        event_key=f"protocol-pdf:{row['code']}",
                        created_at=row["created_at"],
                    )
                )
            except Exception:
                had_failure = True
                # Równoległe otwarcie panelu może wygrać wyścig o UNIQUE;
                # pojedynczy taki wiersz nie może przerwać reszty migracji.
                logger.debug(
                    "proel journal: pominięto backfill PDF %s",
                    row["code"],
                    exc_info=True,
                )
        # Przy realnej awarii ponowimy brakujące wiersze przy kolejnym odczycie.
        # Kolizja UNIQUE po równoległym odczycie także jest bezpieczna: następne
        # zapytanie nie wybierze już wstawionego przez drugi proces kodu.
        _protocol_pdf_backfill_done = not had_failure
    except Exception:
        logger.debug("proel journal: backfill PDF nieudany", exc_info=True)


async def _require_admin(actor: Actor) -> None:
    if not await is_admin(actor.judge_id):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={
                "code": "FORBIDDEN",
                "message": "Dziennik meczów jest dostępny tylko dla administratora.",
            },
        )


def _effective_event(event: str, details: Optional[Dict[str, Any]]) -> str:
    """Nazwa zdarzenia poprawiona o to, co widać w szczegółach.

    Do niedawna zdarzenie wybierał sam status DOCELOWY, więc cofnięcie
    zatwierdzenia (z „approved" do „finished") zapisywało się jako zwykłe
    zakończenie meczu. Emiter jest już naprawiony, ale wiersze sprzed poprawki
    leżą w bazie - i to one opisują mecze, o które ktoś zapyta. Prostujemy je
    przy ODCZYCIE, bo dziennik jest księgą: wpisów się nie przepisuje.
    """
    d = details or {}
    if str(event) == "field.changed":
        paths = [str(x) for x in (d.get("paths") or []) if str(x or "").strip()]
        if len(paths) == 1 and paths[0] in _SENT_EVENT_BY_PATH:
            # Prostujemy także wpisy już istniejące w bazie. Dziennik jest
            # niezmienny, więc nie robimy migracji historycznych wierszy.
            return _SENT_EVENT_BY_PATH[paths[0]]
    if str(event) == "match.finished" and str(d.get("from") or "") == "approved":
        return "match.unapproved"
    return str(event or "")


def _row_out(row: Any) -> Dict[str, Any]:
    d = dict(row)
    created = d.get("created_at")
    details = d.get("details_json") or {}
    event = _effective_event(str(d.get("event") or ""), details)
    return {
        "id": int(d["id"]),
        "match_number": d.get("match_number") or "",
        "zprp_match_id": d.get("zprp_match_id"),
        "event": event,
        "label": EVENT_LABELS.get(event, event),
        # Jedno zdanie po ludzku - patrz `event_summary`. Panel NIE składa
        # tego sam, żeby nie powstała druga lista nazw pól.
        "summary": event_summary(event, details),
        # Dla właściwego zdarzenia wysyłki ścieżka markera jest szczegółem
        # technicznym, nie „zmienionym polem" do pokazania administratorowi.
        "fields": (
            [describe_field(x) for x in (details.get("paths") or [])]
            if event == "field.changed"
            else []
        ),
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
    await _backfill_protocol_pdf_events()

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
    await _backfill_protocol_pdf_events()

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

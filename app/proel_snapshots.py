"""Migawki meczu - zapis, sprzątanie i odczyt.

Reguły (co zdejmujemy, co jest kamieniem milowym, jakie są limity) mieszkają
w `app/snapshot_rules.py` i mają tam testy bez bazy. Tutaj zostaje to, co
naprawdę dotyka bazy.

ZASADA NADRZĘDNA: TO NIE MOŻE NICZEGO ZEPSUĆ. Migawka jest dodatkiem do
zapisu meczu, a nie jego częścią. Dlatego:

  * zapisujemy ją PO zatwierdzeniu transakcji meczu i w OSOBNEJ transakcji -
    gdyby szła w tej samej, jej błąd wycofałby zapis protokołu;
  * każda porażka jest cicha (log, nie wyjątek) - sędzia prowadzący mecz
    nie ma prawa zobaczyć problemu z archiwum;
  * nie trzymamy blokad na wierszu meczu i nie wołamy niczego po sieci.

Bliźniak po stronie aplikacji: `BAZA/utils/matchSnapshots.ts`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, delete, func, select

from app.season_rules import season_start_year
from app.snapshot_rules import (
    expires_at,
    may_store,
    milestone_of,
    pack,
    snapshot_hash,
    strip_heavy,
    too_big,
    unpack,
)

logger = logging.getLogger(__name__)

#: Co ile sprząta pętla w tle. Godzina wystarczy - wpisy wygasają dobowo.
CLEANUP_INTERVAL_SECONDS = 3600
#: Ile wierszy kasujemy za jednym razem. Bez tego pierwsze uruchomienie po
#: miesiącu przerwy zablokowałoby zapisy na minuty.
CLEANUP_BATCH = 5000

#: Pola, w których bywa data meczu - zależnie od tego, kto zbudował blob.
_DATE_KEYS = ("matchDateTime", "date", "data_fakt", "matchDate")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _match_date(blob: Any) -> Optional[datetime]:
    """Data meczu z bloba - próbujemy kilku nazw, bo bywały różne."""
    if not isinstance(blob, dict):
        return None
    cfg = blob.get("matchConfig") if isinstance(blob.get("matchConfig"), dict) else {}
    for source in (cfg, blob):
        for key in _DATE_KEYS:
            raw = source.get(key)
            if not raw:
                continue
            text = str(raw).strip().replace(" ", "T")
            if not text:
                continue
            try:
                return datetime.fromisoformat(text[:19])
            except ValueError:
                continue
    return None


def _int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _short_tag(value: Any) -> Optional[str]:
    """Krótki znacznik zdarzenia - dziś numer czasu dla drużyny („T1", „T2").

    Pole `extra` protokołu niesie dwie zupełnie różne rzeczy: przy czasie dla
    drużyny krótki znacznik, a przy usuniętej bramce CAŁY obiekt JSON z czasem
    pierwotnym. Do kafelka nadaje się wyłącznie to pierwsze, więc bierzemy
    tylko napis krótki i niebędący JSON-em - reszta przepada świadomie.
    """
    text = str(value or "").strip()
    if not text or len(text) > 8 or text[0] in "{[":
        return None
    return text


def _last_event(protocol: Any) -> Dict[str, Any]:
    """Ostatnie zdarzenie protokołu - do kafelka w panelu.

    Panel rysuje wersję ikoną tego, co ją odróżnia od poprzedniej: bramka ma
    piłkę, upomnienie żółtą kartkę z numerem, kara swój znak. Sam typ nie
    wystarczy - numer zawodnika i drużyna są częścią tego, co sędzia widzi
    w przebiegu meczu.
    """
    if not isinstance(protocol, list) or not protocol:
        return {}
    last = protocol[-1]
    if not isinstance(last, dict):
        return {}
    return {
        "last_event_type": str(last.get("type") or "") or None,
        "last_event_team": str(last.get("team") or "") or None,
        "last_event_player": _int(last.get("player")),
        "last_event_ms": _int(last.get("time")),
        # Czas dla drużyny nie ma zawodnika - ma numer („T2"). Bez tego kafelek
        # pokazywał przy nim numer 0, czyli zawodnika, którego nie ma.
        "last_event_tag": _short_tag(last.get("extra")),
    }


def _head(blob: Any) -> Dict[str, Any]:
    """Metadane do listy - żeby panel nie rozpakowywał treści dla każdego wiersza."""
    if not isinstance(blob, dict):
        return {}
    protocol = blob.get("protocol")
    return {
        "score_host": _int(blob.get("scoreHost")),
        "score_guest": _int(blob.get("scoreGuest")),
        "main_time_ms": _int(blob.get("mainTime")),
        "first_half": bool(blob["isFirstHalf"]) if "isFirstHalf" in blob else None,
        "protocol_len": len(protocol) if isinstance(protocol, list) else None,
        **_last_event(protocol),
    }


async def _last_and_count(match_number: str, now: datetime) -> tuple:
    """Poprzednia migawka tego meczu i ile ich dziś było."""
    from app.db import database, proel_match_snapshots as T

    last = await database.fetch_one(
        select(
            T.c.created_at, T.c.phase, T.c.status, T.c.first_half, T.c.content_hash
        )
        .where(T.c.match_number == match_number)
        .order_by(T.c.created_at.desc(), T.c.id.desc())
        .limit(1)
    )
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    count = await database.fetch_val(
        select(func.count())
        .select_from(T)
        .where(and_(T.c.match_number == match_number, T.c.received_at >= day_start))
    )
    return (dict(last) if last is not None else None, int(count or 0))


async def record_snapshot(
    *,
    match_number: str,
    blob: Any,
    overlay: Any = None,
    doc_rev: Optional[int] = None,
    status: Optional[str] = None,
    phase: Optional[str] = None,
    zprp_match_id: Optional[str] = None,
    writer_judge: Optional[str] = None,
    writer_name: Optional[str] = None,
    writer_install: Optional[str] = None,
    source: str = "server",
    created_at: Optional[datetime] = None,
    milestone: Optional[str] = None,
) -> Optional[str]:
    """Odłóż migawkę tego zapisu. Zwraca powód pominięcia albo `None`.

    NIGDY nie rzuca - patrz nagłówek modułu. Zwracany powód służy wyłącznie
    testom i dziennikowi.
    """
    try:
        from app.db import database, proel_match_snapshots as T

        key = str(match_number or "").strip()
        if not key or not isinstance(blob, dict):
            return "brak_tresci"

        now = _now()
        stamp = created_at or now
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)

        prev, today = await _last_and_count(key, now)

        mark = milestone or milestone_of(
            prev=prev,
            phase=str(phase or ""),
            status=status,
            first_half=bool(blob["isFirstHalf"]) if "isFirstHalf" in blob else None,
        )

        allowed, why = may_store(
            now=stamp,
            last_at=(prev or {}).get("created_at"),
            today_count=today,
            milestone=mark,
            from_device=(source == "device"),
        )
        if not allowed:
            if why == "limit":
                # Dziura w historii MA SIĘ WYTŁUMACZYĆ. Bez tego wpisu wygląda
                # tak samo jak mecz, którego nikt nie prowadził. Klucz gasi
                # powtórzenia - jeden wpis na mecz na dobę, nie setka.
                from app.proel_journal import log_match_event

                await log_match_event(
                    match_number=key,
                    event="match.snapshot_limit",
                    details={"limit": today},
                    event_key=f"snapshot_limit:{key}:{now.date().isoformat()}",
                )
            return why

        lean, stats = strip_heavy(blob)
        digest = snapshot_hash(lean)
        if prev is not None and prev.get("content_hash") == digest:
            # Ten sam odcisk co poprzednio - zapis niczego nie zmienił.
            return "bez_zmian"

        oversized = too_big(lean)
        head = _head(blob)
        season = season_start_year(_match_date(blob))

        values = {
            "match_number": key,
            "zprp_match_id": str(zprp_match_id).strip() if zprp_match_id else None,
            "season": season,
            "doc_rev": _int(doc_rev),
            "content_hash": digest,
            # Za duża treść zostawia SAM wiersz - wersja ma być widoczna w osi
            # czasu nawet wtedy, gdy nie da się jej przechować.
            "payload": None if oversized else pack(lean),
            "overlay": pack(overlay) if overlay else None,
            "payload_bytes": stats.get("saved_bytes", 0) + len(str(lean)),
            "phase": str(phase) if phase else None,
            "status": str(status) if status else None,
            "milestone": mark,
            "signatures_count": stats.get("stripped", 0),
            "writer_judge": writer_judge or None,
            "writer_name": writer_name or None,
            "writer_install": writer_install or None,
            "source": "device" if source == "device" else "server",
            "created_at": stamp,
            "received_at": now,
            "expires_at": expires_at(stamp, mark),
            **head,
        }

        stmt = T.insert().values(**values)
        try:
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            stmt = (
                pg_insert(T)
                .values(**values)
                .on_conflict_do_nothing(constraint="uq_snapshot_match_hash")
            )
        except Exception:  # noqa: BLE001 - SQLite w testach nie ma tego dialektu
            pass
        await database.execute(stmt)
        return None
    except Exception:  # noqa: BLE001 - archiwum nie ma prawa wywrocic zapisu meczu
        logger.warning("migawka meczu nieudana (%s)", match_number, exc_info=True)
        return "blad"


async def carry_snapshots(old_key: str, new_key: str) -> int:
    """Przenieś migawki pod nowy numer meczu - awans szkoleniowego na oficjalny.

    Bez tego historia takiego meczu zaczynałaby się od chwili awansu, jakby
    wcześniej nic nie było: wiersze zostają pod kluczem `T-XXXXXXXX/NUMER`,
    którego panel już nie szuka.
    """
    try:
        from app.db import database, proel_match_snapshots as T

        old = str(old_key or "").strip()
        new = str(new_key or "").strip()
        if not old or not new or old == new:
            return 0
        return int(
            await database.execute(
                T.update().where(T.c.match_number == old).values(match_number=new)
            )
            or 0
        )
    except Exception:  # noqa: BLE001
        logger.warning("przeniesienie migawek nieudane (%s -> %s)", old_key, new_key, exc_info=True)
        return 0


async def drop_snapshots(match_number: str) -> int:
    """Skasuj migawki meczu - wołane razem z usunięciem samego meczu.

    Usunięty mecz nie ma prawa wracać w panelu historii.
    """
    try:
        from app.db import database, proel_match_snapshots as T

        key = str(match_number or "").strip()
        if not key:
            return 0
        return int(await database.execute(delete(T).where(T.c.match_number == key)) or 0)
    except Exception:  # noqa: BLE001
        logger.warning("kasowanie migawek nieudane (%s)", match_number, exc_info=True)
        return 0


async def cleanup_expired(limit: int = CLEANUP_BATCH) -> int:
    """Skasuj wygasłe migawki - PARTIAMI, żeby nie blokować zapisów."""
    from app.db import database, proel_match_snapshots as T

    now = _now()
    ids = [
        row["id"]
        for row in await database.fetch_all(
            select(T.c.id)
            .where(and_(T.c.expires_at.is_not(None), T.c.expires_at < now))
            .limit(limit)
        )
    ]
    if not ids:
        return 0
    await database.execute(delete(T).where(T.c.id.in_(ids)))
    return len(ids)


async def run_snapshot_cleanup() -> None:
    """Pętla sprzątająca. Jedna porażka nie kończy pętli."""
    while True:
        try:
            removed = await cleanup_expired()
            while removed == CLEANUP_BATCH:
                await asyncio.sleep(1)  # oddech dla bazy między partiami
                removed = await cleanup_expired()
        except Exception:  # noqa: BLE001
            logger.warning("sprzatanie migawek nieudane", exc_info=True)
        await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)


# ═══════════════════════════ trasy ═══════════════════════════
#
# UWAGA NA KOLEJNOŚĆ REJESTRACJI. `app/proel.py` ma catch-all
# `GET /proel/{match_number:path}`, więc ten router MUSI stanąć przed nim
# w `main.py` - inaczej `/proel/snapshots/...` wpadnie w tamten wzorzec jako
# numer meczu. To ta sama pułapka, o której mówi komentarz przy rejestracji.

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from app.proel_auth import Actor, is_admin, proel_actor  # noqa: E402
from app.snapshot_rules import MILESTONES  # noqa: E402

router = APIRouter(prefix="/proel/snapshots", tags=["ProEl - migawki"])

#: Ile wersji przyjmujemy w jednej paczce z telefonu.
MAX_BATCH = 50


class DeviceSnapshot(BaseModel):
    """Jedna wersja przysłana przez telefon po ciszy sieciowej."""

    at: Optional[str] = Field(None, description="Kiedy powstała NA TELEFONIE (ISO)")
    milestone: Optional[str] = None
    status: Optional[str] = None
    phase: Optional[str] = None
    data_json: Any = None


class DeviceBatch(BaseModel):
    snapshots: List[DeviceSnapshot] = Field(default_factory=list)


#: Pierwsze segmenty ścieżek panelu - nigdy nie są numerem meczu.
_RESERVED_PATHS = frozenset({"restore", "matches", "one"})


async def _require_admin(actor: Actor) -> None:
    if not await is_admin(actor.judge_id):
        raise HTTPException(
            403,
            detail={
                "code": "ADMIN_ONLY",
                "message": "Historia wersji meczu jest dostępna dla administratora.",
            },
        )


def _stamp(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    try:
        text = str(raw).strip().replace(" ", "T")
        out = datetime.fromisoformat(text[:19])
        return out if out.tzinfo else out.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ─────────────────────────── odczyt: panel administratora ───────────────────
#
# KOLEJNOŚĆ TRAS MA ZNACZENIE także WEWNĄTRZ tego routera: `/{match_number:path}`
# połyka wszystko, więc ścieżki stałe („matches", „one") muszą stać przed nim.


def _public_row(row: Any) -> Dict[str, Any]:
    """Wiersz migawki BEZ treści - do listy. Treść schodzi osobną trasą."""
    created = row["created_at"]
    received = row["received_at"]
    return {
        "id": row["id"],
        "at": _iso(created),
        # Rozjazd tych dwóch znaczników mówi wprost: telefon pracował bez sieci.
        "received_at": _iso(received),
        "late_seconds": (
            int((received - created).total_seconds())
            if created is not None and received is not None
            else 0
        ),
        "source": row["source"],
        "doc_rev": row["doc_rev"],
        "phase": row["phase"],
        "status": row["status"],
        "milestone": row["milestone"],
        "score": [row["score_host"], row["score_guest"]],
        "main_time_ms": row["main_time_ms"],
        "first_half": row["first_half"],
        "protocol_len": row["protocol_len"],
        # Ostatnie zdarzenie tej wersji - panel porównuje je z sąsiednim
        # wierszem i stąd wie, CO tę wersję odróżnia.
        "last_event": (
            {
                "type": row["last_event_type"],
                "team": row["last_event_team"],
                "player": row["last_event_player"],
                "ms": row["last_event_ms"],
                "tag": row["last_event_tag"],
            }
            if row["last_event_type"]
            else None
        ),
        "signatures": row["signatures_count"],
        "writer": {
            "judge_id": row["writer_judge"],
            "name": row["writer_name"],
            "install": (str(row["writer_install"] or "")[-6:] or None),
        },
        # Pusto = treść była za duża, żeby ją przechować. Wiersz zostaje,
        # bo wersja ma być widoczna w osi czasu.
        "has_body": row["payload"] is not None,
        "bytes": row["payload_bytes"],
    }


def _iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


@router.get("/matches", summary="Mecze, dla których jest historia wersji")
async def snapshot_matches(
    season: Optional[int] = Query(None, description="Rok początku sezonu (2026 = 2026/2027)"),
    search: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    """Pierwszy poziom panelu: przy którym meczu w ogóle coś się działo."""
    await _require_admin(actor)
    from app.db import database, proel_match_snapshots as T

    query = select(
        T.c.match_number,
        T.c.zprp_match_id,
        T.c.season,
        func.count().label("versions"),
        func.min(T.c.created_at).label("first_at"),
        func.max(T.c.created_at).label("last_at"),
        func.count(func.distinct(T.c.writer_install)).label("devices"),
        func.sum(func.coalesce(T.c.payload_bytes, 0)).label("bytes"),
    ).group_by(T.c.match_number, T.c.zprp_match_id, T.c.season)

    if season is not None:
        query = query.where(T.c.season == season)
    needle = str(search or "").strip()
    if needle:
        query = query.where(T.c.match_number.ilike(f"%{needle}%"))

    rows = await database.fetch_all(query.order_by(func.max(T.c.created_at).desc()).limit(limit))
    return {
        "matches": [
            {
                "match_number": row["match_number"],
                "zprp_match_id": row["zprp_match_id"],
                "season": row["season"],
                "versions": int(row["versions"] or 0),
                "first_at": _iso(row["first_at"]),
                "last_at": _iso(row["last_at"]),
                # Więcej niż jedno urządzenie w jednym meczu to nie awaria,
                # ale to pierwsza rzecz, na którą patrzy się przy reklamacji.
                "devices": int(row["devices"] or 0),
                "bytes": int(row["bytes"] or 0),
            }
            for row in rows
        ]
    }


@router.get("/one/{snapshot_id}", summary="Treść jednej wersji")
async def snapshot_body(
    snapshot_id: int = Path(...),
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    """Pełna treść wersji - do podglądu i do zestawienia różnic."""
    await _require_admin(actor)
    from app.db import database, proel_match_snapshots as T

    row = await database.fetch_one(select(T).where(T.c.id == snapshot_id))
    if row is None:
        raise HTTPException(404, "Nie ma takiej wersji.")
    body = unpack(row["payload"])
    if body is None:
        raise HTTPException(
            410,
            detail={
                "code": "NO_BODY",
                "message": (
                    "Tej wersji nie przechowujemy - treść była za duża albo "
                    "wygasła. W osi czasu zostaje sam ślad."
                ),
            },
        )
    return {
        **_public_row(row),
        "match_number": row["match_number"],
        "data_json": body,
        "overlay": unpack(row["overlay"]),
    }


@router.get("/{match_number:path}", summary="Oś czasu wersji jednego meczu")
async def snapshot_timeline(
    match_number: str = Path(...),
    limit: int = Query(500, ge=1, le=2000),
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    """Drugi poziom panelu: wszystkie wersje jednego meczu, od najnowszej."""
    await _require_admin(actor)
    from app.db import database, proel_match_snapshots as T

    key = str(match_number or "").strip()
    rows = await database.fetch_all(
        select(T)
        .where(T.c.match_number == key)
        .order_by(T.c.created_at.desc(), T.c.id.desc())
        .limit(limit)
    )
    return {
        "match_number": key,
        "versions": [_public_row(row) for row in rows],
        # Ile z tego przyszło z telefonu po ciszy - panel mówi to wprost.
        "from_device": sum(1 for row in rows if row["source"] == "device"),
    }


# ─────────────────────────── przywracanie ───────────────────────────
#
# JEDYNA operacja w systemie, która cofa czas. Trzy rzeczy stoją na straży:
# bramka administratora, zachowanie wersji nadpisywanej i wpis w dzienniku
# z nazwiskiem. Sama zmiana idzie ZWYKŁĄ drogą zapisu - z reprojekcją overlaya,
# podbiciem wersji i autorem - żeby przywrócony protokół niczym nie różnił się
# od normalnie zapisanego.


class RestoreRequest(BaseModel):
    """Czego administrator chce od przywracania."""

    #: Powiadomić obsadę meczu. DOMYŚLNIE NIE - decyzja użytkownika 14.09.2026.
    notify_crew: bool = False
    #: Przywrócić także pola wspólne (podpisy, obsada, uwagi) z tamtej chwili.
    #: Domyślnie NIE: overlay nie jest wersjonowany nigdzie indziej, więc jego
    #: cofnięcie jest osobną, świadomą decyzją.
    restore_overlay: bool = False


@router.post("/restore/{snapshot_id}", summary="Przywróć mecz do tej wersji")
async def restore_snapshot(
    snapshot_id: int = Path(...),
    body: RestoreRequest = Body(default_factory=RestoreRequest),
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    """Nadpisz bieżącą treść meczu tą wersją.

    CO PRZEŻYWA PRZYWRÓCENIE:
      * podpisy - dwiema drogami naraz. Serwer nakłada overlay przy zapisie
        (tam żyją podpisy złożone w aplikacji), a `merge_signatures_forward`
        dokłada te, które przez rejestr pól nigdy nie przeszły. Sędzia, który
        podpisał o 20:10, nie traci podpisu przez cofnięcie meczu do 18:40;
      * obsada, osoby towarzyszące, badania, pola pomeczowe - wszystko, co
        siedzi w overlayu.
    CO ZOSTAJE NADPISANE: przebieg meczu, wynik, czasy, SKŁADY. To jest cel
    tej operacji i dlatego aplikacja pokazuje różnice przed potwierdzeniem.

    CZEGO NIE ROBIMY: nie kasujemy wersji nowszych. Bieżąca ląduje w historii
    (`proel_doc_history`, powód `restored_over`), więc „zepsuta" wersja dalej
    da się obejrzeć - i przywrócić z powrotem.
    """
    await _require_admin(actor)
    import copy

    from app.db import (
        database,
        proel_doc_history,
        proel_match_snapshots as T,
        proel_match_state,
        saved_matches,
    )
    from app.proel_doc_version import restore_install
    from app.proel_fields import project
    from app.proel_journal import log_match_event
    from app.proel_fields import same_judge_number
    from app.proel_lease import lease_active
    from app.snapshot_rules import merge_signatures_forward

    snap = await database.fetch_one(select(T).where(T.c.id == snapshot_id))
    if snap is None:
        raise HTTPException(404, "Nie ma takiej wersji.")
    restored = unpack(snap["payload"])
    if restored is None:
        raise HTTPException(
            410,
            detail={
                "code": "NO_BODY",
                "message": "Tej wersji nie przechowujemy - nie ma czego przywrócić.",
            },
        )

    key = str(snap["match_number"])
    row = await database.fetch_one(
        select(saved_matches).where(saved_matches.c.match_number == key)
    )
    if row is None:
        raise HTTPException(404, "Tego meczu nie ma już w ProElu.")

    current_status = str(row["status"] or "")
    if current_status == "approved":
        raise HTTPException(
            409,
            detail={
                "code": "MATCH_APPROVED",
                "message": (
                    "Ten protokół jest zatwierdzony. Najpierw cofnij "
                    "zatwierdzenie - zamknięty dokument zostaje zamknięty."
                ),
            },
        )

    state = await database.fetch_one(
        select(proel_match_state).where(proel_match_state.c.match_number == key)
    )
    state_dict = dict(state) if state is not None else None
    # Prowadzenie blokuje przywrócenie tylko wtedy, gdy trzyma je KTOŚ INNY.
    #
    # Własne prowadzenie nie jest przeszkodą: to ten sam człowiek podejmuje
    # obie decyzje, a jego telefon dowie się o cofnięciu natychmiast - zapis
    # przywrócenia nie jest podpisany żadnym urządzeniem (`restore_install`),
    # więc najbliższy autozapis odbija się o bezpiecznik i ekran pyta o wersję
    # od razu. Odmowa w tej sytuacji znaczyła tylko tyle: „poczekaj na koniec
    # meczu, którego sam nie możesz skończyć, bo właśnie go prowadzisz".
    if lease_active(state_dict) and not same_judge_number(
        (state_dict or {}).get("lease_judge_id"), actor.judge_id
    ):
        holder = str((state_dict or {}).get("lease_name") or "").strip()
        raise HTTPException(
            409,
            detail={
                "code": "LEASE_ACTIVE",
                "message": (
                    f"Ten mecz prowadzi teraz {holder or 'inne urządzenie'}. "
                    "Przywrócona wersja zostałaby nadpisana przy najbliższym "
                    "autozapisie - poczekaj na koniec meczu."
                ),
            },
        )

    current_blob = row["data_json"]
    if isinstance(current_blob, str):
        try:
            current_blob = json.loads(current_blob)
        except ValueError:
            current_blob = None

    # 1) Podpisy z wersji bieżącej wchodzą do przywracanej.
    target = merge_signatures_forward(copy.deepcopy(restored), current_blob)
    # 2) Overlay z wierzchu - tą samą drogą, co przy zwykłym zapisie.
    overlay = (state_dict or {}).get("fields_json")
    if isinstance(overlay, dict) and not body.restore_overlay:
        target = project(overlay, target)

    async with database.transaction():
        # Wersja nadpisywana NIE ginie - to jest cała różnica między
        # przywróceniem a skasowaniem.
        await database.execute(
            proel_doc_history.insert().values(
                match_number=key,
                doc_rev=row["doc_rev"],
                data_json=current_blob,
                status=current_status,
                writer_install=row["doc_writer_install"],
                writer_judge=row["doc_writer_judge"],
                writer_name=row["doc_writer_name"],
                written_at=row["doc_written_at"],
                archived_by_judge=actor.judge_id or None,
                archived_by_name=actor.name or None,
                archived_by_install=actor.installation_id or None,
                reason="restored_over",
                expires_at=_now() + timedelta(days=365),
            )
        )
        await database.execute(
            saved_matches.update()
            .where(saved_matches.c.match_number == key)
            .values(
                data_json=target,
                doc_rev=saved_matches.c.doc_rev + 1,
                # NIE identyfikator urządzenia - patrz `restore_install`.
                # Inaczej autozapis tego samego telefonu przeszedłby jako
                # „mój własny zapis" i po cichu cofnąłby przywrócenie.
                doc_writer_install=restore_install(actor.installation_id),
                doc_writer_judge=actor.judge_id or None,
                doc_writer_name=actor.name or None,
                doc_written_at=func.now(),
                updated_at=func.now(),
            )
        )

        if state_dict is not None:
            # Budzik dla POZOSTAŁYCH urządzeń. Long-poll stanu czeka na wyższą
            # rewizję wiersza stanu, a przywrócenie tego wiersza nie dotyka -
            # więc drugi telefon dowiadywałby się o cofnięciu meczu dopiero
            # przy najbliższym wygaśnięciu długiego zapytania. Jedna liczba
            # w górę i wiedzą od razu.
            await database.execute(
                proel_match_state.update()
                .where(proel_match_state.c.match_number == key)
                .values(rev=proel_match_state.c.rev + 1, updated_at=func.now())
            )

    await log_match_event(
        match_number=key,
        event="match.restored",
        actor=actor,
        zprp_match_id=snap["zprp_match_id"],
        details={
            "snapshot_id": snapshot_id,
            "from_at": _iso(snap["created_at"]),
            "from_doc_rev": snap["doc_rev"],
            "over_doc_rev": row["doc_rev"],
            "source": snap["source"],
            "notify_crew": bool(body.notify_crew),
        },
    )

    # Przywrócenie jest zdarzeniem w historii tak samo jak każde inne -
    # i kamieniem milowym, bo to chwila, o którą ktoś kiedyś zapyta.
    await record_snapshot(
        match_number=key,
        blob=target,
        overlay=overlay if isinstance(overlay, dict) else None,
        status=current_status,
        phase=str(snap["phase"] or ""),
        zprp_match_id=snap["zprp_match_id"],
        writer_judge=actor.judge_id,
        writer_name=actor.name,
        writer_install=actor.installation_id,
        milestone="restore",
    )

    return {
        "success": True,
        "match_number": key,
        "restored_from": _iso(snap["created_at"]),
        "kept_as_history": True,
    }


# ─────────────── dosylka z telefonu (TRASA ZACHLANNA) ──────────────
#
# STOI NA KOŃCU PLIKU I MA TU ZOSTAĆ. `/{match_number:path}` połyka każdą
# ścieżkę POST tego routera, łącznie z ukosnikami - a FastAPI dopasowuje trasy
# W KOLEJNOŚCI REJESTRACJI. Gdy ta trasa stała wyżej, `POST /restore/{id}`
# trafiał tutaj jako „dosłano paczkę dla meczu restore/123": pusta lista
# migawek, odpowiedź 200, toast „Przywrócono" - i ani jednej zmiany w bazie
# (zgłoszenie 15.09.2026). Test `test_snapshots_wiring.py` tego pilnuje.

@router.post("/{match_number:path}", summary="Dosyłka historii z telefonu")
async def upload_device_snapshots(
    match_number: str = Path(...),
    body: DeviceBatch = Body(...),
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    """Przyjmij paczkę wersji zebranych przez telefon poza zasięgiem.

    TO SĄ DEKLARACJE URZĄDZENIA, nie obserwacje serwera - zapisujemy je ze
    źródłem `device` i z ich własnym czasem powstania, a obok własny czas
    odbioru. Po rozjeździe tych dwóch znaczników widać, że telefon pracował
    bez sieci, i to jest cała wartość tej trasy.

    Limity są te same, co przy zapisie z serwera (`app/snapshot_rules.py`):
    odcisk treści odsiewa powtórki, a limit dobowy broni przed zalaniem bazy.
    """
    # Numer przyjeżdża w postaci kanonicznej z telefonu (`proelMatchKey`) -
    # tak samo, jak na każdej innej trasie ProEla.
    key = str(match_number or "").strip()
    if not key:
        raise HTTPException(400, "Brak numeru meczu.")
    if key.split("/", 1)[0] in _RESERVED_PATHS:
        # Druga linia obrony za kolejnością tras. Gdyby ta trasa kiedykolwiek
        # znów stanęła nad którąś ze stałych, żądanie skończy się GŁOŚNO -
        # a nie cichym „przyjęto 0 wersji", które wygląda jak sukces.
        raise HTTPException(
            404,
            detail={
                "code": "RESERVED_PATH",
                "message": (
                    f"Adres {key} to ścieżka panelu, a nie numer meczu."
                ),
            },
        )

    items = list(body.snapshots or [])[:MAX_BATCH]
    if not items:
        return {"accepted": 0, "skipped": 0, "failed": 0}

    # HISTORIA NALEŻY DO MECZU, KTÓRY ISTNIEJE.
    #
    # Bez tego warunku dowolny klucz zakładał w panelu mecz-widmo: wiersze
    # migawek i wpisy w dzienniku pod numerem, którego nie ma w ProElu. Tak
    # właśnie wyglądał mecz „W/JmK/3" obok prowadzonego naprawdę zapisu
    # szkoleniowego „T-.../W/JmK/3" (zgłoszenie 15.09.2026) - telefon dosyłał
    # historię pod GOŁYM numerem zamiast pod kluczem wiersza.
    #
    # Odmowa, a nie ciche przyjęcie: telefon ma zatrzymać paczkę i spróbować
    # ponownie, gdy mecz na serwerze już będzie (zakłada go pierwszy zapis).
    from app.db import database, saved_matches

    known = await database.fetch_val(
        select(saved_matches.c.match_number).where(
            saved_matches.c.match_number == key
        )
    )
    if known is None:
        raise HTTPException(
            404,
            detail={
                "code": "MATCH_NOT_FOUND",
                "message": (
                    "Nie ma w ProElu meczu o tym kluczu, więc nie ma do czego "
                    "dołączyć historii wersji."
                ),
            },
        )

    accepted = 0
    skipped = 0
    failed = 0
    for item in items:
        why = await record_snapshot(
            match_number=key,
            blob=item.data_json,
            status=item.status,
            phase=item.phase,
            milestone=item.milestone if item.milestone in MILESTONES else None,
            writer_judge=actor.judge_id,
            writer_name=actor.name,
            writer_install=actor.installation_id,
            source="device",
            created_at=_stamp(item.at),
        )
        if why is None:
            accepted += 1
        elif why == "blad":
            # Awaria po NASZEJ stronie - to nie jest powtórka ani limit.
            failed += 1
        else:
            skipped += 1
    if accepted:
        # Widać wtedy, że telefon pracował poza zasięgiem serwera - i ile
        # tego było. Jeden wpis na paczkę, nie na wersję.
        from app.proel_journal import log_match_event

        await log_match_event(
            match_number=key,
            event="match.snapshots_backfilled",
            actor=actor,
            details={"accepted": accepted, "skipped": skipped},
        )

    if accepted == 0 and failed:
        # NIC nie weszło, a powodem była awaria bazy - nie wolno odpowiedzieć
        # „przyjęte", bo telefon kasuje u siebie całą wysłaną paczkę i historia
        # meczu prowadzonego bez zasięgu przepadłaby bezpowrotnie. Tak właśnie
        # zniknęła historia z 15.09.2026: tabela migawek nie miała kolumn
        # dołożonych w kodzie, każdy zapis się wywracał, a telefony po cichu
        # czyściły kolejkę. Błąd = telefon zatrzymuje paczkę i spróbuje za
        # minutę (`utils/matchSnapshotSync.ts`).
        raise HTTPException(
            503,
            detail={
                "code": "SNAPSHOT_STORE_FAILED",
                "message": "Nie udało się odłożyć historii wersji - spróbuj za chwilę.",
            },
        )

    # Telefon kasuje u siebie CAŁĄ paczkę: pominięta wersja to albo powtórka,
    # albo limit - w obu wypadkach ponawianie niczego nie zmieni.
    return {"accepted": accepted, "skipped": skipped, "failed": failed}

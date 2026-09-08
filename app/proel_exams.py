"""Badania lekarskie w ProElu: ślad w dzienniku i awans z bazy związku.

Dwa braki zgłoszone z terenu przy SK/5 (GAKIDOVA, nr 77):

1. **Ręczne potwierdzenie z ekranu konfiguracji nie zostawiało śladu.** Arkusz
   „Sprawdź badania" w szczegółach meczu pisze do overlaya i dziennika, ale
   ten sam arkusz otwarty z ekranu konfiguracji zmienia tylko lokalną tablicę
   telefonu - znacznik jedzie potem w kartach zawodników w blobie, a zapis
   bloba loguje wyłącznie zmiany statusu. Na pytanie „kto i kiedy potwierdził
   nr 77" dziennik odpowiadał ciszą.

2. **Baza związku potwierdziła badania później, a protokół dalej niósł ręczny
   ptaszek.** Krata `none < manual < wzpr < zprp` od zawsze dopuszcza taki
   awans, ale nikt go nie robił: monitor okręgu nie czyta rosterów, a telefon
   pyta API o skład tylko przy wczytaniu meczu.

Oba braki domyka ten moduł, w JEDNYM miejscu prawdy - overlayu:

* `absorb_blob_exams` - przy każdym zapisie bloba ręczne potwierdzenia z kart
  zawodników, o których overlay nie wie, wchodzą do overlaya z aktorem zapisu
  i idą do dziennika jako „Potwierdzenie badań"; cofnięcie z tego samego
  urządzenia wraca tą samą drogą,
* `promote_manual_exams` - pyta publiczne API po numerze meczu i ręczne
  znaczniki, które związek ma już jako „OK", awansuje w overlayu na
  `zprp`/`wzpr`. Reprojekcja nakłada to na blob, więc kolejny snapshot z
  telefonu prowadzącego niczego nie cofa; generator PDF nakłada overlay na
  blob do wydruku, więc ptaszek na protokole też się zmienia,
* `run_exam_promotion_sweep` - przebieg w tle dla meczów, przy których nikt
  nie zapisuje bloba (skonfigurowanych, jeszcze nierozpoczętych).

GRANICA CZASOWA (decyzja z 2026-09-08): awans dzieje się WYŁĄCZNIE przed
pierwszym gwizdkiem (`PHASE_PRE`). Protokół ma mówić, co było wiadomo w
chwili rozpoczęcia meczu - ręczny ptaszek postawiony, bo baza związku nie
miała wtedy badań, jest prawdą o TYM meczu i potwierdzenie dosłane nazajutrz
nie ma prawa jej przepisać. W rozgrywkach centralnych dochodzi drugi rygiel:
awans na WZPR jest tam odebraniem prawa gry, więc nie zachodzi wcale.

Reguły bez bazy i bez sieci mieszkają w `app/proel_fields.py` i mają testy;
tutaj jest wyłącznie ich spięcie z bazą, siecią i dziennikiem.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from httpx import AsyncClient
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import database, proel_match_state, saved_matches
from app.proel_auth import Actor
from app.proel_fields import (
    EXAM_SRC_ZPRP,
    PHASE_PRE,
    PathRejected,
    adopt_blob_exams,
    exam_entry,
    exam_recheck_from_blob,
    manual_exam_candidates,
    merge_exam,
    phase_of,
    promotions_for,
    roster_marks,
)
from app.protocol_category import exam_requirement_for_code
from app.proel_journal import log_match_event
from app.proel_match_key import local_key_from_blob, zprp_id_of

logger = logging.getLogger(__name__)

#: Nie częściej niż co tyle sekund pytamy związek o TEN mecz. Blob prowadzącego
#: przychodzi co minutę przez cały mecz - bez tego rygla każdy z nich byłby
#: osobnym wejściem na cudzy serwer.
PROMOTION_MIN_INTERVAL_S = 300

#: Co ile sekund chodzi przebieg w tle dla meczów bez świeżych zapisów bloba.
PROMOTION_SWEEP_S = 600

#: Ile meczów jeden przebieg w tle bierze pod uwagę.
PROMOTION_SWEEP_BATCH = 40

#: Jak stare wiersze jeszcze sprawdzamy. Awans ma sens do pierwszego
#: gwizdka, a mecz konfiguruje się najwyżej kilka dni przed terminem.
PROMOTION_LOOKBACK_DAYS = 7

#: Ile sekund ma publiczne API na odpowiedź - pytamy przy zapisie bloba, więc
#: krótko, jak w giełdzie meczów (`LIVE_CREW_REQUEST_SECONDS`).
ROSTER_TIMEOUT_S = 8.0

#: Podpis wpisu overlaya, który postawił nie człowiek, a baza związku.
ZPRP_BY: Dict[str, Any] = {
    "judge_id": "",
    "name": "Baza ZPRP",
    "install": "",
    "verified": True,
}

#: Znacznik czasu ostatniego pytania do związku, per numer meczu. Pamięć
#: procesu wystarcza: po restarcie najwyżej zapytamy raz za wcześnie.
_last_checked: Dict[str, float] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _throttled(match_number: str, force: bool) -> bool:
    if force:
        return False
    loop = asyncio.get_running_loop()
    last = _last_checked.get(match_number)
    return last is not None and (loop.time() - last) < PROMOTION_MIN_INTERVAL_S


def _mark_checked(match_number: str) -> None:
    _last_checked[match_number] = asyncio.get_running_loop().time()


def _as_dict(row: Any) -> Dict[str, Any]:
    if row is None:
        return {}
    return dict(row._mapping) if hasattr(row, "_mapping") else dict(row)


def _by_of(actor: Optional[Actor], install: str) -> Dict[str, Any]:
    """Podpis wpisu z zapisu bloba - aktor miękki, więc bywa pusty."""
    if actor is not None:
        return actor.as_by()
    return {"judge_id": "", "name": "", "install": install, "verified": False}


# ───────────────────────── potwierdzenia z bloba ─────────────────────────


async def ensure_state_row(match_number: str, blob: Any) -> Dict[str, Any]:
    """Wiersz stanu dla bloba, który przyszedł bez niego (starsza aplikacja).

    Overlay jest jedynym miejscem, w którym potwierdzenie może zostawić ślad,
    więc gdy w blobie jedzie ręczny ptaszek, a wiersza stanu nie ma - zakładamy
    go. Tożsamość bierzemy z bloba (`zprp_match_id`, odcisk numer+drużyny),
    dokładnie tak, jak robi to `/proel/ensure` z guarda.
    """
    number = str(match_number or "").strip()
    existing = await database.fetch_one(
        select(proel_match_state).where(proel_match_state.c.match_number == number)
    )
    if existing is not None:
        return _as_dict(existing)
    # `ON CONFLICT DO NOTHING`: aplikacja wola `/proel/ensure` mniej wiecej w tej
    # samej chwili, co pierwszy zapis bloba. Zwykly INSERT przegrywalby ten
    # wyscig unikatem i wywracal zapis meczu w srodku transakcji.
    await database.execute(
        pg_insert(proel_match_state)
        .values(
            match_number=number,
            zprp_match_id=zprp_id_of(blob) or None,
            local_key=local_key_from_blob(blob) or None,
            guard_json=None,
            rev=1,
            fields_json={},
            audit_json={"log": [], "ops": []},
            status_cache=None,
        )
        .on_conflict_do_nothing(index_elements=["match_number"])
    )
    row = await database.fetch_one(
        select(proel_match_state).where(proel_match_state.c.match_number == number)
    )
    return _as_dict(row)


async def absorb_blob_exams(
    match_number: str,
    state: Dict[str, Any],
    blob: Any,
    actor: Optional[Actor],
    install: str,
) -> Dict[str, Any]:
    """Wciągnij do overlaya ręczne potwierdzenia, które przyszły w kartach.

    Woła się WEWNĄTRZ transakcji zapisu bloba, PRZED reprojekcją - inaczej
    reprojekcja przepisałaby stan overlaya na karty i nie byłoby czego czytać.
    Zwraca stan po zmianie (do reprojekcji) i listy do dziennika. Gdy nic nie
    weszło, oddaje stan bez zmian i puste listy.
    """
    untouched = {"state": state, "confirmed": [], "withdrawn": [], "rev": int(state.get("rev") or 0)}
    try:
        overlay = state.get("fields_json") if isinstance(state.get("fields_json"), dict) else {}
        rev = int(state.get("rev") or 0) + 1
        new_overlay, confirmed, withdrawn = adopt_blob_exams(
            overlay,
            blob,
            rev=rev,
            at=_now().isoformat(),
            by=_by_of(actor, install),
            install=str(install or "").strip(),
        )
    except Exception:  # noqa: BLE001
        # Slad w overlayu jest dodatkiem do zapisu meczu, nie jego warunkiem:
        # blob o ksztalcie, ktorego nie przewidzielismy, ma sie zapisac jak dotad.
        logger.warning("badania: nie wchlonieto potwierdzen z bloba %s", match_number, exc_info=True)
        return untouched
    if not confirmed and not withdrawn:
        return untouched
    await database.execute(
        update(proel_match_state)
        .where(proel_match_state.c.match_number == str(match_number or "").strip())
        .values(fields_json=new_overlay, rev=rev, updated_at=func.now())
    )
    refreshed = dict(state)
    refreshed["fields_json"] = new_overlay
    refreshed["rev"] = rev
    return {"state": refreshed, "confirmed": confirmed, "withdrawn": withdrawn, "rev": rev}


async def journal_absorbed(
    match_number: str,
    zprp_match_id: Optional[str],
    absorbed: Dict[str, Any],
    actor: Optional[Actor],
    *,
    app_version: Optional[str] = None,
    ip: Optional[str] = None,
) -> None:
    """Wpisy dziennika za potwierdzenia wchłonięte z bloba - PO transakcji.

    `event_key` z rewizją overlaya: ten sam snapshot ponowiony przez telefon
    nie dopisze zdarzenia drugi raz. Dziennik nigdy nie rzuca (patrz
    `log_match_event`), więc i to wołanie nie ma prawa wywrócić zapisu.
    """
    rev = int(absorbed.get("rev") or 0)
    for event, players in (
        ("exam.confirmed", absorbed.get("confirmed") or []),
        ("exam.withdrawn", absorbed.get("withdrawn") or []),
    ):
        if not players:
            continue
        await log_match_event(
            match_number=match_number,
            event=event,
            actor=actor,
            zprp_match_id=zprp_match_id,
            details={"players": players, "source": "config", "rev": rev},
            event_key=f"exam:{event}:{match_number}:{rev}",
            app_version=app_version,
            ip=ip,
        )


async def journal_exam_recheck(
    match_number: str,
    zprp_match_id: Optional[str],
    blob: Any,
    actor: Optional[Actor],
    *,
    app_version: Optional[str] = None,
    ip: Optional[str] = None,
) -> None:
    """Wpis za sprawdzenie badań w bazie związku przed pierwszym gwizdkiem.

    `event_key` bierze GODZINĘ sprawdzenia, więc blob wysyłany co minutę
    przez cały mecz dopisuje to zdarzenie dokładnie raz. Dziennik nigdy nie
    rzuca (patrz `log_match_event`), więc i to wołanie nie wywróci zapisu.
    """
    check = exam_recheck_from_blob(blob)
    if not check:
        return
    await log_match_event(
        match_number=match_number,
        event="exam.rechecked",
        actor=actor,
        zprp_match_id=zprp_match_id,
        details={
            "players": check["players"],
            "at": check["at"],
            "clock": check["clock"],
            "source": "start",
        },
        event_key=f"exam:recheck:{match_number}:{check['at']}",
        app_version=app_version,
        ip=ip,
    )


# ───────────────────────── awans z bazy związku ─────────────────────────


async def _fetch_roster(zprp_match_id: str) -> Optional[Dict[str, Any]]:
    """Odpowiedź `pokaz_mecze_szczegoly.php` z rosterami - albo `None`.

    Ten sam pobieracz, którym chodzi monitor okręgu (oba kształty odpowiedzi,
    `[null]` = brak meczu), tylko na krótszej smyczy.
    """
    # Import lokalny: monitor ciągnie za sobą scraper z bs4, a moduł badań nie
    # ma powodu budzić go przy starcie aplikacji.
    from app.province_match_monitor import _fetch_public_details

    async with AsyncClient(follow_redirects=True) as client:
        return await _fetch_public_details(
            client, zprp_match_id, timeout=ROSTER_TIMEOUT_S, retries=1
        )


async def promote_manual_exams(match_number: str, *, force: bool = False) -> Dict[str, Any]:
    """Ręczne znaczniki, które związek ma już jako „OK", awansują w overlayu.

    Odpowiedź mówi, co się stało, bo przebieg w tle i test chcą to wiedzieć:
    `skipped` z powodem albo `promoted` z listą zawodników.
    """
    number = str(match_number or "").strip()
    if not number:
        return {"skipped": "no_number"}
    if _throttled(number, force):
        return {"skipped": "throttled"}

    doc = _as_dict(
        await database.fetch_one(
            select(
                saved_matches.c.data_json,
                saved_matches.c.status,
                saved_matches.c.zprp_match_id,
            ).where(saved_matches.c.match_number == number)
        )
    )
    if str(doc.get("status") or "") == "approved":
        # Zatwierdzonego protokołu nie ruszamy - ta sama reguła, co w reprojekcji.
        return {"skipped": "approved"}
    state = _as_dict(
        await database.fetch_one(
            select(proel_match_state).where(proel_match_state.c.match_number == number)
        )
    )
    if str(state.get("status_cache") or "") == "approved":
        return {"skipped": "approved"}

    # Nadpisywanie ręcznych potwierdzeń kończy się z pierwszym gwizdkiem.
    #
    # Decyzja z 2026-09-08. Protokół ma mówić, co było wiadomo w chwili
    # rozpoczęcia meczu: jeżeli sędzia potwierdził badania ręcznie, bo baza
    # związku ich wtedy nie miała, to ręczny ptaszek jest PRAWDĄ o tym meczu
    # i potwierdzenie dosłane nazajutrz nie ma prawa jej przepisać.
    if phase_of(state, doc.get("status")) != PHASE_PRE:
        return {"skipped": "started"}

    blob = doc.get("data_json") if isinstance(doc.get("data_json"), dict) else {}
    overlay = state.get("fields_json") if isinstance(state.get("fields_json"), dict) else {}
    candidates = manual_exam_candidates(overlay, blob)
    if not candidates:
        return {"skipped": "no_manual"}

    zprp_id = (
        str(state.get("zprp_match_id") or "").strip()
        or str(doc.get("zprp_match_id") or "").strip()
        or zprp_id_of(blob)
    )
    if not zprp_id.isdigit():
        # Mecz założony ręcznie albo ćwiczenie - związek go nie zna.
        return {"skipped": "no_zprp_id"}

    _mark_checked(number)
    try:
        payload = await _fetch_roster(zprp_id)
    except Exception:  # noqa: BLE001 - pytanie do cudzego serwera, nie nasz błąd
        logger.debug("badania: związek nie odpowiedział dla %s", number, exc_info=True)
        payload = None
    if not payload:
        return {"skipped": "no_answer"}

    # Próg rozgrywki: w Superlidze awans „ręczne -> WZPR" odebrałby prawo gry
    # zawodniczce, którą sędzia dopuścił - patrz `promotions_for`.
    promotions = promotions_for(
        candidates,
        roster_marks(payload),
        exam_requirement_for_code(number),
    )
    if not promotions:
        return {"promoted": []}

    done: List[Dict[str, Any]] = []
    rev = 0
    async with database.transaction():
        locked = _as_dict(
            await database.fetch_one(
                select(proel_match_state)
                .where(proel_match_state.c.match_number == number)
                .with_for_update()
            )
        )
        if not locked:
            locked = await ensure_state_row(number, blob)
        overlay = dict(locked.get("fields_json") or {}) if isinstance(locked.get("fields_json"), dict) else {}
        rev = int(locked.get("rev") or 0) + 1
        stamp = _now().isoformat()
        for item in promotions:
            path = str(item["path"])
            value = {"mark": item["mark"], "name": item["name"]}
            try:
                # Ta sama krata, co przy zapisie z telefonu: awans wchodzi tylko
                # w górę, a ponowienie jest nieszkodliwe.
                merge_exam(overlay.get(path), value, False)
            except PathRejected:
                continue
            current = str(((overlay.get(path) or {}).get("v") or {}).get("mark") or "none")
            if current == item["mark"]:
                continue
            overlay[path] = exam_entry(
                item["mark"], item["name"], rev=rev, at=stamp, by=ZPRP_BY, src=EXAM_SRC_ZPRP
            )
            done.append(
                {
                    "team": item["team"],
                    "number": item["number"],
                    "name": item["name"],
                    "from": "manual",
                    "to": item["mark"],
                }
            )
        if done:
            await database.execute(
                update(proel_match_state)
                .where(proel_match_state.c.match_number == number)
                .values(fields_json=overlay, rev=rev, updated_at=func.now())
            )
            # Import lokalny - `app.proel` importuje ten moduł; odwrotny import
            # na poziomie modułu zamknąłby pętlę.
            from app.proel import _apply_reprojection_to_doc

            refreshed = dict(locked)
            refreshed["fields_json"] = overlay
            await _apply_reprojection_to_doc(number, refreshed)

    if done:
        await log_match_event(
            match_number=number,
            event="exam.promoted",
            actor=None,
            zprp_match_id=zprp_id,
            details={"players": done, "source": "zprp", "rev": rev},
            event_key=f"exam:promoted:{number}:{rev}",
        )
    return {"promoted": done}


async def _promote_safely(match_number: str) -> None:
    try:
        await promote_manual_exams(match_number)
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001
        logger.debug("badania: awans dla %s nie powiódł się", match_number, exc_info=True)


#: Zadania w tle trzymamy mocno - `create_task` bez referencji może zostać
#: sprzątnięty przez GC w połowie pracy.
_kicked: set = set()


def kick_promotion(match_number: str) -> None:
    """Sprawdź awans W TLE - zapis bloba nie czeka na cudzy serwer.

    Rygiel czasu siedzi w `promote_manual_exams`, więc wołanie przy każdym
    zapisie jest tanie: najwyżej jedno pytanie do związku na pięć minut.
    """
    number = str(match_number or "").strip()
    if not number:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    task = loop.create_task(_promote_safely(number))
    _kicked.add(task)
    task.add_done_callback(_kicked.discard)


# ───────────────────────── przebieg w tle ─────────────────────────


async def _sweep_once() -> int:
    """Mecze PRZED pierwszym gwizdkiem, przy których nikt nie zapisuje bloba.

    Przebieg szedł po `saved_matches` ze statusem „w toku"/„zakończony", bo
    awans wolno było robić do zatwierdzenia protokołu. Od 2026-09-08 wolno go
    robić tylko do rozpoczęcia meczu, a mecz jeszcze nierozpoczęty często NIE
    MA wiersza w `saved_matches` - blob powstaje razem z ekranem meczu. Stąd
    pytamy o wiersze stanu bez `live_started_at`: to dokładnie te mecze, które
    ktoś skonfigurował i którym związek może jeszcze dosłać badania.
    """
    since = _now() - timedelta(days=PROMOTION_LOOKBACK_DAYS)
    rows = await database.fetch_all(
        select(
            proel_match_state.c.match_number,
            proel_match_state.c.fields_json,
        )
        .where(proel_match_state.c.live_started_at.is_(None))
        .where(proel_match_state.c.updated_at >= since)
        .order_by(proel_match_state.c.updated_at.desc())
        .limit(PROMOTION_SWEEP_BATCH)
    )
    checked = 0
    for raw in rows:
        row = _as_dict(raw)
        number = str(row.get("match_number") or "").strip()
        overlay = row.get("fields_json") if isinstance(row.get("fields_json"), dict) else {}
        doc = _as_dict(
            await database.fetch_one(
                select(saved_matches.c.data_json).where(
                    saved_matches.c.match_number == number
                )
            )
        )
        blob = doc.get("data_json") if isinstance(doc.get("data_json"), dict) else {}
        if not manual_exam_candidates(overlay, blob):
            continue
        await _promote_safely(number)
        checked += 1
    return checked


async def run_exam_promotion_sweep() -> None:
    """Pętla w tle: mecze przed gwizdkiem, przy których nikt nie zapisuje bloba."""
    await asyncio.sleep(120)
    while True:
        try:
            await _sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("badania: przebieg awansów w tle nie powiódł się")
        await asyncio.sleep(PROMOTION_SWEEP_S)

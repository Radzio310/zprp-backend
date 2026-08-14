import asyncio
import copy
import logging
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, insert, update, delete, func
from app.db import database, saved_matches, proel_match_state
from app.proel_auth import Actor, is_admin, proel_actor, roles_for
from app.proel_fields import (
    PHASE_LIVE,
    PHASE_LOCKED,
    PHASE_POST,
    PHASE_PRE,
    PathRejected,
    UnknownPath,
    live_signal,
    parse_path,
    project,
)
from app.schemas import (
    CreateSavedMatchRequest,
    PlayerInfo,
    PlayersResponse,
    PlayersSide,
    UpdateSavedMatchRequest,
    MatchItem,
    ListSavedMatchesResponse,
    ProElEnsureRequest,
    ProElPatchRequest,
    ProElStateResponse,
)
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/proel",
    tags=["ProEl"],
    responses={404: {"description": "Not found"}},
)

_VALID_STATUSES = ("in_progress", "finished", "approved")

#: Ile op_id pamiętamy, żeby ponowienie z outboxa nie zadziałało dwa razy.
_AUDIT_OPS_KEEP = 100
#: Ile wpisów historii trzymamy w audycie (ring).
_AUDIT_LOG_KEEP = 50
#: Górny limit `wait` dla long-polla. Trzymany krótko, żeby proxy Railway
#: nie zrywało połączenia w połowie.
_MAX_WAIT_SECONDS = 25.0
#: Odstęp między sprawdzeniami rewizji w long-pollu. Świadomie sprawdzamy BAZĘ,
#: a nie zdarzenie w pamięci procesu — inaczej zmiana zrobiona przez inny
#: worker/replikę nigdy by nie obudziła czekającego.
_WAIT_POLL_SECONDS = 0.8


def _resolve_status(status: Optional[str], is_finished: Optional[bool], fallback: str) -> str:
    """Ustal status na podstawie (priorytetowo) jawnego pola status, a w jego braku
    starego pola is_finished. is_finished=True z dawnych klientów mapujemy na 'finished'
    (nigdy na 'approved' — zatwierdzenie to świadoma, osobna akcja)."""
    if status:
        s = str(status).strip().lower()
        if s in _VALID_STATUSES:
            return s
    if is_finished is not None:
        return "finished" if is_finished else "in_progress"
    return fallback


def _is_finished_for(status: str) -> bool:
    return status in ("finished", "approved")


# ════════════════════════ warstwa stanu współpracy ════════════════════════
#
# Overlay (`proel_match_state.fields_json`) jest źródłem prawdy dla pól
# z rejestru; `proel_matches.data_json` jest widokiem pochodnym. Reprojekcja
# przy KAŻDYM zapisie jest jedynym powodem, dla którego potwierdzenie badań
# przeżywa pełny snapshot wysyłany co 60 s przez telefon prowadzącego mecz.


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_dict(row: Any) -> Dict[str, Any]:
    return dict(row) if row is not None else {}


def _overlay_of(state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not state:
        return {}
    fields = state.get("fields_json")
    return fields if isinstance(fields, dict) else {}


def _phase_of(state: Optional[Dict[str, Any]], status_value: Optional[str]) -> str:
    """Faza meczu — jedna reguła dla całego systemu."""
    if status_value == "approved":
        return PHASE_LOCKED
    if status_value == "finished":
        return PHASE_POST
    if state and state.get("live_started_at") is not None:
        return PHASE_LIVE
    return PHASE_PRE


async def _fetch_state(
    match_number: str, *, for_update: bool = False
) -> Optional[Dict[str, Any]]:
    stmt = select(proel_match_state).where(
        proel_match_state.c.match_number == match_number
    )
    if for_update:
        # Serializuje równoległe patche tego samego meczu. Bez tego dwa
        # jednoczesne potwierdzenia mogłyby przepisać sobie `rev`.
        stmt = stmt.with_for_update()
    return _as_dict(await database.fetch_one(stmt)) or None


async def _fetch_doc_status(match_number: str) -> Optional[str]:
    row = await database.fetch_one(
        select(saved_matches.c.status, saved_matches.c.is_finished).where(
            saved_matches.c.match_number == match_number
        )
    )
    if row is None:
        return None
    try:
        return row["status"] or ("finished" if row["is_finished"] else "in_progress")
    except (KeyError, IndexError):
        return "finished" if row["is_finished"] else "in_progress"


def _reproject_blob(state: Optional[Dict[str, Any]], blob: Any) -> Any:
    """Nałóż overlay na przychodzący blob. Bezpieczne dla dowolnego kształtu."""
    overlay = _overlay_of(state)
    if not overlay or not isinstance(blob, dict):
        return blob
    try:
        return project(overlay, blob)
    except Exception:  # noqa: BLE001 — projekcja nigdy nie wywraca zapisu meczu
        logger.warning("reprojekcja overlaya nieudana", exc_info=True)
        return blob


def _lease_view(state: Optional[Dict[str, Any]], actor_install: str) -> Dict[str, Any]:
    if not state:
        return {"held": False}
    until = state.get("lease_until")
    if until is None:
        return {"held": False}
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    if until <= _now():
        return {"held": False, "expired": True}
    return {
        "held": True,
        "kind": state.get("lease_kind") or "app",
        "name": state.get("lease_name") or "",
        "judge_id": state.get("lease_judge_id") or "",
        "epoch": int(state.get("lease_epoch") or 0),
        "until": until.isoformat(),
        "is_you": bool(
            actor_install and state.get("lease_install") == actor_install
        ),
    }


def _officials_of(state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    guard = (state or {}).get("guard_json")
    if isinstance(guard, dict):
        officials = guard.get("officials")
        if isinstance(officials, dict):
            return officials
    return {}


def _audit_push(
    state_audit: Any, *, op_ids: List[str], note: Dict[str, Any]
) -> Dict[str, Any]:
    """Audyt trzyma ring historii i listę zużytych op_id (idempotencja)."""
    prev = state_audit if isinstance(state_audit, dict) else {}
    log = prev.get("log")
    log = list(log) if isinstance(log, list) else []
    seen = prev.get("ops")
    seen = list(seen) if isinstance(seen, list) else []

    if note:
        log.append(note)
    seen.extend(op_ids)
    return {
        "log": log[-_AUDIT_LOG_KEEP:],
        "ops": seen[-_AUDIT_OPS_KEEP:],
    }


def _seen_ops(state: Optional[Dict[str, Any]]) -> set:
    audit = (state or {}).get("audit_json")
    if isinstance(audit, dict) and isinstance(audit.get("ops"), list):
        return {str(x) for x in audit["ops"]}
    return set()


async def _apply_reprojection_to_doc(
    match_number: str, state: Optional[Dict[str, Any]]
) -> None:
    """Po zmianie overlaya odśwież widok pochodny w `proel_matches`.

    Robimy to tylko, gdy wiersz dokumentu ISTNIEJE — przed pierwszym realnym
    zapisem rozgrywki nie zakładamy go, żeby lista „Wczytaj z serwera"
    (`GET /proel/?finished=false`) nie pokazywała widmowych meczów.
    """
    row = await database.fetch_one(
        select(saved_matches.c.data_json, saved_matches.c.status).where(
            saved_matches.c.match_number == match_number
        )
    )
    if row is None:
        return
    if (row["status"] or "") == "approved":
        return  # zatwierdzonego protokołu nie ruszamy
    blob = copy.deepcopy(row["data_json"])
    projected = _reproject_blob(state, blob)
    await database.execute(
        update(saved_matches)
        .where(saved_matches.c.match_number == match_number)
        .values(data_json=projected, updated_at=func.now())
    )


# ════════════════════════ endpointy stanu współpracy ════════════════════════
#
# ⚠ KOLEJNOŚĆ DEKLARACJI MA ZNACZENIE. Konwerter `:path` jest zachłanny, więc
# `GET /proel/{match_number:path}` złapałby też `/proel/state`. Wszystkie
# ścieżki statyczne muszą być zadeklarowane WCZEŚNIEJ, a `GET /{…:path}` na
# samym końcu pliku.


async def _build_state_response(
    match_number: str, actor: Actor
) -> ProElStateResponse:
    state = await _fetch_state(match_number)
    doc_status = await _fetch_doc_status(match_number)
    phase = _phase_of(state, doc_status)
    roles = roles_for(actor, _officials_of(state))
    return ProElStateResponse(
        match_number=match_number,
        rev=int((state or {}).get("rev") or 0),
        phase=phase,
        status=doc_status,
        exists=state is not None,
        doc_exists=doc_status is not None,
        updated_at=(state or {}).get("updated_at"),
        server_now=_now(),
        lease=_lease_view(state, actor.installation_id),
        fields=_overlay_of(state),
        your_roles=sorted(roles),
        retry_after_ms=4000,
    )


@router.get(
    "/state",
    response_model=ProElStateResponse,
    summary="Stan współpracy nad meczem (lekki; nie czyta data_json)",
)
async def get_proel_state(
    match: str = Query(..., description="Numer meczu (RozgrywkiCode)"),
    since: Optional[int] = Query(
        None, description="Ostatnia znana rewizja — do long-polla"
    ),
    wait: float = Query(
        0.0, ge=0.0, description="Ile sekund czekać na zmianę (0 = odpowiedz od razu)"
    ),
    actor: Actor = Depends(proel_actor),
):
    """Jedyny endpoint odpytywany na żywo. Czyta wyłącznie wąskie kolumny —
    nigdy `data_json`, który potrafi mieć setki kilobajtów.

    Long-poll jest realizowany przez pętlę sprawdzającą BAZĘ co ~0,8 s, a nie
    przez zdarzenie w pamięci procesu. To celowe: zmiana zapisana przez inny
    proces (albo inną replikę) i tak zostanie zauważona.
    """
    deadline = min(float(wait or 0.0), _MAX_WAIT_SECONDS)
    if deadline > 0 and since is not None:
        loop_until = _now() + timedelta(seconds=deadline)
        while _now() < loop_until:
            row = await database.fetch_one(
                select(proel_match_state.c.rev).where(
                    proel_match_state.c.match_number == match
                )
            )
            current_rev = int(row["rev"]) if row is not None else 0
            if current_rev != since:
                break
            await asyncio.sleep(_WAIT_POLL_SECONDS)

    return await _build_state_response(match, actor)


@router.post(
    "/ensure",
    response_model=ProElStateResponse,
    summary="Załóż wiersz stanu współpracy, jeśli go nie ma",
)
async def ensure_proel_state(
    req: ProElEnsureRequest,
    actor: Actor = Depends(proel_actor),
):
    """Zakłada WYŁĄCZNIE wiersz stanu — nigdy wiersza w `proel_matches`.

    Dzięki temu sędzia potwierdzający badania trzy godziny przed meczem nie
    tworzy widmowego „meczu w toku" na liście „Wczytaj z serwera".
    """
    match_number = str(req.match_number or "").strip()
    if not match_number:
        raise HTTPException(
            422, detail={"code": "BAD_MATCH_NUMBER", "message": "Brak numeru meczu"}
        )

    guard = dict(req.guard or {})
    zprp_id = str(req.zprp_match_id or "").strip() or None

    async with database.transaction():
        state = await _fetch_state(match_number, for_update=True)
        if state is None:
            await database.execute(
                insert(proel_match_state).values(
                    match_number=match_number,
                    zprp_match_id=zprp_id,
                    guard_json=guard or None,
                    rev=1,
                    fields_json={},
                    audit_json={"log": [], "ops": []},
                    status_cache=await _fetch_doc_status(match_number),
                )
            )
        else:
            # Guard: ten sam RozgrywkiCode w innym sezonie to INNY mecz.
            known = str(state.get("zprp_match_id") or "").strip()
            if known and zprp_id and known != zprp_id:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    detail={
                        "code": "MATCH_ID_MISMATCH",
                        "message": (
                            "Ten numer meczu należy na serwerze do innego meczu. "
                            "Odśwież listę meczów."
                        ),
                    },
                )
            values: Dict[str, Any] = {}
            if zprp_id and not known:
                values["zprp_match_id"] = zprp_id
            if guard:
                merged = dict(state.get("guard_json") or {})
                merged.update(guard)
                values["guard_json"] = merged
            if values:
                values["updated_at"] = func.now()
                await database.execute(
                    update(proel_match_state)
                    .where(proel_match_state.c.match_number == match_number)
                    .values(**values)
                )

    return await _build_state_response(match_number, actor)


@router.post(
    "/patch",
    response_model=dict,
    summary="Zapisz pojedyncze pola meczu (bez dotykania całego bloba)",
)
async def patch_proel_state(
    req: ProElPatchRequest,
    actor: Actor = Depends(proel_actor),
):
    """Zapis polowy. Sukces CZĘŚCIOWY jest normalnym wynikiem — czternaście
    przełączeń badań nie może polec dlatego, że jeden podpis był już złożony.
    """
    match_number = str(req.match_number or "").strip()
    admin = await is_admin(actor.judge_id)

    async with database.transaction():
        state = await _fetch_state(match_number, for_update=True)
        if state is None:
            raise HTTPException(
                404,
                detail={
                    "code": "MATCH_NOT_FOUND",
                    "message": "Najpierw załóż stan meczu (/proel/ensure).",
                },
            )

        doc_status = await _fetch_doc_status(match_number)
        phase = _phase_of(state, doc_status)
        if phase == PHASE_LOCKED:
            raise HTTPException(
                status.HTTP_423_LOCKED,
                detail={
                    "code": "MATCH_APPROVED",
                    "message": "Nie można edytować zatwierdzonego meczu",
                },
            )

        roles = roles_for(actor, _officials_of(state))
        overlay: Dict[str, Any] = dict(_overlay_of(state))
        seen = _seen_ops(state)
        base_rev = int(state.get("rev") or 0)
        next_rev = base_rev + 1

        applied: List[str] = []
        rejected: List[Dict[str, Any]] = []
        fresh_ops: List[str] = []
        stamp = _now().isoformat()

        for op in req.ops:
            op_id = str(op.op_id or "").strip()
            path = str(op.path or "").strip()

            # Ponowienie z outboxa — traktujemy jak sukces, nie jak kolejny zapis.
            if op_id and op_id in seen:
                applied.append(op_id)
                continue

            try:
                spec, params = parse_path(path)
            except UnknownPath:
                rejected.append(
                    {
                        "op_id": op_id,
                        "path": path,
                        "code": "UNKNOWN_PATH",
                        "message": "Nieznane pole — zaktualizuj aplikację.",
                        "current": None,
                    }
                )
                continue

            if phase not in spec.phases:
                rejected.append(
                    {
                        "op_id": op_id,
                        "path": path,
                        "code": "PHASE_FORBIDDEN",
                        "message": (
                            "Tego pola nie można zmieniać na tym etapie meczu "
                            f"(faza: {phase})."
                        ),
                        "current": (overlay.get(path) or {}).get("v"),
                    }
                )
                continue

            if not admin and spec.roles and not (roles & spec.roles):
                rejected.append(
                    {
                        "op_id": op_id,
                        "path": path,
                        "code": "ROLE_FORBIDDEN",
                        "message": "Nie masz roli uprawniającej do tej zmiany.",
                        "current": (overlay.get(path) or {}).get("v"),
                    }
                )
                continue

            try:
                merged_value = spec.merge(
                    overlay.get(path), op.value, bool(op.force) or admin
                )
            except PathRejected as exc:
                rejected.append(
                    {
                        "op_id": op_id,
                        "path": path,
                        "code": exc.code,
                        "message": exc.message,
                        "current": exc.current,
                    }
                )
                continue

            overlay[path] = {
                "v": merged_value,
                "rev": next_rev,
                "at": stamp,
                "by": actor.as_by(),
                "src": "patch",
                "superseded_at": None,
            }
            if op_id:
                applied.append(op_id)
                fresh_ops.append(op_id)

        if fresh_ops:
            audit = _audit_push(
                state.get("audit_json"),
                op_ids=fresh_ops,
                note={
                    "at": stamp,
                    "by": actor.as_by(),
                    "paths": [
                        o.path for o in req.ops if str(o.op_id or "") in fresh_ops
                    ],
                },
            )
            await database.execute(
                update(proel_match_state)
                .where(proel_match_state.c.match_number == match_number)
                .values(
                    fields_json=overlay,
                    rev=next_rev,
                    audit_json=audit,
                    status_cache=doc_status,
                    updated_at=func.now(),
                )
            )
            # Widok pochodny musi natychmiast zobaczyć zmianę, inaczej stary
            # klient pobrałby blob bez świeżego potwierdzenia badań.
            refreshed = dict(state)
            refreshed["fields_json"] = overlay
            await _apply_reprojection_to_doc(match_number, refreshed)

        final_rev = next_rev if fresh_ops else base_rev

    return {
        "ok": True,
        "rev": final_rev,
        "phase": phase,
        "server_now": _now().isoformat(),
        "stale_base": req.base_rev is not None and int(req.base_rev) != base_rev,
        "applied": applied,
        "rejected": rejected,
        "fields": overlay,
    }


@router.post(
    "/",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Dodaj nowy mecz do ProEl'a"
)
async def create_proel_match(req: CreateSavedMatchRequest):
    existing = await database.fetch_one(
        select(saved_matches)
        .where(saved_matches.c.match_number == req.match_number)
    )
    if existing:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": "MATCH_EXISTS", "message": "Mecz o takim numerze już istnieje"},
        )

    new_status = _resolve_status(req.status, req.is_finished, "in_progress")

    async with database.transaction():
        state = await _fetch_state(req.match_number, for_update=True)
        # Nakładamy overlay JUŻ na pierwszy zapis: sędzia mógł potwierdzić
        # badania na długo przed tym, jak stolikowy w ogóle otworzył mecz.
        data_json = _reproject_blob(state, copy.deepcopy(req.data_json))

        stmt = insert(saved_matches).values(
            match_number=req.match_number,
            data_json=data_json,
            status=new_status,
            is_finished=_is_finished_for(new_status),
        )
        await database.execute(stmt)

        if state is not None:
            await _sync_state_after_doc_write(
                req.match_number, state, data_json, new_status
            )

    return {"success": True}


async def _sync_state_after_doc_write(
    match_number: str,
    state: Dict[str, Any],
    blob: Any,
    status_value: str,
) -> None:
    """Po zapisie bloba odśwież wiersz stanu: status, faza, rewizja.

    `live_started_at` ustawiamy także na podstawie SAMEJ TREŚCI bloba
    (`live_signal`), bo stara wersja aplikacji nie zna leasingu i nigdy nie
    zawoła `/lease`. Bez tego mecz prowadzony ze starego telefonu zostałby na
    zawsze w fazie „pre" i dało by się nadpisywać pola przedmeczowe.
    """
    values: Dict[str, Any] = {
        "status_cache": status_value,
        "rev": proel_match_state.c.rev + 1,
        "updated_at": func.now(),
    }
    if state.get("live_started_at") is None and live_signal(blob):
        values["live_started_at"] = func.now()
    await database.execute(
        update(proel_match_state)
        .where(proel_match_state.c.match_number == match_number)
        .values(**values)
    )


@router.put(
    "/{match_number:path}",
    response_model=dict,
    summary="Aktualizuj mecz w ProEl'u (jeśli nie zakończony)"
)
async def update_proel_match(
    match_number: str,
    req: UpdateSavedMatchRequest
):
    # Cała ścieżka w JEDNEJ transakcji: blokada wiersza stanu (`FOR UPDATE`)
    # działa tylko wewnątrz transakcji, a reprojekcja musi widzieć overlay
    # dokładnie taki, jaki obowiązuje w chwili zapisu bloba.
    async with database.transaction():
        row = await database.fetch_one(
            select(saved_matches)
            .where(saved_matches.c.match_number == match_number)
        )
        if not row:
            raise HTTPException(404, "Nie znaleziono meczu w ProEl'u")
        # Blokada DOPIERO po zatwierdzeniu (status="approved"), NIE po zakończeniu.
        try:
            current_status = row["status"] or ("finished" if row["is_finished"] else "in_progress")
        except (KeyError, IndexError):
            current_status = "finished" if row["is_finished"] else "in_progress"
        if current_status == "approved":
            raise HTTPException(
                status.HTTP_423_LOCKED,
                detail={"code": "MATCH_APPROVED", "message": "Nie można edytować zatwierdzonego meczu"},
            )

        # Budujemy słownik pól do aktualizacji
        #
        # TU JEST SEDNO CAŁEGO MECHANIZMU. `req.data_json` to pełny snapshot
        # zbudowany z lokalnego stanu telefonu prowadzącego (MatchScreen wysyła
        # go co 60 s) — nie wie NIC o tym, co w międzyczasie zmienili inni.
        # Gdybyśmy zapisali go bez zmian, potwierdzenie badań zrobione przez
        # sędziego na innym urządzeniu znikałoby w ciągu minuty. Overlay
        # nakładamy z powrotem w tej samej transakcji, więc działa to także dla
        # wersji aplikacji, które o współpracy nie mają pojęcia.
        state = await _fetch_state(match_number, for_update=True)
        projected = _reproject_blob(state, copy.deepcopy(req.data_json))

        to_update: dict = {"data_json": projected}
        # status (lub stare is_finished) — jeśli cokolwiek przyszło, przelicz oba pola
        if req.status is not None or req.is_finished is not None:
            new_status = _resolve_status(req.status, req.is_finished, current_status)
            to_update["status"] = new_status
            to_update["is_finished"] = _is_finished_for(new_status)
        # Zawsze przepisujemy updated_at na teraz. `func.now()`, nie
        # `datetime.utcnow()`: kolumna jest `DateTime(timezone=True)`, więc
        # naiwny znacznik z Pythona zapisywał się bez strefy i psuł porównania
        # czasu (m.in. „ostatnia edycja mniej niż 2 min temu"). Zegar bazy jest
        # jedynym zegarem porządkującym w całym systemie.
        to_update["updated_at"] = func.now()

        stmt = (
            update(saved_matches)
            .where(saved_matches.c.match_number == match_number)
            .values(**to_update)
        )
        await database.execute(stmt)

        if state is not None:
            await _sync_state_after_doc_write(
                match_number,
                state,
                projected,
                to_update.get("status", current_status),
            )

    return {"success": True}


@router.delete(
    "/{match_number:path}",
    response_model=dict,
    summary="Usuń mecz ProEl"
)
async def delete_proel_match(match_number: str):
    result = await database.execute(
        delete(saved_matches)
        .where(saved_matches.c.match_number == match_number)
    )
    if result == 0:
        raise HTTPException(404, "Nie znaleziono meczu w ProEl'u")
    return {"success": True}


@router.get(
    "/",
    response_model=ListSavedMatchesResponse,
    summary="Lista wszystkich meczów w ProEl'u"
)
async def list_proel_matches(
    finished: Optional[bool] = Query(
        None,
        description="Filtruj po zakończonych (true) lub niezakończonych (false); domyślnie wszystkie"
    ),
    status: Optional[str] = Query(
        None,
        description="Filtruj po statusie: in_progress | finished | approved"
    ),
):
    # budujemy bazowy SELECT
    stmt = select(saved_matches)

    # jeżeli użytkownik podał finished, dodajemy WHERE
    if finished is not None:
        stmt = stmt.where(saved_matches.c.is_finished == finished)

    # filtr po statusie (priorytetowy względem finished, jeśli oba podane)
    if status is not None:
        s = str(status).strip().lower()
        if s in _VALID_STATUSES:
            stmt = stmt.where(saved_matches.c.status == s)

    # najnowsze (ostatnio edytowane) najpierw
    stmt = stmt.order_by(
        saved_matches.c.updated_at.desc(),
        saved_matches.c.match_number.desc()
    )

    rows = await database.fetch_all(stmt)
    return ListSavedMatchesResponse(
        matches=[MatchItem(**dict(r)) for r in rows]
    )


# ⚠ MUSI BYĆ OSTATNIE W PLIKU.
# `{match_number:path}` łapie wszystko, łącznie z "/state", "/ensure" i
# "/patch". FastAPI dopasowuje trasy w kolejności rejestracji, więc ta
# deklaracja musi stać PO wszystkich ścieżkach statycznych.
@router.get(
    "/{match_number:path}",
    response_model=MatchItem,
    summary="Pobierz jeden mecz ProEl po numerze",
)
async def get_proel_match(
    match_number: str,
    actor: Actor = Depends(proel_actor),
):
    """Pojedynczy mecz zamiast całej tabeli.

    Do tej pory aplikacja, chcąc znaleźć JEDEN mecz, pobierała `GET /proel/`
    z całą zawartością `proel_matches` (bez paginacji, z pełnymi blobami) i
    filtrowała po stronie klienta — w sześciu różnych miejscach.
    """
    row = await database.fetch_one(
        select(saved_matches).where(saved_matches.c.match_number == match_number)
    )
    if row is None:
        raise HTTPException(
            404,
            detail={
                "code": "MATCH_NOT_FOUND",
                "message": "Nie znaleziono meczu w ProEl'u",
            },
        )
    return MatchItem(**dict(row))
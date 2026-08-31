import asyncio
import copy
import logging
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy import select, insert, update, delete, func
from app.db import (
    database,
    proel_deleted_matches,
    proel_match_state,
    saved_matches,
)
from app.proel_auth import (
    Actor,
    can_approve,
    crew_is_known,
    is_admin,
    merge_guard,
    merged_officials,
    officials_from_config,
    officials_with_overlay,
    proel_actor,
    roles_for,
)
from app.proel_journal import client_ip as _client_ip, log_match_event, soft_actor
from app.proel_match_key import (
    live_head as _live_head,
    match_head as _match_head,
    match_id_conflict as _match_id_conflict,
    zprp_id_of as _zprp_id_of,
)
from app.proel_lease import (
    LEASE_TTL_BACKGROUND_SECONDS as _LEASE_TTL_BACKGROUND_SECONDS,
    LEASE_TTL_SECONDS as _LEASE_TTL_SECONDS,
    HEARTBEAT_LOST as _HEARTBEAT_LOST,
    HEARTBEAT_RECLAIM as _HEARTBEAT_RECLAIM,
    heartbeat_decision as _heartbeat_decision,
    lease_active as _lease_active,
    legacy_lease_values as _legacy_lease_values,
    now_utc as _now,
    same_judge_lease as _same_judge_lease,
)
from app.proel_status import (
    VALID_STATUSES,
    is_finished_for,
    resolve_status,
    unapprove_requested,
)
from app.proel_fields import (
    PHASE_LIVE,
    PHASE_LOCKED,
    PHASE_POST,
    PHASE_PRE,
    PathRejected,
    UnknownPath,
    live_signal,
    parse_path,
    phase_refusal,
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
    ProElLeaseRequest,
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

# Status meczu mieszka w liściu `app/proel_status.py` - patrz komentarz tam.
_VALID_STATUSES = VALID_STATUSES
_resolve_status = resolve_status
_is_finished_for = is_finished_for

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


# ════════════════════════ warstwa stanu współpracy ════════════════════════
#
# Overlay (`proel_match_state.fields_json`) jest źródłem prawdy dla pól
# z rejestru; `proel_matches.data_json` jest widokiem pochodnym. Reprojekcja
# przy KAŻDYM zapisie jest jedynym powodem, dla którego potwierdzenie badań
# przeżywa pełny snapshot wysyłany co 60 s przez telefon prowadzącego mecz.


def _as_dict(row: Any) -> Dict[str, Any]:
    return dict(row) if row is not None else {}


class _MatchIdConflict(Exception):
    """Sygnał z wnętrza transakcji: blob opisuje inny mecz niż ten pod numerem.

    Osobny wyjątek, a nie `HTTPException` od razu, bo wpis do dziennika MUSI
    powstać poza transakcją - rzucone w środku, wycofałoby się razem z nią
    i konflikt nie zostawiłby po sobie żadnego śladu.
    """

    def __init__(self, known: str, incoming: str) -> None:
        super().__init__("match id mismatch")
        self.known = known
        self.incoming = incoming


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


async def _fetch_doc_updated_at(match_number: str) -> Optional[datetime]:
    """Czas ostatniego pełnego autosave'u, bez czytania ciężkiego data_json."""
    row = await database.fetch_one(
        select(saved_matches.c.updated_at).where(
            saved_matches.c.match_number == match_number
        )
    )
    if row is None:
        return None
    try:
        return row["updated_at"]
    except (KeyError, IndexError):
        return None


async def _fetch_doc_config(match_number: str) -> Any:
    """Sama `matchConfig` protokołu - bez przebiegu, składów i statystyk.

    `data_json` bywa megabajtem, a do rozstrzygnięcia „kto należy do tej obsady"
    wystarczy nagłówek meczu. Trasa stanu bywa odpytywana długim pollingiem,
    więc czytanie tam całego bloba byłoby widoczne.
    """
    try:
        row = await database.fetch_one(
            select(saved_matches.c.data_json["matchConfig"].label("cfg")).where(
                saved_matches.c.match_number == match_number
            )
        )
    except Exception:  # noqa: BLE001 — awaria odczytu nie może blokować meczu
        logger.warning("_fetch_doc_config: nie udało się odczytać konfiguracji", exc_info=True)
        return None
    if row is None:
        return None
    try:
        return row["cfg"]
    except (KeyError, IndexError):
        return None


async def _approval_officials(
    match_number: str, state: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Obsada, na której stoi prawo do zatwierdzenia - JEDNO źródło.

    Ta sama funkcja odpowiada trasie stanu (pole `can_approve`) i zapisowi
    (`_require_approver`). Rozjazd między nimi to zapalony przycisk, który po
    dotknięciu mówi „ta decyzja należy do kogo innego" - a to najgorsza z
    możliwych odpowiedzi, bo obie strony brzmią pewnie i przeczą sobie.

    Protokół czytamy TYLKO wtedy, gdy wiersz stanu nie zna obsady - czyli gdy
    nikt nie zawołał `/ensure` z guardem. Overlay nakładamy ZAWSZE i na końcu:
    to w nim ląduje nazwisko dopisane albo skasowane w ekranie finalizacji.
    """
    officials = _officials_of(state)
    if not crew_is_known(officials):
        from_doc = officials_from_config(await _fetch_doc_config(match_number))
        officials = merged_officials(officials, from_doc)
    return officials_with_overlay(officials, _overlay_of(state))


async def _may_approve(
    match_number: str, state: Optional[Dict[str, Any]], actor: Actor
) -> bool:
    """Czy TEN aktor może zatwierdzić ten mecz albo cofnąć zatwierdzenie."""
    if await is_admin(actor.judge_id):
        return True
    return can_approve(actor, await _approval_officials(match_number, state))


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


def _lease_view(
    state: Optional[Dict[str, Any]], actor_install: str, actor_judge_id: str = ""
) -> Dict[str, Any]:
    if not state:
        return {"held": False}
    until = state.get("lease_until")
    if until is None:
        return {"held": False}
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    is_you = bool(actor_install and state.get("lease_install") == actor_install)
    identity = {
        "kind": state.get("lease_kind") or "app",
        "name": state.get("lease_name") or "",
        "judge_id": state.get("lease_judge_id") or "",
        "epoch": int(state.get("lease_epoch") or 0),
        "until": until.isoformat(),
        "is_you": is_you,
        "same_judge": is_you or _same_judge_lease(state, actor_judge_id),
    }
    if until <= _now():
        # Tożsamość ostatniego prowadzącego nadal jest potrzebna, gdy heartbeat
        # na chwilę wygaśnie, ale pełny autosave pozostaje świeży.
        return {"held": False, "expired": True, **identity}
    return {
        "held": True,
        **identity,
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
    doc_status, doc_updated_at = await asyncio.gather(
        _fetch_doc_status(match_number),
        _fetch_doc_updated_at(match_number),
    )
    phase = _phase_of(state, doc_status)
    # `your_roles` liczymy z SAMEGO wiersza stanu - dokładnie tak, jak robi to
    # `/patch`, który z tych ról korzysta. Prawo do zatwierdzenia ma własne,
    # szersze źródło (patrz `_approval_officials`) i własne pole.
    roles = roles_for(actor, _officials_of(state))
    return ProElStateResponse(
        match_number=match_number,
        rev=int((state or {}).get("rev") or 0),
        phase=phase,
        status=doc_status,
        exists=state is not None,
        doc_exists=doc_status is not None,
        zprp_match_id=(str((state or {}).get("zprp_match_id") or "").strip() or None),
        doc_updated_at=doc_updated_at,
        updated_at=(state or {}).get("updated_at"),
        server_now=_now(),
        lease=_lease_view(state, actor.installation_id, actor.judge_id),
        fields=_overlay_of(state),
        your_roles=sorted(roles),
        can_approve=await _may_approve(match_number, state, actor),
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
                values["guard_json"] = merge_guard(state.get("guard_json"), guard)
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
                        "message": phase_refusal(spec),
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
        changed_paths = [
            o.path for o in req.ops if str(o.op_id or "") in fresh_ops
        ]

    # Zdarzenie po transakcji i tylko gdy coś naprawdę weszło. Klucz z pierwszego
    # op_id gasi ponowienie z outboxa: te same operacje nie dopiszą się drugi raz.
    if fresh_ops:
        journal_event = (
            {
                "post.shortResultSent": "zprp.summary_sent",
                "post.fullDataSent": "zprp.full_data_sent",
                "post.protocolSent": "zprp.attachment_sent",
            }.get(changed_paths[0], "field.changed")
            if len(changed_paths) == 1
            else "field.changed"
        )
        await log_match_event(
            match_number=match_number,
            event=journal_event,
            actor=actor,
            zprp_match_id=str(state.get("zprp_match_id") or ""),
            details={"paths": changed_paths, "rev": final_rev},
            event_key=f"patch:{match_number}:{fresh_ops[0]}",
        )

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
    "/lease",
    response_model=dict,
    summary="Obejmij albo przedłuż prowadzenie meczu",
)
async def lease_proel_match(
    req: ProElLeaseRequest,
    actor: Actor = Depends(proel_actor),
):
    """W trakcie meczu pisze dokładnie JEDNA osoba.

    Twarda blokada, nie ostrzeżenie: kto nie ma leasingu, nie zapisuje bloba.
    Przejąć prowadzenie może wyłącznie DELEGAT albo ADMINISTRATOR — sędzia
    boiskowy i stolikowy widzą wtedy podgląd na żywo, bez akcji przejęcia.
    """
    match_number = str(req.match_number or "").strip()

    async with database.transaction():
        state = await _fetch_state(match_number, for_update=True)
        if state is None and may_open_state_on_lease(req.action):
            # Sieć bezpieczeństwa dla klientów, które nie wołają `/ensure`
            # (starsze wydania aplikacji). Strażnik obsady zostaje pusty, czyli
            # „obsada nieznana" - dokładnie jak przy meczu stolikowym zakładanym
            # ręcznie. Uzupełni go pierwsze `/ensure`, które przyjdzie później;
            # `merge_guard` nie kasuje niczego, co już wiemy.
            await database.execute(
                insert(proel_match_state).values(
                    match_number=match_number,
                    zprp_match_id=None,
                    guard_json=None,
                    rev=1,
                    fields_json={},
                    audit_json={"log": [], "ops": []},
                    status_cache=await _fetch_doc_status(match_number),
                )
            )
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
        if doc_status == "approved":
            raise HTTPException(
                status.HTTP_423_LOCKED,
                detail={
                    "code": "MATCH_APPROVED",
                    "message": "Mecz jest zatwierdzony.",
                },
            )

        held = _lease_active(state)
        mine = held and state.get("lease_install") == actor.installation_id
        epoch = int(state.get("lease_epoch") or 0)
        took_over = False
        going_live = (
            req.intent == "live" and state.get("live_started_at") is None
        )
        zprp_id = str(state.get("zprp_match_id") or "")

        if req.action == "heartbeat":
            # Bicie serca NIE przejmuje cudzego prowadzenia - ale wygaśnięcie
            # własnego przejęciem nie jest i nie wolno go tak nazywać.
            # Rozstrzyga `heartbeat_decision`, opisana tam do końca.
            decision = _heartbeat_decision(
                held=held,
                mine=bool(mine),
                epoch=epoch,
                claimed_epoch=req.epoch,
            )
            if decision == _HEARTBEAT_LOST:
                raise HTTPException(
                    412,
                    detail={
                        "code": "LEASE_LOST",
                        "message": "Prowadzenie meczu przejął ktoś inny.",
                        "holder": state.get("lease_name") or "",
                    },
                )
            if decision == _HEARTBEAT_RECLAIM:
                # Leasing wygasł, nikt go nie ma - wracamy do swojego meczu.
                epoch += 1
        elif held and not mine:
            # Ten sam sędzia z drugiego urządzenia przechodzi BEZ czekania na
            # wygaśnięcie i bez `force`.
            #
            # Blokada istnieje po to, żeby dwie OSOBY nie pisały jednego
            # protokołu. Jedna osoba z dwóch swoich telefonów to nie ten
            # przypadek: telefon padł, przesiadka na tablet, drugie urządzenie
            # pod ręką - a stary leasing i tak trzyma jeszcze przez chwilę po
            # ostatniej edycji i blokował własnego właściciela.
            #
            # To pełnoprawne PRZEJĘCIE, nie współdzielenie: `lease_install`
            # przechodzi na nowe urządzenie i epoka rośnie, więc poprzednie
            # dostanie 412 przy najbliższym biciu serca i przestanie pisać.
            # Regułę „w danej chwili pisze dokładnie jedno urządzenie"
            # zachowujemy w całości.
            allowed = _same_judge_lease(state, actor.judge_id)
            if not allowed and req.force:
                roles = roles_for(actor, _officials_of(state))
                allowed = "delegate" in roles or await is_admin(actor.judge_id)
            if not allowed:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    detail={
                        "code": "LEASE_HELD",
                        "message": "Mecz prowadzi już inna osoba.",
                        "holder": state.get("lease_name") or "",
                        "holder_judge_id": state.get("lease_judge_id") or "",
                    },
                )
            epoch += 1  # przejęcie unieważnia bicie serca poprzednika
            took_over = True
        elif not held:
            epoch += 1

        ttl = (
            _LEASE_TTL_BACKGROUND_SECONDS
            if req.intent == "edit"
            else _LEASE_TTL_SECONDS
        )
        values: Dict[str, Any] = {
            "lease_install": actor.installation_id,
            "lease_judge_id": actor.judge_id,
            "lease_name": actor.name,
            "lease_kind": "app",
            "lease_epoch": epoch,
            "lease_until": _now() + timedelta(seconds=ttl),
            "rev": proel_match_state.c.rev + 1,
            "updated_at": func.now(),
        }
        if req.intent == "live" and state.get("live_started_at") is None:
            values["live_started_at"] = func.now()

        await database.execute(
            update(proel_match_state)
            .where(proel_match_state.c.match_number == match_number)
            .values(**values)
        )

        fresh = await _fetch_state(match_number)

    # Start prowadzenia i przejęcie stolika - dwa zdarzenia, o które pyta się
    # najczęściej („kto właściwie prowadził ten mecz"). Bicie serca co 25 s nie
    # tworzy niczego: klucz zdarzenia zawiera epokę leasingu, a ta zmienia się
    # wyłącznie przy realnym przejęciu.
    if going_live:
        await log_match_event(
            match_number=match_number,
            event="match.live_started",
            actor=actor,
            zprp_match_id=zprp_id,
            details={"intent": req.intent},
            event_key=f"live:{match_number}",
        )
    if took_over:
        await log_match_event(
            match_number=match_number,
            event="table.taken_over",
            actor=actor,
            zprp_match_id=zprp_id,
            details={"from": state.get("lease_name") or "", "epoch": epoch},
            event_key=f"lease:{match_number}:{epoch}",
        )

    return {
        "ok": True,
        "epoch": epoch,
        "until": (fresh or {}).get("lease_until").isoformat()
        if (fresh or {}).get("lease_until")
        else None,
        "server_now": _now().isoformat(),
        "rev": int((fresh or {}).get("rev") or 0),
        "phase": _phase_of(fresh, doc_status),
        "ttl_seconds": ttl,
        # Czy TO wywołanie odebrało prowadzenie komuś innemu.
        #
        # Aplikacja pyta o to po nieudanym biciu serca: odzyskanie WŁASNEGO,
        # wygasłego leasingu ma przejść w ciszy (nikogo nie skrzywdziliśmy),
        # a odebranie go drugiemu urządzeniu musi się pokazać sędziemu -
        # inaczej dwa telefony tego samego sędziego odbierałyby sobie mecz
        # w kółko, co 25 sekund, i nikt by o tym nie wiedział.
        "took_over": bool(took_over),
    }


@router.delete(
    "/lease",
    response_model=dict,
    summary="Oddaj prowadzenie meczu",
)
async def release_proel_lease(
    match: str = Query(..., description="Numer meczu"),
    actor: Actor = Depends(proel_actor),
):
    """Idempotentne — oddanie cudzego (albo już wygasłego) leasingu to nie błąd."""
    async with database.transaction():
        state = await _fetch_state(match, for_update=True)
        if state is None:
            return {"ok": True}
        if state.get("lease_install") != actor.installation_id:
            return {"ok": True}
        await database.execute(
            update(proel_match_state)
            .where(proel_match_state.c.match_number == match)
            .values(
                lease_until=None,
                lease_install=None,
                lease_judge_id=None,
                lease_name=None,
                lease_kind=None,
                rev=proel_match_state.c.rev + 1,
                updated_at=func.now(),
            )
        )
    return {"ok": True}


@router.post(
    "/",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Dodaj nowy mecz do ProEl'a"
)
async def create_proel_match(
    req: CreateSavedMatchRequest,
    request: Request,
    x_baza_proel: Optional[str] = Header(None, alias="X-BAZA-Proel"),
    x_installation_id: Optional[str] = Header(None, alias="X-Installation-Id"),
    x_judge_id: Optional[str] = Header(None, alias="X-Judge-Id"),
    x_actor_name: Optional[str] = Header(None, alias="X-Actor-Name"),
    x_app_version: Optional[str] = Header(None, alias="X-App-Version"),
    x_forwarded_for: Optional[str] = Header(None, alias="X-Forwarded-For"),
):
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
    zprp_id = _zprp_id_of(req.data_json)

    # Aktora czytamy MIĘKKO: stara wersja aplikacji nie wysyła nagłówków, a
    # 401 na zapisie bloba oznaczałby ciche gubienie meczu.
    actor = await soft_actor(x_judge_id, x_installation_id, x_actor_name)

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
            zprp_match_id=zprp_id or None,
        )
        await database.execute(stmt)

        if state is not None:
            await _sync_state_after_doc_write(
                req.match_number,
                state,
                data_json,
                new_status,
                legacy_writer=str(x_baza_proel or "") != "2",
                writer_install=str(x_installation_id or "").strip(),
            )

    await log_match_event(
        match_number=req.match_number,
        event="match.created",
        actor=actor,
        zprp_match_id=zprp_id,
        details={"status": new_status},
        app_version=x_app_version,
        ip=_client_ip(request, x_forwarded_for),
    )

    return {"success": True}


async def _require_approver(
    *,
    match_number: str,
    state: Optional[Dict[str, Any]],
    legacy: bool,
    x_judge_id: Optional[str],
    x_installation_id: Optional[str],
    x_actor_name: Optional[str],
    authorization: Optional[str],
) -> None:
    """Wpuszcza do zmiany statusu na „zatwierdzony" i z powrotem.

    Starszej wersji aplikacji (bez `X-BAZA-Proel: 2`) NIE pytamy o zgodę - ten
    sam kompromis co przy twardej blokadzie prowadzenia. Taka wersja nie umie
    obsłużyć odmowy: porzuciłaby błąd po cichu i grała dalej ze swojego stanu,
    więc odrzucanie jej zapisów oznaczałoby ciche rozjeżdżanie się protokołu.
    Furtka zamyka się sama, w miarę jak flota się aktualizuje.
    """
    if legacy:
        return

    actor = await proel_actor(x_judge_id, x_installation_id, x_actor_name, authorization)
    if await _may_approve(match_number, state, actor):
        return

    raise HTTPException(
        status.HTTP_403_FORBIDDEN,
        detail={
            "code": "NOT_AN_APPROVER",
            "message": (
                "Zatwierdzenie meczu i jego cofnięcie należą do delegata, a gdy "
                "delegata nie ma - do sędziów prowadzących. Poproś jedną z tych "
                "osób albo administratora."
            ),
        },
    )


async def _sync_state_after_doc_write(
    match_number: str,
    state: Dict[str, Any],
    blob: Any,
    status_value: str,
    *,
    legacy_writer: bool = False,
    writer_install: str = "",
) -> None:
    """Po zapisie bloba odśwież wiersz stanu: status, faza, rewizja.

    `live_started_at` ustawiamy także na podstawie SAMEJ TREŚCI bloba
    (`live_signal`), bo stara wersja aplikacji nie zna leasingu i nigdy nie
    zawoła `/lease`. Bez tego mecz prowadzony ze starego telefonu zostałby na
    zawsze w fazie „pre" i dało by się nadpisywać pola przedmeczowe.

    Z tego samego powodu obejmujemy za starego klienta LEASING-WIDMO. Bez niego
    mecz prowadzony ze starego telefonu wyglądałby dla nowej aplikacji na
    nieprowadzony przez nikogo — a to jest dokładnie ta sytuacja, w której dwa
    stoliki zaczynają pisać ten sam protokół. Widmo obejmujemy WYŁĄCZNIE gdy
    nikt inny nie trzyma prowadzenia; leasingu objętego świadomie nigdy nie
    podbieramy.
    """
    values: Dict[str, Any] = {
        "status_cache": status_value,
        "rev": proel_match_state.c.rev + 1,
        "updated_at": func.now(),
    }
    going_live = state.get("live_started_at") is None and live_signal(blob)
    if going_live:
        values["live_started_at"] = func.now()

    if legacy_writer and (going_live or state.get("live_started_at") is not None):
        ghost = _legacy_lease_values(state, writer_install)
        if ghost:
            values.update(ghost)

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
    req: UpdateSavedMatchRequest,
    request: Request,
    x_baza_proel: Optional[str] = Header(None, alias="X-BAZA-Proel"),
    x_installation_id: Optional[str] = Header(None, alias="X-Installation-Id"),
    x_judge_id: Optional[str] = Header(None, alias="X-Judge-Id"),
    x_actor_name: Optional[str] = Header(None, alias="X-Actor-Name"),
    x_app_version: Optional[str] = Header(None, alias="X-App-Version"),
    x_forwarded_for: Optional[str] = Header(None, alias="X-Forwarded-For"),
    authorization: Optional[str] = Header(None),
):
    # Cała ścieżka w JEDNEJ transakcji: blokada wiersza stanu (`FOR UPDATE`)
    # działa tylko wewnątrz transakcji, a reprojekcja musi widzieć overlay
    # dokładnie taki, jaki obowiązuje w chwili zapisu bloba.
    try:
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
                # Przepuszczamy WYŁĄCZNIE świadome cofnięcie zatwierdzenia -
                # patrz `unapprove_requested`.
                if not unapprove_requested(req.status):
                    raise HTTPException(
                        status.HTTP_423_LOCKED,
                        detail={"code": "MATCH_APPROVED", "message": "Nie można edytować zatwierdzonego meczu"},
                    )

            # ── Guard: czy to na pewno TEN mecz ────────────────────────────────
            #
            # Numer meczu ("OSK/12") jest unikalny w rozgrywkach, ale NIE między
            # sezonami - a jest kluczem głównym tej tabeli. Bez tego sprawdzenia
            # mecz z nowego sezonu nadpisywał protokół sprzed roku: `POST` wracał
            # z 409, aplikacja logowała to do konsoli i szła dalej, a `PUT`
            # przechodził bez słowa. Leasing tego nie łapał, bo mecz sprzed roku
            # od dawna nikogo nie ma.
            try:
                known_id = str(row["zprp_match_id"] or "").strip()
            except (KeyError, IndexError):
                known_id = ""
            incoming_id = _zprp_id_of(req.data_json)
            if _match_id_conflict(known_id, incoming_id):
                raise _MatchIdConflict(known_id, incoming_id)

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

            # Twarda blokada prowadzenia — ale WYŁĄCZNIE dla klientów, które o niej
            # wiedzą (`X-BAZA-Proel: 2`). Stara wersja aplikacji nie potrafiłaby
            # obsłużyć odrzucenia: po cichu porzuciłaby błąd i grała dalej z
            # własnego stanu, więc odrzucanie jej zapisów oznaczałoby ciche gubienie
            # meczu. Zamykanie tej furtki następuje naturalnie, w miarę jak flota
            # się aktualizuje.
            if (
                str(x_baza_proel or "") == "2"
                and state is not None
                and _phase_of(state, current_status) == PHASE_LIVE
                and _lease_active(state)
                and state.get("lease_install") != str(x_installation_id or "").strip()
            ):
                raise HTTPException(
                    412,
                    detail={
                        "code": "LEASE_LOST",
                        "message": "Mecz prowadzi teraz inna osoba.",
                        "holder": state.get("lease_name") or "",
                    },
                )

            # ── Zatwierdzenie i jego cofnięcie to nie jest zwykły zapis ──
            #
            # Reguła „delegat, a gdy go nie ma - sędziowie prowadzący" istniała
            # do tej pory WYŁĄCZNIE w aplikacji, gdzie sterowała widocznością
            # przycisku i opierała się na nazwisku wpisanym w ustawieniach.
            # Serwer przyjmował zmianę statusu od każdego, kto znał numer meczu,
            # więc zatwierdzony protokół potrafiła odtwierdzić osoba spoza tego
            # meczu - i nie zostawał po tym żaden ślad odmowy.
            requested_status = (
                _resolve_status(req.status, req.is_finished, current_status)
                if (req.status is not None or req.is_finished is not None)
                else current_status
            )
            if (requested_status == "approved") != (current_status == "approved"):
                await _require_approver(
                    match_number=match_number,
                    state=state,
                    legacy=str(x_baza_proel or "") != "2",
                    x_judge_id=x_judge_id,
                    x_installation_id=x_installation_id,
                    x_actor_name=x_actor_name,
                    authorization=authorization,
                )

            projected = _reproject_blob(state, copy.deepcopy(req.data_json))

            to_update: dict = {"data_json": projected}
            # Uzupełniamy identyfikator meczu, gdy wiersz powstał przed tą kolumną
            # albo przez `POST` bez konfiguracji. Od tej chwili guard wyżej ma się
            # o co oprzeć.
            if incoming_id and not known_id:
                to_update["zprp_match_id"] = incoming_id
            # status (lub stare is_finished) — jeśli cokolwiek przyszło, przelicz oba pola
            if req.status is not None or req.is_finished is not None:
                to_update["status"] = requested_status
                to_update["is_finished"] = _is_finished_for(requested_status)
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
                    legacy_writer=str(x_baza_proel or "") != "2",
                    writer_install=str(x_installation_id or "").strip(),
                )
    except _MatchIdConflict as conflict:
        # Wpis powstaje PO wycofaniu transakcji - inaczej wycofałby się
        # razem z nią i odrzucony zapis nie zostawiłby żadnego śladu.
        await log_match_event(
            match_number=match_number,
            event="match.id_conflict",
            actor=await soft_actor(x_judge_id, x_installation_id, x_actor_name),
            zprp_match_id=conflict.incoming,
            details={"known": conflict.known, "incoming": conflict.incoming},
            app_version=x_app_version,
            ip=_client_ip(request, x_forwarded_for),
        )
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={
                "code": "MATCH_ID_MISMATCH",
                "message": (
                    "Ten numer meczu należy na serwerze do innego meczu "
                    "(inny sezon albo inne rozgrywki). Zapis wstrzymany, "
                    "żeby nie nadpisać cudzego protokołu."
                ),
                "known": conflict.known,
                "incoming": conflict.incoming,
            },
        ) from conflict

    # Dziennik WYŁĄCZNIE przy faktycznej zmianie statusu. Blob leci co 60 s
    # przez cały mecz - zapisywanie każdego zapisu zamieniłoby oś czasu meczu
    # w ścianę identycznych wierszy, w której nie widać niczego.
    final_status = to_update.get("status", current_status)
    if final_status != current_status:
        # Zdarzenie opisuje PRZEJŚCIE, nie stan docelowy. Cofnięcie
        # zatwierdzenia kończy się w „finished" tak samo jak ostatni gwizdek,
        # więc sam status docelowy nazywał je „Zakończeniem meczu" - a w osi
        # czasu meczu wyglądało to na drugi koniec tego samego meczu.
        if current_status == "approved" and final_status != "approved":
            event = "match.unapproved"
        else:
            event = {
                "finished": "match.finished",
                "approved": "match.approved",
                "in_progress": "match.reopened",
            }.get(final_status)
        if event:
            await log_match_event(
                match_number=match_number,
                event=event,
                actor=await soft_actor(x_judge_id, x_installation_id, x_actor_name),
                zprp_match_id=incoming_id or known_id,
                details={"from": current_status, "to": final_status},
                app_version=x_app_version,
                ip=_client_ip(request, x_forwarded_for),
            )

    return {"success": True}


def _state_snapshot(row) -> Dict[str, Any]:
    """Wiersz `proel_match_state` jako czysty JSON do archiwum.

    Daty zamieniamy na ISO, bo kolumna docelowa jest JSON-em, a `datetime` nie
    jest serializowalny. Nie wybieramy pól „tych ważnych": przy przywracaniu
    liczy się komplet, a lista ważnych pól rozjechałaby się z tabelą przy
    pierwszej nowej kolumnie.
    """
    out: Dict[str, Any] = {}
    for key, value in dict(row).items():
        out[key] = value.isoformat() if isinstance(value, datetime) else value
    return out


@router.delete(
    "/{match_number:path}",
    response_model=dict,
    summary="Usuń mecz ProEl (tylko administrator)"
)
async def delete_proel_match(
    match_number: str,
    actor: Actor = Depends(proel_actor),
):
    """Kasuje zapis meczu RAZEM ze stanem współpracy nad nim.

    Skasowanie samego `saved_matches` zostawiało osierocony wiersz w
    `proel_match_state`: aplikacja dalej widziała mecz jako istniejący
    (`/proel/state` odpowiada z tej tabeli), a jego overlay wracał przy
    następnym `ensure`. Usunięty ma być mecz, nie połowa meczu.

    Tylko administrator - dostęp mają mieć ci sami ludzie, którzy widzą
    przycisk w aplikacji, i lista jest ta sama (`admin_settings.allowed_admins`).

    Usunięcie NIE jest już nieodwracalne: komplet (protokół + overlay pól razem
    z autorstwem) przenosi się najpierw do `proel_deleted_matches` na rok.
    Sędzia kasuje zapis, żeby posprzątać listę, a nie żeby zniszczyć protokół -
    i zdarza się, że kasuje nie ten. Przepisanie i skasowanie idą w JEDNEJ
    transakcji: archiwum bez skasowanego wiersza byłoby duplikatem, a skasowany
    wiersz bez archiwum - tym samym, co przedtem.
    """
    if not await is_admin(actor.judge_id):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={
                "code": "FORBIDDEN",
                "message": "Usuwanie zapisu meczu jest dostępne tylko dla administratora.",
            },
        )

    async with database.transaction():
        row = await database.fetch_one(
            select(saved_matches).where(saved_matches.c.match_number == match_number)
        )
        if row is None:
            raise HTTPException(404, "Nie znaleziono meczu w ProEl'u")

        state_row = await database.fetch_one(
            select(proel_match_state).where(
                proel_match_state.c.match_number == match_number
            )
        )
        state_json = _state_snapshot(state_row) if state_row is not None else None

        await database.execute(
            proel_deleted_matches.insert().values(
                match_number=match_number,
                zprp_match_id=(
                    state_row["zprp_match_id"] if state_row is not None else None
                ),
                status=row["status"],
                data_json=row["data_json"],
                state_json=state_json,
                deleted_by_judge_id=actor.judge_id,
                deleted_by_name=actor.name,
                deleted_by_install=actor.installation_id,
                deleted_by_verified=bool(actor.verified),
                expires_at=datetime.now(timezone.utc) + timedelta(days=365),
            )
        )

        await database.execute(
            delete(proel_match_state)
            .where(proel_match_state.c.match_number == match_number)
        )
        await database.execute(
            delete(saved_matches)
            .where(saved_matches.c.match_number == match_number)
        )

    # Po transakcji: wiersz meczu znika, wpis w dzienniku zostaje. To jedyny
    # ślad, po którym da się później powiedzieć, kto skasował zapis - archiwum
    # zna to samo, ale archiwum też można wyczyścić po roku.
    await log_match_event(
        match_number=match_number,
        event="match.deleted",
        actor=actor,
        zprp_match_id=(
            str(state_row["zprp_match_id"] or "") if state_row is not None else ""
        ),
        details={"status": row["status"]},
    )

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
    slim: bool = Query(
        False,
        description="Zwróć sam nagłówek meczu zamiast pełnego protokołu",
    ),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    actor: Actor = Depends(proel_actor),
):
    """Lista meczów - z tożsamością i z projekcją.

    Do niedawna ta trasa nie miała ŻADNEJ autoryzacji i oddawała każdemu, kto
    zna adres, wszystkie mecze w systemie razem z pełnym `data_json`: nazwiska
    zawodników, licencje, badania, obsadę i cały przebieg. Aplikacja wołała ją
    gołym `fetch`, bez nagłówków.

    `slim=true` zwraca sam nagłówek meczu (numer, drużyny, wynik, data) w tym
    samym kształcie `data_json.matchConfig`, w jakim czyta go lista wyboru -
    dzięki temu ekran nie musi wiedzieć o zmianie, a pełny protokół pobiera
    dopiero przy dotknięciu wiersza (`GET /proel/{numer}`).
    """
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

    stmt = stmt.limit(limit).offset(offset)

    rows = await database.fetch_all(stmt)
    items: List[MatchItem] = []
    for row in rows:
        data = dict(row)
        data.pop("zprp_match_id", None)  # nie należy do kształtu MatchItem
        if slim:
            data["data_json"] = _match_head(row["data_json"])
        items.append(MatchItem(**data))
    return ListSavedMatchesResponse(matches=items)


@router.get(
    "/head",
    response_model=dict,
    summary="Tablica wyniku meczu w toku (lekka projekcja data_json)",
)
async def get_proel_match_head(
    match: str = Query(..., description="Numer meczu (RozgrywkiCode)"),
    actor: Actor = Depends(proel_actor),
):
    """Wynik, zegar i faza meczu - bez składów, badań i przebiegu.

    ISTNIEJE PO TO, ŻEBY KAFELEK „NA ŻYWO" NIE KOSZTOWAŁ BLOBA. Szczegóły
    meczu pokazują wynik prowadzonego spotkania tak długo, jak długo ktoś na
    nie patrzy, i odświeżają go przy każdej zmianie rewizji. Pobieranie w tym
    rytmie całego `data_json` (składy z licencjami, przebieg, stos cofania)
    to kilkadziesiąt kilobajtów na minutę w hali, gdzie zasięg bywa jedyną
    brakującą rzeczą. Pełny blob dalej idzie osobno - dopiero gdy ktoś
    naprawdę otworzy podgląd meczu.

    Dane osobowe zostają na serwerze: projekcja `live_head` przepuszcza
    wyłącznie nazwy drużyn, kolory koszulek, wynik i stan zegara.
    """
    # Numer przychodzi w tej samej pisowni, co do `/state` - normalizuje go
    # klient (`proelMatchKey`), bo to on jest kluczem głównym tabeli.
    match_number = match
    row = await database.fetch_one(
        select(
            saved_matches.c.data_json,
            saved_matches.c.status,
            saved_matches.c.updated_at,
        ).where(saved_matches.c.match_number == match_number)
    )
    data = _as_dict(row) or {}
    if not data:
        # Brak wiersza to nie błąd: mecz może być dopiero zakładany. Pusty
        # nagłówek pozwala kafelkowi powiedzieć „jeszcze nic nie wiem"
        # zamiast pokazać błąd sieci.
        return {"match_number": match_number, "exists": False, "head": None}
    return {
        "match_number": match_number,
        "exists": True,
        "status": data.get("status"),
        "head": _live_head(data.get("data_json")),
        "updated_at": (
            data["updated_at"].isoformat() if data.get("updated_at") else None
        ),
    }


@router.get(
    "/live",
    response_model=dict,
    summary="Mecze prowadzone w tej chwili (podgląd administratora)",
)
async def list_live_proel_matches(
    limit: int = Query(60, ge=1, le=200),
    actor: Actor = Depends(proel_actor),
):
    """Kto w tej chwili pisze protokół i którego meczu.

    Jedno zapytanie zamiast listy meczy plus `/state` po kolei dla każdego -
    ekran podglądu ma pokazać obraz JEDNEJ chwili, a nie kilkunastu odpowiedzi
    zebranych przez pół minuty.

    Życiem leasingu rządzi `lease_until` (90 s, bicie serca co 25 s), więc
    warunek „prowadzony teraz" to po prostu nieprzeterminowany leasing. Zegarem
    jest Postgres, nie telefon pytającego.

    Tylko administrator: to jest podgląd CUDZEJ pracy w toku, razem z
    nazwiskami prowadzących.
    """
    if not await is_admin(actor.judge_id):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={
                "code": "ADMIN_REQUIRED",
                "message": "Podgląd prowadzonych meczów ma wyłącznie administrator.",
            },
        )

    rows = await database.fetch_all(
        select(proel_match_state)
        .where(proel_match_state.c.lease_until > _now())
        .order_by(proel_match_state.c.updated_at.desc())
        .limit(limit)
    )

    items: List[Dict[str, Any]] = []
    for raw in rows:
        state = _as_dict(raw) or {}
        match_number = str(state.get("match_number") or "")
        doc = await database.fetch_one(
            select(saved_matches.c.data_json, saved_matches.c.status, saved_matches.c.updated_at)
            .where(saved_matches.c.match_number == match_number)
        )
        doc_row = _as_dict(doc) or {}
        # Sam nagłówek, nigdy pełny blob: podgląd listy nie ma prawa ściągać na
        # telefon składów, licencji i przebiegu każdego trwającego meczu.
        head = _match_head(doc_row.get("data_json"))
        until = state.get("lease_until")
        items.append(
            {
                "match_number": match_number,
                "zprp_match_id": state.get("zprp_match_id") or "",
                "phase": _phase_of(state, doc_row.get("status")),
                "status": doc_row.get("status"),
                "rev": int(state.get("rev") or 0),
                "holder": {
                    "name": state.get("lease_name") or "",
                    "judge_id": state.get("lease_judge_id") or "",
                    "kind": state.get("lease_kind") or "app",
                    "until": until.isoformat() if until is not None else None,
                    "is_you": bool(
                        actor.installation_id
                        and state.get("lease_install") == actor.installation_id
                    ),
                },
                "head": head,
                "updated_at": state.get("updated_at"),
                "doc_updated_at": doc_row.get("updated_at"),
            }
        )

    return {"matches": items, "server_now": _now().isoformat()}


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

"""Handball Bastion w Mentorze - API BAZY (etap 1, prefiks `/mentor-panel/bastion`, za flagą `BASTION_ENABLED`).

Kontrakt: `docs/mentor-panel.md`, sekcja „Handball Bastion". Zasady:
  - zarządzanie połączeniami używa PRAWDZIWEGO aktora (`base_actor`), nigdy `act_as`: administrator „okiem mentora”
    nie widzi, nie odnawia i nie używa osobistej sesji tego mentora; połączenie domyślne odnawia tylko prawdziwy admin,
  - dostęp do pokoju (para/mecz/nagranie) sprawdzają istniejące reguły Mentora (`pair_context`, także z `act_as`),
  - błędy Bastionu NIE wylogowują z Mentora: 409 BASTION_AUTH_REQUIRED, 403 BASTION_RESOURCE_FORBIDDEN,
    503 BASTION_UNAVAILABLE, 429 BASTION_RATE_LIMITED (nigdy 401),
  - adres embed Bunny jest czasowy i wrażliwy: tylko w odpowiedzi `playback` z `no-store`, nigdy w bazie ani logach,
  - sukces logowania wynika wyłącznie ze statusu connectora, nigdy z zamknięcia okna.
Importy bazy w funkcjach/na górze jak w reszcie panelu (`app.db` łączy się przy imporcie).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app import mentor_bastion_client as CL
from app import mentor_bastion_rules as BR
from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app.db import database, mentor_bastion_connections, mentor_bastion_login_attempts, mentor_match_videos
from app.mentor_panel_auth import base_actor, mentor_actor

logger = logging.getLogger("app.mentor_bastion")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor Bastion"])
Actor = C.MentorActor
CONN = mentor_bastion_connections
ATT = mentor_bastion_login_attempts


def berr(status: int, code: str, message: str, **extra: Any) -> HTTPException:
    """Koperta jak w `C.err`; dodatkowe pola trafiają na wierzch odpowiedzi (patrz handler w main.py)."""
    return HTTPException(status, detail={"code": code, "message": message, **extra})


def _iso(value: Any) -> Optional[str]:
    dt = R.aware(value) if value else None
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def _parse_time(value: Any) -> Optional[datetime]:
    if isinstance(value, (int, float)) and value > 0:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def _flags() -> BR.Flags:
    return BR.load_flags()


def _need_enabled(flags: BR.Flags, scope: Optional[str] = None) -> None:
    if not flags.enabled:
        raise berr(404, "BASTION_DISABLED", BR.MSG_DISABLED)
    if scope and not flags.scope_on(scope):
        raise berr(404, "BASTION_SCOPE_DISABLED", BR.MSG_SCOPE_OFF[scope])


def _unavailable(reason: str = "") -> HTTPException:
    return berr(503, "BASTION_UNAVAILABLE", BR.MSG_UNAVAILABLE)


def _client() -> CL.ConnectorClient:
    try:
        return CL.get_client()
    except CL.ConnectorUnavailable as exc:
        raise _unavailable(exc.reason) from exc


async def _call(coro) -> CL.Reply:
    try:
        return await coro
    except CL.ConnectorUnavailable as exc:
        raise _unavailable(exc.reason) from exc


def _scope_judge(scope: str, real: Actor) -> Optional[str]:
    return real.judge_id if scope == "personal" else None


def _manage_guard(scope: str, real: Actor) -> None:
    if scope == "default" and not real.is_admin:
        raise berr(403, "BASTION_CONNECTION_FORBIDDEN", BR.MSG_CONNECTION_FORBIDDEN)


def _acting_as(request: Request, real: Actor) -> Optional[str]:
    value = R.s(request.query_params.get("act_as"))
    return value if value and value != real.judge_id else None


# ─── Połączenia (metadane w bazie, sesja w connectorze) ────────────────────


async def get_connection(key: str) -> Optional[Dict[str, Any]]:
    return await C.one(select(CONN).where(CONN.c.connection_key == key))


async def _ensure_connection(scope: str, owner: Optional[str]) -> Dict[str, Any]:
    key = BR.connection_key(scope, owner)
    found = await get_connection(key)
    if found:
        return found
    stamp = C.now()
    row = {"id": R.new_id(), "connection_key": key, "scope": scope, "owner_judge_id": owner if scope == "personal" else None,
           "status": "unconfigured", "session_generation": 0, "created_at": stamp, "updated_at": stamp}
    try:
        await database.execute(CONN.insert().values(**row))
    except Exception:  # noqa: BLE001 - wyścig: drugie żądanie założyło wiersz (unikalny connection_key)
        found = await get_connection(key)
        if not found:
            raise
        return found
    return row


async def _set_connection(row: Dict[str, Any], **values: Any) -> Dict[str, Any]:
    """Zapis stanu połączenia; przejście w stan bez sesji wstrzymuje aktywne zadania klipów (to samo konto wznowi)."""
    values["updated_at"] = C.now()
    await database.execute(update(CONN).where(CONN.c.id == row["id"]).values(**values))
    new = values.get("status")
    if new == "ready":
        from app.mentor_bastion_jobs import release_waiting_jobs

        try:
            await release_waiting_jobs(row["id"])  # to samo konto: zadania czekające na sesję wracają do kolejki
        except Exception:  # noqa: BLE001
            logger.warning("bastion: wznowienie zadan po odnowieniu sesji nieudane", exc_info=True)
    if new in ("reauth_required", "revoked", "unconfigured") and row.get("status") not in (new, "unconfigured"):
        from app.mentor_bastion_jobs import hold_jobs_for_connection

        try:
            await hold_jobs_for_connection(row["id"], "BASTION_AUTH_REQUIRED")
        except Exception:  # noqa: BLE001 - wstrzymanie zadań nie może psuć odpowiedzi o połączeniu
            logger.warning("bastion: wstrzymanie zadan nieudane", exc_info=True)
    return {**row, **values}


async def sync_connection(client: CL.ConnectorClient, scope: str, owner: Optional[str]) -> Optional[Dict[str, Any]]:
    """Odczyt stanu z connectora do metadanych w bazie. Zwraca wiersz albo None (nigdy nie istniało).
    `ConnectorUnavailable` wychodzi do wołającego: awaria to NIE zmiana stanu sesji."""
    reply = await client.connection_status(scope, owner)
    if reply.status != 200:
        raise CL.ConnectorUnavailable(f"status_{reply.status}")
    body = reply.body
    state = BR.connector_status_to_state(body)
    row = await get_connection(BR.connection_key(scope, owner))
    if state == "unconfigured":
        if not row:
            return None
        if row["status"] in ("unconfigured", "revoked"):
            return row
        return await _set_connection(row, status="unconfigured", last_error_code=None)
    row = row or await _ensure_connection(scope, owner)
    identity = R.s(body.get("external_identity_id")) or None
    values: Dict[str, Any] = {
        "status": state, "session_generation": int(body.get("generation") or row.get("session_generation") or 0),
        "last_validated_at": _parse_time(body.get("last_validated_at")) or row.get("last_validated_at"),
        "last_error_code": R.s(body.get("last_error_code")) or None, "revoked_at": None, "expires_at": None,
    }
    label = R.s(body.get("external_identity_label"))[:80] or None
    if identity or label:
        values["external_identity_id"] = identity or row.get("external_identity_id")
        values["external_identity_label"] = label
    return await _set_connection(row, **values)


def connection_shape(scope: str, row: Optional[Dict[str, Any]], real: Actor, flags: BR.Flags,
                     service_down: bool = False) -> Dict[str, Any]:
    status = row["status"] if row else "unconfigured"
    if not flags.scope_on(scope):
        return {"enabled": False, "status": "unconfigured", "can_reconnect": False, "last_validated_at": None,
                "expires_at": None, "account_label": None, "last_error_code": None}
    out = {
        "enabled": True,
        "status": "unavailable" if service_down else status,
        "last_known_status": status if service_down else None,
        "can_reconnect": real.is_admin if scope == "default" else True,
        "account_label": None,
        "last_validated_at": _iso(row.get("last_validated_at")) if row else None,
        #: Zawsze null, dopóki TTL sesji Bastionu nie jest ustalony (nie zgadujemy ważności).
        "expires_at": None,
        "last_error_code": row.get("last_error_code") if row else None,
        "generation": int(row.get("session_generation") or 0) if row else 0,
    }
    if scope == "personal":
        out["account_label"] = (row or {}).get("external_identity_label") or ("Twoje konto" if status == "ready" else None)
    elif real.is_admin:
        out["account_label"] = (row or {}).get("external_identity_label")
    return out


async def build_status(real: Actor, flags: BR.Flags, *, refresh: bool = True) -> Dict[str, Any]:
    service = "ok"
    rows: Dict[str, Optional[Dict[str, Any]]] = {}
    client: Optional[CL.ConnectorClient] = None
    if not flags.configured:
        service = "unconfigured"
    else:
        try:
            client = CL.get_client()
        except CL.ConnectorUnavailable:
            service = "unconfigured"
    for scope in BR.SCOPES:
        owner = _scope_judge(scope, real)
        rows[scope] = await get_connection(BR.connection_key(scope, owner))
        if refresh and client is not None and flags.scope_on(scope) and service == "ok":
            try:
                if not await client.healthy():
                    service = "unavailable"
                else:
                    rows[scope] = await sync_connection(client, scope, owner)
            except CL.ConnectorUnavailable:
                service = "unavailable"
    down = service != "ok"
    out = {s: connection_shape(s, rows[s], real, flags, service_down=down and flags.scope_on(s)) for s in BR.SCOPES}
    effective = next((s for s in BR.candidate_scopes(flags) if out[s]["status"] == "ready"), None)
    validated = [out[s]["last_validated_at"] for s in BR.SCOPES if out[s]["last_validated_at"]]
    return {"enabled": True, "service": service, "default": out["default"], "personal": out["personal"],
            "effective_scope": effective, "last_validated_at": max(validated) if validated else None, "expires_at": None,
            "is_admin": real.is_admin}


# ─── Status i sprawdzenie ───────────────────────────────────────────────────


@router.get("/bastion/status")
async def bastion_status(response: Response, real: Actor = Depends(base_actor)):
    response.headers["Cache-Control"] = "no-store"
    flags = _flags()
    if not flags.enabled:
        return {"enabled": False, "service": "disabled", "default": None, "personal": None, "effective_scope": None,
                "last_validated_at": None, "expires_at": None, "is_admin": real.is_admin}
    return await build_status(real, flags)


async def _check(scope: str, real: Actor, response: Response) -> Dict[str, Any]:
    flags = _flags()
    _need_enabled(flags, scope)
    _manage_guard(scope, real)
    client = _client()
    owner = _scope_judge(scope, real)
    probe = flags.probe_bunny_item_id
    validated = False
    if probe:
        # Kontrolowany test: realny odczyt game-context (bez adresu embed) z zapisanej sesji tego połączenia.
        reply = await _call(client.playback(scope, owner, probe, include_embed=False))
        verdict = BR.classify_playback(reply.status, reply.body)
        await apply_verdict(scope, owner, verdict)
        validated = verdict.kind in ("ok", "forbidden")
        if verdict.kind in ("unavailable", "rate_limited"):
            raise (berr(429, "BASTION_RATE_LIMITED", BR.MSG_RATE_LIMITED) if verdict.kind == "rate_limited" else _unavailable())
    try:
        row = await sync_connection(client, scope, owner)
    except CL.ConnectorUnavailable as exc:
        raise _unavailable(exc.reason) from exc
    response.headers["Cache-Control"] = "no-store"
    return {"checked": validated, "connection": connection_shape(scope, row, real, flags)}


@router.post("/bastion/default/check")
async def check_default(response: Response, real: Actor = Depends(base_actor)):
    return await _check("default", real, response)


@router.post("/bastion/personal/check")
async def check_personal(response: Response, real: Actor = Depends(base_actor)):
    return await _check("personal", real, response)


# ─── Próby logowania ────────────────────────────────────────────────────────


class AttemptBody(BaseModel):
    scope: str = Field(pattern="^(default|personal)$")
    return_context: Optional[Dict[str, Any]] = None
    probe_bunny_item_id: Optional[int] = Field(default=None, ge=1, le=10**12)


def _ws_url(flags: BR.Flags, ws_path: str) -> str:
    base = flags.login_view_base_url or flags.connector_url
    if base.startswith("https://"):
        base = "wss://" + base[len("https://"):]
    elif base.startswith("http://"):
        base = "ws://" + base[len("http://"):]
    return f"{base.rstrip('/')}{ws_path}"


def attempt_shape(row: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
    status = row["status"]
    expires = R.aware(row.get("expires_at"))
    if status in BR.ATTEMPT_ACTIVE and expires and expires <= C.now():
        status = "expired"
    return {"id": row["id"], "scope": row["scope"], "status": status, "expires_at": _iso(row.get("expires_at")),
            "error": row.get("last_error_code"), "return_context": R.json_value(row.get("return_context_json"), {}), **extra}


async def _own_attempt(attempt_id: str, real: Actor) -> Dict[str, Any]:
    """Próba widoczna dla inicjatora; próbę połączenia domyślnego widzi też prawdziwy admin.
    Cudza próba osobista = 404 (nie ujawniamy jej istnienia)."""
    row = await C.one(select(ATT).where(ATT.c.id == str(attempt_id)))
    if not row:
        raise berr(404, "BASTION_ATTEMPT_NOT_FOUND", "Nie ma takiej próby logowania.")
    if row["initiator_judge_id"] != real.judge_id and not (row["scope"] == "default" and real.is_admin):
        raise berr(404, "BASTION_ATTEMPT_NOT_FOUND", "Nie ma takiej próby logowania.")
    return row


@router.post("/bastion/login-attempts")
async def start_login(body: AttemptBody, request: Request, response: Response, real: Actor = Depends(base_actor)):
    response.headers["Cache-Control"] = "no-store"
    flags = _flags()
    _need_enabled(flags, body.scope)
    _manage_guard(body.scope, real)
    client = _client()
    reply = await _call(client.create_attempt(body.scope, real.judge_id, body.probe_bunny_item_id or flags.probe_bunny_item_id))
    data = reply.body
    if reply.status == 409:
        raise berr(409, "BASTION_LOGIN_BUSY", BR.MSG_LOGIN_BUSY)
    if reply.status == 429:
        raise berr(429, "BASTION_RATE_LIMITED", BR.MSG_RATE_LIMITED)
    if reply.status != 200 or not data.get("id") or not data.get("ticket"):
        logger.warning("bastion: connector odmowil proby logowania: %s %s", reply.status, data.get("error"))
        raise _unavailable()
    key = BR.connection_key(body.scope, real.judge_id)
    stamp = C.now()
    row = {
        "id": str(data["id"]), "connection_key": key, "scope": body.scope, "initiator_judge_id": real.judge_id,
        "acted_as_judge_id": _acting_as(request, real), "status": data.get("status") if data.get("status") in BR.ATTEMPT_STATES else "waiting_for_user",
        "created_at": stamp, "expires_at": _parse_time(data.get("expires_at")),
        "return_context_json": json.dumps(BR.clean_return_context(body.return_context)),
    }
    existing = await C.one(select(ATT).where(ATT.c.id == row["id"]))
    if existing:  # wznowiona próba tej samej osoby (odświeżenie karty): nowy bilet, ten sam wpis
        await database.execute(update(ATT).where(ATT.c.id == row["id"]).values(status=row["status"], expires_at=row["expires_at"]))
    else:
        await database.execute(ATT.insert().values(**row))
    merged = {**existing, "status": row["status"], "expires_at": row["expires_at"]} if existing else row
    return attempt_shape(merged, ticket=data["ticket"], ticket_ttl_s=data.get("ticket_ttl_s"),
                         ws_url=_ws_url(flags, str(data.get("ws_path") or f"/ws/login/{row['id']}")),
                         resumed=bool(data.get("resumed")))


@router.get("/bastion/login-attempts/{attempt_id}")
async def login_attempt(attempt_id: str, response: Response, real: Actor = Depends(base_actor)):
    response.headers["Cache-Control"] = "no-store"
    row = await _own_attempt(attempt_id, real)
    if row["status"] not in BR.ATTEMPT_ACTIVE:
        return attempt_shape(row)
    try:
        reply = await CL.get_client().get_attempt(row["id"])
    except CL.ConnectorUnavailable:
        # Awaria connectora to nie porażka logowania: pokazujemy ostatni znany stan i flagę.
        return attempt_shape(row, service="unavailable")
    if reply.status == 404:
        await database.execute(update(ATT).where(ATT.c.id == row["id"]).values(status="expired", last_error_code="BASTION_ATTEMPT_LOST"))
        return attempt_shape({**row, "status": "expired", "last_error_code": "BASTION_ATTEMPT_LOST"})
    if reply.status != 200:
        return attempt_shape(row, service="unavailable")
    status = reply.body.get("status")
    status = status if status in BR.ATTEMPT_STATES else row["status"]
    values: Dict[str, Any] = {"status": status, "last_error_code": R.s(reply.body.get("error")) or None}
    extra: Dict[str, Any] = {}
    if status == "succeeded":
        # Sukces dopiero TU, ze statusu connectora: wymiana generacji sesji jest już po jego stronie.
        values["consumed_at"] = C.now()
        flags = _flags()
        try:
            conn = await sync_connection(CL.get_client(), row["scope"], real.judge_id if row["scope"] == "personal" else None)
            values["verified_identity_id"] = (conn or {}).get("external_identity_id")
            extra["connection"] = connection_shape(row["scope"], conn, real, flags)
        except CL.ConnectorUnavailable:
            extra["service"] = "unavailable"
    await database.execute(update(ATT).where(ATT.c.id == row["id"]).values(**values))
    return attempt_shape({**row, **values}, **extra)


@router.post("/bastion/login-attempts/{attempt_id}/ticket")
async def login_attempt_ticket(attempt_id: str, response: Response, real: Actor = Depends(base_actor)):
    """Nowy jednorazowy bilet (odświeżenie karty, ponowne otwarcie widoku). Tylko dla aktywnej próby."""
    response.headers["Cache-Control"] = "no-store"
    row = await _own_attempt(attempt_id, real)
    shaped = attempt_shape(row)
    if shaped["status"] not in BR.ATTEMPT_ACTIVE:
        raise berr(409, "BASTION_ATTEMPT_CLOSED", "Ta próba logowania już się zakończyła. Zacznij nową.")
    reply = await _call(_client().new_ticket(row["id"]))
    if reply.status != 200 or not reply.body.get("ticket"):
        raise berr(409, "BASTION_ATTEMPT_CLOSED", "Ta próba logowania już się zakończyła. Zacznij nową.")
    flags = _flags()
    return {"id": row["id"], "ticket": reply.body["ticket"], "ticket_ttl_s": reply.body.get("ticket_ttl_s"),
            "ws_url": _ws_url(flags, f"/ws/login/{row['id']}")}


@router.post("/bastion/login-attempts/{attempt_id}/cancel")
async def cancel_login(attempt_id: str, response: Response, real: Actor = Depends(base_actor)):
    response.headers["Cache-Control"] = "no-store"
    row = await _own_attempt(attempt_id, real)
    if row["status"] not in BR.ATTEMPT_ACTIVE:
        return attempt_shape(row)
    reply = await _call(_client().cancel_attempt(row["id"]))
    status = reply.body.get("status") if reply.status == 200 else "cancelled"
    status = status if status in BR.ATTEMPT_STATES else "cancelled"
    await database.execute(update(ATT).where(ATT.c.id == row["id"]).values(status=status))
    return attempt_shape({**row, "status": status})


# ─── Rozłączenie ────────────────────────────────────────────────────────────


async def _disconnect(scope: str, real: Actor, response: Response) -> Dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    flags = _flags()
    _need_enabled(flags)
    _manage_guard(scope, real)
    owner = _scope_judge(scope, real)
    reply = await _call(_client().disconnect(scope, owner))
    if reply.status != 200:
        raise _unavailable()
    row = await get_connection(BR.connection_key(scope, owner))
    if row:
        await _set_connection(row, status="revoked", revoked_at=C.now(), external_identity_id=None,
                              external_identity_label=None, last_error_code=None, last_validated_at=None)
    # Zaimportowane klipy pary zostają: ich dostęp wynika z BAZY, nie z sesji Bastionu.
    return {"ok": True, "status": "revoked", "scope": scope}


@router.delete("/bastion/default")
async def disconnect_default(response: Response, real: Actor = Depends(base_actor)):
    return await _disconnect("default", real, response)


@router.delete("/bastion/personal")
async def disconnect_personal(response: Response, real: Actor = Depends(base_actor)):
    return await _disconnect("personal", real, response)


# ─── Odtwarzanie pełnego meczu ──────────────────────────────────────────────

CAPABILITIES = {"seek": True, "rate": False, "mute": False}  # P4: Player.js nie wspiera setMuted


def _playback_failure(flags: BR.Flags, real: Actor, verdicts: List[Tuple[str, BR.PlaybackVerdict]]) -> HTTPException:
    status, code = BR.final_playback_error(verdicts)
    by_scope = {scope: v.kind for scope, v in verdicts}
    extra = {
        "connections": by_scope,
        "can_connect_personal": flags.personal_enabled and by_scope.get("personal", "auth_required") in ("auth_required", "forbidden"),
        "can_renew_default": bool(real.is_admin and flags.default_enabled and by_scope.get("default") == "auth_required"),
    }
    if code == "BASTION_RATE_LIMITED":
        return berr(status, code, BR.MSG_RATE_LIMITED, **extra)
    if code == "BASTION_UNAVAILABLE":
        return berr(status, code, BR.MSG_UNAVAILABLE, **extra)
    if code == "BASTION_RESOURCE_FORBIDDEN":
        return berr(status, code, BR.MSG_FORBIDDEN, **extra)
    message = BR.MSG_DEFAULT_DOWN if (flags.default_enabled and flags.personal_enabled) else BR.MSG_AUTH_REQUIRED
    return berr(status, code, message, **extra)


async def apply_verdict(scope: str, owner: Optional[str], verdict: BR.PlaybackVerdict) -> None:
    """Zapis skutku odczytu w metadanych (best effort): 401 = reauth (tylko gdy połączenie kiedyś istniało),
    OK/403 = sesja żyje. Awaria sieci/portalu i limit nie zmieniają niczego."""
    try:
        if verdict.kind == "auth_required":
            row = await get_connection(BR.connection_key(scope, owner))
            if row and row["status"] not in ("unconfigured", "revoked", "reauth_required"):
                await _set_connection(row, status="reauth_required", last_error_code=verdict.code)
        elif verdict.kind in ("ok", "forbidden"):
            row = await _ensure_connection(scope, owner)
            await _set_connection(row, status="ready", last_validated_at=C.now(), last_error_code=None, revoked_at=None)
    except Exception:  # noqa: BLE001
        logger.warning("bastion: zapis stanu po odczycie nieudany", exc_info=True)


@router.post("/pairs/{pair_id}/matches/{match_id}/videos/{video_id}/playback")
async def video_playback(pair_id: str, match_id: str, video_id: str, response: Response,
                         real: Actor = Depends(base_actor), acting: Actor = Depends(mentor_actor)):
    """Adres odtwarzania nagrania Bastion. Uprawnienia do pary/meczu/nagrania wg reguł Mentora (`acting`, także
    `act_as`); połączenie wybiera PRAWDZIWY użytkownik (`real`): domyślne -> jego własne. `act_as` nigdy nie
    daje dostępu do osobistej sesji odgrywanego mentora."""
    response.headers["Cache-Control"] = "no-store"
    flags = _flags()
    _need_enabled(flags)
    ctx = await C.pair_context(pair_id, acting)
    card = await C.match_card(ctx, match_id)
    row = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == video_id))
    if not row or R.s(row.get("match_id")) != card["match_id"] or R.s(row.get("pair_key")) != ctx["pair_key"]:
        raise berr(404, "VIDEO_NOT_FOUND", "Nie znaleziono tego nagrania - mogło zostać usunięte.")
    item = BR.parse_game_url(row.get("url")) if row.get("provider") == BR.PROVIDER else None
    if not item:
        raise berr(422, "VIDEO_NOT_BASTION", "To nagranie nie pochodzi z Handball Bastion.")
    scopes = BR.candidate_scopes(flags)
    if not scopes or not flags.configured:
        raise _unavailable()
    client = _client()
    verdicts: List[Tuple[str, BR.PlaybackVerdict]] = []
    for scope in scopes:
        owner = _scope_judge(scope, real)
        try:
            reply = await client.playback(scope, owner, item)
        except CL.ConnectorUnavailable:
            verdicts.append((scope, BR.PlaybackVerdict("unavailable", "BASTION_UNAVAILABLE")))
            break
        verdict = BR.classify_playback(reply.status, reply.body)
        if verdict.kind == "ok" and not BR.embed_url_ok(reply.body.get("embed_url")):
            verdict = BR.PlaybackVerdict("unavailable", "BASTION_BAD_RESPONSE")
        await apply_verdict(scope, owner, verdict)
        if verdict.kind == "ok":
            logger.info("bastion playback ok judge=%s scope=%s item=%s", real.judge_id, scope, item)  # bez adresu embed
            return {
                "provider": BR.PROVIDER, "mode": "bunny_embed", "embed_url": reply.body["embed_url"],
                "expires_at": BR.embed_expiry_hint(reply.body.get("expires_at")), "connection_scope": scope,
                "capabilities": dict(CAPABILITIES), "duration_s": row.get("duration_s"),
                "video_state": reply.body.get("video_state"), "bunny_item_id": item,
            }
        verdicts.append((scope, verdict))
        if verdict.kind in ("rate_limited", "unavailable"):
            break
    raise _playback_failure(flags, real, verdicts)


# ─── Klipy MP4 z nagrań Bastion (etap 4) ────────────────────────────────────
# MP4 NIE powstaje samo: użytkownik wybiera przy zapisie klipu (`mp4: true`) albo zamawia później. Klip wirtualny
# (tylko znaczniki czasu) gra z pełnego meczu. Odtwarzanie i pobieranie gotowych plików nie wymaga Bastionu ani flagi.


class Mp4Body(BaseModel):
    action: str = Field(default="order", pattern="^(order|cancel)$")


async def _clip_for(clip_id: str, actor: Actor, *, action: str = "view") -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    from app.db import mentor_clips

    clip = await C.one(select(mentor_clips).where(mentor_clips.c.id == clip_id))
    if not clip or clip.get("deleted_at") is not None:
        raise C.err(404, "NOT_FOUND", "Nie ma takiego klipu.")
    ctx = await C.pair_context(clip["pair_id"], actor, action=action)
    if action == "edit":
        C.check(ctx, "edit", owner=R.s(clip.get("author_id")) == actor.judge_id)
    video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == clip["video_id"])) or {}
    return ctx, clip, video


async def _media_block(clip: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    from app import mentor_bastion_jobs as J

    return (await J.media_for_clips([clip])).get(clip["id"])


async def order_mp4(ctx: Dict[str, Any], clip: Dict[str, Any], video: Dict[str, Any], actor: Actor) -> Dict[str, Any]:
    """Zamów MP4 dla istniejącego klipu (idempotentnie po rewizji). Rzuca 404 przy wyłączonej integracji."""
    from app import mentor_bastion_jobs as J

    flags = _flags()
    _need_enabled(flags)
    if not J.bastion_item_of(video):
        raise C.err(409, "MP4_LINK_VIDEO", "Plik MP4 z Bastionu robimy tylko z nagrań z Handball Bastion.")
    try:
        BR.bastion_clip_range(float(clip["start_s"]), float(clip["end_s"]))
    except BR.ClipRangeError as exc:
        raise C.err(422, "CLIP_RANGE", str(exc)) from exc
    existing = await J.current_job(clip)
    if existing and existing["state"] != "cancelled":
        job = existing
    else:
        job = await J.after_clip_saved(clip, video, actor, want_mp4=True)
        if job is None:
            raise _unavailable()
        await C.touch(ctx, actor.judge_id, "clip_mp4", "clips", clip["match_id"], {"id": clip["id"]})
    media = await _media_block(clip)
    return {"mp4_status": J.mp4_status_of(media, "none"), "media": media, "mp4_offer": await J.mp4_offer(clip, video, actor)}


@router.post("/pairs/{pair_id}/clips/{clip_id}/mp4")
async def pair_clip_mp4(pair_id: str, clip_id: str, response: Response, body: Optional[Mp4Body] = None, actor: Actor = Depends(mentor_actor)):
    """`action: "order"` (domyślnie): zamów MP4 później dla klipu wirtualnego (idempotentnie po rewizji).
    `action: "cancel"`: anuluj oczekujące zadanie, o ile nic nie poszło jeszcze do Bastionu (inaczej 409 MP4_CANCEL_TOO_LATE)."""
    from app import mentor_bastion_jobs as J

    response.headers["Cache-Control"] = "no-store"
    ctx, clip, video = await _clip_for(clip_id, actor, action="edit")
    if clip["pair_id"] != pair_id:
        raise C.err(404, "NOT_FOUND", "Nie ma takiego klipu.")
    if body and body.action == "cancel":
        result = await J.cancel_clip_media(clip)
        if result["cancelled"]:
            await C.touch(ctx, actor.judge_id, "clip_mp4_cancelled", "clips", clip["match_id"], {"id": clip_id})
        media = await _media_block(clip)
        return {"cancelled": result["cancelled"], "mp4_status": J.mp4_status_of(media, "none"), "media": media}
    return await order_mp4(ctx, clip, video, actor)


@router.get("/clips/{clip_id}/media")
async def clip_media(clip_id: str, response: Response, actor: Actor = Depends(mentor_actor)):
    """Stan pliku MP4 klipu w kształcie klipu (`media`); `null` dla nagrań spoza Bastionu."""
    response.headers["Cache-Control"] = "no-store"
    _, clip, _video = await _clip_for(clip_id, actor)
    return {"media": await _media_block(clip)}


@router.post("/clips/{clip_id}/media/resume")
async def clip_media_resume(clip_id: str, response: Response, actor: Actor = Depends(mentor_actor)):
    """„Wznów”: oczekiwanie na połączenie (to samo konto), niepowodzenie albo niepewny wynik. Wymaga włączonej integracji."""
    from app import mentor_bastion_jobs as J

    response.headers["Cache-Control"] = "no-store"
    flags = _flags()
    _need_enabled(flags)
    ctx, clip, video = await _clip_for(clip_id, actor, action="edit")
    await J.resume_clip_media(clip, video, actor)
    return {"media": await _media_block(clip)}


@router.get("/clips/{clip_id}/playback")
async def clip_playback(clip_id: str, response: Response, actor: Actor = Depends(mentor_actor)):
    """Wspólny resolver odtwarzania klipu (`docs/mentor-panel.md` 8.6): gotowy plik -> podpisane adresy odtwarzania
    i pobrania (Range, nazwa pliku); w przygotowaniu / wirtualny -> zakres oryginału + status; brak -> oczekiwanie.
    Działa także po odłączeniu Bastionu i przy wyłączonej fladze (gotowe pliki są własnością BAZY)."""
    from app import mentor_bastion_jobs as J
    from app import mentor_panel_media as M

    response.headers["Cache-Control"] = "no-store"
    ctx, clip, video = await _clip_for(clip_id, actor)
    media = await _media_block(clip)
    if media is None:
        media = BR.resolve_clip_playback(clip=clip, video_provider=video.get("provider"), video_present=bool(video))
    out: Dict[str, Any] = {"clip_id": clip_id, **media, "play_url": None, "poster_url": None, "download_url": None,
                           "filename": None}
    if media["mode"] == "asset":
        asset = await J.current_asset(clip)
        card = None
        try:
            from app.db import mentoring_pairs
            from app.mentoring_rules import json_value

            pair = await C.one(select(mentoring_pairs.c.judge_ids).where(mentoring_pairs.c.id == clip["pair_id"]))
            cards = await C.pair_match_cards(json_value((pair or {}).get("judge_ids"), []))
            card = next((c for c in cards if c["match_id"] == clip["match_id"]), None)
        except Exception:  # noqa: BLE001
            card = None
        filename = R.clip_filename(clip.get("title"), (card or {}).get("match_code"), float(clip["start_s"]))
        out.update(J.signed_urls(clip, asset, filename))
        if not out["play_url"]:
            raise C.err(503, "STORAGE_OFF", "Magazyn nagrań jest chwilowo niedostępny.")
    return out


# ─── Bilet meczu: podgląd linku przed dodaniem nagrania ─────────────────────


class ResolveBody(BaseModel):
    url: str = Field(min_length=1, max_length=2000)


@router.post("/pairs/{pair_id}/matches/{match_id}/bastion/resolve")
async def resolve_link(pair_id: str, match_id: str, body: ResolveBody, response: Response,
                       real: Actor = Depends(base_actor), acting: Actor = Depends(mentor_actor)):
    """Podgląd linku Bastion: `{bunny_item_id, match_summary, same_match, access}`. Bez embedu i bez zapisu. `same_match`
    porównuje mecz z game-context z meczem pokoju (true/false) albo null, gdy brak danych (np. brak dostępu konta).
    Brak sesji / dostępu to nie błąd: `match_summary: null`, `access` mówi dlaczego (auth_required / forbidden /
    unavailable / rate_limited), a nagranie można i tak dodać."""
    response.headers["Cache-Control"] = "no-store"
    flags = _flags()
    _need_enabled(flags)
    ctx = await C.pair_context(pair_id, acting)
    card = await C.match_card(ctx, match_id)
    item = BR.parse_game_url(body.url)
    if not item:
        raise berr(422, "BAD_BASTION_URL", "To nie jest adres meczu z Handball Bastion (portal.handball-bastion.pl/game?bunny_item_id=...).")
    out: Dict[str, Any] = {"bunny_item_id": item, "match_summary": None, "same_match": None, "access": "unavailable",
                           "connection_scope": None}
    scopes = BR.candidate_scopes(flags)
    if not scopes or not flags.configured:
        return out
    client = _client()
    for scope in scopes:
        owner = _scope_judge(scope, real)
        try:
            reply = await client.playback(scope, owner, item, include_embed=False)
        except CL.ConnectorUnavailable:
            out["access"] = "unavailable"
            break
        verdict = BR.classify_playback(reply.status, reply.body)
        await apply_verdict(scope, owner, verdict)
        out["access"] = verdict.kind
        if verdict.kind == "ok":
            summary = reply.body.get("match") if isinstance(reply.body.get("match"), dict) else None
            out["match_summary"] = BR.public_match_summary(summary)
            out["same_match"] = BR.same_match(summary, card)
            out["connection_scope"] = scope
            out["video_state"] = reply.body.get("video_state")
            break
        if verdict.kind in ("rate_limited", "unavailable"):
            break
    return out

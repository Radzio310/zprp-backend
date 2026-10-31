"""Teczka pary - Dysk Google (30.10.2026): połączenie, wybór folderu, księga zapisów, kolejka wysyłki, trasy.

Model: JEDNO połączenie na parę = konto osoby, która podłączyła. Serwer ZAWSZE działa tokenem tej osoby, więc drugi
partner nie potrzebuje zgody Google (a `drive.file` nie ma problemu izolacji). Partner dostaje dostęp do folderu przez
`permissions.create` (rola writer) na podany adres e-mail; błąd nadania nie blokuje, tylko zostaje widoczny.

Cała sieć Google siedzi w `mentor_drive_google` (podmieniana w testach); reguły czyste w `mentor_drive_rules`.
Importy bazy na górze jak w reszcie panelu (`app.db` łączy się przy imporcie).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import or_, select, update

from app import mentor_drive_google as G
from app import mentor_drive_rules as DR
from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app.db import database, mentor_clips, mentor_drive_connections, mentor_drive_files, mentor_drive_folders, mentor_match_videos
from app.mentor_panel_auth import mentor_actor

logger = logging.getLogger("app.mentor_drive")
router = APIRouter(prefix="/mentor-panel", tags=["Mentor Teczka pary"])
Actor = C.MentorActor
CONN, FILES, FOLDERS = mentor_drive_connections, mentor_drive_files, mentor_drive_folders


def derr(status: int, code: str, message: str, **extra: Any) -> HTTPException:
    """Koperta `{"error": "<KOD>", "code", "message"}` (handler w main.py: `error_code` wygrywa nad obiektem)."""
    exc = HTTPException(status, detail={"code": code, "message": message, **extra})
    exc.error_code = code  # type: ignore[attr-defined]
    return exc


def need_on() -> None:
    if not DR.enabled():
        raise derr(403, "DRIVE_OFF", "Teczka pary (Dysk Google) jest jeszcze wyłączona.")


class NeedsReconnect(Exception):
    def __init__(self, reason: str = "REVOKED"):
        super().__init__(reason)
        self.reason = reason


class MissingMp4(Exception):
    pass


def _secret() -> str:
    from app.deps import get_settings

    return get_settings().SECRET_KEY


def _configured() -> bool:
    try:
        from app.deps import get_settings

        s = get_settings()
        return bool(s.GOOGLE_CLIENT_ID and s.GOOGLE_CLIENT_SECRET)
    except Exception:  # noqa: BLE001
        return False


def _aad(pair_id: str) -> str:
    return f"mentor-drive:{pair_id}"


def _iso(value: Any) -> Optional[str]:
    dt = R.aware(value) if value else None
    return dt.isoformat().replace("+00:00", "Z") if dt else None


# ─── Połączenie i token ──────────────────────────────────────────────────────

_locks: Dict[str, asyncio.Lock] = {}
_wake: Optional[asyncio.Event] = None


def _lock(name: str) -> asyncio.Lock:
    if name not in _locks:
        if len(_locks) > 2000:
            _locks.clear()
        _locks[name] = asyncio.Lock()
    return _locks[name]


def wake_worker() -> None:
    if _wake is not None:
        _wake.set()


async def get_conn(pair_id: str) -> Optional[Dict[str, Any]]:
    return await C.one(select(CONN).where(CONN.c.pair_id == pair_id))


async def _store_tokens(pair_id: str, tokens: Dict[str, Any]) -> None:
    blob = DR.seal_tokens(tokens, DR.token_key(_secret()), _aad(pair_id))
    await database.execute(update(CONN).where(CONN.c.pair_id == pair_id).values(token_enc=blob, updated_at=C.now()))


def _expiry(data: Dict[str, Any]) -> float:
    return C.now().timestamp() + float(data.get("expires_in") or 3000)


async def access_for(pair_id: str) -> str:
    """Ważny access token właściciela połączenia (odświeżany leniwie). Brak/cofnięcie = `NeedsReconnect`."""
    async with _lock(f"tok:{pair_id}"):
        conn = await get_conn(pair_id)
        if not conn:
            raise NeedsReconnect("NOT_CONNECTED")
        if conn.get("state") == "needs_reconnect":
            raise NeedsReconnect(R.s(conn.get("reconnect_reason")) or "REVOKED")
        tokens = DR.unseal_tokens(conn["token_enc"], DR.token_key(_secret()), _aad(pair_id))
        if not tokens or not tokens.get("refresh_token"):
            await mark_needs_reconnect(pair_id, "TOKEN_UNREADABLE")
            raise NeedsReconnect("TOKEN_UNREADABLE")
        if DR.token_fresh(tokens, C.now()):
            return str(tokens["access_token"])
        try:
            data = await G.api().refresh(tokens["refresh_token"])
        except G.GoogleError as exc:
            if exc.kind == "revoked":
                await mark_needs_reconnect(pair_id, "REVOKED")
                raise NeedsReconnect("REVOKED") from None
            raise
        tokens = {**tokens, "access_token": data["access_token"], "expires_at": _expiry(data)}
        if data.get("refresh_token"):
            tokens["refresh_token"] = data["refresh_token"]
        await _store_tokens(pair_id, tokens)
        return str(tokens["access_token"])


async def mark_needs_reconnect(pair_id: str, reason: str) -> bool:
    """Wygasły/cofnięty token: stan `needs_reconnect`, zadania czekają, JEDEN push do właściciela. Nigdy 401."""
    async with _lock(f"rc:{pair_id}"):
        conn = await get_conn(pair_id)
        if not conn or conn.get("state") == "needs_reconnect":
            return False
        stamp = C.now()
        await database.execute(update(CONN).where(CONN.c.pair_id == pair_id).values(
            state="needs_reconnect", reconnect_reason=reason, reconnect_notified_at=stamp, updated_at=stamp))
    try:
        await C.touch(pair_id, R.s(conn["owner_judge_id"]), "drive_reconnect", "drive")
    except Exception:  # noqa: BLE001
        logger.warning("mentor: zmiana rewizji po utracie tokenu Dysku nieudana", exc_info=True)
    try:
        await send_push(pair_id, R.s(conn["owner_judge_id"]), "Teczka pary: połącz Dysk ponownie",
                        "Google przestał wpuszczać BAZĘ do Twojego Dysku. Klipy czekają, nic nie przepadło.", "reconnect")
    except Exception:  # noqa: BLE001
        logger.warning("mentor: push o ponownym połączeniu Dysku nieudany", exc_info=True)
    return True


async def send_push(pair_id: str, judge_id: str, title: str, body: str, kind: str) -> None:
    from app.mentor_panel_notify import PREFERENCE_KEY, push_data
    from app.push.push import send_push_to_judges_report

    data = push_data(pair_id, target="drive", tag=f"mentor-drive-{kind}-{pair_id}", extra={"drive": kind})
    await send_push_to_judges_report([judge_id], title, body, data, app_variant="baza", preference_key=PREFERENCE_KEY)


# ─── Widok połączenia ────────────────────────────────────────────────────────

FILE_STATES = ("waiting_mp4", "queued", "working", "done", "failed")


async def counts_of(pair_id: str) -> Dict[str, int]:
    out = {"waiting": 0, "queued": 0, "uploading": 0, "saved": 0, "failed": 0}
    names = {"waiting_mp4": "waiting", "queued": "queued", "working": "uploading", "done": "saved", "failed": "failed"}
    for row in await C.rows(select(FILES.c.state).where(FILES.c.pair_id == pair_id)):
        key = names.get(R.s(row["state"]))
        if key:
            out[key] += 1
    return out


async def state_view(ctx: Dict[str, Any], actor: Actor) -> Dict[str, Any]:
    conn = await get_conn(ctx["pair_id"])
    base = {"enabled": True, "configured": _configured(), "pair_id": ctx["pair_id"], "state": "disconnected",
            "connected_by": None, "is_owner": False, "can_manage": False, "google_email": None, "connected_at": None,
            "folder": None, "folder_problem": None, "layout": DR.DEFAULT_LAYOUT, "partner": None,
            "reconnect_reason": None, "counts": await counts_of(ctx["pair_id"]), "layout_options": list(DR.LAYOUTS)}
    if not conn:
        return base
    owner = R.s(conn["owner_judge_id"])
    names = await C.people([owner])
    is_owner = owner == actor.judge_id
    base.update(
        state=R.s(conn.get("state")) or "connected", connected_by={**C.person(names, owner), "is_me": is_owner},
        is_owner=is_owner, can_manage=bool(is_owner or actor.is_admin), google_email=conn.get("google_email"),
        connected_at=_iso(conn.get("connected_at")), layout=R.s(conn.get("layout")) or DR.DEFAULT_LAYOUT,
        folder_problem=conn.get("folder_problem"),
        reconnect_reason=conn.get("reconnect_reason") if conn.get("state") == "needs_reconnect" else None,
    )
    if conn.get("folder_id"):
        base["folder"] = {"id": conn["folder_id"], "name": conn.get("folder_name"), "url": conn.get("folder_url")}
    if conn.get("partner_email"):
        base["partner"] = {"email": conn["partner_email"], "share_status": conn.get("share_status") or "none",
                           "share_error": conn.get("share_error"), "shared_at": _iso(conn.get("shared_at"))}
    return base


async def _touch(ctx: Dict[str, Any], action: str, match_id: Optional[str] = None) -> None:
    await C.touch(ctx, ctx["actor"].judge_id, action, "drive", match_id)


async def _context(pair_id: str, actor: Actor, action: str = "view") -> Dict[str, Any]:
    need_on()
    return await C.pair_context(pair_id, actor, action=action)


def _require_owner(conn: Optional[Dict[str, Any]], actor: Actor, *, token: bool = False) -> Dict[str, Any]:
    if not conn:
        raise derr(409, "DRIVE_NOT_CONNECTED", "Teczka pary nie jest jeszcze połączona z Dyskiem Google.")
    owner = R.s(conn["owner_judge_id"]) == actor.judge_id
    if not owner and (token or not actor.is_admin):
        raise derr(403, "DRIVE_NOT_OWNER", "Tę czynność może wykonać tylko osoba, która podłączyła Dysk.")
    return conn


async def _google(pair_id: str, call):
    """Wywołanie Google z tłumaczeniem błędów na kopertę serwera (nigdy 401 - to wylogowanie z Mentora)."""
    try:
        return await call(await access_for(pair_id))
    except NeedsReconnect as exc:
        raise derr(409, "DRIVE_NEEDS_RECONNECT", "Połączenie z Dyskiem wygasło - połącz Dysk ponownie.", reason=exc.reason) from None
    except G.GoogleError as exc:
        if exc.kind == "revoked":
            await mark_needs_reconnect(pair_id, "REVOKED")
            raise derr(409, "DRIVE_NEEDS_RECONNECT", "Google cofnął dostęp - połącz Dysk ponownie.", reason="REVOKED") from None
        if exc.kind == "retry":
            raise derr(502, "GOOGLE_UNAVAILABLE", "Dysk Google chwilowo nie odpowiada. Spróbuj za chwilę.") from None
        if exc.kind == "folder":
            raise derr(409, "FOLDER_UNAVAILABLE", "Ten folder nie jest dostępny dla BAZY. Wybierz go ponownie przez okno wyboru Dysku.") from None
        raise derr(502, "GOOGLE_ERROR", f"Dysk Google odmówił ({exc.reason or exc.status}).") from None


# ─── Status, połączenie, callback ────────────────────────────────────────────


@router.get("/drive/status")
async def drive_status(response: Response, actor: Actor = Depends(mentor_actor)):
    """Czy Teczka pary jest włączona (flaga `MENTOR_DRIVE_ENABLED`) - klient pyta tu zanim narysuje cokolwiek."""
    response.headers["Cache-Control"] = "no-store"
    on = DR.enabled()
    return {"enabled": on, "configured": _configured(), "reason": None if on else "DRIVE_OFF",
            "message": None if on else "Teczka pary (Dysk Google) jest jeszcze wyłączona.", "app_id": DR.app_id(), "scope": DR.SCOPE}


@router.get("/pairs/{pair_id}/drive")
async def get_drive(pair_id: str, response: Response, actor: Actor = Depends(mentor_actor)):
    response.headers["Cache-Control"] = "no-store"
    ctx = await _context(pair_id, actor)
    return await state_view(ctx, actor)


class ConnectBody(BaseModel):
    return_url: Optional[str] = Field(default=None, max_length=500)


@router.post("/pairs/{pair_id}/drive/connect")
async def connect_drive(pair_id: str, body: Optional[ConnectBody] = None, actor: Actor = Depends(mentor_actor)):
    """Adres zgody Google (state podpisany; `access_type=offline`, `prompt=consent`, tylko `drive.file`)."""
    ctx = await _context(pair_id, actor, "video")
    if not _configured():
        raise derr(503, "DRIVE_NOT_CONFIGURED", "Serwer nie ma jeszcze kluczy Google do Dysku.")
    return_url = (body.return_url if body else None) or None
    if return_url and not DR.return_url_ok(return_url):
        raise derr(422, "RETURN_URL", "Ten adres powrotu nie jest dozwolony.")
    conn = await get_conn(ctx["pair_id"])
    if conn and conn.get("state") == "connected" and R.s(conn["owner_judge_id"]) != actor.judge_id:
        names = await C.people([conn["owner_judge_id"]])
        raise derr(409, "DRIVE_ALREADY_CONNECTED", "Dysk tej pary jest już podłączony przez inną osobę.",
                   connected_by=C.person(names, conn["owner_judge_id"]))
    state = DR.sign_state({"p": ctx["pair_id"], "j": actor.judge_id, "r": return_url, "n": secrets.token_hex(6)}, _secret(), C.now())
    url = G.auth_url(G.client_id(), DR.redirect_uri(), state)
    return {"url": url, "expires_in": DR.STATE_TTL_S}


def _landing(status: str, return_url: Optional[str], pair_id: str):
    if return_url and DR.return_url_ok(return_url):
        return RedirectResponse(DR.append_query(return_url, {"drive": status, "pair": pair_id}), status_code=303)
    texts = {"connected": "Dysk Google połączony. Możesz wrócić do BAZY.", "denied": "Nie zgodzono się na dostęp - nic nie połączono.",
             "scope": "Brakuje zgody na pliki utworzone przez BAZĘ - spróbuj ponownie i zostaw pole zaznaczone.",
             "error": "Nie udało się połączyć z Dyskiem Google. Spróbuj ponownie w BAZIE."}
    html = f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>BAZA - Teczka pary</title><body style='font-family:sans-serif;padding:32px'><h2>{texts.get(status, texts['error'])}</h2></body>"
    return HTMLResponse(html, status_code=200 if status == "connected" else 400)


@router.get("/drive/callback")
async def drive_callback(code: Optional[str] = Query(None), state: Optional[str] = Query(None), error: Optional[str] = Query(None)):
    need_on()
    body = DR.verify_state(state, _secret(), C.now())
    if not body or not body.get("p") or not body.get("j"):
        raise derr(400, "BAD_STATE", "Ten link zgody wygasł. Zacznij łączenie od nowa w BAZIE.")
    pair_id, judge_id, back = R.s(body["p"]), R.s(body["j"]), body.get("r")
    if error or not code:
        return _landing("denied", back, pair_id)
    try:
        data = await G.api().exchange_code(code, DR.redirect_uri())
    except G.GoogleError:
        logger.warning("mentor: wymiana kodu Dysku nieudana (para %s)", pair_id)
        return _landing("error", back, pair_id)
    if DR.SCOPE not in R.s(data.get("scope")).split():
        return _landing("scope", back, pair_id)
    existing = await get_conn(pair_id)
    same_owner = bool(existing and R.s(existing["owner_judge_id"]) == judge_id)
    refresh = data.get("refresh_token")
    if not refresh and same_owner:
        old = DR.unseal_tokens(existing["token_enc"], DR.token_key(_secret()), _aad(pair_id)) or {}
        refresh = old.get("refresh_token")
    if not refresh or not data.get("access_token"):
        return _landing("error", back, pair_id)
    tokens = {"access_token": data["access_token"], "refresh_token": refresh, "expires_at": _expiry(data)}
    try:
        user = await G.api().about(tokens["access_token"])
    except G.GoogleError:
        user = {}  # adres konta to ozdobnik (widać go w statusie); bez niego połączenie działa
    stamp = C.now()
    values = {"owner_judge_id": judge_id, "google_email": user.get("emailAddress"), "google_name": user.get("displayName"),
              "token_enc": DR.seal_tokens(tokens, DR.token_key(_secret()), _aad(pair_id)), "state": "connected",
              "reconnect_reason": None, "reconnect_notified_at": None, "updated_at": stamp}
    if existing and same_owner:
        await database.execute(update(CONN).where(CONN.c.pair_id == pair_id).values(**values))
    else:
        # Inne konto = inny Dysk: stary folder byłby dla nowego tokenu niewidoczny (drive.file), więc zaczynamy od wyboru.
        keep = {"partner_email": existing.get("partner_email")} if existing else {}
        if existing:
            await database.execute(CONN.delete().where(CONN.c.pair_id == pair_id))
            await database.execute(FOLDERS.delete().where(FOLDERS.c.pair_id == pair_id))
        await database.execute(CONN.insert().values(pair_id=pair_id, connected_at=stamp, layout=DR.DEFAULT_LAYOUT,
                                                    share_status="none", **keep, **values))
    try:
        await C.touch(pair_id, judge_id, "drive_connected", "drive")
    except Exception:  # noqa: BLE001
        logger.warning("mentor: rewizja po połączeniu Dysku nieudana", exc_info=True)
    wake_worker()
    return _landing("connected", back, pair_id)


# ─── Picker, folder, udostępnienie, odłączenie ───────────────────────────────


@router.post("/pairs/{pair_id}/drive/picker-token")
async def picker_token(pair_id: str, response: Response, actor: Actor = Depends(mentor_actor)):
    """Token właściciela do okna wyboru folderu (Google Picker). Tylko dla osoby, która podłączyła Dysk."""
    response.headers["Cache-Control"] = "no-store"
    ctx = await _context(pair_id, actor, "video")
    conn = _require_owner(await get_conn(ctx["pair_id"]), actor, token=True)
    try:
        access = await access_for(ctx["pair_id"])
    except NeedsReconnect as exc:
        raise derr(409, "DRIVE_NEEDS_RECONNECT", "Połączenie z Dyskiem wygasło - połącz Dysk ponownie.", reason=exc.reason) from None
    except G.GoogleError:
        raise derr(502, "GOOGLE_UNAVAILABLE", "Dysk Google chwilowo nie odpowiada. Spróbuj za chwilę.") from None
    tokens = DR.unseal_tokens(conn["token_enc"], DR.token_key(_secret()), _aad(ctx["pair_id"])) or {}
    left = max(60, int(float(tokens.get("expires_at") or 0) - C.now().timestamp())) if tokens.get("expires_at") else 1800
    return {"access_token": access, "expires_in": left, "app_id": DR.app_id(), "scope": DR.SCOPE}


class FolderBody(BaseModel):
    file_id: Optional[str] = Field(default=None, max_length=120)
    create: bool = False
    name: Optional[str] = Field(default=None, max_length=120)
    layout: Optional[str] = Field(default=None, max_length=30)


_FILE_ID = re.compile(r"^[A-Za-z0-9_-]{10,120}$")


@router.post("/pairs/{pair_id}/drive/folder")
async def set_folder(pair_id: str, body: FolderBody, actor: Actor = Depends(mentor_actor)):
    """Folder pary: `file_id` (z Pickera) albo `create: true` (+ `name`); samo `layout` zmienia układ podfolderów."""
    ctx = await _context(pair_id, actor, "video")
    conn = _require_owner(await get_conn(ctx["pair_id"]), actor)
    layout = DR.clean_layout(body.layout) if body.layout is not None else None
    if body.layout is not None and not layout:
        raise derr(422, "LAYOUT", "Nieznany układ folderów.")
    if not body.file_id and not body.create and not layout:
        raise derr(422, "NOTHING_TO_DO", "Podaj file_id, create albo layout.")
    pid = ctx["pair_id"]
    folder: Optional[Dict[str, Any]] = None
    if body.file_id:
        if not _FILE_ID.match(body.file_id):
            raise derr(422, "FILE_ID", "To nie wygląda na identyfikator folderu z Dysku.")
        folder = await _google(pid, lambda token: G.api().get_file(token, body.file_id))
        if folder.get("mimeType") != G.FOLDER_MIME:
            raise derr(422, "NOT_A_FOLDER", "Wybrany element nie jest folderem.")
        if folder.get("trashed"):
            raise derr(422, "FOLDER_TRASHED", "Ten folder jest w koszu Dysku.")
    elif body.create:
        names = await C.people(ctx["judge_ids"])
        label = [C.person(names, j)["name"] for j in ctx["judge_ids"]]
        title = DR.drive_name(body.name) if body.name else DR.default_folder_name(label)
        folder = await _google(pid, lambda token: G.api().create_folder(token, title))
    values: Dict[str, Any] = {"updated_at": C.now()}
    if layout:
        values["layout"] = layout
    if folder:
        values.update(folder_id=folder["id"], folder_name=folder.get("name"), folder_url=folder.get("webViewLink"),
                      folder_problem=None, share_status="none", share_error=None, shared_at=None)
    await database.execute(update(CONN).where(CONN.c.pair_id == pid).values(**values))
    if folder and conn.get("partner_email"):
        await attempt_share(pid, conn["partner_email"])
    await _touch(ctx, "drive_folder")
    wake_worker()
    return await state_view(ctx, actor)


class ShareBody(BaseModel):
    email: str = Field(max_length=254)


async def attempt_share(pair_id: str, email: str) -> None:
    """`permissions.create` (writer). Wynik zostaje w połączeniu (`share_status`/`share_error`) - błąd nie blokuje."""
    conn = await get_conn(pair_id)
    if not conn or not conn.get("folder_id"):
        return
    status, problem, shared = "ok", None, C.now()
    if email == R.s(conn.get("google_email")).lower():
        status, shared = "owner", None  # to konto właściciela - folder i tak jest jego
    else:
        try:
            await _google(pair_id, lambda token: G.api().create_permission(token, conn["folder_id"], email, "writer"))
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            status, problem, shared = "error", R.s(detail.get("code")) or "SHARE_FAILED", None
        except Exception:  # noqa: BLE001
            status, problem, shared = "error", "SHARE_FAILED", None
    await database.execute(update(CONN).where(CONN.c.pair_id == pair_id).values(
        partner_email=email, share_status=status, share_error=problem, shared_at=shared, updated_at=C.now()))


@router.post("/pairs/{pair_id}/drive/share")
async def share_folder(pair_id: str, body: ShareBody, actor: Actor = Depends(mentor_actor)):
    """Nadaje partnerowi dostęp do folderu (writer) na podany adres. Odpowiedź 200 także przy błędzie nadania:
    wynik czytaj z `partner.share_status` / `partner.share_error`."""
    ctx = await _context(pair_id, actor, "video")
    conn = _require_owner(await get_conn(ctx["pair_id"]), actor)
    email = DR.clean_email(body.email)
    if not email:
        raise derr(422, "EMAIL", "Podaj poprawny adres e-mail konta Google partnera.")
    if not conn.get("folder_id"):
        raise derr(409, "NO_FOLDER", "Najpierw wybierz albo załóż folder pary.")
    await database.execute(update(CONN).where(CONN.c.pair_id == ctx["pair_id"]).values(partner_email=email))
    await attempt_share(ctx["pair_id"], email)
    await _touch(ctx, "drive_share")
    return await state_view(ctx, actor)


@router.delete("/pairs/{pair_id}/drive")
async def disconnect_drive(pair_id: str, actor: Actor = Depends(mentor_actor)):
    """Odłączenie: token znika, kolejka się zamyka. Pliki zostają na Dysku (i w księdze jako zapisane)."""
    ctx = await _context(pair_id, actor, "video")
    conn = _require_owner(await get_conn(ctx["pair_id"]), actor)
    tokens = DR.unseal_tokens(conn["token_enc"], DR.token_key(_secret()), _aad(ctx["pair_id"])) or {}
    if tokens.get("refresh_token"):
        try:
            await G.api().revoke(tokens["refresh_token"])
        except Exception:  # noqa: BLE001
            pass
    pid = ctx["pair_id"]
    await database.execute(CONN.delete().where(CONN.c.pair_id == pid))
    await database.execute(FOLDERS.delete().where(FOLDERS.c.pair_id == pid))
    await database.execute(update(FILES).where(FILES.c.pair_id == pid).where(FILES.c.state.in_(DR.ACTIVE_STATES))
                           .values(state="cancelled", lease_until=None, worker_id=None, updated_at=C.now()))
    await _touch(ctx, "drive_disconnected")
    return await state_view(ctx, actor)


# ─── Drzewo (z naszej księgi) ────────────────────────────────────────────────

STATUS_NAMES = {"waiting_mp4": "waiting", "queued": "queued", "working": "uploading", "done": "saved", "failed": "failed",
                "cancelled": "cancelled"}


def file_view(row: Dict[str, Any], names: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    return {"id": row["id"], "clip_id": row["clip_id"], "match_id": row["match_id"], "match": row.get("match_label"),
            "category": row.get("category"), "name": row["name"], "title_card": row.get("variant") == "card",
            "author": C.person(names, row.get("author_judge_id")), "thumb": row.get("thumb"),
            "web_view_link": row.get("web_view_link"), "status": STATUS_NAMES.get(R.s(row["state"]), R.s(row["state"])),
            "error": row.get("error"), "size": row.get("size"), "created_at": _iso(row.get("created_at")),
            "updated_at": _iso(row.get("updated_at")), "done_at": _iso(row.get("done_at"))}


def _parse_since(since: Optional[str]) -> Optional[datetime]:
    if not since:
        return None
    try:
        return R.aware(datetime.fromisoformat(since.strip().replace("Z", "+00:00")))
    except ValueError:
        raise derr(422, "BAD_SINCE", "Parametr since to czas ISO z poprzedniej odpowiedzi (cursor).") from None


@router.get("/pairs/{pair_id}/drive/tree")
async def drive_tree(pair_id: str, response: Response, since: Optional[str] = Query(None), actor: Actor = Depends(mentor_actor)):
    """Drzewo z księgi zapisów (mecz, kategoria, nazwa, autor, miniatura, link, status). Z `since` (= `cursor` z poprzedniej
    odpowiedzi) tylko zmiany, razem z anulowanymi."""
    response.headers["Cache-Control"] = "no-store"
    ctx = await _context(pair_id, actor)
    after = _parse_since(since)
    query = select(FILES).where(FILES.c.pair_id == ctx["pair_id"])
    if after is None:
        query = query.where(FILES.c.state != "cancelled")
    rows = await C.rows(query.order_by(FILES.c.created_at.desc()).limit(2000))
    if after is not None:
        rows = [r for r in rows if (R.aware(r.get("updated_at")) or after) > after]
    names = await C.people([r.get("author_judge_id") for r in rows])
    items = [file_view(r, names) for r in rows]
    stamps = [R.aware(r["updated_at"]) for r in rows if r.get("updated_at")]
    cursor = _iso(max(stamps)) if stamps else (since or None)
    conn = await get_conn(ctx["pair_id"])
    return {"items": items, "cursor": cursor, "full": after is None, "rev": await C.current_rev(ctx["pair_id"]),
            "state": R.s((conn or {}).get("state")) or "disconnected", "layout": R.s((conn or {}).get("layout")) or DR.DEFAULT_LAYOUT}


# ─── Sprawdzanie, czy zapisane pliki nadal są na Dysku ───────────────────────

VERIFY_LIMIT = 50  # bez filtra: tyle najdawniej sprawdzanych wpisów naraz
VERIFY_FILTERED_LIMIT = 200
VERIFY_PARALLEL = 5
VERIFY_FRESH = timedelta(minutes=10)  # `save` nie pyta Google o plik sprawdzony przed chwilą
VERIFY_EVERY = timedelta(hours=24)  # tło: każda para raz na dobę


class VerifyBody(BaseModel):
    clip_ids: Optional[List[str]] = Field(default=None, max_length=VERIFY_FILTERED_LIMIT)
    match_id: Optional[str] = Field(default=None, max_length=120)


async def _probe(access: str, drive_file_id: str) -> Dict[str, Any]:
    """Jednoznaczna odpowiedź Google albo `unknown`. `gone` WYŁĄCZNIE: 404 pliku albo `trashed=true`.
    401/cofnięty token = `revoked`; sieć, 403, limity, 5xx = `unknown` (plik zostaje zapisany)."""
    try:
        meta = await G.api().file_state(access, drive_file_id)
    except G.GoogleError as exc:
        if exc.status == 404:
            return {"result": "gone"}
        return {"result": "revoked" if exc.kind == "revoked" else "unknown"}
    except Exception:  # noqa: BLE001 - nic poza jednoznaczną odpowiedzią Google nie kasuje wpisu
        return {"result": "unknown"}
    if not isinstance(meta, dict):
        return {"result": "unknown"}
    if meta.get("trashed") is True:
        return {"result": "gone"}
    return {"result": "saved", "link": meta.get("webViewLink")}


async def _mark_gone(row: Dict[str, Any], stamp: datetime) -> None:
    """Wpis przestaje być zapisem: `cancelled` (stare buildy znają ten stan: klip wygląda na niezapisany, drzewo go nie
    pokazuje), a `save` zapisze go od nowa. Warunek na stan i id pliku chroni przed wyścigiem z ponownym zapisem."""
    await database.execute(update(FILES).where(FILES.c.id == row["id"]).where(FILES.c.state == "done")
                           .where(FILES.c.drive_file_id == row["drive_file_id"])
                           .values(state="cancelled", error="DRIVE_GONE", drive_file_id=None, web_view_link=None, size=None,
                                   done_at=None, lease_until=None, worker_id=None, verified_at=stamp, updated_at=stamp))


async def verify_pair(pair_id: str, judge_id: str, *, clip_ids: Optional[List[str]] = None, match_id: Optional[str] = None,
                      limit: Optional[int] = None, access: Optional[str] = None) -> Dict[str, Any]:
    """Sprawdza u Google zapisy (`done`) pary, najdawniej sprawdzane najpierw. Sesji bazy nie trzymamy na czas Google."""
    filtered = bool(clip_ids or match_id)
    cap = limit or (VERIFY_FILTERED_LIMIT if filtered else VERIFY_LIMIT)
    query = select(FILES).where(FILES.c.pair_id == pair_id).where(FILES.c.state == "done").where(FILES.c.drive_file_id.is_not(None))
    if clip_ids:
        query = query.where(FILES.c.clip_id.in_([R.s(i) for i in clip_ids if R.s(i)]))
    if match_id:
        query = query.where(FILES.c.match_id == match_id)
    rows = await C.rows(query.limit(2000))
    floor = datetime(1970, 1, 1, tzinfo=C.now().tzinfo)
    rows.sort(key=lambda r: (R.aware(r.get("verified_at")) or floor, R.s(r["id"])))
    rows = rows[:cap]
    if not rows:
        return {"items": [], "checked": 0, "gone": 0}
    token = access or await access_for(pair_id)  # NeedsReconnect idzie do wołającego
    gate = asyncio.Semaphore(VERIFY_PARALLEL)
    state = {"revoked": False}

    async def probe(row: Dict[str, Any]) -> Dict[str, Any]:
        async with gate:
            if state["revoked"]:
                return {"result": "unknown"}
            out = await _probe(token, row["drive_file_id"])
        if out["result"] == "revoked":
            state["revoked"] = True
            await mark_needs_reconnect(pair_id, "REVOKED")
            return {"result": "unknown"}
        return out

    results = await asyncio.gather(*(probe(r) for r in rows))
    stamp = C.now()
    per_clip: Dict[str, Dict[str, Any]] = {}
    changed = 0
    for row, out in zip(rows, results):
        entry = per_clip.setdefault(row["clip_id"], {"saved": False, "link": None})
        link = row.get("web_view_link")
        if out["result"] == "gone":
            await _mark_gone(row, stamp)
            changed += 1
            continue
        values: Dict[str, Any] = {"verified_at": stamp}
        if out["result"] == "saved" and out.get("link") and out["link"] != link:
            link = out["link"]
            values.update(web_view_link=link, updated_at=stamp)
            changed += 1
        if not state["revoked"]:
            await database.execute(update(FILES).where(FILES.c.id == row["id"]).where(FILES.c.state == "done").values(**values))
        entry["saved"], entry["link"] = True, entry["link"] or link
    if changed:
        try:
            await C.touch(pair_id, judge_id, "drive_verify", "drive", match_id)
        except Exception:  # noqa: BLE001
            logger.warning("mentor: rewizja po sprawdzeniu Dysku nieudana", exc_info=True)
    items = [{"clip_id": cid, "status": "saved" if v["saved"] else "gone", "web_view_link": v["link"] if v["saved"] else None}
             for cid, v in per_clip.items()]
    return {"items": items, "checked": len(items), "gone": sum(1 for i in items if i["status"] == "gone")}


@router.post("/pairs/{pair_id}/drive/verify")
async def verify_drive(pair_id: str, body: Optional[VerifyBody] = None, actor: Actor = Depends(mentor_actor)):
    """Prostuje księgę z Dyskiem: dla zapisanych plików pyta Google (`files.get`). `gone` tylko przy jednoznacznym 404 albo
    koszu; błąd sieci, 403, limit czy wygasły token zostawiają wpis jako `saved`. Widzą oboje z pary (token właściciela)."""
    ctx = await _context(pair_id, actor)
    pid = ctx["pair_id"]
    if not await get_conn(pid):
        raise derr(409, "DRIVE_NOT_CONNECTED", "Teczka pary nie jest jeszcze połączona z Dyskiem Google.")
    try:
        access = await access_for(pid)
    except NeedsReconnect as exc:
        raise derr(409, "DRIVE_NEEDS_RECONNECT", "Połączenie z Dyskiem wygasło - połącz Dysk ponownie.", reason=exc.reason) from None
    except G.GoogleError:
        raise derr(502, "GOOGLE_UNAVAILABLE", "Dysk Google chwilowo nie odpowiada. Spróbuj za chwilę.") from None
    body = body or VerifyBody()
    return await verify_pair(pid, actor.judge_id, clip_ids=body.clip_ids, match_id=body.match_id, access=access)


async def verify_due(now: Optional[datetime] = None) -> int:
    """Tło: pary z zapisami niesprawdzanymi od doby (ten sam kod co trasa). Zwraca liczbę sprawdzonych par."""
    now = now or C.now()
    due = now - VERIFY_EVERY
    pairs = {r["pair_id"] for r in await C.rows(select(FILES.c.pair_id, FILES.c.verified_at).where(FILES.c.state == "done")
                                                .where(FILES.c.drive_file_id.is_not(None)).limit(5000))
             if not r.get("verified_at") or (R.aware(r["verified_at"]) or now) < due}
    done = 0
    for pid in sorted(pairs):
        conn = await get_conn(pid)
        if not conn or conn.get("state") != "connected":
            continue
        try:
            await verify_pair(pid, R.s(conn["owner_judge_id"]))
            done += 1
        except NeedsReconnect:
            continue
        except Exception:  # noqa: BLE001
            logger.warning("mentor: sprawdzanie zapisów Dysku nieudane (para %s)", pid, exc_info=True)
        await asyncio.sleep(1)
    return done


async def run_drive_verifier() -> None:
    """Rzadka pętla w tle (start z `main.py`). Wyłączenie: `MENTOR_DRIVE_VERIFY=0` (poza tym wymaga `MENTOR_DRIVE_ENABLED`)."""
    if not DR.enabled() or os.getenv("MENTOR_DRIVE_VERIFY", "1") == "0":
        logger.info("mentor: sprawdzanie zapisów Dysku wyłączone")
        return
    await asyncio.sleep(180)
    while True:
        try:
            await verify_due()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("mentor: pętla sprawdzania zapisów Dysku")
        await asyncio.sleep(3600)


# ─── Zapis klipów ────────────────────────────────────────────────────────────


class SaveBody(BaseModel):
    clip_ids: Optional[List[str]] = Field(default=None, max_length=DR.BATCH_LIMIT)
    match_id: Optional[str] = Field(default=None, max_length=120)
    title_card: bool = False


def _fallback_name(clip: Dict[str, Any]) -> str:
    return R.clip_filename(clip.get("title"), None, float(clip["start_s"]))


@router.post("/pairs/{pair_id}/drive/save")
async def save_clips(pair_id: str, body: SaveBody, actor: Actor = Depends(mentor_actor)):
    """Wysyła klipy na Dysk pary (autor = kto kliknął). Gdy MP4 jeszcze nie ma, zamawia go i czeka. Wynik per klip w `items`."""
    from app import mentor_clip_download as D

    ctx = await _context(pair_id, actor, "video")
    pid = ctx["pair_id"]
    conn = await get_conn(pid)
    if not conn:
        raise derr(409, "DRIVE_NOT_CONNECTED", "Teczka pary nie jest jeszcze połączona z Dyskiem Google.")
    if not conn.get("folder_id"):
        raise derr(409, "NO_FOLDER", "Najpierw wybierz albo załóż folder pary.")
    if body.clip_ids:
        ids = list(dict.fromkeys(R.s(i) for i in body.clip_ids if R.s(i)))
        clips = await C.rows(select(mentor_clips).where(mentor_clips.c.id.in_(ids)))
        by_id = {c["id"]: c for c in clips}
        ordered = [(i, by_id.get(i)) for i in ids]
    elif body.match_id:
        clips = await C.rows(select(mentor_clips).where(mentor_clips.c.pair_id == pid).where(mentor_clips.c.match_id == body.match_id)
                             .where(mentor_clips.c.deleted_at.is_(None)).order_by(mentor_clips.c.start_s.asc()).limit(DR.BATCH_LIMIT + 1))
        if len(clips) > DR.BATCH_LIMIT:
            raise derr(422, "TOO_MANY", f"Najwyżej {DR.BATCH_LIMIT} klipów naraz.")
        ordered = [(c["id"], c) for c in clips]
    else:
        raise derr(422, "NO_CLIPS", "Podaj clip_ids albo match_id.")
    if not ordered:
        raise derr(422, "NO_CLIPS", "Nie ma klipów do zapisania.")
    variant = "card" if body.title_card else "plain"
    shared = D.Context(ctx)
    items: List[Dict[str, Any]] = []
    accepted = 0
    for clip_id, clip in ordered:
        if not clip or clip.get("deleted_at") is not None or R.s(clip.get("pair_id")) != pid:
            items.append({"clip_id": clip_id, "status": "rejected", "reason": "NOT_FOUND"})
            continue
        outcome = await _enqueue_clip(ctx, conn, clip, actor, variant, shared)
        accepted += 1 if outcome["status"] in ("queued", "waiting", "requeued") else 0
        items.append(outcome)
    if accepted:
        await _touch(ctx, "drive_save", body.match_id)
        wake_worker()
    return {"items": items, "accepted": accepted}


async def _enqueue_clip(ctx: Dict[str, Any], conn: Dict[str, Any], clip: Dict[str, Any], actor: Actor, variant: str, shared) -> Dict[str, Any]:
    from app import mentor_clip_download as D

    pid, clip_id = ctx["pair_id"], clip["id"]
    existing = await C.one(select(FILES).where(FILES.c.pair_id == pid).where(FILES.c.clip_id == clip_id).where(FILES.c.variant == variant))
    if existing and existing["state"] == "done" and existing.get("drive_file_id"):
        verified = R.aware(existing.get("verified_at")) if existing.get("verified_at") else None
        if not verified or verified + VERIFY_FRESH < C.now():
            try:  # użytkownik mógł skasować plik na Dysku: sprawdzamy, zanim powiemy "już zapisane"
                checked = await verify_pair(pid, actor.judge_id, clip_ids=[clip_id])
                if any(i["status"] == "gone" for i in checked["items"]):
                    existing = await C.one(select(FILES).where(FILES.c.id == existing["id"]))
            except Exception:  # noqa: BLE001 - bez pewności zostaje "zapisane"
                pass
    if existing and existing["state"] == "done":
        return {"clip_id": clip_id, "status": "already_saved", "file_id": existing["id"], "web_view_link": existing.get("web_view_link")}
    if existing and existing["state"] in DR.ACTIVE_STATES:
        return {"clip_id": clip_id, "status": "already_queued", "file_id": existing["id"]}
    title_card = variant == "card"
    try:
        plan = await D.build_plan(shared, clip, actor, title_card=title_card)
    except Exception:  # noqa: BLE001 - bez planu nie wiemy, skąd wziąć MP4
        logger.warning("mentor: plan klipu dla Dysku nieudany (%s)", clip_id, exc_info=True)
        return {"clip_id": clip_id, "status": "rejected", "reason": "NO_SOURCE"}
    state = "queued"
    if plan.get("mp4_status") != "ready":
        if not plan.get("can_download"):
            return {"clip_id": clip_id, "status": "rejected", "reason": plan.get("reason") or "NO_SOURCE", "hint": plan.get("hint")}
        try:
            await D.order(ctx, clip, actor, title_card, shared)
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            return {"clip_id": clip_id, "status": "rejected", "reason": R.s(detail.get("code")) or "ORDER_FAILED", "hint": detail.get("message")}
        state = "waiting_mp4"
    cat = (plan.get("folder") or {}).get("category")
    match_label = (plan.get("folder") or {}).get("match")
    values = {"match_id": clip["match_id"], "match_label": match_label, "category": cat,
              "name": DR.drive_name(plan.get("filename") or _fallback_name(clip)), "thumb": await _thumb_of(clip),
              "author_judge_id": actor.judge_id, "state": state, "attempts": 0, "next_at": None, "lease_until": None,
              "worker_id": None, "error": None, "updated_at": C.now()}
    if existing:
        await database.execute(update(FILES).where(FILES.c.id == existing["id"]).values(**values))
        return {"clip_id": clip_id, "status": "requeued", "file_id": existing["id"]}
    file_id = R.new_id()
    try:
        await database.execute(FILES.insert().values(id=file_id, pair_id=pid, clip_id=clip_id, variant=variant, created_at=C.now(), **values))
    except Exception:  # noqa: BLE001 - wyścig dwóch kliknięć: unikalny (para, klip, wariant) trzyma jeden wiersz
        again = await C.one(select(FILES).where(FILES.c.pair_id == pid).where(FILES.c.clip_id == clip_id).where(FILES.c.variant == variant))
        return {"clip_id": clip_id, "status": "already_queued", "file_id": (again or {}).get("id")}
    return {"clip_id": clip_id, "status": "waiting" if state == "waiting_mp4" else "queued", "file_id": file_id}


async def _thumb_of(clip: Dict[str, Any]) -> Optional[str]:
    video = await C.one(select(mentor_match_videos.c.thumbnail_url).where(mentor_match_videos.c.id == clip.get("video_id")))
    return (video or {}).get("thumbnail_url") or None


# ─── Kolejka wysyłki (trwała: stan i dzierżawa w bazie, restart ją wznawia) ──


def open_mp4(key: str):
    """Strumień MP4 z R2 i jego rozmiar (cienka warstwa, podmieniana w testach). Brak obiektu = `MissingMp4`."""
    from app import mentor_panel_media as M

    config = M.storage_config()
    try:
        obj = M.s3_client(config).get_object(Bucket=config["bucket"], Key=key)
    except Exception as exc:  # noqa: BLE001
        if "NoSuchKey" in repr(exc) or "404" in repr(exc):
            raise MissingMp4(key) from None
        raise
    return obj["Body"], int(obj.get("ContentLength") or 0)


async def _read_exact(stream, want: int) -> bytes:
    out = bytearray()
    while len(out) < want:
        part = await asyncio.to_thread(stream.read, want - len(out))
        if not part:
            break
        out += part
    return bytes(out)


async def promote_waiting(now: datetime) -> int:
    """`waiting_mp4` -> `queued`, gdy plik klipu jest gotowy; `failed`, gdy MP4 się nie udał albo czeka za długo."""
    moved = 0
    for job in await C.rows(select(FILES).where(FILES.c.state == "waiting_mp4").order_by(FILES.c.created_at.asc()).limit(200)):
        clip = await C.one(select(mentor_clips).where(mentor_clips.c.id == job["clip_id"]))
        if not clip or clip.get("deleted_at") is not None:
            await _finish(job, state="cancelled", error="CLIP_DELETED")
            continue
        card = job["variant"] == "card"
        status = clip.get("card_status") if card else clip.get("mp4_status")
        key = clip.get("card_key") if card else clip.get("mp4_key")
        if status == "ready" and key:
            await database.execute(update(FILES).where(FILES.c.id == job["id"]).where(FILES.c.state == "waiting_mp4")
                                   .values(state="queued", updated_at=now))
            moved += 1
        elif status == "failed":
            await _finish(job, state="failed", error="MP4_FAILED")
        elif (R.aware(job["created_at"]) or now) + DR.MP4_WAIT < now:
            await _finish(job, state="failed", error="MP4_TIMEOUT")
    if moved:
        wake_worker()
    return moved


async def _finish(job: Dict[str, Any], *, state: str, error: Optional[str] = None, **extra: Any) -> None:
    await database.execute(update(FILES).where(FILES.c.id == job["id"]).values(
        state=state, error=error, lease_until=None, worker_id=None, updated_at=C.now(), **extra))
    try:
        await C.touch(job["pair_id"], R.s(job.get("author_judge_id")), f"drive_{state}", "drive", job.get("match_id"))
    except Exception:  # noqa: BLE001
        logger.warning("mentor: rewizja po zadaniu Dysku nieudana", exc_info=True)


async def claim_next(worker_id: str, now: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
    """Jedno zadanie do wykonania; UPDATE z warunkiem wolnej dzierżawy (bezpieczne przy wielu workerach). Zadania par bez
    ważnego połączenia i folderu czekają nietknięte (nie zużywają prób)."""
    now = now or C.now()
    usable = {r["pair_id"] for r in await C.rows(select(CONN.c.pair_id).where(CONN.c.state == "connected")
                                                 .where(CONN.c.folder_id.is_not(None)).where(CONN.c.folder_problem.is_(None)))}
    for job in await C.rows(select(FILES).where(FILES.c.state.in_(("queued", "working"))).order_by(FILES.c.created_at.asc()).limit(200)):
        if job["pair_id"] not in usable:
            continue
        due = R.aware(job["next_at"]) if job.get("next_at") else None
        held = R.aware(job["lease_until"]) if job.get("lease_until") else None
        if (due and due > now) or (held and held > now):
            continue
        await database.execute(update(FILES).where(FILES.c.id == job["id"]).where(FILES.c.state == job["state"])
                               .where(or_(FILES.c.lease_until.is_(None), FILES.c.lease_until < now))
                               .values(state="working", worker_id=worker_id, lease_until=now + timedelta(seconds=DR.LEASE_S), updated_at=now))
        again = await C.one(select(FILES).where(FILES.c.id == job["id"]))
        if again and again.get("worker_id") == worker_id and again["state"] == "working":
            return again
    return None


async def _heartbeat(job_id: str, worker_id: str) -> None:
    await database.execute(update(FILES).where(FILES.c.id == job_id).where(FILES.c.worker_id == worker_id)
                           .values(lease_until=C.now() + timedelta(seconds=DR.LEASE_S)))


async def _release(job: Dict[str, Any]) -> None:
    """Zadanie wraca do kolejki bez zużycia próby (np. czeka na ponowne połączenie)."""
    await database.execute(update(FILES).where(FILES.c.id == job["id"]).where(FILES.c.state == "working")
                           .values(state="queued", lease_until=None, worker_id=None))


async def _folder_alive(access: str, folder_id: str) -> bool:
    """Zapamiętany podfolder: `False` tylko przy jednoznacznym 404 albo koszu; inny błąd Google idzie dalej jak dotąd."""
    try:
        meta = await G.api().get_file(access, folder_id)
    except G.GoogleError as exc:
        if exc.status == 404:
            return False
        raise
    return not (isinstance(meta, dict) and meta.get("trashed") is True)


async def ensure_path(access: str, conn: Dict[str, Any], job: Dict[str, Any]) -> str:
    """Podfoldery wg układu pary; find-or-create z pamięcią id w księdze (bez dubli po restarcie)."""
    pid, parent = job["pair_id"], conn["folder_id"]
    async with _lock(f"path:{pid}"):
        for name in DR.subpath(R.s(conn.get("layout")) or DR.DEFAULT_LAYOUT, job.get("match_label"), job.get("category")):
            memo = await C.one(select(FOLDERS).where(FOLDERS.c.pair_id == pid).where(FOLDERS.c.parent_id == parent).where(FOLDERS.c.name == name))
            if memo:
                if await _folder_alive(access, memo["folder_id"]):
                    parent = memo["folder_id"]
                    continue
                await database.execute(FOLDERS.delete().where(FOLDERS.c.pair_id == pid).where(FOLDERS.c.parent_id == parent)
                                       .where(FOLDERS.c.name == name))  # podfolder skasowany na Dysku: zakładamy od nowa
            found = await G.api().find_folder(access, parent, name) or await G.api().create_folder(access, name, parent)
            try:
                await database.execute(FOLDERS.insert().values(pair_id=pid, parent_id=parent, name=name, folder_id=found["id"], created_at=C.now()))
            except Exception:  # noqa: BLE001 - ktoś zdążył zapisać ten sam podfolder
                pass
            parent = found["id"]
    return parent


async def upload(access: str, job: Dict[str, Any], worker_id: str, parent: str, key: str) -> Dict[str, Any]:
    """Strumień R2 -> Dysk (resumable, części po 8 MiB; cały plik nigdy nie leży w pamięci)."""
    stream, size = await asyncio.to_thread(open_mp4, key)
    try:
        if size <= 0:
            raise MissingMp4(key)
        meta = {"name": job["name"], "parents": [parent], "mimeType": "video/mp4",
                "appProperties": {"baza_file": job["id"], "baza_clip": job["clip_id"]}}
        session = await G.api().start_upload(access, meta, size, "video/mp4")
        offset, buf = 0, b""
        while True:
            want = min(DR.CHUNK, size - offset)
            if len(buf) < want:
                buf += await _read_exact(stream, want - len(buf))
            if len(buf) < want:
                raise MissingMp4(key)  # magazyn oddał mniej, niż zapowiedział
            piece = buf[:want]
            for attempt in range(3):
                try:
                    kind, value = await G.api().put_chunk(session, piece, offset, size)
                    break
                except G.GoogleError as exc:
                    if exc.kind != "retry" or attempt == 2:
                        raise
                    await asyncio.sleep(1 + attempt * 2)
            if kind == "done":
                return value
            consumed = max(0, min(int(value) - offset, len(buf)))
            buf, offset = buf[consumed:], offset + consumed
            await _heartbeat(job["id"], worker_id)
    finally:
        close = getattr(stream, "close", None)
        if close:
            close()


async def process(job: Dict[str, Any], worker_id: str) -> str:
    """Jedno zadanie. Zwraca `done` | `retry` | `failed` | `waiting` | `cancelled`."""
    pid = job["pair_id"]
    try:
        clip = await C.one(select(mentor_clips).where(mentor_clips.c.id == job["clip_id"]))
        if not clip or clip.get("deleted_at") is not None:
            await _finish(job, state="cancelled", error="CLIP_DELETED")
            return "cancelled"
        card = job["variant"] == "card"
        key = clip.get("card_key") if card else clip.get("mp4_key")
        ready = (clip.get("card_status") if card else clip.get("mp4_status")) == "ready"
        if not (ready and key):
            await database.execute(update(FILES).where(FILES.c.id == job["id"]).values(
                state="waiting_mp4", lease_until=None, worker_id=None, updated_at=C.now()))
            return "waiting"
        access = await access_for(pid)
        conn = await get_conn(pid)
        if not conn or not conn.get("folder_id"):
            await _release(job)
            return "waiting"
        parent = await ensure_path(access, conn, job)
        found = await G.api().find_by_prop(access, parent, "baza_file", job["id"])  # po restarcie plik mógł już dojść
        if not found:
            found = await upload(access, job, worker_id, parent, key)
        await _finish(job, state="done", error=None, drive_file_id=found.get("id"), web_view_link=found.get("webViewLink"),
                      size=int(found.get("size") or 0) or None, done_at=C.now())
        return "done"
    except NeedsReconnect:
        await _release(job)
        return "waiting"
    except MissingMp4:
        await _finish(job, state="failed", error="MP4_MISSING")
        return "failed"
    except G.GoogleError as exc:
        return await _handle_google_error(job, exc)
    except Exception:  # noqa: BLE001 - nieznany błąd traktujemy jak chwilowy, z limitem prób
        logger.exception("mentor: wysyłka na Dysk nieudana (%s)", job["id"])
        return await _retry_or_fail(job, "INTERNAL")


async def _retry_or_fail(job: Dict[str, Any], error: str) -> str:
    attempts = int(job.get("attempts") or 0) + 1
    if attempts >= DR.MAX_ATTEMPTS:
        await _finish(job, state="failed", error=error, attempts=attempts)
        return "failed"
    await database.execute(update(FILES).where(FILES.c.id == job["id"]).values(
        state="queued", attempts=attempts, error=error, next_at=C.now() + DR.retry_delay(attempts),
        lease_until=None, worker_id=None, updated_at=C.now()))
    return "retry"


async def _handle_google_error(job: Dict[str, Any], exc: G.GoogleError) -> str:
    pid = job["pair_id"]
    kind = exc.kind
    if kind == "revoked":
        await mark_needs_reconnect(pid, "REVOKED")
        await _release(job)
        return "waiting"
    if kind == "folder":
        # Może zniknął tylko zapamiętany podfolder - czyścimy pamięć i sprawdzamy folder pary.
        await database.execute(FOLDERS.delete().where(FOLDERS.c.pair_id == pid))
        conn = await get_conn(pid)
        try:
            root = await G.api().get_file(await access_for(pid), conn["folder_id"]) if conn else None
        except G.GoogleError as probe:
            root = None if probe.kind == "folder" else {"id": conn["folder_id"]}
        except NeedsReconnect:
            await _release(job)
            return "waiting"
        if conn and (not root or root.get("trashed")):
            await database.execute(update(CONN).where(CONN.c.pair_id == pid).values(folder_problem="FOLDER_GONE", updated_at=C.now()))
            try:
                await C.touch(pid, R.s(conn["owner_judge_id"]), "drive_folder_gone", "drive")
            except Exception:  # noqa: BLE001
                pass
            await _release(job)
            return "waiting"
        return await _retry_or_fail(job, "FOLDER_RETRY")
    code = f"GOOGLE_{(exc.reason or str(exc.status)).upper()}"[:60]
    if kind == "retry":
        return await _retry_or_fail(job, code)
    await _finish(job, state="failed", error=code)
    return "failed"


async def work_once(worker_id: str, now: Optional[datetime] = None) -> bool:
    await promote_waiting(now or C.now())
    job = await claim_next(worker_id, now)
    if not job:
        return False
    await process(job, worker_id)
    return True


async def run_drive_worker(number: int = 1) -> None:
    """Pętla w tle (start z `main.py`). Bez flagi `MENTOR_DRIVE_ENABLED` nie robi nic."""
    global _wake
    if not DR.enabled():
        logger.info("mentor: Teczka pary wyłączona (MENTOR_DRIVE_ENABLED)")
        return
    if _wake is None:
        _wake = asyncio.Event()
    worker_id = f"drive-{secrets.token_hex(4)}-{number}"
    await asyncio.sleep(30)
    while True:
        try:
            busy = await work_once(worker_id)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("mentor: pętla Teczki pary")
            busy = False
        if not busy:
            try:
                await asyncio.wait_for(_wake.wait(), timeout=15)
            except asyncio.TimeoutError:
                pass
            _wake.clear()

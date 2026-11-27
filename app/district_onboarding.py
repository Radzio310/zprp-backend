"""
Wdrożenie okręgu - trasy (`docs/wdrozenie-okregu.md`, sekcja 4).

Trzy routery:
  - `/public/onboarding/*` - bez logowania: mapa (bez nazwisk), wejście kodem,
    klucz publiczny sejfu;
  - `/onboarding/*`        - okręg z tokenem z wejścia (`X-Onboarding-Token`);
  - `/admin/onboarding/*`  - administrator aplikacji (BAZA na telefonie).

Reguły (postęp, etap, kod, token, walidacja, treść powiadomień) mieszkają w
`app/district_onboarding_rules.py`; tu jest tylko baza i HTTP.

Hasła ZPRP: serwer dostaje i oddaje WYŁĄCZNIE szyfrogram NaCl sealed box.
Ani hasło, ani szyfrogram, ani kod nie trafiają do zdarzeń ani do logów.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, Response, UploadFile
from pydantic import BaseModel
from sqlalchemy import and_, delete, desc, func, insert, select, update

from app import district_onboarding_rules as R
from app.access_control import require_app_admin
from app.admin_guard import admin_write_guard
from app.db import (
    active_provinces,
    database,
    district_onboarding,
    district_onboarding_events,
    district_onboarding_files,
    onboarding_sealing_keys,
    province_judges,
    province_modules,
    sealed_secrets,
)
from app.settlement_province import canonical, display, spellings

logger = logging.getLogger(__name__)

public_router = APIRouter(prefix="/public/onboarding", tags=["district_onboarding"])
district_router = APIRouter(prefix="/onboarding", tags=["district_onboarding"])
admin_router = APIRouter(
    prefix="/admin/onboarding",
    tags=["district_onboarding"],
    dependencies=[Depends(admin_write_guard)],
)

ADMIN_BY = "Administrator BAZY"

_LIMITER = R.EnterLimiter()
_BATCHER = R.NotifyBatcher()
_FLUSH: Dict[str, asyncio.Task] = {}


# ── Sekrety serwera ─────────────────────────────────────────────────────────


def _secret_key() -> str:
    from app.deps import get_settings

    return get_settings().SECRET_KEY


def _pepper() -> str:
    return os.getenv("ONBOARDING_CODE_PEPPER", "").strip() or hashlib.sha256(
        f"onboarding-code:{_secret_key()}".encode("utf-8")
    ).hexdigest()


def _token_secret() -> str:
    return os.getenv("ONBOARDING_TOKEN_SECRET", "").strip() or hashlib.sha256(
        f"onboarding-token:{_secret_key()}".encode("utf-8")
    ).hexdigest()


# ── Pomocnicze ──────────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if isinstance(value, (datetime, date)) else (value or None)


def _json(raw: Any, default: Any) -> Any:
    """JSONB z `databases` potrafi wrócić napisem."""
    if raw is None:
        return default
    if isinstance(raw, (dict, list)):
        return raw
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return default
    return value if isinstance(value, type(default)) else default


def _province_or_404(raw: str) -> str:
    key = canonical(raw)
    if key not in R.PROVINCE_ADJECTIVE:
        raise HTTPException(404, "Nie znam takiego okręgu.")
    return key


def _client_ip(request: Request) -> str:
    from app.pod_reka_login_rules import client_key

    return client_key(request.headers.get("x-forwarded-for", ""), request.client.host if request.client else "")


async def _row(province: str) -> Optional[Dict[str, Any]]:
    row = await database.fetch_one(select(district_onboarding).where(district_onboarding.c.province == province))
    if not row:
        return None
    data = dict(row._mapping) if hasattr(row, "_mapping") else dict(row)
    data["modules"] = R.clean_modules(_json(data.get("modules"), []))
    data["items"] = _json(data.get("items"), {})
    return data


async def _ensure_row(province: str) -> Dict[str, Any]:
    row = await _row(province)
    if row:
        return row
    await database.execute(
        insert(district_onboarding).values(
            province=province, modules=[], items={}, progress=0, stage=R.STAGE_WAITING, updated_at=_now()
        )
    )
    return await _row(province)  # type: ignore[return-value]


async def _live_provinces() -> set:
    rows = await database.fetch_all(select(active_provinces.c.province, active_provinces.c.enabled))
    return {canonical(r["province"]) for r in rows if r["enabled"]}


async def _is_live(province: str) -> bool:
    return province in await _live_provinces()


async def _event(province: str, by: str, key: Optional[str], action: str, payload: Optional[Dict[str, Any]] = None) -> None:
    await database.execute(
        insert(district_onboarding_events).values(
            province=province, at=_now(), by=(by or None), key=key, action=action, payload=R.scrub(payload or {})
        )
    )


async def _store(
    province: str,
    row: Dict[str, Any],
    *,
    items: Optional[Dict[str, Any]] = None,
    modules: Optional[List[str]] = None,
    entered: Optional[bool] = None,
    live: Optional[bool] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Zapis stanu z przeliczeniem postępu i etapu."""
    items = items if items is not None else row["items"]
    modules = R.clean_modules(modules if modules is not None else row["modules"])
    was_entered = row.get("stage") not in (None, R.STAGE_WAITING)
    if live is None:
        live = await _is_live(province)
    stage = R.compute_stage(items, modules, entered=bool(entered) or was_entered, live=live)
    values = {
        "items": items,
        "modules": modules,
        "progress": 100 if live else R.compute_progress(items, modules),
        "stage": stage,
        "updated_at": _now(),
        **(extra or {}),
    }
    await database.execute(
        update(district_onboarding).where(district_onboarding.c.province == province).values(**values)
    )
    row.update(values)
    return row


def _set_item(items: Dict[str, Any], key: str, by: str, **fields: Any) -> Dict[str, Any]:
    entry = dict(items.get(key) or {})
    entry.update(fields)
    entry["updated_at"] = _now().isoformat()
    entry["by"] = by
    items[key] = entry
    return entry


# ── Powiadomienia (łączone: jeden push na okręg na 10 minut) ────────────────


async def _send_batch(province: str, changes: List[Dict[str, Any]]) -> None:
    from app.admin_alerts import notify_admins

    title, body = R.batch_text(province, changes)
    await notify_admins(
        "district_onboarding",
        title,
        body,
        # Odnośnik unikalny na paczkę: deduplikacja w `admin_alerts` jest wieczna
        # w obrębie procesu, a kolejna paczka tego okręgu musi przejść.
        reference=f"{province}:{int(_now().timestamp())}:{len(changes)}",
        extra={"province": province, "screen": "district_onboarding", "changes": len(changes)},
    )


async def _flush_later(province: str) -> None:
    try:
        delay = max(0.0, _BATCHER.due_at(province) - _now().timestamp())
        await asyncio.sleep(delay)
        changes = _BATCHER.flush(province)
        if changes:
            await _send_batch(province, changes)
    except Exception:  # noqa: BLE001
        logger.warning("district_onboarding: zaległa paczka powiadomień nie wyszła", exc_info=True)
    finally:
        _FLUSH.pop(province, None)


def _notify(province: str, change: Dict[str, Any]) -> None:
    """Dorzuca zmianę do paczki. Nigdy nie rzuca i nie wstrzymuje odpowiedzi."""
    try:
        now = _now().timestamp()
        ready = _BATCHER.add(province, R.scrub(change), now)
        if ready:
            asyncio.get_running_loop().create_task(_send_batch(province, ready))
        elif province not in _FLUSH:
            _FLUSH[province] = asyncio.get_running_loop().create_task(_flush_later(province))
    except Exception:  # noqa: BLE001
        logger.warning("district_onboarding: powiadomienie pominięte", exc_info=True)


# ── Odpowiedzi ──────────────────────────────────────────────────────────────


async def _events(province: str, limit: int) -> List[Dict[str, Any]]:
    rows = await database.fetch_all(
        select(district_onboarding_events)
        .where(district_onboarding_events.c.province == province)
        .order_by(desc(district_onboarding_events.c.id))
        .limit(limit)
    )
    return [
        {
            "id": r["id"],
            "at": _iso(r["at"]),
            "by": r["by"],
            "key": r["key"],
            "action": r["action"],
            "payload": R.scrub(_json(r["payload"], {})),
        }
        for r in rows
    ]


async def _files(province: str) -> List[Dict[str, Any]]:
    rows = await database.fetch_all(
        select(
            district_onboarding_files.c.id,
            district_onboarding_files.c.key,
            district_onboarding_files.c.filename,
            district_onboarding_files.c.mime,
            district_onboarding_files.c.size,
            district_onboarding_files.c.uploaded_by,
            district_onboarding_files.c.uploaded_at,
        )
        .where(district_onboarding_files.c.province == province)
        .order_by(desc(district_onboarding_files.c.id))
    )
    return [
        {
            "id": r["id"],
            "key": r["key"],
            "filename": r["filename"],
            "mime": r["mime"],
            "size": r["size"],
            "uploaded_by": r["uploaded_by"],
            "uploaded_at": _iso(r["uploaded_at"]),
        }
        for r in rows
    ]


def _state(row: Dict[str, Any], events: List[Dict[str, Any]], files: List[Dict[str, Any]], *, for_admin: bool = False) -> Dict[str, Any]:
    province = row["province"]
    live = row.get("stage") == R.STAGE_LIVE
    return {
        "province": province,
        "label": R.province_label(province),
        "modules": row["modules"],
        "items": R.public_items(row["items"], for_admin=for_admin),
        "progress": row.get("progress") or 0,
        "stage": row.get("stage") or R.STAGE_WAITING,
        "lit": R.lit_modules(row["items"], row["modules"], live=live),
        "missing": R.missing_summary(row["items"], row["modules"]),
        "scope": R.scope_keys(row["modules"]),
        "updated_at": _iso(row.get("updated_at")),
        "events": events,
        "files": files,
        "catalog": R.keys_catalog(),
    }


# ── Publiczne ───────────────────────────────────────────────────────────────


@public_router.get("/map", summary="Mapa wdrożeń: etap i postęp 16 okręgów (bez nazwisk)")
async def onboarding_map():
    rows = {r["province"]: r for r in await database.fetch_all(select(district_onboarding))}
    live = await _live_provinces()
    module_rows = await database.fetch_all(select(province_modules))
    live_modules: Dict[str, List[str]] = {}
    for r in module_rows:
        if not r["enabled"]:
            continue
        name = {"stats": "statystyki", "settlements": "rozliczenia"}.get(str(r["module"]))
        if name:
            live_modules.setdefault(canonical(r["province"]), []).append(name)
    out = []
    for province in R.PROVINCES:
        row = rows.get(province)
        items = _json(row["items"], {}) if row else {}
        modules = R.clean_modules(_json(row["modules"], [])) if row else []
        if province in live:
            modules = modules or R.clean_modules(live_modules.get(province, []))
            out.append({
                "province": province,
                "stage": R.STAGE_LIVE,
                "progress": 100,
                "lit": R.lit_modules(items, modules, live=True),
                "skipped": R.skipped_keys(items, modules),
                "updated_at": _iso(row["updated_at"]) if row else None,
            })
            continue
        stage = row["stage"] if row else R.STAGE_WAITING
        if stage == R.STAGE_LIVE:
            # Okręg wyłączony po włączeniu: wszystko wgrane, czeka na ponowne włączenie.
            stage = R.STAGE_READY
        out.append({
            "province": province,
            "stage": stage,
            "progress": int(row["progress"] or 0) if row else 0,
            "lit": R.lit_modules(items, modules),
            "skipped": R.skipped_keys(items, modules),
            "updated_at": _iso(row["updated_at"]) if row else None,
        })
    return out


class EnterRequest(BaseModel):
    code: str = ""
    name: str = ""


@public_router.post("/enter", summary="Wejście kodem okręgu")
async def enter(req: EnterRequest, request: Request):
    ip = _client_ip(request)
    wait = _LIMITER.retry_after(ip)
    if wait:
        raise HTTPException(429, detail={"message": R.wait_message(wait), "retry_after": wait})

    code = R.normalize_code(req.code)
    row = None
    if code:
        found = await database.fetch_one(
            select(district_onboarding).where(
                and_(
                    district_onboarding.c.code_hash == R.code_hash(code, _pepper()),
                    district_onboarding.c.code_revoked.is_(False),
                )
            )
        )
        row = await _row(found["province"]) if found else None
    _LIMITER.attempt(ip, ok=row is not None)
    if row is None:
        if _LIMITER.is_blocked(ip):
            wait = _LIMITER.retry_after(ip)
            raise HTTPException(429, detail={"message": R.wait_message(wait), "retry_after": wait})
        raise HTTPException(401, detail={"message": R.BAD_CODE})

    province = row["province"]
    name = R.clean_name(req.name)
    if not name:
        # Dobry kod, jeszcze bez podpisu - strona pyta „Jak się podpiszesz?".
        return {"need_name": True, "province": province, "label": R.province_label(province)}

    token = R.sign_token(_token_secret(), province=province, code_version=row["code_version"], name=name)
    first = row.get("stage") == R.STAGE_WAITING
    await _event(province, name, None, "opened", {})
    await _store(province, row, entered=True)
    _notify(province, {"key": None, "action": "opened", "by": name, "first": first})
    return {"token": token, "province": province, "label": R.province_label(province), "name": name}


@public_router.get("/sealing-key", summary="Klucz publiczny sejfu administratora")
async def sealing_key():
    row = await database.fetch_one(
        select(onboarding_sealing_keys)
        .where(onboarding_sealing_keys.c.revoked_at.is_(None))
        .order_by(desc(onboarding_sealing_keys.c.created_at))
        .limit(1)
    )
    if not row:
        raise HTTPException(503, detail={"message": "Sejf nie jest jeszcze gotowy. Administrator BAZY musi go uruchomić w aplikacji."})
    return {"key_id": row["key_id"], "public_key": row["public_key"], "alg": R.SEAL_ALG}


# ── Okręg z tokenem ─────────────────────────────────────────────────────────


async def district_session(x_onboarding_token: Optional[str] = Header(None)) -> Tuple[str, str, Dict[str, Any]]:
    claims = R.verify_token(_token_secret(), x_onboarding_token)
    if not claims:
        raise HTTPException(401, detail={"message": "Sesja wygasła. Wpisz kod jeszcze raz."})
    row = await _row(claims.province)
    if not row or row.get("code_revoked") or int(row.get("code_version") or 0) != claims.code_version:
        raise HTTPException(401, detail={"message": "Ten kod został wymieniony. Poproś administratora BAZY o nowy."})
    return claims.province, claims.name, row


@district_router.get("/state", summary="Stan wdrożenia okręgu")
async def district_state(session=Depends(district_session)):
    province, _name, row = session
    return _state(row, await _events(province, 50), await _files(province))


class ModulesRequest(BaseModel):
    modules: List[str] = []


@district_router.put("/modules", summary="Wybór modułów okręgu")
async def set_modules(req: ModulesRequest, session=Depends(district_session)):
    province, name, row = session
    modules = R.clean_modules(req.modules)
    if modules != row["modules"]:
        await _event(province, name, None, "modules_changed", {"modules": modules})
        await _store(province, row, modules=modules)
        _notify(province, {"key": None, "action": "modules_changed"})
    return _state(row, await _events(province, 50), await _files(province))


class SecretRequest(BaseModel):
    key: str
    login: str = ""
    ciphertext: str = ""
    key_id: str = ""
    same_as_sync: bool = False


@district_router.post("/secret", summary="Hasło ZPRP do sejfu (tylko szyfrogram)")
async def submit_secret(req: SecretRequest, session=Depends(district_session)):
    province, name, row = session
    if req.key not in R.SECRET_KEYS:
        raise HTTPException(400, detail={"message": "Ten klucz nie idzie do sejfu."})
    items = dict(row["items"])
    login = " ".join(str(req.login or "").split())[:80]

    if req.key == "zprp_assign" and req.same_as_sync:
        _set_item(items, req.key, name, status=R.SUBMITTED, same_as_sync=True, sealed=False, login=None, note=None)
        await _event(province, name, req.key, "submitted", {"same_as_sync": True})
    else:
        ciphertext = R.check_ciphertext(req.ciphertext)
        if not login or not ciphertext:
            raise HTTPException(400, detail={"message": "Brakuje loginu albo zaszyfrowanego hasła."})
        current = await database.fetch_one(
            select(onboarding_sealing_keys.c.key_id).where(
                and_(onboarding_sealing_keys.c.key_id == req.key_id, onboarding_sealing_keys.c.revoked_at.is_(None))
            )
        )
        if not current:
            raise HTTPException(409, detail={"message": "Sejf dostał nowy klucz. Odśwież stronę i zamknij hasło jeszcze raz."})
        # Poprzedni, niewklejony szyfrogram tego klucza przestaje mieć sens.
        await database.execute(
            delete(sealed_secrets).where(
                and_(
                    sealed_secrets.c.province == province,
                    sealed_secrets.c.key == req.key,
                    sealed_secrets.c.consumed_at.is_(None),
                )
            )
        )
        await database.execute(
            insert(sealed_secrets).values(
                province=province, key=req.key, login=login, ciphertext=ciphertext,
                alg=R.SEAL_ALG, key_id=req.key_id, created_at=_now(), created_by=name,
            )
        )
        _set_item(items, req.key, name, status=R.SUBMITTED, sealed=True, same_as_sync=False, login=login, note=None)
        await _event(province, name, req.key, "submitted", {"sealed": True})
    await _store(province, row, items=items)
    _notify(province, {"key": req.key, "action": "submitted"})
    return _state(row, await _events(province, 50), await _files(province))


@district_router.post("/file", summary="Plik do przeglądu (ryczałty, odległości)")
async def upload_file(key: str = Form(...), file: UploadFile = File(...), session=Depends(district_session)):
    province, name, row = session
    if key not in R.EDITOR_KEYS:
        raise HTTPException(400, detail={"message": "Do tego klucza nie wgrywa się pliku."})
    kind = R.file_kind(file.filename)
    if not kind:
        raise HTTPException(415, detail={"message": "Przyjmujemy PDF, Excel, CSV i zdjęcia (JPG, PNG, HEIC, WebP)."})
    data = await file.read(R.FILE_MAX_BYTES + 1)
    if len(data) > R.FILE_MAX_BYTES:
        raise HTTPException(413, detail={"message": "Plik ma więcej niż 15 MB. Zmniejsz go albo podziel."})
    if not data:
        raise HTTPException(400, detail={"message": "Plik jest pusty."})
    await database.execute(
        insert(district_onboarding_files).values(
            province=province, key=key, filename=R.safe_filename(file.filename), mime=R.FILE_TYPES[kind],
            size=len(data), sha256=hashlib.sha256(data).hexdigest(), data=data,
            uploaded_by=name, uploaded_at=_now(),
        )
    )
    items = dict(row["items"])
    entry = dict(items.get(key) or {})
    status = entry.get("status")
    _set_item(
        items, key, name,
        status=status if status == R.ACTIVE else R.IN_REVIEW,
        files=int(entry.get("files") or 0) + 1,
        note=None,
    )
    await _event(province, name, key, "submitted", {"via": "file", "filename": R.safe_filename(file.filename), "size": len(data)})
    await _store(province, row, items=items)
    _notify(province, {"key": key, "action": "submitted", "via": "file"})
    return _state(row, await _events(province, 50), await _files(province))


@district_router.put("/draft/{key}", summary="Szkic z edytora (ryczałty, odległości)")
async def save_draft(key: str, draft: Dict[str, Any], session=Depends(district_session)):
    province, name, row = session
    if key not in R.EDITOR_KEYS:
        raise HTTPException(400, detail={"message": "Ten klucz nie ma edytora."})
    clean, errors = R.validate_draft(key, draft)
    items = dict(row["items"])
    entry = dict(items.get(key) or {})
    was_admin_draft = bool(entry.get("draft_by_admin"))
    complete = not errors
    status = entry.get("status") or R.MISSING
    if complete and status != R.ACTIVE:
        status = R.SUBMITTED
    _set_item(items, key, name, draft=clean, draft_by_admin=False, status=status, **({"note": None} if complete else {}))
    if complete:
        await _event(province, name, key, "submitted", {"via": "editor", "confirmed_admin_draft": was_admin_draft})
    await _store(province, row, items=items)
    if complete:
        _notify(province, {"key": key, "action": "submitted", "via": "editor"})
    state = _state(row, await _events(province, 50), await _files(province))
    state["errors"] = errors
    return state


@district_router.put("/people/{key}", summary="Ludzie: opiekun, komisja, masterzy, mentorzy")
async def save_people(key: str, payload: Dict[str, Any], session=Depends(district_session)):
    province, name, row = session
    if key not in R.PEOPLE_KEYS:
        raise HTTPException(400, detail={"message": "Ten klucz nie zbiera ludzi."})
    people, errors = R.clean_people(key, payload.get("people") if key != "keeper" else payload.get("person", payload))
    if errors:
        raise HTTPException(422, detail={"message": errors[0], "errors": errors})
    items = dict(row["items"])
    _set_item(items, key, name, draft=people, status=R.SUBMITTED, note=None)
    count = R.people_count(people)
    await _event(province, name, key, "submitted", {"count": count})
    await _store(province, row, items=items)
    _notify(province, {"key": key, "action": "submitted", "count": count})
    return _state(row, await _events(province, 50), await _files(province))


class SkipRequest(BaseModel):
    reason: str = ""


@district_router.post("/skip/{key}", summary="Świadome pominięcie klucza")
async def skip_key(key: str, req: SkipRequest, session=Depends(district_session)):
    province, name, row = session
    meta = R.KEY_META.get(key)
    if not meta or not meta.skippable:
        raise HTTPException(400, detail={"message": "Tego klucza nie da się pominąć - bez niego panel nie ruszy."})
    items = dict(row["items"])
    prev = R.item_status(items, key)
    if prev != R.SKIPPED:
        reason = " ".join(str(req.reason or "").split())[:200] or None
        _set_item(items, key, name, status=R.SKIPPED, skip_reason=reason, prev_status=prev)
        await _event(province, name, key, "skipped", {"reason": reason})
        await _store(province, row, items=items)
        _notify(province, {"key": key, "action": "skipped"})
    return _state(row, await _events(province, 50), await _files(province))


@district_router.post("/unskip/{key}", summary="Klucz wraca z tacki „Na później”")
async def unskip_key(key: str, session=Depends(district_session)):
    province, name, row = session
    items = dict(row["items"])
    if R.item_status(items, key) == R.SKIPPED:
        prev = (items.get(key) or {}).get("prev_status")
        restored = prev if prev in R.STATUSES and prev != R.SKIPPED else R.MISSING
        _set_item(items, key, name, status=restored, skip_reason=None, prev_status=None)
        await _event(province, name, key, "unskipped", {})
        await _store(province, row, items=items)
        _notify(province, {"key": key, "action": "unskipped"})
    return _state(row, await _events(province, 50), await _files(province))


@district_router.get("/judges", summary="Sędziowie tego okręgu (do wyboru masterów i mentorów)")
async def district_judges(q: str = "", session=Depends(district_session)):
    province, _name, _row = session
    text = " ".join(str(q or "").split())
    if len(text) < 3:
        return []
    names = spellings(province) + [province, display(province)]
    words = [w for w in text.split(" ") if w][:3]
    query = select(province_judges.c.judge_id, province_judges.c.full_name).where(
        province_judges.c.province.in_(list(dict.fromkeys(names)))
    )
    for word in words:
        like = f"%{word.replace('%', '').replace('_', '')}%"
        query = query.where(func.lower(province_judges.c.full_name).like(func.lower(like)))
    rows = await database.fetch_all(query.order_by(province_judges.c.full_name).limit(20))
    return [{"id": r["judge_id"], "name": r["full_name"]} for r in rows]


# ── Administrator ───────────────────────────────────────────────────────────


@admin_router.get("", summary="Wdrożenia wszystkich okręgów")
async def admin_list(_admin: dict = Depends(require_app_admin)):
    rows = {r["province"]: r for r in await database.fetch_all(select(district_onboarding))}
    live = await _live_provinces()
    pending_secrets = await database.fetch_all(
        select(sealed_secrets.c.province, func.count().label("n"))
        .where(sealed_secrets.c.consumed_at.is_(None))
        .group_by(sealed_secrets.c.province)
    )
    secrets_by = {r["province"]: int(r["n"]) for r in pending_secrets}
    out = []
    for province in R.PROVINCES:
        row = rows.get(province)
        items = _json(row["items"], {}) if row else {}
        modules = R.clean_modules(_json(row["modules"], [])) if row else []
        waiting = [k for k in R.scope_keys(modules) if R.item_status(items, k) in (R.SUBMITTED, R.IN_REVIEW)] if row else []
        out.append({
            "province": province,
            "label": R.province_label(province),
            "stage": R.STAGE_LIVE if province in live else (row["stage"] if row else R.STAGE_WAITING),
            "progress": 100 if province in live else (int(row["progress"] or 0) if row else 0),
            "code_issued_at": _iso(row["code_issued_at"]) if row else None,
            "code_active": bool(row and row["code_hash"] and not row["code_revoked"]),
            "to_review": waiting,
            "sealed_waiting": secrets_by.get(province, 0),
            "updated_at": _iso(row["updated_at"]) if row else None,
        })
    return out


async def _secrets(province: str) -> List[Dict[str, Any]]:
    rows = await database.fetch_all(
        select(sealed_secrets).where(sealed_secrets.c.province == province).order_by(desc(sealed_secrets.c.id))
    )
    out = []
    for r in rows:
        user_env, pass_env = R.railway_env_names(province, r["key"])
        out.append({
            "id": r["id"],
            "key": r["key"],
            "login": r["login"],
            "ciphertext": r["ciphertext"],
            "alg": r["alg"],
            "key_id": r["key_id"],
            "created_at": _iso(r["created_at"]),
            "created_by": r["created_by"],
            "consumed_at": _iso(r["consumed_at"]),
            "env_username": user_env,
            "env_password": pass_env,
        })
    return out


async def _admin_state(province: str) -> Dict[str, Any]:
    row = await _ensure_row(province)
    state = _state(row, await _events(province, 100), await _files(province), for_admin=True)
    state["secrets"] = await _secrets(province)
    state["code"] = {
        "version": int(row.get("code_version") or 0),
        "issued_at": _iso(row.get("code_issued_at")),
        "active": bool(row.get("code_hash") and not row.get("code_revoked")),
    }
    return state


# Stałe ścieżki PRZED `/{province}`, żeby nie zostały wzięte za nazwę okręgu.


class SealingKeyRequest(BaseModel):
    public_key: str


@admin_router.put("/sealing-key", summary="Nowy klucz publiczny sejfu (z telefonu administratora)")
async def put_sealing_key(req: SealingKeyRequest, admin: dict = Depends(require_app_admin)):
    public_key = R.check_public_key(req.public_key)
    if not public_key:
        raise HTTPException(400, detail={"message": "To nie jest klucz publiczny X25519 (32 bajty w base64)."})
    key_id = hashlib.sha256(public_key.encode("ascii")).hexdigest()[:16]
    now = _now()
    await database.execute(
        update(onboarding_sealing_keys)
        .where(and_(onboarding_sealing_keys.c.revoked_at.is_(None), onboarding_sealing_keys.c.key_id != key_id))
        .values(revoked_at=now)
    )
    exists = await database.fetch_one(select(onboarding_sealing_keys).where(onboarding_sealing_keys.c.key_id == key_id))
    if exists:
        await database.execute(
            update(onboarding_sealing_keys).where(onboarding_sealing_keys.c.key_id == key_id).values(revoked_at=None)
        )
    else:
        await database.execute(
            insert(onboarding_sealing_keys).values(
                key_id=key_id, public_key=public_key, created_at=now, created_by=str(admin.get("judge_id") or "")
            )
        )
    return {"key_id": key_id}


@admin_router.post("/secrets/{secret_id}/consumed", summary="Wklejone do Railway: kasuje szyfrogram")
async def secret_consumed(secret_id: int, _admin: dict = Depends(require_app_admin)):
    row = await database.fetch_one(select(sealed_secrets).where(sealed_secrets.c.id == secret_id))
    if not row:
        raise HTTPException(404, detail={"message": "Nie ma takiego wpisu w sejfie."})
    await database.execute(
        update(sealed_secrets).where(sealed_secrets.c.id == secret_id).values(ciphertext=None, consumed_at=_now())
    )
    await _event(row["province"], ADMIN_BY, row["key"], "commented", {"note": "Wklejone do Railway, szyfrogram skasowany."})
    return await _admin_state(row["province"])


@admin_router.get("/{province}", summary="Pełny stan wdrożenia okręgu")
async def admin_province(province: str, _admin: dict = Depends(require_app_admin)):
    return await _admin_state(_province_or_404(province))


@admin_router.get("/{province}/files/{file_id}", summary="Plik od okręgu")
async def admin_file(province: str, file_id: int, _admin: dict = Depends(require_app_admin)):
    key = _province_or_404(province)
    row = await database.fetch_one(
        select(district_onboarding_files).where(
            and_(district_onboarding_files.c.id == file_id, district_onboarding_files.c.province == key)
        )
    )
    if not row:
        raise HTTPException(404, detail={"message": "Nie ma takiego pliku."})
    safe = row["filename"].encode("ascii", "ignore").decode() or "plik"
    return Response(
        content=bytes(row["data"]),
        media_type=row["mime"],
        headers={"Content-Disposition": f'inline; filename="{safe}"', "Cache-Control": "private, no-store"},
    )


@admin_router.post("/{province}/code", summary="Wydaje nowy kod (pokazany raz) i unieważnia stary")
async def issue_code(province: str, _admin: dict = Depends(require_app_admin)):
    key = _province_or_404(province)
    row = await _ensure_row(key)
    for _ in range(5):
        code = R.generate_code()
        hashed = R.code_hash(code, _pepper())
        clash = await database.fetch_one(
            select(district_onboarding.c.province).where(district_onboarding.c.code_hash == hashed)
        )
        if not clash:
            break
    else:  # pragma: no cover - 32^8 możliwości
        raise HTTPException(500, detail={"message": "Nie udało się wylosować kodu. Spróbuj jeszcze raz."})
    version = int(row.get("code_version") or 0) + 1
    await _store(key, row, extra={
        "code_hash": hashed, "code_version": version, "code_issued_at": _now(), "code_revoked": False,
    })
    await _event(key, ADMIN_BY, None, "code_rotated", {"version": version})
    return {
        "province": key,
        "label": R.province_label(key),
        "code": code,
        "display": R.format_code(code),
        "link": R.code_link(code),
        "version": version,
    }


@admin_router.post("/{province}/code/revoke", summary="Unieważnia kod bez wydawania nowego")
async def revoke_code(province: str, _admin: dict = Depends(require_app_admin)):
    key = _province_or_404(province)
    row = await _ensure_row(key)
    version = int(row.get("code_version") or 0) + 1
    await _store(key, row, extra={"code_hash": None, "code_revoked": True, "code_version": version})
    await _event(key, ADMIN_BY, None, "code_rotated", {"version": version, "revoked": True})
    return await _admin_state(key)


async def _publish(province: str, key: str, entry: Dict[str, Any]) -> Dict[str, Any]:
    """Przenosi zatwierdzony klucz tam, gdzie czyta go reszta aplikacji.

    Bez duplikowania logiki: stawki i odległości idą przez te same funkcje, co
    panel admina (`app/admin.py`), więc wersjonowanie i odcisk dla telefonów
    zostają jedne.
    """
    name = display(province)
    draft = entry.get("draft")
    if key in R.EDITOR_KEYS:
        clean, errors = R.validate_draft(key, draft)
        if errors:
            raise HTTPException(422, detail={"message": errors[0], "errors": errors})
        if key == "rates":
            from app.admin import create_okreg_rate_version
            from app.schemas import CreateOkregRateVersionRequest

            try:
                await create_okreg_rate_version(name, CreateOkregRateVersionRequest(
                    province=name, content=clean["content"], enabled=True,
                    valid_from=date.fromisoformat(clean["validFrom"]),
                ))
            except HTTPException as exc:
                # Wersja JEST zapisana; 404 mówi tylko, że od dziś jeszcze nie
                # obowiązuje (data w przyszłości) - funkcja panelu oddaje na koniec
                # stawki aktualne na dzisiaj.
                if exc.status_code != 404:
                    raise
            return {"published": "okreg_rates", "validFrom": clean["validFrom"]}
        from app.admin import upsert_okreg_distance
        from app.schemas import UpsertOkregDistanceRequest

        await upsert_okreg_distance(name, UpsertOkregDistanceRequest(province=name, content=clean, enabled=True))
        return {"published": "okreg_distances", "validFrom": clean["validFrom"], "cities": len(clean["cities"])}

    if key == "commission":
        people = draft if isinstance(draft, list) else []
        if not people:
            raise HTTPException(422, detail={"message": "Komisja jest pusta - nie ma czego zatwierdzić."})
        await _upsert_vips(name, people)
        return {"published": "baza_vips", "count": len(people)}

    if key == "masters":
        people = draft if isinstance(draft, list) else []
        without = [f"{p.get('first_name')} {p.get('last_name')}" for p in people if not p.get("judge_id")]
        if without:
            raise HTTPException(422, detail={"message": f"Bez numeru sędziego: {', '.join(without)}. Wybierz ich z listy sędziów okręgu."})
        from app.admin import add_master

        for person in people:
            for kind in person.get("kinds") or []:
                await add_master(kind, name, str(person["judge_id"]))
        return {"published": "masters", "count": len(people)}

    if key == "zprp_assign":
        await _set_assign_mode(name, "same_as_sync" if entry.get("same_as_sync") else "own")
        return {"published": "province_module_config", "assign_account_mode": "same_as_sync" if entry.get("same_as_sync") else "own"}

    # zprp_sync (hasło wkleja administrator w Railway), keeper i mentors
    # (pary mentoringu potrzebują młodego sędziego - zakłada je komisja w BAZA).
    return {"published": None}


async def _upsert_vips(province_name: str, people: List[Dict[str, Any]]) -> None:
    from app.db import baza_vips
    from app.province_panel_access import vip_permissions

    for person in people:
        login = str(person.get("login") or "").strip()
        if not login:
            continue
        rights = {r: (r in (person.get("rights") or [])) for r in R.RIGHTS}
        existing = await database.fetch_one(
            select(baza_vips).where(func.lower(baza_vips.c.username) == login.lower())
        )
        if existing:
            perms = vip_permissions(existing["permissions_json"])
            perms.update({k: True for k, v in rights.items() if v})
            values: Dict[str, Any] = {"permissions_json": perms, "updated_at": _now()}
            if not existing["province"]:
                values["province"] = province_name
            await database.execute(update(baza_vips).where(baza_vips.c.id == existing["id"]).values(**values))
        else:
            await database.execute(
                insert(baza_vips).values(
                    username=login,
                    province=province_name,
                    permissions_json={k: True for k, v in rights.items() if v},
                )
            )


async def _set_assign_mode(province_name: str, mode: str) -> None:
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from app.db import province_module_config
    from app.province_access import normalize_province

    key = normalize_province(province_name)
    await database.execute(
        pg_insert(province_module_config)
        .values(province=key, assign_account_mode=mode)
        .on_conflict_do_update(index_elements=[province_module_config.c.province], set_={"assign_account_mode": mode})
    )


@admin_router.post("/{province}/approve/{key}", summary="Zatwierdza klucz i publikuje go do aplikacji")
async def approve(province: str, key: str, _admin: dict = Depends(require_app_admin)):
    prov = _province_or_404(province)
    if key not in R.KEY_META:
        raise HTTPException(404, detail={"message": "Nie ma takiego klucza."})
    row = await _ensure_row(prov)
    items = dict(row["items"])
    entry = dict(items.get(key) or {})
    if R.item_status(items, key) in (R.MISSING, R.SKIPPED):
        raise HTTPException(409, detail={"message": "Okręg jeszcze nic tu nie wgrał."})
    result = await _publish(prov, key, entry)
    _set_item(items, key, ADMIN_BY, status=R.ACTIVE, note=None, draft_by_admin=False)
    await _event(prov, ADMIN_BY, key, "approved", result)
    await _store(prov, row, items=items)
    return await _admin_state(prov)


class NoteRequest(BaseModel):
    note: str = ""


@admin_router.post("/{province}/reject/{key}", summary="Odrzuca klucz z notatką dla okręgu")
async def reject(province: str, key: str, req: NoteRequest, _admin: dict = Depends(require_app_admin)):
    prov = _province_or_404(province)
    if key not in R.KEY_META:
        raise HTTPException(404, detail={"message": "Nie ma takiego klucza."})
    note = " ".join(str(req.note or "").split())[:400]
    if not note:
        raise HTTPException(400, detail={"message": "Napisz okręgowi jednym zdaniem, co poprawić."})
    row = await _ensure_row(prov)
    items = dict(row["items"])
    _set_item(items, key, ADMIN_BY, status=R.REJECTED, note=note)
    await _event(prov, ADMIN_BY, key, "rejected", {"note": note})
    await _store(prov, row, items=items)
    return await _admin_state(prov)


@admin_router.post("/{province}/draft/{key}", summary="Administrator przepisuje plik do szkicu")
async def admin_draft(province: str, key: str, draft: Dict[str, Any], _admin: dict = Depends(require_app_admin)):
    prov = _province_or_404(province)
    if key not in R.EDITOR_KEYS:
        raise HTTPException(400, detail={"message": "Ten klucz nie ma edytora."})
    clean, errors = R.validate_draft(key, draft)
    row = await _ensure_row(prov)
    items = dict(row["items"])
    _set_item(items, key, ADMIN_BY, draft=clean, draft_by_admin=True, status=R.IN_REVIEW, note=None)
    await _event(prov, ADMIN_BY, key, "commented", {"note": "Plik przepisany do tabeli. Okręg sprawdza podgląd."})
    await _store(prov, row, items=items)
    state = await _admin_state(prov)
    state["errors"] = errors
    return state


@admin_router.post("/{province}/go-live", summary="Włącza okręg i jego moduły")
async def go_live(province: str, _admin: dict = Depends(require_app_admin)):
    prov = _province_or_404(province)
    row = await _ensure_row(prov)
    if row.get("stage") not in (R.STAGE_READY, R.STAGE_LIVE):
        missing = [R.KEY_META[k].label for k in R.scope_keys(row["modules"]) if R.item_status(row["items"], k) not in R.DONE]
        raise HTTPException(409, detail={"message": "Okręg nie jest jeszcze gotowy. Brakuje: " + ", ".join(missing) + "."})
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    name = display(prov)
    await database.execute(
        pg_insert(active_provinces)
        .values(province=name, enabled=True)
        .on_conflict_do_update(index_elements=[active_provinces.c.province], set_={"enabled": True})
    )
    turned_on = []
    for module, table_module in (("statystyki", "stats"), ("rozliczenia", "settlements")):
        if module not in row["modules"]:
            continue
        await database.execute(
            pg_insert(province_modules)
            .values(province=prov, module=table_module, enabled=True)
            .on_conflict_do_update(
                index_elements=[province_modules.c.province, province_modules.c.module], set_={"enabled": True}
            )
        )
        turned_on.append(table_module)
    await _event(prov, ADMIN_BY, None, "approved", {"go_live": True, "modules": turned_on})
    await _store(prov, row, live=True)
    return await _admin_state(prov)

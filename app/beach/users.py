from __future__ import annotations

import secrets
from datetime import datetime, timezone
import logging
import traceback
from typing import Any, Dict, List, Optional

import asyncpg
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, update, delete
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from app.db import database, beach_users, beach_admins
from app.schemas import (
    BeachUserCreateRequest,
    BeachUserUpdateRequest,
    BeachUserItem,
    BeachUsersListResponse,
    BeachLoginRequest,
    BeachLoginResponse,
)
from app.deps import get_rsa_keys, beach_create_access_token, beach_get_current_user_id


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/users", tags=["Beach: Users"])
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def _hash_password(password: str) -> str:
    return pwd_context.hash(password)


def _verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _parse_jsonish(raw: Any, fallback: Any):
    if raw is None:
        return fallback
    if isinstance(raw, (dict, list)):
        return raw
    try:
        import json
        return json.loads(raw)
    except Exception:
        return fallback


def _extract_badge_names(badges_raw: Any) -> List[str]:
    if badges_raw is None:
        return []
    if isinstance(badges_raw, dict):
        return [str(k) for k, v in badges_raw.items() if v is not None and v]
    if isinstance(badges_raw, list):
        return [str(x) for x in badges_raw if x is not None]
    return []


def _normalize_province(p: Optional[str]) -> Optional[str]:
    if p is None:
        return None
    s = (p or "").strip().upper()
    return s or None


def _decrypt_password_from_b64(password_encrypted_b64: str) -> str:
    from base64 import b64decode

    private_key, _ = get_rsa_keys()
    try:
        encrypted_password_bytes = b64decode(password_encrypted_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Niepoprawny format zaszyfrowanego hasła")

    try:
        decrypted_password_bytes = private_key.decrypt(
            encrypted_password_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted_password_bytes.decode("utf-8")
    except Exception:
        raise HTTPException(status_code=400, detail="Nie udało się odszyfrować hasła")


def _normalize_roles(raw: Any) -> Any:
    if raw is None:
        return []
    if isinstance(raw, (list, dict)):
        return raw
    return []


def _to_user_item(row: dict, is_admin: bool = False) -> BeachUserItem:
    return BeachUserItem(
        id=int(row["id"]),
        judge_id=row.get("judge_id"),
        person_id=row.get("person_id"),
        player_id=row.get("player_id"),
        full_name=row["full_name"],
        province=row.get("province"),
        city=row.get("city"),
        phone=row.get("phone"),
        email=row.get("email"),
        login=row["login"],
        roles=_parse_jsonish(row.get("roles"), []),
        badges=_parse_jsonish(row.get("badges"), {}),
        last_login_at=row.get("last_login_at"),
        app_opens=int(row.get("app_opens") or 0),
        app_version=row.get("app_version"),
        device_ids=list(row.get("device_ids") or []),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        is_admin=is_admin,
        is_active=bool(row.get("is_active", True)),
    )


async def _check_is_admin(user_id: int) -> bool:
    row = await database.fetch_one(
        select(beach_admins.c.user_id).where(beach_admins.c.user_id == user_id)
    )
    return bool(row)


def _merge_device_ids(
    existing: List[str],
    add_one: Optional[str],
    provided_list: Optional[List[str]],
) -> List[str]:
    out = list(existing or [])
    if provided_list:
        for d in provided_list:
            if d and d not in out:
                out.append(d)
    if add_one and add_one not in out:
        out.append(add_one)
    return out


async def _remove_device_from_other_users(installation_id: str, current_user_id: int) -> None:
    """Usuwa installation_id z device_ids wszystkich innych użytkowników (multi-account cleanup)."""
    rows = await database.fetch_all(
        select(beach_users.c.id, beach_users.c.device_ids).where(
            beach_users.c.id != current_user_id
        )
    )
    for row in rows:
        ids = list(row["device_ids"] or [])
        if installation_id in ids:
            ids.remove(installation_id)
            await database.execute(
                update(beach_users)
                .where(beach_users.c.id == row["id"])
                .values(device_ids=ids, updated_at=datetime.now(timezone.utc))
            )


# ─────────────────── endpoints ───────────────────

@router.get("/", response_model=BeachUsersListResponse, summary="Lista użytkowników (BEACH)")
async def list_users(
    badge: Optional[str] = Query(None),
    player_id: Optional[int] = Query(None),
    person_id: Optional[int] = Query(None),
    include_inactive: bool = Query(False),
):
    """
    Zwraca listę użytkowników.
    - `badge`             — filtruje po nazwie badge'a
    - `player_id`         — filtruje po player_id
    - `person_id`         — filtruje po person_id
    - `include_inactive`  — gdy True, zwraca też dezaktywowanych (domyślnie False)
    """
    query = select(beach_users)
    if not include_inactive:
        query = query.where(beach_users.c.is_active == True)  # noqa: E712
    if player_id is not None:
        query = query.where(beach_users.c.player_id == player_id)
    if person_id is not None:
        query = query.where(beach_users.c.person_id == person_id)
    query = query.order_by(beach_users.c.id.asc())

    rows = await database.fetch_all(query)
    result = []
    for r in rows:
        r_d = dict(r)
        if badge:
            badge_names = set(_extract_badge_names(r_d.get("badges")))
            if badge not in badge_names:
                continue
        result.append(_to_user_item(r_d))
    return BeachUsersListResponse(users=result)


@router.get("/me", response_model=BeachUserItem, summary="Pobierz zalogowanego użytkownika (BEACH)")
async def get_me(user_id: int = Depends(beach_get_current_user_id)):
    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    row_dict = dict(row)
    if not row_dict.get("is_active", True):
        raise HTTPException(403, "Konto zostało dezaktywowane")

    is_admin = await _check_is_admin(user_id)
    return _to_user_item(row_dict, is_admin=is_admin)


@router.post("/me/deactivate", response_model=dict, summary="Dezaktywuj własne konto (BEACH)")
async def deactivate_me(user_id: int = Depends(beach_get_current_user_id)):
    """
    Dezaktywuje konto zalogowanego użytkownika:
    - anonimizuje dane osobowe (full_name, login, phone, email, city, province)
    - ustawia losowe hasło blokujące
    - ustawia is_active = False
    - zachowuje: judge_id, person_id, player_id, roles, badges, app_opens, last_login_at
    """
    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    row_dict = dict(row)
    if not row_dict.get("is_active", True):
        raise HTTPException(409, "Konto jest już dezaktywowane")

    anon_login = f"dezaktywowany_{user_id}"
    random_password_hash = _hash_password(secrets.token_hex(32))

    await database.execute(
        update(beach_users)
        .where(beach_users.c.id == user_id)
        .values(
            full_name="DEZAKTYWOWANY Użytkownik",
            login=anon_login,
            phone=None,
            email=None,
            province=None,
            city=None,
            device_ids=[],
            password_hash=random_password_hash,
            is_active=False,
            updated_at=datetime.now(timezone.utc),
        )
    )

    return {"success": True}


@router.get("/{user_id}", response_model=BeachUserItem, summary="Pobierz użytkownika po ID (BEACH)")
async def get_user(user_id: int):
    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not row:
        raise HTTPException(404, "Użytkownik nie znaleziony")
    return _to_user_item(dict(row))


@router.post("/", response_model=BeachUserItem, summary="Utwórz użytkownika (BEACH)")
async def create_user(req: BeachUserCreateRequest):
    if not req.password_encrypted and not req.password:
        raise HTTPException(400, "Hasło jest wymagane")

    if req.password_encrypted:
        password_plain = _decrypt_password_from_b64(req.password_encrypted)
    else:
        password_plain = str(req.password)

    now = datetime.now(timezone.utc)
    province = _normalize_province(req.province)

    hashed = _hash_password(password_plain)
    badges = req.badges if req.badges is not None else {}
    roles = _normalize_roles(req.roles)
    device_ids = req.device_ids or []

    stmt = beach_users.insert().values(
        judge_id=req.judge_id,
        person_id=req.person_id,
        player_id=req.player_id,
        full_name=req.full_name.strip(),
        province=province,
        city=(req.city or None),
        phone=(req.phone or None),
        email=(req.email or None),
        login=req.login.strip(),
        password_hash=hashed,
        roles=roles,
        badges=badges,
        last_login_at=None,
        app_opens=0,
        app_version=req.app_version,
        device_ids=device_ids,
        is_active=True,
        created_at=now,
        updated_at=now,
    )

    try:
        new_id = await database.execute(stmt)
    except (IntegrityError, asyncpg.exceptions.UniqueViolationError) as e:
        msg = str(e).lower()
        if "login" in msg:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "LOGIN_EXISTS",
                    "field": "login",
                    "message": "Użytkownik o tym loginie już istnieje",
                },
            )
        raise HTTPException(status_code=409, detail="Unikalność naruszona") from e
    except Exception as e:
        logger.error("create_user failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(500, f"create_user failed: {e}")

    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == int(new_id)))
    return _to_user_item(dict(row))


@router.patch("/{user_id}/add-badge", response_model=BeachUserItem, summary="Dodaj badge użytkownikowi (admin)")
async def add_badge_to_user(
    user_id: int,
    badge_name: str = Query(..., description="Nazwa badge'a do dodania"),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _check_is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    row_d = dict(row)
    badges_raw = _parse_jsonish(row_d.get("badges"), {})

    if isinstance(badges_raw, dict):
        if badge_name not in badges_raw or not badges_raw[badge_name]:
            badges_raw[badge_name] = True
    elif isinstance(badges_raw, list):
        if badge_name not in badges_raw:
            badges_raw.append(badge_name)
    else:
        badges_raw = {badge_name: True}

    await database.execute(
        update(beach_users)
        .where(beach_users.c.id == user_id)
        .values(badges=badges_raw, updated_at=datetime.now(timezone.utc))
    )

    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    return _to_user_item(dict(row))


@router.patch("/{user_id}", response_model=BeachUserItem)
async def patch_user(user_id: int, req: BeachUserUpdateRequest):
    existing = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not existing:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    update_data = req.model_dump(exclude_unset=True)

    if "full_name" in update_data and update_data["full_name"] is not None:
        update_data["full_name"] = update_data["full_name"].strip()

    if "province" in update_data:
        update_data["province"] = _normalize_province(update_data["province"])

    if "phone" in update_data:
        update_data["phone"] = (update_data["phone"] or "").strip() or None

    if "email" in update_data:
        update_data["email"] = (update_data["email"] or "").strip() or None

    if "login" in update_data and update_data["login"] is not None:
        update_data["login"] = update_data["login"].strip()

    if "roles" in update_data:
        update_data["roles"] = _normalize_roles(update_data["roles"])

    if "device_ids" in update_data:
        update_data["device_ids"] = _merge_device_ids(
            list(existing["device_ids"] or []), None, update_data["device_ids"]
        )

    if "password_encrypted" in update_data or "password" in update_data:
        password_encrypted = update_data.pop("password_encrypted", None)
        password = update_data.pop("password", None)

        if password_encrypted:
            password_plain = _decrypt_password_from_b64(password_encrypted)
            update_data["password_hash"] = _hash_password(password_plain)
        elif password:
            update_data["password_hash"] = _hash_password(str(password))

    if not update_data:
        return _to_user_item(dict(existing))

    update_data["updated_at"] = datetime.now(timezone.utc)

    await database.execute(
        update(beach_users)
        .where(beach_users.c.id == user_id)
        .values(**update_data)
    )

    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    return _to_user_item(dict(row))


@router.delete("/{user_id}", response_model=dict, summary="Usuń użytkownika permanentnie (BEACH) — tylko superadmin")
async def delete_user(
    user_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    SUPER_ADMIN_ID = 2
    if current_user_id != SUPER_ADMIN_ID:
        raise HTTPException(status_code=403, detail="Brak uprawnień — tylko superadmin może usuwać konta")

    if user_id == SUPER_ADMIN_ID:
        raise HTTPException(status_code=400, detail="Nie można usunąć konta superadmina")

    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not row:
        raise HTTPException(status_code=404, detail="Użytkownik nie znaleziony")

    await database.execute(delete(beach_users).where(beach_users.c.id == user_id))
    return {"success": True}


@router.post("/login", response_model=BeachLoginResponse, summary="Logowanie użytkownika (BEACH)")
async def login_user(req: BeachLoginRequest):
    login_value = (req.login or "").strip()
    if not login_value:
        raise HTTPException(400, "Login jest wymagany")
    if not req.password_encrypted and not req.password:
        raise HTTPException(400, "Hasło jest wymagane")

    if req.password_encrypted:
        password = _decrypt_password_from_b64(req.password_encrypted)
    else:
        password = str(req.password)

    row = await database.fetch_one(
        select(beach_users).where(beach_users.c.login == login_value)
    )
    if not row:
        raise HTTPException(status_code=401, detail="Nie ma takiego użytkownika")

    row_dict = dict(row)

    # Sprawdź czy konto jest aktywne
    if not row_dict.get("is_active", True):
        raise HTTPException(status_code=403, detail="Konto zostało dezaktywowane")

    if not _verify_password(password, row_dict["password_hash"]):
        raise HTTPException(status_code=401, detail="Nieprawidłowe hasło")

    now = datetime.now(timezone.utc)

    device_ids = list(row_dict.get("device_ids") or [])
    device_ids = _merge_device_ids(device_ids, req.device_id, None)

    # Multi-account: jeśli installation_id należał do innego usera, usuń go stamtąd
    if req.device_id:
        await _remove_device_from_other_users(req.device_id, int(row_dict["id"]))

    upd_values: Dict[str, Any] = {
        "last_login_at": now,
        "app_opens": (beach_users.c.app_opens + 1),
        "device_ids": device_ids,
        "updated_at": now,
    }
    if req.app_version is not None:
        upd_values["app_version"] = req.app_version

    await database.execute(
        update(beach_users)
        .where(beach_users.c.id == int(row_dict["id"]))
        .values(**upd_values)
    )

    updated = await database.fetch_one(
        select(beach_users).where(beach_users.c.id == int(row_dict["id"]))
    )

    is_admin = await _check_is_admin(int(row_dict["id"]))

    user_model = _to_user_item(dict(updated), is_admin=is_admin)
    token = beach_create_access_token(user_model.id)

    return BeachLoginResponse(user=user_model, token=token)


class SyncDeviceRequest(BaseModel):
    installation_id: str


@router.post("/me/sync-device", response_model=dict, summary="Synchronizuj device_id zalogowanego usera (BEACH)")
async def sync_device(req: SyncDeviceRequest, user_id: int = Depends(beach_get_current_user_id)):
    """
    Sprawdza czy installation_id jest już w device_ids usera i dodaje je jeśli nie.
    Wywołuj raz na dobę z aplikacji aby utrzymać device_ids aktualne.
    """
    if not req.installation_id or len(req.installation_id) < 5:
        raise HTTPException(400, "Nieprawidłowy installation_id")

    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    row_dict = dict(row)
    if not row_dict.get("is_active", True):
        raise HTTPException(403, "Konto zostało dezaktywowane")

    device_ids = list(row_dict.get("device_ids") or [])
    if req.installation_id in device_ids:
        return {"ok": True, "updated": False}

    # Multi-account cleanup
    await _remove_device_from_other_users(req.installation_id, user_id)

    device_ids = _merge_device_ids(device_ids, req.installation_id, None)
    await database.execute(
        update(beach_users)
        .where(beach_users.c.id == user_id)
        .values(device_ids=device_ids, updated_at=datetime.now(timezone.utc))
    )
    return {"ok": True, "updated": True}
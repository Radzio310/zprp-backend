from __future__ import annotations

import asyncio
import re
import secrets
import unicodedata
from datetime import datetime, timezone
import logging
import traceback
from typing import Any, Dict, List, Optional

import asyncpg
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, update, delete, and_, func as sa_func
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from app.db import database, beach_users, beach_admins
from app.beach.notifications import notify_admins, create_notification
from app.beach.badges import (
    DEFAULT_LOVER_BADGE_NAME,
    ensure_default_lover_badge_definition,
)
from app.beach.capabilities import resolve_user_capabilities
from app.schemas import (
    BeachUserCreateRequest,
    BeachUserUpdateRequest,
    BeachPasswordResetRequest,
    BeachUserItem,
    BeachUsersListResponse,
    BeachClaimedIdentitiesRequest,
    BeachClaimedIdentitiesResponse,
    BeachLoginRequest,
    BeachLoginResponse,
)
from app.deps import (
    get_rsa_keys,
    beach_create_access_token,
    beach_get_current_user_id,
    beach_get_optional_user_id,
)
from app.beach.activity_log import log_activity, get_actor_name
from app.beach.email_verification import (
    has_approved_role,
    maybe_issue_on_register,
    is_signup_email_verified,
    consume_signup_verification,
)
from app.beach.email_config import get_email_config
from app.beach.email_normalization import normalize_email


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/beach/users", tags=["Beach: Users"])
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def _remove_diacritics(s: str) -> str:
    s = s.replace("ł", "l").replace("Ł", "L")
    normalized = unicodedata.normalize("NFD", s)
    return "".join(c for c in normalized if unicodedata.category(c) != "Mn")


def _build_login(surname: str, name: str) -> str:
    sn = re.sub(r"\s+", "_", surname.strip())
    sn = _remove_diacritics(sn).lower()
    nm = re.sub(r"\s+", "", name.strip())
    nm = _remove_diacritics(nm).lower()
    result = f"{sn}_{nm}"
    result = re.sub(r"_+", "_", result).strip("_")
    return result


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


def _add_badge_to_jsonish(badges_raw: Any, badge_name: str) -> tuple[Any, bool]:
    badges = _parse_jsonish(badges_raw, {})
    if isinstance(badges, dict):
        if badges.get(badge_name):
            return badges, False
        badges[badge_name] = True
        return badges, True
    if isinstance(badges, list):
        if badge_name in badges:
            return badges, False
        badges.append(badge_name)
        return badges, True
    return {badge_name: True}, True


async def _ensure_lover_badge_for_user(user_id: int) -> bool:
    await ensure_default_lover_badge_definition()

    row = await database.fetch_one(
        select(beach_users.c.badges).where(beach_users.c.id == user_id)
    )
    if not row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    badges, changed = _add_badge_to_jsonish(row["badges"], DEFAULT_LOVER_BADGE_NAME)
    if not changed:
        return False

    await database.execute(
        update(beach_users)
        .where(beach_users.c.id == user_id)
        .values(badges=badges, updated_at=datetime.now(timezone.utc))
    )
    return True


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


ROLE_LABELS_PL = {
    "judge": "Sędzia",
    "coach": "Trener",
    "player": "Zawodnik",
}


def _role_label_pl(role_type: Any) -> str:
    role_key = str(role_type or "").strip()
    return ROLE_LABELS_PL.get(role_key, role_key or "?")


def _to_user_item(
    row: dict,
    is_admin: bool = False,
    effective_capabilities: Optional[List[str]] = None,
    viewer_user_id: Optional[int] = None,
    hide_if_not_owner: bool = False,
) -> BeachUserItem:
    device_ids = list(row.get("device_ids") or [])
    parsed_roles = _parse_jsonish(row.get("roles"), [])
    email_verified = bool(row.get("email_verified") or False)
    requires_email_verification = (not email_verified) and not has_approved_role(parsed_roles)
    email_public = bool(row.get("email_public", True))
    # W widoku katalogu/kontaktów (``hide_if_not_owner=True``) ukrywamy e-mail
    # oznaczony jako niepubliczny — także we własnym wpisie, bo ta lista
    # odzwierciedla to, co widzą inni. Adres pozostaje widoczny dla właściciela
    # w Ustawieniach (/me, login → hide_if_not_owner=False).
    _ = viewer_user_id  # zachowane dla kompatybilności sygnatury
    email_value = row.get("email")
    if hide_if_not_owner and not email_public:
        email_value = None
    return BeachUserItem(
        id=int(row["id"]),
        judge_id=row.get("judge_id"),
        person_id=row.get("person_id"),
        player_id=row.get("player_id"),
        full_name=row["full_name"],
        province=row.get("province"),
        city=row.get("city"),
        phone=row.get("phone"),
        email=email_value,
        email_verified=email_verified,
        email_verified_at=row.get("email_verified_at"),
        email_public=email_public,
        requires_email_verification=requires_email_verification,
        login=row["login"],
        roles=parsed_roles,
        badges=_parse_jsonish(row.get("badges"), {}),
        last_login_at=row.get("last_login_at"),
        app_opens=int(row.get("app_opens") or 0),
        app_version=row.get("app_version"),
        device_ids=device_ids,
        device_infos=_device_infos_for_response(row.get("device_infos"), device_ids),
        notification_prefs=_parse_jsonish(row.get("notification_prefs"), {}),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        is_admin=is_admin,
        is_active=bool(row.get("is_active", True)),
        effective_capabilities=list(effective_capabilities or []),
    )


async def _claimed_identity_maps(
    person_ids: List[int],
    player_ids: List[int],
    exclude_user_id: Optional[int] = None,
) -> tuple[Dict[int, int], Dict[int, int]]:
    clean_person_ids = sorted({int(x) for x in (person_ids or []) if x is not None})
    clean_player_ids = sorted({int(x) for x in (player_ids or []) if x is not None})
    claimed_persons: Dict[int, int] = {}
    claimed_players: Dict[int, int] = {}

    if clean_person_ids:
        query = select(beach_users.c.id, beach_users.c.person_id).where(
            beach_users.c.is_active == True,  # noqa: E712
            beach_users.c.person_id.in_(clean_person_ids),
        )
        if exclude_user_id:
            query = query.where(beach_users.c.id != int(exclude_user_id))
        rows = await database.fetch_all(query)
        claimed_persons = {
            int(row["person_id"]): int(row["id"])
            for row in rows
            if row["person_id"] is not None
        }

    if clean_player_ids:
        query = select(beach_users.c.id, beach_users.c.player_id).where(
            beach_users.c.is_active == True,  # noqa: E712
            beach_users.c.player_id.in_(clean_player_ids),
        )
        if exclude_user_id:
            query = query.where(beach_users.c.id != int(exclude_user_id))
        rows = await database.fetch_all(query)
        claimed_players = {
            int(row["player_id"]): int(row["id"])
            for row in rows
            if row["player_id"] is not None
        }

    return claimed_persons, claimed_players


async def _ensure_identity_available(
    *,
    person_id: Optional[int] = None,
    player_id: Optional[int] = None,
    exclude_user_id: Optional[int] = None,
) -> None:
    claimed_persons, claimed_players = await _claimed_identity_maps(
        [person_id] if person_id else [],
        [player_id] if player_id else [],
        exclude_user_id=exclude_user_id,
    )
    if person_id and int(person_id) in claimed_persons:
        raise HTTPException(
            409,
            {
                "code": "IDENTITY_ALREADY_CLAIMED",
                "field": "person_id",
                "message": "Konto dla tej osoby juz istnieje.",
            },
        )
    if player_id and int(player_id) in claimed_players:
        raise HTTPException(
            409,
            {
                "code": "IDENTITY_ALREADY_CLAIMED",
                "field": "player_id",
                "message": "Konto dla tej osoby juz istnieje.",
            },
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


def _normalize_device_platform(platform: Optional[str]) -> Optional[str]:
    p = (platform or "").strip().lower()
    if p in {"ios", "android", "web"}:
        return p
    return None


def _device_infos_dict(raw: Any) -> Dict[str, Dict[str, Any]]:
    parsed = _parse_jsonish(raw, {})
    out: Dict[str, Dict[str, Any]] = {}
    if isinstance(parsed, dict):
        items = parsed.items()
    elif isinstance(parsed, list):
        items = ((x.get("installation_id"), x) for x in parsed if isinstance(x, dict))
    else:
        items = []
    for key, value in items:
        installation_id = str(
            (value or {}).get("installation_id") if isinstance(value, dict) else key
        ).strip() or str(key or "").strip()
        if not installation_id:
            continue
        info = dict(value) if isinstance(value, dict) else {}
        info["installation_id"] = installation_id
        platform = _normalize_device_platform(info.get("platform"))
        if platform:
            info["platform"] = platform
        else:
            info.pop("platform", None)
        out[installation_id] = info
    return out


def _device_infos_for_response(raw: Any, device_ids: List[str]) -> List[Dict[str, Any]]:
    infos = _device_infos_dict(raw)
    result: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for installation_id in device_ids:
        info = dict(infos.get(installation_id) or {})
        info["installation_id"] = installation_id
        result.append(info)
        seen.add(installation_id)
    for installation_id, info in infos.items():
        if installation_id not in seen:
            result.append(info)
    return result


def _merge_device_infos(
    existing: Any,
    installation_id: Optional[str],
    platform: Optional[str],
    app_version: Optional[str],
    seen_at: datetime,
) -> Dict[str, Dict[str, Any]]:
    infos = _device_infos_dict(existing)
    if not installation_id:
        return infos
    current = dict(infos.get(installation_id) or {})
    current["installation_id"] = installation_id
    normalized_platform = _normalize_device_platform(platform)
    if normalized_platform:
        current["platform"] = normalized_platform
    if app_version:
        current["app_version"] = app_version
    current["last_seen_at"] = seen_at.isoformat()
    infos[installation_id] = current
    return infos


async def _remove_device_from_other_users(installation_id: str, current_user_id: int) -> None:
    """Usuwa installation_id z device_ids wszystkich innych użytkowników (multi-account cleanup)."""
    rows = await database.fetch_all(
        select(beach_users.c.id, beach_users.c.device_ids, beach_users.c.device_infos).where(
            beach_users.c.id != current_user_id
        )
    )
    for row in rows:
        ids = list(row["device_ids"] or [])
        if installation_id in ids:
            ids.remove(installation_id)
            infos = _device_infos_dict(row["device_infos"])
            infos.pop(installation_id, None)
            await database.execute(
                update(beach_users)
                .where(beach_users.c.id == row["id"])
                .values(
                    device_ids=ids,
                    device_infos=infos,
                    updated_at=datetime.now(timezone.utc),
                )
            )


# ─────────────────── endpoints ───────────────────

@router.get("/public-stats", response_model=dict, summary="Publiczne statystyki aplikacji (bez auth)")
async def public_stats():
    """Zwraca liczbę aktywnych użytkowników — endpoint publiczny, bez autoryzacji."""
    row = await database.fetch_one(
        select(sa_func.count(beach_users.c.id)).where(beach_users.c.is_active == True)  # noqa: E712
    )
    active_users = row[0] if row else 0
    return {"active_users": active_users}


@router.get("/", response_model=BeachUsersListResponse, summary="Lista użytkowników (BEACH)")
async def list_users(
    badge: Optional[str] = Query(None),
    player_id: Optional[int] = Query(None),
    person_id: Optional[int] = Query(None),
    include_inactive: bool = Query(False),
    viewer_user_id: Optional[int] = Depends(beach_get_optional_user_id),
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
        result.append(
            _to_user_item(r_d, viewer_user_id=viewer_user_id, hide_if_not_owner=True)
        )
    return BeachUsersListResponse(users=result)


@router.post(
    "/claimed-identities",
    response_model=BeachClaimedIdentitiesResponse,
    summary="Sprawdz zajete identyfikatory osob w aplikacji BEACH",
)
async def claimed_identities(req: BeachClaimedIdentitiesRequest):
    persons, players = await _claimed_identity_maps(
        req.person_ids,
        req.player_ids,
        exclude_user_id=req.exclude_user_id,
    )
    return BeachClaimedIdentitiesResponse(persons=persons, players=players)


@router.get("/me", response_model=BeachUserItem, summary="Pobierz zalogowanego użytkownika (BEACH)")
async def get_me(user_id: int = Depends(beach_get_current_user_id)):
    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    row_dict = dict(row)
    if not row_dict.get("is_active", True):
        raise HTTPException(403, "Konto zostało dezaktywowane")

    if await _ensure_lover_badge_for_user(user_id):
        row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
        row_dict = dict(row)

    is_admin = await _check_is_admin(user_id)
    caps = sorted(await resolve_user_capabilities(row_dict.get("badges")))
    return _to_user_item(row_dict, is_admin=is_admin, effective_capabilities=caps)


@router.post("/me/ensure-lover-badge", response_model=BeachUserItem, summary="Dodaj domyslny badge Beach Handball Lover, jesli go brakuje")
async def ensure_me_lover_badge(user_id: int = Depends(beach_get_current_user_id)):
    await _ensure_lover_badge_for_user(user_id)
    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not row:
        raise HTTPException(404, "Uzytkownik nie znaleziony")
    is_admin = await _check_is_admin(user_id)
    caps = sorted(await resolve_user_capabilities(dict(row).get("badges")))
    return _to_user_item(dict(row), is_admin=is_admin, effective_capabilities=caps)


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

    # ── Activity log ──
    await log_activity(
        area="user",
        action="user.deactivated",
        actor_user_id=user_id,
        actor_name=row_dict.get("full_name", ""),
        target_id=str(user_id),
        target_label=row_dict.get("full_name", ""),
    )

    # ── Notify admins ──
    import asyncio as _asyncio
    _asyncio.ensure_future(notify_admins(
        notif_type="admin_user_deactivated",
        title="🚫 Użytkownik dezaktywował konto",
        body=f"{row_dict.get('full_name', 'Użytkownik')} (ID: {user_id}) dezaktywował swoje konto.",
        data={"user_id": user_id},
    ))

    return {"success": True}


@router.get("/{user_id}", response_model=BeachUserItem, summary="Pobierz użytkownika po ID (BEACH)")
async def get_user(
    user_id: int,
    viewer_user_id: Optional[int] = Depends(beach_get_optional_user_id),
):
    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not row:
        raise HTTPException(404, "Użytkownik nie znaleziony")
    return _to_user_item(dict(row), viewer_user_id=viewer_user_id, hide_if_not_owner=True)


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
    await ensure_default_lover_badge_definition()
    badges = req.badges if req.badges is not None else {}
    badges, _ = _add_badge_to_jsonish(badges, DEFAULT_LOVER_BADGE_NAME)
    roles = _normalize_roles(req.roles)
    device_ids = req.device_ids or []

    await _ensure_identity_available(
        person_id=req.person_id,
        player_id=req.player_id,
    )

    # ── E-mail: normalizacja + unikalność (case-insensitive) ──
    email_clean = (req.email or "").strip() or None
    email_norm = normalize_email(email_clean) if email_clean else None
    if email_norm:
        existing_email = await database.fetch_one(
            select(beach_users.c.id).where(beach_users.c.email_normalized == email_norm)
        )
        if existing_email:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "EMAIL_EXISTS",
                    "field": "email",
                    "message": "Ten adres e-mail jest już używany przez inne konto.",
                },
            )

    # ── Bramka weryfikacji e-mail dla kont BEZ zatwierdzonej roli ──
    # Takie konto musi podać e-mail i potwierdzić go kodem PRZED utworzeniem.
    # Konta z zatwierdzoną rolą (zawodnik/trener/sędzia) są zwolnione ("luz").
    has_role_approved = has_approved_role(roles)
    email_pre_verified = False
    if not has_role_approved:
        if not email_norm:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "EMAIL_REQUIRED",
                    "field": "email",
                    "message": "Adres e-mail jest wymagany do utworzenia konta.",
                },
            )
        if not await is_signup_email_verified(email_norm):
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "EMAIL_NOT_VERIFIED",
                    "field": "email",
                    "message": "Potwierdź adres e-mail kodem, aby utworzyć konto.",
                },
            )
        email_pre_verified = True

    stmt = beach_users.insert().values(
        judge_id=req.judge_id,
        person_id=req.person_id,
        player_id=req.player_id,
        full_name=req.full_name.strip(),
        province=province,
        city=(req.city or None),
        phone=(req.phone or None),
        email=email_clean,
        email_normalized=email_norm,
        email_verified=email_pre_verified,
        email_verified_at=(now if email_pre_verified else None),
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
    user_item = _to_user_item(dict(row))

    import asyncio
    asyncio.ensure_future(notify_admins(
        notif_type="admin_new_user",
        title="👤 Nowy użytkownik",
        body=f"✅ {user_item.full_name} założył konto w aplikacji.",
        data={"user_id": int(new_id)},
    ))

    # ── Activity log ──
    await log_activity(
        area="user",
        action="user.registered",
        actor_user_id=int(new_id),
        actor_name=req.full_name.strip(),
        target_id=str(new_id),
        target_label=req.full_name.strip(),
        details={"roles": roles, "province": province},
    )

    # ── Self-verification detection ──
    if isinstance(roles, list):
        for role in roles:
            if isinstance(role, dict) and role.get("verified") == "approved":
                import asyncio as _asyncio
                _asyncio.ensure_future(notify_admins(
                    notif_type="admin_user_self_verified",
                    title="✅ Automatyczna weryfikacja",
                    body=f"{req.full_name.strip()} — rola {_role_label_pl(role.get('type'))} zweryfikowana automatycznie przy rejestracji.",
                    data={"user_id": int(new_id)},
                ))
                break

    # ── Weryfikacja e-mail ──
    # Konta z zatwierdzoną rolą (zawodnik/trener/sędzia) są zwolnione ("luz").
    # Pozostałe — jeśli podały e-mail — dostają kod od razu (best-effort: brak
    # dostarczenia nie blokuje rejestracji, użytkownik dokończy przez resend
    # lub modal w aplikacji). Ustawiany jest też 90-dniowy termin.
    try:
        # Zużyj pre-weryfikację (kont bez roli) — jednorazowa.
        if email_pre_verified and email_norm:
            await consume_signup_verification(email_norm)
        # Konta z rolą bez e-maila/weryfikacji: ustaw 90-dniowy termin (gdy dotyczy).
        await maybe_issue_on_register(int(new_id), get_email_config().grace_days)
        # Odśwież flagi (email_verified / deadline mogły się zmienić).
        refreshed = await database.fetch_one(select(beach_users).where(beach_users.c.id == int(new_id)))
        if refreshed:
            user_item = _to_user_item(dict(refreshed))
    except Exception:
        logger.exception("create_user: post-registration email step failed (non-fatal)")

    return user_item


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

    # ── Activity log ──
    await log_activity(
        area="user",
        action="user.badge_added",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(user_id),
        target_label=dict(row).get("full_name", ""),
        details={"badge_name": badge_name},
    )

    return _to_user_item(dict(row))


@router.patch("/{user_id}/remove-badge", response_model=BeachUserItem, summary="Usuń badge użytkownikowi (admin lub własny badge)")
async def remove_badge_from_user(
    user_id: int,
    badge_name: str = Query(..., description="Nazwa badge'a do usunięcia"),
    current_user_id: int = Depends(beach_get_current_user_id),
):
    # Allow self-removal OR admin removal
    if current_user_id != user_id and not await _check_is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    row_d = dict(row)
    badges_raw = _parse_jsonish(row_d.get("badges"), {})

    if isinstance(badges_raw, dict):
        badges_raw.pop(badge_name, None)
    elif isinstance(badges_raw, list):
        badges_raw = [b for b in badges_raw if b is not None and str(b) != badge_name]

    await database.execute(
        update(beach_users)
        .where(beach_users.c.id == user_id)
        .values(badges=badges_raw, updated_at=datetime.now(timezone.utc))
    )

    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))

    # ── Activity log ──
    await log_activity(
        area="user",
        action="user.badge_removed",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(user_id),
        target_label=dict(row).get("full_name", ""),
        details={"badge_name": badge_name},
    )

    return _to_user_item(dict(row))


# ─────────────── Helper: sprawdź czy kolumna istnieje w beach_users ───────────────

def _users_table_has_column(col_name: str) -> bool:
    return col_name in getattr(beach_users.c, "keys", lambda: [])()


# ─────────────── Default Squad endpoints ───────────────

class DefaultSquadUpdateRequest(BaseModel):
    team_id: int
    default_players: Optional[List[int]] = None
    default_companions: Optional[List[int]] = None
    default_companion_roles: Optional[Dict[str, str]] = None  # personId(str) → "A"|"B"|"C"|"D"
    protocol_players: Optional[List[int]] = None


@router.get("/{user_id}/default-squad", summary="Pobierz domyślny skład użytkownika")
async def get_user_default_squad(
    user_id: int,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if current_user_id != user_id and not await _check_is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    if not _users_table_has_column("default_squad_json"):
        return {"teams": {}}

    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    data = _parse_jsonish(dict(row).get("default_squad_json"), {})
    if not isinstance(data, dict):
        data = {}
    return {"teams": data}


@router.patch("/{user_id}/default-squad", summary="Zaktualizuj domyślny skład użytkownika")
async def update_user_default_squad(
    user_id: int,
    req: DefaultSquadUpdateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if current_user_id != user_id and not await _check_is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    if not _users_table_has_column("default_squad_json"):
        return {"teams": {}}

    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    current_data = _parse_jsonish(dict(row).get("default_squad_json"), {})
    if not isinstance(current_data, dict):
        current_data = {}

    team_key = str(req.team_id)
    existing_entry = current_data.get(team_key, {})
    if not isinstance(existing_entry, dict):
        existing_entry = {}

    if req.default_players is not None:
        existing_entry["default_players"] = req.default_players
    if req.default_companions is not None:
        existing_entry["default_companions"] = req.default_companions
    if req.default_companion_roles is not None:
        existing_entry["default_companion_roles"] = req.default_companion_roles
    if req.protocol_players is not None:
        existing_entry["protocol_players"] = req.protocol_players

    current_data[team_key] = existing_entry

    await database.execute(
        update(beach_users)
        .where(beach_users.c.id == user_id)
        .values(default_squad_json=current_data, updated_at=datetime.now(timezone.utc))
    )

    return {"teams": current_data}


def _password_hash_from_reset_request(req: BeachPasswordResetRequest) -> str:
    if not req.password_encrypted and not req.password:
        raise HTTPException(400, "Hasło jest wymagane")

    if req.password_encrypted:
        password_plain = _decrypt_password_from_b64(req.password_encrypted)
    else:
        password_plain = str(req.password)

    password_plain = password_plain.strip()
    if len(password_plain) < 8:
        raise HTTPException(400, "Hasło musi mieć co najmniej 8 znaków")

    return _hash_password(password_plain)


async def _set_user_password(
    user_id: int,
    req: BeachPasswordResetRequest,
    *,
    actor_user_id: int,
    admin_reset: bool,
) -> BeachUserItem:
    existing = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not existing:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    password_hash = _password_hash_from_reset_request(req)
    await database.execute(
        update(beach_users)
        .where(beach_users.c.id == user_id)
        .values(password_hash=password_hash, updated_at=datetime.now(timezone.utc))
    )

    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    row_dict = dict(row)
    await log_activity(
        area="user",
        action="user.password_reset" if admin_reset else "user.password_changed",
        actor_user_id=actor_user_id,
        actor_name=await get_actor_name(actor_user_id),
        target_id=str(user_id),
        target_label=row_dict.get("full_name", ""),
    )
    return _to_user_item(row_dict)


@router.patch("/me/password", response_model=BeachUserItem, summary="Zmień własne hasło użytkownika Beach")
async def change_my_password(
    req: BeachPasswordResetRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    return await _set_user_password(
        current_user_id,
        req,
        actor_user_id=current_user_id,
        admin_reset=False,
    )


@router.patch("/{user_id}/password", response_model=BeachUserItem, summary="Reset hasła użytkownika Beach (admin)")
async def admin_reset_user_password(
    user_id: int,
    req: BeachPasswordResetRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _check_is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")
    return await _set_user_password(
        user_id,
        req,
        actor_user_id=current_user_id,
        admin_reset=True,
    )


@router.patch("/{user_id}", response_model=BeachUserItem)
async def patch_user(
    user_id: int,
    req: BeachUserUpdateRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if current_user_id != user_id and not await _check_is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

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
        new_email = (update_data["email"] or "").strip() or None
        update_data["email"] = new_email
        new_norm = normalize_email(new_email) if new_email else None
        old_norm = dict(existing).get("email_normalized")
        # Zmiana adresu (po normalizacji) → unikalność + reset weryfikacji.
        if new_norm != old_norm:
            if new_norm:
                clash = await database.fetch_one(
                    select(beach_users.c.id).where(
                        and_(
                            beach_users.c.email_normalized == new_norm,
                            beach_users.c.id != user_id,
                        )
                    )
                )
                if clash:
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "code": "EMAIL_EXISTS",
                            "field": "email",
                            "message": "Ten adres e-mail jest już używany przez inne konto.",
                        },
                    )
            update_data["email_normalized"] = new_norm
            update_data["email_verified"] = False
            update_data["email_verified_at"] = None

    if "login" in update_data and update_data["login"] is not None:
        update_data["login"] = update_data["login"].strip()

    if "roles" in update_data:
        update_data["roles"] = _normalize_roles(update_data["roles"])

    if "person_id" in update_data and update_data["person_id"]:
        await _ensure_identity_available(
            person_id=int(update_data["person_id"]),
            exclude_user_id=user_id,
        )

    if "player_id" in update_data and update_data["player_id"]:
        await _ensure_identity_available(
            player_id=int(update_data["player_id"]),
            exclude_user_id=user_id,
        )

    if "device_ids" in update_data:
        update_data["device_ids"] = _merge_device_ids(
            list(existing["device_ids"] or []), None, update_data["device_ids"]
        )

    if "notification_prefs" in update_data and update_data["notification_prefs"] is not None:
        # Merge with existing prefs (partial update)
        current_prefs = _parse_jsonish(dict(existing).get("notification_prefs"), {})
        if isinstance(current_prefs, dict):
            current_prefs.update(update_data["notification_prefs"])
            update_data["notification_prefs"] = current_prefs

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

    # ── Activity log ──
    changed = {k: v for k, v in update_data.items() if k not in ("updated_at", "password_hash")}
    await log_activity(
        area="user",
        action="user.updated",
        target_id=str(user_id),
        target_label=dict(row).get("full_name", ""),
        details={"changed_fields": list(changed.keys())} if changed else None,
    )

    # ── Self-verification detection ──
    if "roles" in update_data:
        old_roles = _parse_jsonish(dict(existing).get("roles"), [])
        new_roles = update_data["roles"]
        if isinstance(old_roles, list) and isinstance(new_roles, list):
            old_approved = {(r.get("type"), r.get("team_id")) for r in old_roles if isinstance(r, dict) and r.get("verified") == "approved"}
            for r in new_roles:
                if isinstance(r, dict) and r.get("verified") == "approved":
                    key = (r.get("type"), r.get("team_id"))
                    if key not in old_approved:
                        import asyncio as _asyncio
                        user_name = dict(row).get("full_name", f"user#{user_id}")
                        _asyncio.ensure_future(notify_admins(
                            notif_type="admin_user_self_verified",
                            title="✅ Automatyczna weryfikacja",
                            body=f"{user_name} — rola {_role_label_pl(r.get('type'))} zweryfikowana automatycznie.",
                            data={"user_id": user_id},
                        ))
                        break

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

    deleted_name = dict(row).get("full_name", "")
    await database.execute(delete(beach_users).where(beach_users.c.id == user_id))

    # ── Activity log ──
    await log_activity(
        area="user",
        action="user.deleted",
        actor_user_id=current_user_id,
        actor_name=await get_actor_name(current_user_id),
        target_id=str(user_id),
        target_label=deleted_name,
    )

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
    device_infos = _merge_device_infos(
        row_dict.get("device_infos"),
        req.device_id,
        req.device_platform,
        req.app_version,
        now,
    )

    # Multi-account: jeśli installation_id należał do innego usera, usuń go stamtąd
    if req.device_id:
        await _remove_device_from_other_users(req.device_id, int(row_dict["id"]))

    upd_values: Dict[str, Any] = {
        "last_login_at": now,
        "app_opens": (beach_users.c.app_opens + 1),
        "device_ids": device_ids,
        "device_infos": device_infos,
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
    if await _ensure_lover_badge_for_user(int(row_dict["id"])):
        updated = await database.fetch_one(
            select(beach_users).where(beach_users.c.id == int(row_dict["id"]))
        )

    is_admin = await _check_is_admin(int(row_dict["id"]))

    caps = sorted(await resolve_user_capabilities(dict(updated).get("badges")))
    user_model = _to_user_item(dict(updated), is_admin=is_admin, effective_capabilities=caps)
    token = beach_create_access_token(user_model.id)

    return BeachLoginResponse(user=user_model, token=token)


class SyncDeviceRequest(BaseModel):
    installation_id: str
    platform: Optional[str] = None
    app_version: Optional[str] = None


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

    now = datetime.now(timezone.utc)
    device_ids = list(row_dict.get("device_ids") or [])
    existing_infos = _device_infos_dict(row_dict.get("device_infos"))
    existing_info = existing_infos.get(req.installation_id) or {}
    platform = _normalize_device_platform(req.platform)
    needs_info_update = (
        bool(platform and existing_info.get("platform") != platform)
        or bool(req.app_version and existing_info.get("app_version") != req.app_version)
        or req.installation_id not in existing_infos
    )
    if req.installation_id in device_ids and not needs_info_update:
        return {"ok": True, "updated": False}

    # Multi-account cleanup
    await _remove_device_from_other_users(req.installation_id, user_id)

    device_ids = _merge_device_ids(device_ids, req.installation_id, None)
    device_infos = _merge_device_infos(
        row_dict.get("device_infos"),
        req.installation_id,
        req.platform,
        req.app_version,
        now,
    )
    await database.execute(
        update(beach_users)
        .where(beach_users.c.id == user_id)
        .values(device_ids=device_ids, device_infos=device_infos, updated_at=now)
    )
    return {"ok": True, "updated": True}


class AdminRenameRequest(BaseModel):
    surname: str
    first_name: str


@router.patch("/{user_id}/admin-name", response_model=BeachUserItem, summary="Zmień imię i nazwisko użytkownika (admin)")
async def admin_rename_user(
    user_id: int,
    req: AdminRenameRequest,
    current_user_id: int = Depends(beach_get_current_user_id),
):
    if not await _check_is_admin(current_user_id):
        raise HTTPException(403, "Brak uprawnień")

    surname = req.surname.strip().upper()
    first_name = req.first_name.strip()

    if not surname or not first_name:
        raise HTTPException(400, "Nazwisko i imię są wymagane")

    full_name = f"{surname} {first_name}"
    new_login = _build_login(surname, first_name)

    if not new_login:
        raise HTTPException(400, "Nie można wygenerować loginu z podanych danych")

    row = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    if not row:
        raise HTTPException(404, "Użytkownik nie znaleziony")

    old_dict = dict(row)
    old_full_name = old_dict.get("full_name", "")
    old_login = old_dict.get("login", "")

    if new_login != old_login:
        conflict = await database.fetch_one(
            select(beach_users.c.id).where(
                (beach_users.c.login == new_login) & (beach_users.c.id != user_id)
            )
        )
        if conflict:
            raise HTTPException(409, f"Login '{new_login}' jest już zajęty przez innego użytkownika")

    now = datetime.now(timezone.utc)
    await database.execute(
        update(beach_users)
        .where(beach_users.c.id == user_id)
        .values(full_name=full_name, login=new_login, updated_at=now)
    )

    admin_name = await get_actor_name(current_user_id)
    asyncio.ensure_future(create_notification(
        notif_type="admin_name_changed",
        title="Dane zaktualizowane przez admina",
        body=f"Admin zmienił Twoje dane: {old_full_name} → {full_name}. Nowy login: {new_login}",
        data={"old_full_name": old_full_name, "new_full_name": full_name, "old_login": old_login, "new_login": new_login},
        target_user_ids=[user_id],
    ))

    await log_activity(
        area="user",
        action="user.admin_name_changed",
        actor_user_id=current_user_id,
        actor_name=admin_name,
        target_id=str(user_id),
        target_label=old_full_name,
        details={"old_full_name": old_full_name, "new_full_name": full_name, "old_login": old_login, "new_login": new_login},
    )

    updated = await database.fetch_one(select(beach_users).where(beach_users.c.id == user_id))
    return _to_user_item(dict(updated))

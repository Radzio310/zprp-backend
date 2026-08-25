# app/proel_users/users.py
#
# Konta ProEl: rejestracja, logowanie, profil, urządzenia + API admina.
#
# Wzorzec 1:1 z app/beach/users.py (rejestracja :598-750, login :1228-1314) —
# kopiujemy zachowanie, NIE importujemy beachowego modułu (ciągnie app.db przy
# imporcie i sprzęga światy). Prywatne helpery są skopiowane świadomie: to
# kilkanaście linii, a wspólna zależność oznaczałaby, że refaktor Beacha może
# złamać ProEla w niedzielę wieczorem.
#
# Hasła: argon2; transport hasła: RSA-OAEP(SHA-256) tym samym keypairem co
# reszta backendu (aplikacja szyfruje kluczem publicznym z utils/public_key.ts).
# Admin: ta sama lista co panel BAZA (app.proel_auth.is_admin) — panel admina
# w aplikacji uwierzytelnia się nagłówkami aktora ProEl, nie tokenem konta.

from __future__ import annotations

import logging
import re
import secrets
import traceback
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, func as sa_func, or_, select, update
from passlib.context import CryptContext
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from app.beach.email_normalization import normalize_email
from app.deps import get_rsa_keys
# proel_auth importuje bazę leniwie — bezpieczny na poziomie modułu.
from app.proel_auth import proel_actor
from app.proel_users.email_flows import (
    consume_signup_verification,
    is_signup_email_verified,
    maybe_issue_on_register,
)
from app.proel_users.tokens import create_access_token, proel_get_current_user_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/proel/users", tags=["ProEl: Users"])
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def _db():
    """Leniwy import bazy — app/db.py odpala create_all przy imporcie (SQLite
    w testach się na tym wywraca); wzorzec z app/results.py."""
    from app.db import database, proel_users

    return database, proel_users


# ─────────────────────────── helpery (kopiowane z beach) ───────────────────────────

def _remove_diacritics(s: str) -> str:
    s = s.replace("ł", "l").replace("Ł", "L")
    normalized = unicodedata.normalize("NFD", s)
    return "".join(c for c in normalized if unicodedata.category(c) != "Mn")


def build_login(surname: str, name: str) -> str:
    """`nazwisko_imie` bez diakrytyków — ten sam generator co w Beach, żeby
    użytkownik obu aplikacji dostawał loginy w jednym stylu."""
    sn = re.sub(r"\s+", "_", surname.strip())
    sn = _remove_diacritics(sn).lower()
    nm = re.sub(r"\s+", "", name.strip())
    nm = _remove_diacritics(nm).lower()
    result = f"{sn}_{nm}"
    return re.sub(r"_+", "_", result).strip("_")


def _hash_password(password: str) -> str:
    return pwd_context.hash(password)


def _verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def _normalize_province(p: Optional[str]) -> Optional[str]:
    if p is None:
        return None
    s = (p or "").strip().upper()
    return s or None


def _decrypt_password_from_b64(password_encrypted_b64: str) -> str:
    from base64 import b64decode

    private_key, _ = get_rsa_keys()
    try:
        encrypted = b64decode(password_encrypted_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Niepoprawny format zaszyfrowanego hasła")
    try:
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        return decrypted.decode("utf-8")
    except Exception:
        raise HTTPException(status_code=400, detail="Nie udało się odszyfrować hasła")


def _resolve_password(password: Optional[str], password_encrypted: Optional[str]) -> str:
    if not password_encrypted and not password:
        raise HTTPException(400, "Hasło jest wymagane")
    plain = _decrypt_password_from_b64(password_encrypted) if password_encrypted else str(password)
    # Klawiatury mobilne doklejają spacje po podpowiedziach — spójnie z Beach
    # hasło nigdy nie zaczyna się ani nie kończy białym znakiem.
    return plain.strip()


def _merge_device_ids(existing: List[str], add_one: Optional[str]) -> List[str]:
    out = list(existing or [])
    if add_one and add_one not in out:
        out.append(add_one)
    return out


def _device_infos_dict(existing: Any) -> Dict[str, Dict[str, Any]]:
    if isinstance(existing, dict):
        return {str(k): dict(v) if isinstance(v, dict) else {} for k, v in existing.items()}
    return {}


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
    if (platform or "").strip():
        current["platform"] = platform.strip().lower()
    if app_version:
        current["app_version"] = app_version
    current["last_seen_at"] = seen_at.isoformat()
    infos[installation_id] = current
    return infos


async def _remove_device_from_other_users(installation_id: str, current_user_id: int) -> None:
    """Multi-account na jednym telefonie: urządzenie należy do OSTATNIO
    zalogowanego konta.

    UWAGA NA OPERATOR. `device_ids.contains([...])` NIE jest tu operatorem
    tablicowym: `ARRAY` z rdzenia SQLAlchemy (`from sqlalchemy import ARRAY`)
    nie ma własnego `contains`, więc wywołanie schodzi do wersji TEKSTOWEJ
    (LIKE) i wywraca się na liście jeszcze przed dotknięciem bazy - `TypeError`
    w środku silnika, czyli 500 na logowaniu. Ponieważ logowanie jest ostatnim
    krokiem ZAKŁADANIA KONTA i ostatnim krokiem RESETU HASŁA, jeden ten operator
    przewracał trzy różne rzeczy naraz.

    `any()` rdzeń ARRAY zna i kompiluje do `%(param)s = ANY (device_ids)`.
    Alternatywą byłoby przejście po wszystkich kontach w Pythonie (tak robi
    Beach), ale to skan całej tabeli przy każdym logowaniu.

    Czyścimy też `device_infos`: telefon zniknięty z listy urządzeń, ale
    zostawiony w opisach, dalej wisiałby w panelu admina jako aktywny.
    """
    database, users_t = _db()
    rows = await database.fetch_all(
        select(users_t.c.id, users_t.c.device_ids, users_t.c.device_infos).where(
            and_(users_t.c.id != current_user_id, users_t.c.device_ids.any(installation_id))
        )
    )
    now = datetime.now(timezone.utc)
    for row in rows:
        ids = [d for d in (row["device_ids"] or []) if d != installation_id]
        infos = _device_infos_dict(row["device_infos"])
        infos.pop(installation_id, None)
        await database.execute(
            update(users_t)
            .where(users_t.c.id == row["id"])
            .values(device_ids=ids, device_infos=infos, updated_at=now)
        )


# ─────────────────────────── schematy ───────────────────────────

class ProelUserItem(BaseModel):
    id: int
    judge_id: Optional[str] = None
    full_name: str
    province: Optional[str] = None
    city: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    email_verified: bool = False
    email_verified_at: Optional[datetime] = None
    requires_email_verification: bool = False
    email_verification_deadline: Optional[datetime] = None
    login: str
    last_login_at: Optional[datetime] = None
    app_opens: int = 0
    app_version: Optional[str] = None
    device_ids: List[str] = []
    is_active: bool = True
    must_change_password: bool = False
    created_at: Optional[datetime] = None


class ProelUserCreateRequest(BaseModel):
    full_name: str = Field(..., min_length=1, max_length=220)  # "NAZWISKO Imię"
    province: Optional[str] = None
    city: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    judge_id: Optional[str] = None
    login: str = Field(..., min_length=1, max_length=120)
    password: Optional[str] = None
    password_encrypted: Optional[str] = None
    device_id: Optional[str] = None
    device_platform: Optional[str] = None
    app_version: Optional[str] = None


class ProelLoginRequest(BaseModel):
    login: str
    password: Optional[str] = None
    password_encrypted: Optional[str] = None
    device_id: Optional[str] = None
    device_platform: Optional[str] = None
    app_version: Optional[str] = None


class ProelLoginResponse(BaseModel):
    user: ProelUserItem
    token: str


class ProelUserUpdateRequest(BaseModel):
    province: Optional[str] = None
    city: Optional[str] = None
    phone: Optional[str] = None
    judge_id: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    old_password: Optional[str] = None
    old_password_encrypted: Optional[str] = None
    new_password: Optional[str] = None
    new_password_encrypted: Optional[str] = None


class SyncDeviceRequest(BaseModel):
    installation_id: str
    platform: Optional[str] = None
    app_version: Optional[str] = None


def _to_user_item(row: dict) -> ProelUserItem:
    email_verified = bool(row.get("email_verified") or False)
    return ProelUserItem(
        id=int(row["id"]),
        judge_id=row.get("judge_id"),
        full_name=row["full_name"],
        province=row.get("province"),
        city=row.get("city"),
        phone=row.get("phone"),
        email=row.get("email"),
        email_verified=email_verified,
        email_verified_at=row.get("email_verified_at"),
        # W ProElu nie ma ról zwalniających — bramką jest sam stan adresu.
        requires_email_verification=(not email_verified) and bool((row.get("email") or "").strip()),
        email_verification_deadline=row.get("email_verification_deadline"),
        login=row["login"],
        last_login_at=row.get("last_login_at"),
        app_opens=int(row.get("app_opens") or 0),
        app_version=row.get("app_version"),
        device_ids=list(row.get("device_ids") or []),
        is_active=bool(row.get("is_active", True)),
        must_change_password=bool(row.get("must_change_password") or False),
        created_at=row.get("created_at"),
    )


# ─────────────────────────── rejestracja / logowanie ───────────────────────────

@router.post("/", response_model=ProelUserItem, summary="Utwórz konto ProEl")
async def create_user(req: ProelUserCreateRequest):
    database, users_t = _db()
    password_plain = _resolve_password(req.password, req.password_encrypted)

    now = datetime.now(timezone.utc)
    email_clean = (req.email or "").strip() or None
    email_norm = normalize_email(email_clean) if email_clean else None

    if email_norm:
        existing_email = await database.fetch_one(
            select(users_t.c.id).where(users_t.c.email_normalized == email_norm)
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

    # E-mail potwierdzony kodem PRZED rejestracją → konto rodzi się
    # zweryfikowane; pre-weryfikację zużywamy niżej (jednorazowa).
    email_pre_verified = bool(email_norm) and await is_signup_email_verified(email_norm)

    stmt = users_t.insert().values(
        judge_id=(req.judge_id or "").strip() or None,
        full_name=req.full_name.strip(),
        province=_normalize_province(req.province),
        city=(req.city or None),
        phone=(req.phone or None),
        email=email_clean,
        email_normalized=email_norm,
        email_verified=email_pre_verified,
        email_verified_at=(now if email_pre_verified else None),
        login=req.login.strip(),
        password_hash=_hash_password(password_plain),
        last_login_at=None,
        app_opens=0,
        app_version=req.app_version,
        device_ids=[req.device_id] if req.device_id else [],
        device_infos=_merge_device_infos({}, req.device_id, req.device_platform, req.app_version, now),
        is_active=True,
        created_at=now,
        updated_at=now,
    )

    try:
        new_id = await database.execute(stmt)
    except Exception as e:  # IntegrityError / UniqueViolation — zależnie od drivera
        msg = str(e).lower()
        if "login" in msg and ("unique" in msg or "duplicate" in msg or "violat" in msg):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "LOGIN_EXISTS",
                    "field": "login",
                    "message": "Użytkownik o tym loginie już istnieje",
                },
            )
        logger.error("proel create_user failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(500, "Nie udało się utworzyć konta")

    try:
        if email_pre_verified and email_norm:
            await consume_signup_verification(email_norm)
        from app.beach.email_config import get_email_config

        await maybe_issue_on_register(int(new_id), get_email_config().grace_days)
    except Exception:
        logger.exception("proel create_user: post-registration email step failed (non-fatal)")

    row = await database.fetch_one(select(users_t).where(users_t.c.id == int(new_id)))
    logger.info("proel user_registered id=%s login=%s", int(new_id), req.login.strip())
    return _to_user_item(dict(row))


@router.post("/login", response_model=ProelLoginResponse, summary="Logowanie kontem ProEl")
async def login_user(req: ProelLoginRequest):
    database, users_t = _db()
    login_value = (req.login or "").strip()
    if not login_value:
        raise HTTPException(400, "Login jest wymagany")
    password = _resolve_password(req.password, req.password_encrypted)

    row = await database.fetch_one(select(users_t).where(users_t.c.login == login_value))
    # Logowanie adresem e-mail — wyłącznie zweryfikowanym (bez weryfikacji nie
    # wiemy, że adres należy do tej osoby).
    if not row and "@" in login_value:
        row = await database.fetch_one(
            select(users_t).where(
                sa_func.lower(users_t.c.email) == login_value.lower(),
                users_t.c.email_verified == True,  # noqa: E712
            )
        )
    if not row:
        raise HTTPException(status_code=401, detail="Nie ma takiego użytkownika")

    u = dict(row)
    if not u.get("is_active", True):
        raise HTTPException(status_code=403, detail="Konto zostało dezaktywowane")
    if not _verify_password(password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="Nieprawidłowe hasło")

    now = datetime.now(timezone.utc)
    upd: Dict[str, Any] = {
        "last_login_at": now,
        "app_opens": (users_t.c.app_opens + 1),
        "device_ids": _merge_device_ids(list(u.get("device_ids") or []), req.device_id),
        "device_infos": _merge_device_infos(u.get("device_infos"), req.device_id, req.device_platform, req.app_version, now),
        "updated_at": now,
    }
    if req.app_version is not None:
        upd["app_version"] = req.app_version
    await database.execute(update(users_t).where(users_t.c.id == int(u["id"])).values(**upd))

    if req.device_id:
        await _remove_device_from_other_users(req.device_id, int(u["id"]))

    refreshed = await database.fetch_one(select(users_t).where(users_t.c.id == int(u["id"])))
    user_model = _to_user_item(dict(refreshed))
    return ProelLoginResponse(user=user_model, token=create_access_token(user_model.id))


# ─────────────────────────── profil (zalogowany) ───────────────────────────

async def _fetch_me(user_id: int) -> dict:
    database, users_t = _db()
    row = await database.fetch_one(select(users_t).where(users_t.c.id == user_id))
    if not row:
        raise HTTPException(404, "Użytkownik nie znaleziony")
    return dict(row)


@router.get("/me", response_model=ProelUserItem, summary="Moje konto ProEl")
async def get_me(user_id: int = Depends(proel_get_current_user_id)):
    return _to_user_item(await _fetch_me(user_id))


@router.patch("/me", response_model=ProelUserItem, summary="Aktualizacja własnych danych")
async def patch_me(
    req: ProelUserUpdateRequest,
    user_id: int = Depends(proel_get_current_user_id),
):
    database, users_t = _db()
    await _fetch_me(user_id)
    values: Dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
    if req.province is not None:
        values["province"] = _normalize_province(req.province)
    if req.city is not None:
        values["city"] = req.city.strip() or None
    if req.phone is not None:
        values["phone"] = req.phone.strip() or None
    if req.judge_id is not None:
        values["judge_id"] = req.judge_id.strip() or None
    await database.execute(update(users_t).where(users_t.c.id == user_id).values(**values))
    return _to_user_item(await _fetch_me(user_id))


@router.post("/me/change-password", summary="Zmiana hasła (czyści hasło tymczasowe)")
async def change_password(
    req: ChangePasswordRequest,
    user_id: int = Depends(proel_get_current_user_id),
):
    database, users_t = _db()
    u = await _fetch_me(user_id)
    new_password = _resolve_password(req.new_password, req.new_password_encrypted)
    if len(new_password) < 8:
        raise HTTPException(400, detail={"code": "WEAK_PASSWORD", "message": "Hasło musi mieć min. 8 znaków."})

    # Stare hasło wymagane TYLKO, gdy konto nie jest na haśle tymczasowym —
    # po resecie admina użytkownik zna wyłącznie hasło z e-maila.
    if not u.get("must_change_password"):
        old_password = _resolve_password(req.old_password, req.old_password_encrypted)
        if not _verify_password(old_password, u["password_hash"]):
            raise HTTPException(status_code=401, detail="Nieprawidłowe obecne hasło")

    await database.execute(
        update(users_t)
        .where(users_t.c.id == user_id)
        .values(
            password_hash=_hash_password(new_password),
            must_change_password=False,
            updated_at=datetime.now(timezone.utc),
        )
    )
    return {"success": True}


@router.post("/me/sync-device", response_model=ProelUserItem, summary="Dopisz urządzenie do konta")
async def sync_device(
    req: SyncDeviceRequest,
    user_id: int = Depends(proel_get_current_user_id),
):
    database, users_t = _db()
    u = await _fetch_me(user_id)
    now = datetime.now(timezone.utc)
    await database.execute(
        update(users_t)
        .where(users_t.c.id == user_id)
        .values(
            device_ids=_merge_device_ids(list(u.get("device_ids") or []), req.installation_id),
            device_infos=_merge_device_infos(u.get("device_infos"), req.installation_id, req.platform, req.app_version, now),
            updated_at=now,
        )
    )
    if req.installation_id:
        await _remove_device_from_other_users(req.installation_id, user_id)
    return _to_user_item(await _fetch_me(user_id))


# ─────────────────────────── admin (panel BAZA) ───────────────────────────
#
# Uwierzytelnianie jak cały panel admina BAZA: nagłówki aktora ProEl + lista
# `admin_settings.allowed_admins`. NIE token konta ProEl — admin panelu zwykle
# w ogóle nie ma konta ProEl.

async def _require_admin(actor) -> None:
    from app.proel_auth import is_admin

    if not await is_admin(actor.judge_id):
        raise HTTPException(403, detail={"code": "ADMIN_REQUIRED", "message": "Brak uprawnień"})


@router.get("/admin/list", summary="[admin] Lista kont ProEl")
async def admin_list_users(
    query: Optional[str] = Query(None, description="Szukaj w nazwisku, loginie, e-mailu, telefonie, nr sędziego"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    actor=Depends(proel_actor),
):
    await _require_admin(actor)
    database, users_t = _db()

    stmt = select(users_t)
    count_stmt = select(sa_func.count()).select_from(users_t)
    q = (query or "").strip().lower()
    if q:
        like = f"%{q}%"
        cond = or_(
            sa_func.lower(users_t.c.full_name).like(like),
            sa_func.lower(users_t.c.login).like(like),
            sa_func.lower(sa_func.coalesce(users_t.c.email, "")).like(like),
            sa_func.coalesce(users_t.c.phone, "").like(like),
            sa_func.coalesce(users_t.c.judge_id, "").like(like),
        )
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    total_row = await database.fetch_one(count_stmt)
    rows = await database.fetch_all(
        stmt.order_by(users_t.c.created_at.desc()).offset(offset).limit(limit)
    )
    return {
        "total": int(total_row[0]) if total_row else 0,
        "users": [_to_user_item(dict(r)).model_dump(mode="json") for r in rows],
    }


@router.get("/admin/{user_id}", summary="[admin] Szczegóły konta ProEl")
async def admin_get_user(user_id: int, actor=Depends(proel_actor)):
    await _require_admin(actor)
    u = await _fetch_me(user_id)
    item = _to_user_item(u).model_dump(mode="json")
    # Szczegóły ponad ProelUserItem — urządzenia z metadanymi; nigdy hash hasła.
    item["device_infos"] = _device_infos_dict(u.get("device_infos"))
    item["email_delivery_blocked"] = bool(u.get("email_delivery_blocked") or False)
    item["updated_at"] = u.get("updated_at").isoformat() if u.get("updated_at") else None
    return item


@router.post("/admin/{user_id}/toggle-active", summary="[admin] Zablokuj / odblokuj konto")
async def admin_toggle_active(user_id: int, actor=Depends(proel_actor)):
    await _require_admin(actor)
    database, users_t = _db()
    u = await _fetch_me(user_id)
    new_state = not bool(u.get("is_active", True))
    await database.execute(
        update(users_t)
        .where(users_t.c.id == user_id)
        .values(is_active=new_state, updated_at=datetime.now(timezone.utc))
    )
    logger.info("proel admin_toggle_active user_id=%s -> %s by=%s", user_id, new_state, actor.judge_id)
    return {"success": True, "is_active": new_state}


@router.post("/admin/{user_id}/reset-password", summary="[admin] Reset hasła — tymczasowe e-mailem")
async def admin_reset_password(user_id: int, actor=Depends(proel_actor)):
    await _require_admin(actor)
    database, users_t = _db()
    u = await _fetch_me(user_id)
    email = (u.get("email") or "").strip()
    if not email:
        raise HTTPException(
            400,
            detail={"code": "EMAIL_REQUIRED", "message": "Konto nie ma adresu e-mail — nie ma dokąd wysłać hasła."},
        )

    # 10 znaków bez mylących par (0/O, 1/l/I) — hasło i tak jest jednorazowe.
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
    temp_password = "".join(secrets.choice(alphabet) for _ in range(10))

    from app.proel_users.emails import EmailDeliveryError, send_new_password_email

    try:
        await send_new_password_email(email, u.get("full_name"), temp_password, u.get("login"))
    except EmailDeliveryError:
        # Hasła NIE zmieniamy, skoro nie dotarło — inaczej odcinamy człowieka
        # od konta bez wręczenia mu nowego klucza.
        raise HTTPException(
            503,
            detail={"code": "EMAIL_DELIVERY_FAILED", "message": "Nie udało się wysłać e-maila z hasłem. Hasło pozostało bez zmian."},
        )

    await database.execute(
        update(users_t)
        .where(users_t.c.id == user_id)
        .values(
            password_hash=_hash_password(temp_password),
            must_change_password=True,
            updated_at=datetime.now(timezone.utc),
        )
    )
    logger.info("proel admin_reset_password user_id=%s by=%s", user_id, actor.judge_id)
    return {"success": True, "sent_to": email}


@router.delete("/admin/{user_id}", summary="[admin] Dezaktywacja i anonimizacja konta")
async def admin_delete_user(user_id: int, actor=Depends(proel_actor)):
    """Miękkie usunięcie: konto zostaje w bazie (spójność ewentualnych śladów),
    ale traci dane osobowe i możliwość logowania."""
    await _require_admin(actor)
    database, users_t = _db()
    await _fetch_me(user_id)
    now = datetime.now(timezone.utc)
    await database.execute(
        update(users_t)
        .where(users_t.c.id == user_id)
        .values(
            full_name="— konto usunięte —",
            province=None,
            city=None,
            phone=None,
            email=None,
            email_normalized=None,
            email_verified=False,
            email_verified_at=None,
            judge_id=None,
            login=f"deleted_{user_id}_{secrets.token_hex(4)}",
            password_hash=_hash_password(secrets.token_hex(16)),
            device_ids=[],
            device_infos={},
            is_active=False,
            updated_at=now,
        )
    )
    logger.info("proel admin_delete_user user_id=%s by=%s", user_id, actor.judge_id)
    return {"success": True}
